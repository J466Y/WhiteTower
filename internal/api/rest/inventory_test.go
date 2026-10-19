package rest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/J466Y/WhiteTower/api/events"
	"github.com/J466Y/WhiteTower/internal/api/rest/gen"
	"github.com/J466Y/WhiteTower/internal/api/rest/problem"
	"github.com/J466Y/WhiteTower/internal/audit"
	"github.com/J466Y/WhiteTower/internal/authz"
	"github.com/J466Y/WhiteTower/internal/inventory"
	"github.com/J466Y/WhiteTower/internal/platform/clock/clocktest"
	"github.com/J466Y/WhiteTower/internal/platform/db/dbtest"
)

// unbuilt lists the operations of plan P1-04 whose server side is not built
// yet. The pull request that builds one removes it from here.
var unbuilt = []string{
	"exportAgents", "getAgentActions", "listAgentTransitions", "transitionAgent", "listAgentInstances",
	"listAgentOwners", "reassignAgentOwner", "addAgentDelegate", "removeAgentDelegate",
	"requestOwnershipTransfer", "cancelOwnershipTransfer", "acceptOwnershipTransfer",
	"declineOwnershipTransfer", "listAgentReviews", "listReviews", "getReview",
	"completeReview", "signOffReview", "listInboxItems",
}

// An operation that is agreed but not built answers not_implemented to a
// caller the authorizer lets through, whatever the request holds.
func TestAgreedOperationsAnswerNotImplementedUntilBuilt(t *testing.T) {
	permitted := &allow{ops: map[string]bool{}}
	for _, id := range unbuilt {
		permitted.ops[id] = true
	}
	opts := options(io.Discard)
	opts.Authorizer = permitted
	h := Handler(opts)
	ops := operations()
	for _, id := range unbuilt {
		t.Run(id, func(t *testing.T) {
			op, ok := ops[operationKey(id)]
			if !ok {
				t.Fatalf("%s is not an operation of the document", id)
			}
			path, body := target(op)
			problemOf(t, call(h, op.Method, path, olivia, nil, body()), problem.NotImplemented)
		})
	}
}

// The agents and use cases through the API: what each answer carries, and
// how each refusal of the inventory becomes a problem.
func TestTheInventoryThroughTheAPI(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.New(t).Open(t)
	catalog, err := audit.LoadCatalog(events.Files)
	if err != nil {
		t.Fatal(err)
	}
	const otto = "0192f2c4-8d1e-7c3a-9b2f-5e1d2c3b4a60"
	for id, name := range map[string]string{olivia: "Olivia Owner", otto: "Otto Owner"} {
		if _, err := pool.Exec(ctx, `INSERT INTO whitetower.principals (id, kind, issuer, subject, display_name)
			VALUES ($1, 'human', 'https://idp.example.com', $2, $3)`, uuid.MustParse(id), id, name); err != nil {
			t.Fatal(err)
		}
	}
	clk := clocktest.New(time.Date(2026, 10, 19, 9, 0, 0, 0, time.UTC))
	opts := options(io.Discard)
	opts.Authorizer = authz.NewAuthorizer()
	opts.Inventory = inventory.New(inventory.Options{
		DB: pool, Clock: clk, Writer: audit.NewWriter(catalog, clk), Authorizer: opts.Authorizer, Versions: inventory.SequenceVersions{},
	})
	h := Handler(opts)
	send := func(method, path, as, body string, header http.Header) result {
		var r io.Reader
		if body != "" {
			r = strings.NewReader(body)
		}
		return call(h, method, BasePath+path, as, header, r)
	}
	ifMatch := func(etag string) http.Header { return http.Header{"If-Match": []string{etag}} }

	res := send(http.MethodPost, "/use-cases", olivia, `{"title":"Invoice triage","description":"Sorts invoices.",
		"businessJustification":"Saves the finance team a day a week.","dataCategories":["financial_data"]}`, nil)
	var uc gen.UseCase
	if res.status != http.StatusCreated || res.header.Get("ETag") != `"1"` || json.Unmarshal(res.body, &uc) != nil {
		t.Fatalf("createUseCase: %d %s %s", res.status, res.header.Get("ETag"), res.body)
	}
	proposal := fmt.Sprintf(`{"slug":"invoice-triage","name":"Invoice triage","description":"Sorts invoices.",
		"kind":"in_house","framework":"langgraph","deploymentLocation":"eu-west-1","environments":["production"],
		"riskTier":"high","dataCategories":["financial_data"],"useCaseId":%q}`, uc.Id)

	res = send(http.MethodPost, "/agents", olivia, proposal, nil)
	var agent gen.Agent
	if res.status != http.StatusCreated || res.header.Get("ETag") != `"1"` || json.Unmarshal(res.body, &agent) != nil {
		t.Fatalf("proposeAgent: %d %s %s", res.status, res.header.Get("ETag"), res.body)
	}
	if agent.PrimaryOwner.Id.String() != olivia || agent.LifecycleState != gen.LifecycleStateDraft || agent.RunState != gen.Running ||
		agent.Coverage != gen.C0 || agent.Labels == nil || agent.Delegates == nil {
		t.Errorf("proposeAgent: %s", res.body)
	}
	problemOf(t, send(http.MethodPost, "/agents", olivia, proposal, nil), problem.Conflict)
	problemOf(t, send(http.MethodPost, "/agents", olivia, strings.Replace(proposal, `"framework":"langgraph",`, "", 1), nil), problem.BadRequest)

	path := "/agents/" + agent.Id.String()
	if res = send(http.MethodGet, path, olivia, "", nil); res.status != http.StatusOK || res.header.Get("ETag") != `"1"` {
		t.Fatalf("getAgent: %d %s %s", res.status, res.header.Get("ETag"), res.body)
	}
	problemOf(t, send(http.MethodGet, "/agents/"+uuid.NewString(), olivia, "", nil), problem.NotFound)

	edit := `{"name":"Invoice sorter"}`
	problemOf(t, send(http.MethodPatch, path, olivia, edit, nil), problem.PreconditionRequired)
	problemOf(t, send(http.MethodPatch, path, olivia, edit, ifMatch(`"7"`)), problem.PreconditionFailed)
	problemOf(t, send(http.MethodPatch, path, otto, edit, ifMatch(`"1"`)), problem.Forbidden)
	if res = send(http.MethodPatch, path, olivia, edit, ifMatch(`"1"`)); res.status != http.StatusOK || res.header.Get("ETag") != `"2"` {
		t.Fatalf("editAgent: %d %s %s", res.status, res.header.Get("ETag"), res.body)
	}

	var list gen.AgentList
	if res = send(http.MethodGet, "/agents?limit=1", olivia, "", nil); res.status != http.StatusOK || json.Unmarshal(res.body, &list) != nil ||
		len(list.Agents) != 1 || list.NextCursor != nil {
		t.Fatalf("listAgents: %d %s", res.status, res.body)
	}
	problemOf(t, send(http.MethodGet, "/agents?state=draft", olivia, "", nil), problem.NotImplemented)
	problemOf(t, send(http.MethodGet, "/agents?cursor=bm9wZQ", olivia, "", nil), problem.InvalidCursor)

	useCase := "/use-cases/" + uc.Id.String()
	if res = send(http.MethodGet, useCase, olivia, "", nil); res.status != http.StatusOK || res.header.Get("ETag") != `"1"` {
		t.Fatalf("getUseCase: %d %s", res.status, res.body)
	}
	problemOf(t, send(http.MethodPatch, useCase, otto, `{"title":"Invoice sorting"}`, ifMatch(`"1"`)), problem.Forbidden)
	if res = send(http.MethodPatch, useCase, olivia, `{"title":"Invoice sorting"}`, ifMatch(`"1"`)); res.status != http.StatusOK || res.header.Get("ETag") != `"2"` {
		t.Fatalf("editUseCase: %d %s", res.status, res.body)
	}
	for _, p := range []string{"/use-cases", useCase + "/decisions", "/data-categories"} {
		if res = send(http.MethodGet, p, olivia, "", nil); res.status != http.StatusOK {
			t.Errorf("%s: %d %s", p, res.status, res.body)
		}
	}
	problemOf(t, send(http.MethodGet, "/use-cases?status=draft", olivia, "", nil), problem.NotImplemented)
}
