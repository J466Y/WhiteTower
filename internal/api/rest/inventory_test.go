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
	"github.com/J466Y/WhiteTower/internal/govstate"
	"github.com/J466Y/WhiteTower/internal/inventory"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/clock/clocktest"
	"github.com/J466Y/WhiteTower/internal/platform/db/dbtest"
	"github.com/J466Y/WhiteTower/internal/platform/notify"
)

// Otto has the owner role, as Olivia does; Omar is an operator.
const (
	otto = "0192f2c4-8d1e-7c3a-9b2f-5e1d2c3b4a60"
	omar = "0192f2c4-8d1e-7c3a-9b2f-5e1d2c3b4a61"
)

// useCaseJSON is a use case to create, and proposalJSON an agent that it
// justifies.
const useCaseJSON = `{"title":"Invoice triage","description":"Sorts invoices.",
	"businessJustification":"Saves the finance team a day a week.","dataCategories":["financial_data"]}`

func proposalJSON(useCase uuid.UUID) string {
	return fmt.Sprintf(`{"slug":"invoice-triage","name":"Invoice triage","description":"Sorts invoices.",
		"kind":"in_house","framework":"langgraph","deploymentLocation":"eu-west-1","environments":["production"],
		"riskTier":"high","dataCategories":["financial_data"],"useCaseId":%q}`, useCase)
}

// inventoryOptions are the options of a server whose inventory has a
// database of its own, where each of the people is a principal with the
// owner role, from the IdP group wt-owner.
func inventoryOptions(t *testing.T, people map[string]string) Options {
	t.Helper()
	ctx := context.Background()
	pool := dbtest.New(t).Open(t)
	catalog, err := audit.LoadCatalog(events.Files)
	if err != nil {
		t.Fatal(err)
	}
	for id, name := range people {
		if _, err := pool.Exec(ctx, `INSERT INTO whitetower.principals (id, kind, issuer, subject, display_name, idp_groups)
			VALUES ($1, 'human', 'https://idp.example.com', $2, $3, '{wt-owner}')`, uuid.MustParse(id), id, name); err != nil {
			t.Fatal(err)
		}
	}
	clk := clocktest.New(time.Date(2026, 10, 19, 9, 0, 0, 0, time.UTC))
	opts := options(io.Discard)
	opts.Authorizer = authz.NewAuthorizer()
	opts.Inventory = inventory.New(inventory.Options{
		DB: pool, Clock: clk, Writer: audit.NewWriter(catalog, clk), Authorizer: opts.Authorizer,
		Versions:    govstate.NewVersions(notify.NewMemory(), opts.Logger),
		RoleMapping: map[string]string{"wt-owner": "owner"},
	})
	return opts
}

// sender sends requests to the handler, as the principal that "as" names.
func sender(h http.Handler) func(method, path, as, body string, header http.Header) result {
	return func(method, path, as, body string, header http.Header) result {
		var r io.Reader
		if body != "" {
			r = strings.NewReader(body)
		}
		return call(h, method, BasePath+path, as, header, r)
	}
}

func ifMatch(etag string) http.Header { return http.Header{"If-Match": []string{etag}} }

// unbuilt lists the operations of plan P1-04 whose server side is not built
// yet. The pull request that builds one removes it from here.
var unbuilt = []string{
	"exportAgents", "getAgentActions", "listAgentTransitions", "transitionAgent", "listAgentInstances",
	"listAgentReviews", "listReviews", "getReview", "completeReview", "signOffReview", "listInboxItems",
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
	send := sender(Handler(inventoryOptions(t, map[string]string{olivia: "Olivia Owner", otto: "Otto Owner"})))

	res := send(http.MethodPost, "/use-cases", olivia, useCaseJSON, nil)
	var uc gen.UseCase
	if res.status != http.StatusCreated || res.header.Get("ETag") != `"1"` || json.Unmarshal(res.body, &uc) != nil {
		t.Fatalf("createUseCase: %d %s %s", res.status, res.header.Get("ETag"), res.body)
	}
	proposal := proposalJSON(uc.Id)

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

// Owners, delegates and transfers through the API: what each answer carries,
// and how each refusal becomes a problem.
func TestOwnershipThroughTheAPI(t *testing.T) {
	opts := inventoryOptions(t, map[string]string{olivia: "Olivia Owner", otto: "Otto Owner", omar: "Omar Operator"})
	send := sender(Handler(opts))
	operator := opts
	operator.Authenticator = fixedAuthenticator{p: auth.Principal{ID: omar, Kind: auth.Human, Name: "Omar Operator", Roles: []string{"operator"}}}
	asOperator := sender(Handler(operator))

	res := send(http.MethodPost, "/use-cases", olivia, useCaseJSON, nil)
	var uc gen.UseCase
	if res.status != http.StatusCreated || json.Unmarshal(res.body, &uc) != nil {
		t.Fatalf("createUseCase: %d %s", res.status, res.body)
	}
	res = send(http.MethodPost, "/agents", olivia, proposalJSON(uc.Id), nil)
	var agent gen.Agent
	if res.status != http.StatusCreated || json.Unmarshal(res.body, &agent) != nil {
		t.Fatalf("proposeAgent: %d %s", res.status, res.body)
	}
	path := "/agents/" + agent.Id.String()
	etag := func() string { return send(http.MethodGet, path, olivia, "", nil).header.Get("ETag") }
	principal := func(id string) string { return fmt.Sprintf(`{"principalId":%q}`, id) }

	before := etag()
	res = send(http.MethodPost, path+"/delegates", olivia, principal(otto), nil)
	var assignment gen.OwnerAssignment
	if res.status != http.StatusCreated || json.Unmarshal(res.body, &assignment) != nil ||
		assignment.Role != gen.Delegate || assignment.Principal.Id.String() != otto || etag() == before {
		t.Fatalf("addAgentDelegate: %d %s; the agent's ETag must change", res.status, res.body)
	}
	problemOf(t, send(http.MethodPost, path+"/delegates", olivia, principal(otto), nil), problem.Conflict)
	problemOf(t, send(http.MethodPost, path+"/delegates", olivia, principal(uuid.NewString()), nil), problem.BadRequest)
	problemOf(t, send(http.MethodDelete, path+"/delegates/"+otto, olivia, "", nil), problem.BadRequest)
	if res = send(http.MethodDelete, path+"/delegates/"+otto+"?reason=moved+on", olivia, "", nil); res.status != http.StatusNoContent {
		t.Fatalf("removeAgentDelegate: %d %s", res.status, res.body)
	}
	problemOf(t, send(http.MethodDelete, path+"/delegates/"+otto+"?reason=again", olivia, "", nil), problem.NotFound)

	offer := func() string {
		t.Helper()
		res := send(http.MethodPost, path+"/ownership-transfers", olivia, principal(otto), nil)
		var transfer gen.OwnershipTransfer
		if res.status != http.StatusCreated || json.Unmarshal(res.body, &transfer) != nil ||
			transfer.Status != gen.OwnershipTransferStatusPending || transfer.To.Id.String() != otto {
			t.Fatalf("requestOwnershipTransfer: %d %s", res.status, res.body)
		}
		return path + "/ownership-transfers/" + transfer.Id.String()
	}
	transfer := offer()
	problemOf(t, send(http.MethodPost, path+"/ownership-transfers", olivia, principal(otto), nil), problem.Conflict)
	problemOf(t, send(http.MethodPost, path+"/ownership-transfers", otto, principal(olivia), nil), problem.Forbidden)
	var got gen.Agent
	if res = send(http.MethodGet, path, olivia, "", nil); json.Unmarshal(res.body, &got) != nil ||
		got.PendingOwnershipTransfer == nil || path+"/ownership-transfers/"+got.PendingOwnershipTransfer.Id.String() != transfer {
		t.Fatalf("getAgent: %s", res.body)
	}
	problemOf(t, send(http.MethodPost, transfer+"/decline", olivia, "", nil), problem.Forbidden)
	if res = send(http.MethodPost, transfer+"/decline", otto, "", nil); res.status != http.StatusOK || !strings.Contains(string(res.body), `"status":"declined"`) {
		t.Fatalf("declineOwnershipTransfer: %d %s", res.status, res.body)
	}
	problemOf(t, send(http.MethodPost, transfer+"/accept", otto, "", nil), problem.Conflict)
	problemOf(t, send(http.MethodDelete, transfer, olivia, "", nil), problem.Conflict)
	problemOf(t, send(http.MethodPost, path+"/ownership-transfers/"+uuid.NewString()+"/accept", otto, "", nil), problem.NotFound)

	if res = send(http.MethodDelete, offer(), olivia, "", nil); res.status != http.StatusNoContent {
		t.Fatalf("cancelOwnershipTransfer: %d %s", res.status, res.body)
	}
	if res = send(http.MethodPost, offer()+"/accept", otto, "", nil); res.status != http.StatusOK || !strings.Contains(string(res.body), `"status":"accepted"`) {
		t.Fatalf("acceptOwnershipTransfer: %d %s", res.status, res.body)
	}

	reassign := `{"principalId":"` + olivia + `","reason":"Otto moved to another team"}`
	problemOf(t, send(http.MethodPut, path+"/primary-owner", otto, reassign, ifMatch(etag())), problem.Forbidden)
	problemOf(t, asOperator(http.MethodPut, path+"/primary-owner", "", reassign, nil), problem.PreconditionRequired)
	problemOf(t, asOperator(http.MethodPut, path+"/primary-owner", "", reassign, ifMatch(`"1"`)), problem.PreconditionFailed)
	problemOf(t, asOperator(http.MethodPut, path+"/primary-owner", "", `{"principalId":"`+olivia+`","reason":""}`, ifMatch(etag())), problem.BadRequest)
	current := etag()
	res = asOperator(http.MethodPut, path+"/primary-owner", "", reassign, ifMatch(current))
	if res.status != http.StatusOK || res.header.Get("ETag") == current || json.Unmarshal(res.body, &got) != nil || got.PrimaryOwner.Id.String() != olivia {
		t.Fatalf("reassignAgentOwner: %d %s %s", res.status, res.header.Get("ETag"), res.body)
	}

	var history []string
	for query := "?limit=3"; ; {
		var page gen.OwnerAssignmentList
		if res = send(http.MethodGet, path+"/owners"+query, olivia, "", nil); res.status != http.StatusOK || json.Unmarshal(res.body, &page) != nil {
			t.Fatalf("listAgentOwners: %d %s", res.status, res.body)
		}
		for _, o := range page.Owners {
			history = append(history, fmt.Sprintf("%s %s %s", *o.Principal.DisplayName, o.Role, value(o.EndReason)))
		}
		if page.NextCursor == nil {
			break
		}
		query = "?limit=3&cursor=" + *page.NextCursor
	}
	// The current assignment, then those that ended, the latest assigned
	// first.
	want := fmt.Sprint([]string{
		"Olivia Owner primary ",
		"Otto Owner primary Otto moved to another team",
		"Otto Owner delegate moved on",
		"Olivia Owner primary ownership transferred",
	})
	if fmt.Sprint(history) != want {
		t.Errorf("listAgentOwners: %v, want %v", history, want)
	}
	problemOf(t, send(http.MethodGet, path+"/owners?cursor=bm9wZQ", olivia, "", nil), problem.InvalidCursor)
	problemOf(t, send(http.MethodGet, "/agents/"+uuid.NewString()+"/owners", olivia, "", nil), problem.NotFound)
}
