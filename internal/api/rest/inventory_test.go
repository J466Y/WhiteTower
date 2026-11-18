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
	"github.com/J466Y/WhiteTower/internal/platform/db"
	"github.com/J466Y/WhiteTower/internal/platform/db/dbtest"
	"github.com/J466Y/WhiteTower/internal/platform/notify"
)

// Otto has the owner role, as Olivia does; Omar is an operator, and Alex is
// on the advisory committee.
const (
	otto = "0192f2c4-8d1e-7c3a-9b2f-5e1d2c3b4a60"
	omar = "0192f2c4-8d1e-7c3a-9b2f-5e1d2c3b4a61"
	alex = "0192f2c4-8d1e-7c3a-9b2f-5e1d2c3b4a62"
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
	opts, _ := inventoryStore(t, people)
	return opts
}

// inventoryStore returns the options of inventoryOptions and the inventory's
// database, where a test changes rows the way a later plan would.
func inventoryStore(t *testing.T, people map[string]string) (Options, *db.DB) {
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
		Versions:      govstate.NewVersions(notify.NewMemory(), opts.Logger),
		Policies:      inventory.NoAgentPolicies{},
		SelectorHalts: inventory.NoSelectorHalts{},
		Tooling:       inventory.NoTooling{},
		RoleMapping:   map[string]string{"wt-owner": "owner"},
	})
	return opts, pool
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

// unbuilt lists the operations of plans P1-04 and P1-16 whose server side is
// not built yet. The pull request that builds one removes it from here.
var unbuilt = []string{
	"exportAgents", "listAgentInstances", "listInboxItems",
	// P1-16: the catalog, its blocks and usage rules, and agents' tooling.
	"listCatalogServers", "getCatalogServer", "approveCatalogServer", "declineCatalogServer",
	"listCatalogTools", "getCatalogTool", "approveCatalogTool", "declineCatalogTool", "getToolDefinition",
	"listCatalogModels", "getCatalogModel", "approveCatalogModel", "declineCatalogModel", "declinePendingFromAgent",
	"listCatalogBlocks", "issueCatalogBlock", "getCatalogBlock",
	"requestCatalogUnblock", "approveCatalogUnblock", "declineCatalogUnblock", "compileUsageRules",
	"listAgentTooling", "disableAgentTooling", "listAgentToolingRequests", "requestAgentTooling",
	"approveAgentToolingRequest", "declineAgentToolingRequest", "getAgentDeclaredTooling", "declareAgentTooling",
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

// Label keys through the API: the keys that the decision request's schema
// allows reach the agent unchanged, and the others are a bad request
// (CORE-17).
func TestLabelKeysThroughTheAPI(t *testing.T) {
	send := sender(Handler(inventoryOptions(t, map[string]string{olivia: "Olivia Owner"})))
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
	path, etag := "/agents/"+agent.Id.String(), res.header.Get("ETag")
	for _, tc := range []struct {
		name, key string
		valid     bool
	}{
		{name: "one character", key: "a", valid: true},
		{name: "a word", key: "team", valid: true},
		{name: "inner punctuation", key: "a.b/c-d_e", valid: true},
		{name: "63 characters", key: strings.Repeat("a.", 31) + "a", valid: true},

		{name: "a leading dot", key: ".team"},
		{name: "a trailing dot", key: "team."},
		{name: "a leading underscore", key: "_team"},
		{name: "a trailing underscore", key: "team_"},
		{name: "a leading slash", key: "/team"},
		{name: "a trailing slash", key: "team/"},
		{name: "a leading hyphen", key: "-team"},
		{name: "a trailing hyphen", key: "team-"},
		{name: "64 characters", key: strings.Repeat("a.", 31) + "aa"},
		{name: "an uppercase letter", key: "teAm"},
		{name: "an empty key", key: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := send(http.MethodPatch, path, olivia, fmt.Sprintf(`{"labels":{%q:"finance"}}`, tc.key), ifMatch(etag))
			if res.status == http.StatusOK {
				etag = res.header.Get("ETag")
			}
			if !tc.valid {
				problemOf(t, res, problem.BadRequest)
				return
			}
			var edited gen.Agent
			if res.status != http.StatusOK || json.Unmarshal(res.body, &edited) != nil || edited.Labels[tc.key] != "finance" {
				t.Fatalf("editAgent: %d %s", res.status, res.body)
			}
		})
	}
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

// Security test ST-23: Every guarded transition of a proposal is refused through the API when its guard fails, validating one's own use case included
func TestTheProposalPhaseThroughTheAPI(t *testing.T) {
	opts, pool := inventoryStore(t, map[string]string{olivia: "Olivia Owner", alex: "Alex Advisory"})
	send := sender(Handler(opts))
	as := func(p auth.Principal) func(method, path, as, body string, header http.Header) result {
		o := opts
		o.Authenticator = fixedAuthenticator{p: p}
		return sender(Handler(o))
	}
	asAlex := as(auth.Principal{ID: alex, Kind: auth.Human, Name: "Alex Advisory", Roles: []string{"advisory"}})
	// Olivia, who wrote the proposal and its use case, also sits on the
	// advisory committee.
	asOliviaAdvisory := as(auth.Principal{ID: olivia, Kind: auth.Human, Name: "Olivia Owner", Roles: []string{"owner", "advisory"}})
	set := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
			t.Fatal(err)
		}
	}

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
	transitions := path + "/transitions"
	etag := func() http.Header { return ifMatch(send(http.MethodGet, path, olivia, "", nil).header.Get("ETag")) }
	act := func(action, comment string) string {
		return fmt.Sprintf(`{"action":%q,"comment":%q}`, action, comment)
	}
	// guard checks that the action is refused while the row that spoil
	// changes breaks the guard, and restores the row.
	guard := func(send func(method, path, as, body string, header http.Header) result, body, name, spoil, restore string, arg any) {
		t.Helper()
		set(spoil, arg)
		if p := problemOf(t, send(http.MethodPost, transitions, olivia, body, etag()), problem.Conflict); !strings.Contains(p.Detail, name) {
			t.Errorf("the detail %q does not name the guard %s", p.Detail, name)
		}
		set(restore, arg)
	}
	inactive := `UPDATE whitetower.principals SET status = 'inactive' WHERE id = $1`
	active := `UPDATE whitetower.principals SET status = 'active' WHERE id = $1`
	rejected := `UPDATE whitetower.use_cases SET status = 'rejected' WHERE id = $1`

	// T2 needs complete metadata, an active owner and a use case that is not
	// rejected.
	submit := `{"action":"submit"}`
	guard(send, submit, "metadata_complete", `UPDATE whitetower.agents SET framework = NULL WHERE id = $1`,
		`UPDATE whitetower.agents SET framework = 'langgraph' WHERE id = $1`, agent.Id)
	guard(send, submit, "owner_active", inactive, active, olivia)
	guard(send, submit, "use_case_not_rejected", rejected, `UPDATE whitetower.use_cases SET status = 'draft' WHERE id = $1`, uc.Id)
	problemOf(t, send(http.MethodPost, transitions, olivia, submit, nil), problem.PreconditionRequired)
	problemOf(t, send(http.MethodPost, transitions, olivia, submit, ifMatch(`"9"`)), problem.PreconditionFailed)
	if res = send(http.MethodPost, transitions, olivia, submit, etag()); res.status != http.StatusOK ||
		!strings.Contains(string(res.body), `"lifecycleState":"proposed"`) || res.header.Get("ETag") != `"2"` {
		t.Fatalf("submit: %d %s %s", res.status, res.header.Get("ETag"), res.body)
	}

	// T4 to T6 are refused to whoever wrote the proposal or its use case, and
	// need a comment; T6 also needs a use case that is neither prohibited nor
	// rejected, and an active owner.
	for _, action := range []string{"request_changes", "reject", "validate"} {
		problemOf(t, asOliviaAdvisory(http.MethodPost, transitions, "", act(action, "My own."), etag()), problem.Forbidden)
		problemOf(t, asAlex(http.MethodPost, transitions, "", act(action, " "), etag()), problem.BadRequest)
	}
	validate := act("validate", "The use case holds.")
	guard(asAlex, validate, "use_case_not_prohibited", `UPDATE whitetower.use_cases SET ai_act_classification = 'prohibited' WHERE id = $1`,
		`UPDATE whitetower.use_cases SET ai_act_classification = 'not_assessed' WHERE id = $1`, uc.Id)
	guard(asAlex, validate, "use_case_not_rejected", rejected, `UPDATE whitetower.use_cases SET status = 'submitted' WHERE id = $1`, uc.Id)
	guard(asAlex, validate, "owner_active", inactive, active, olivia)

	// Actions that the agent's state refuses, or that White Tower takes.
	problemOf(t, send(http.MethodPost, transitions, olivia, submit, etag()), problem.Conflict)
	problemOf(t, send(http.MethodPost, transitions, olivia, `{"action":"mark_ready"}`, etag()), problem.BadRequest)
	problemOf(t, send(http.MethodPost, transitions, olivia, `{"action":"activate"}`, etag()), problem.Conflict)
	if res = asAlex(http.MethodPost, transitions, "", validate, etag()); res.status != http.StatusOK ||
		!strings.Contains(string(res.body), `"lifecycleState":"validated"`) {
		t.Fatalf("validate: %d %s", res.status, res.body)
	}

	// The history, newest first, a page at a time.
	var page gen.TransitionList
	if res = send(http.MethodGet, transitions+"?limit=2", olivia, "", nil); res.status != http.StatusOK || json.Unmarshal(res.body, &page) != nil ||
		len(page.Transitions) != 2 || page.NextCursor == nil {
		t.Fatalf("listAgentTransitions: %d %s", res.status, res.body)
	}
	latest := page.Transitions[0]
	if latest.Transition != "T6" || latest.Action != gen.LifecycleActionValidate || *latest.FromState != gen.LifecycleStateProposed ||
		latest.Actor.Type != gen.ActorTypeHuman || latest.Actor.Id.String() != alex || *latest.Actor.DisplayName != "Alex Advisory" ||
		*latest.Comment != "The use case holds." || page.Transitions[1].Transition != "T2" {
		t.Errorf("listAgentTransitions: %s", res.body)
	}
	var last gen.TransitionList
	if res = send(http.MethodGet, transitions+"?cursor="+*page.NextCursor, olivia, "", nil); res.status != http.StatusOK ||
		json.Unmarshal(res.body, &last) != nil || len(last.Transitions) != 1 || last.Transitions[0].FromState != nil || last.NextCursor != nil {
		t.Fatalf("listAgentTransitions, last page: %d %s", res.status, res.body)
	}
	problemOf(t, send(http.MethodGet, "/agents/"+uuid.NewString()+"/transitions", olivia, "", nil), problem.NotFound)
}

// Security test ST-23: Activation without the invariant of active, and reinstatement without its conditions, are refused through the API, each guard named
func TestIntoAndOutOfServiceThroughTheAPI(t *testing.T) {
	opts, pool := inventoryStore(t, map[string]string{olivia: "Olivia Owner", alex: "Alex Advisory", omar: "Omar Operator"})
	send := sender(Handler(opts))
	as := func(p auth.Principal) func(method, path, as, body string, header http.Header) result {
		o := opts
		o.Authenticator = fixedAuthenticator{p: p}
		return sender(Handler(o))
	}
	asAlex := as(auth.Principal{ID: alex, Kind: auth.Human, Name: "Alex Advisory", Roles: []string{"advisory"}})
	asOmar := as(auth.Principal{ID: omar, Kind: auth.Human, Name: "Omar Operator", Roles: []string{"operator"}})
	asBot := as(auth.Principal{ID: uuid.NewString(), Kind: auth.ServiceAccount, Name: "Deploy bot", Roles: []string{"operator"}})
	set := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
			t.Fatal(err)
		}
	}

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
	transitions := path + "/transitions"
	etag := func() http.Header { return ifMatch(send(http.MethodGet, path, olivia, "", nil).header.Get("ETag")) }
	take := func(send func(method, path, as, body string, header http.Header) result, action, state string) {
		t.Helper()
		body := fmt.Sprintf(`{"action":%q,"comment":"Reviewed."}`, action)
		if res := send(http.MethodPost, transitions, olivia, body, etag()); res.status != http.StatusOK ||
			!strings.Contains(string(res.body), `"lifecycleState":"`+state+`"`) {
			t.Fatalf("%s: %d %s", action, res.status, res.body)
		}
	}
	// refusedBy checks that the action is refused, and that the detail names
	// each guard, while the rows that spoil changes break them.
	refusedBy := func(send func(method, path, as, body string, header http.Header) result, action string, guards []string, spoil, restore string, arg any) {
		t.Helper()
		if spoil != "" {
			set(spoil, arg)
			defer set(restore, arg)
		}
		p := problemOf(t, send(http.MethodPost, transitions, olivia, `{"action":"`+action+`","comment":"Reviewed."}`, etag()), problem.Conflict)
		for _, g := range guards {
			if !strings.Contains(p.Detail, g) {
				t.Errorf("%s: the detail %q does not name the guard %s", action, p.Detail, g)
			}
		}
	}
	actions := func(send func(method, path, as, body string, header http.Header) result, want string) {
		t.Helper()
		res := send(http.MethodGet, path+"/actions", olivia, "", nil)
		var got gen.AgentActions
		if res.status != http.StatusOK || json.Unmarshal(res.body, &got) != nil {
			t.Fatalf("getAgentActions: %d %s", res.status, res.body)
		}
		if s := fmt.Sprint(got.LifecycleState, " ", got.Actions); s != want {
			t.Errorf("getAgentActions: %s, want %s", s, want)
		}
	}
	inactive, active := `UPDATE whitetower.principals SET status = 'inactive' WHERE id = $1`, `UPDATE whitetower.principals SET status = 'active' WHERE id = $1`
	halted := `UPDATE whitetower.governance_state SET run_state = 'halted', agent_halt_ids = ARRAY[gen_random_uuid()],
		state_version = whitetower.next_governance_version() WHERE agent_id = $1`
	running := `UPDATE whitetower.governance_state SET run_state = 'running', agent_halt_ids = '{}',
		state_version = whitetower.next_governance_version() WHERE agent_id = $1`

	take(send, "submit", "proposed")
	take(asAlex, "validate", "validated")
	actions(send, "validated [{suspend true true [] T10} {retire true true [] T14}]")
	actions(asBot, "validated [{suspend true true [] T10} {retire false true [permission] T14}]")

	// T13 needs an active owner, no overdue review and no halt.
	take(asOmar, "suspend", "suspended")
	problemOf(t, send(http.MethodPost, transitions, olivia, `{"action":"reinstate","comment":"My own."}`, etag()), problem.Forbidden)
	refusedBy(asAlex, "reinstate", []string{"owner_active"}, inactive, active, olivia)
	refusedBy(asAlex, "reinstate", []string{"review_not_overdue"},
		`INSERT INTO whitetower.reviews (id, agent_id, due_at, grace_ends_at, signoff_required)
		 VALUES (gen_random_uuid(), $1, '2026-01-01', '2026-01-01', false)`,
		`UPDATE whitetower.reviews SET status = 'cancelled' WHERE agent_id = $1`, agent.Id)
	refusedBy(asAlex, "reinstate", []string{"not_halted"}, halted, running, agent.Id)
	take(asAlex, "reinstate", "validated")

	// The agent becomes ready, as T7 will make it (part 4c). No agent policy
	// is active until plan P1-06 brings policies, so T9 is refused, with every
	// other guard of the invariant of active that does not hold; a ready agent
	// always has its harness.
	set(`UPDATE whitetower.agents SET harness = '{"description": "A container."}', lifecycle_state = 'ready', version = version + 1 WHERE id = $1`, agent.Id)
	problemOf(t, asBot(http.MethodPost, transitions, "", `{"action":"activate"}`, etag()), problem.Forbidden)
	refusedBy(send, "activate", []string{"agent_policy_active"}, "", "", nil)
	refusedBy(send, "activate", []string{"agent_policy_active", "owner_active"}, inactive, active, olivia)
	refusedBy(asOmar, "activate", []string{"agent_policy_active", "use_case_validated"},
		`UPDATE whitetower.use_cases SET status = 'submitted' WHERE id = $1`, `UPDATE whitetower.use_cases SET status = 'validated' WHERE id = $1`, uc.Id)
	refusedBy(asOmar, "activate", []string{"agent_policy_active", "not_halted"}, halted, running, agent.Id)
	actions(asOmar, "ready [{activate false false [agent_policy_active] T9} {suspend true true [] T10} {retire true true [] T14}]")

	// An agent suspended from ready returns there only with an active agent
	// policy.
	take(asOmar, "suspend", "suspended")
	refusedBy(asAlex, "reinstate", []string{"previous_state_invariants_hold"}, "", "", nil)
	actions(asAlex, "suspended [{reinstate false true [previous_state_invariants_hold] T13} {retire true true [] T14}]")
	take(asAlex, "retire", "retired")
	actions(send, "retired []")
	problemOf(t, send(http.MethodGet, "/agents/"+uuid.NewString()+"/actions", olivia, "", nil), problem.NotFound)
}

// Reviews through the API: what each answer carries, with its ETag, and how
// each refusal of the inventory becomes a problem.
func TestReviewsThroughTheAPI(t *testing.T) {
	opts, pool := inventoryStore(t, map[string]string{olivia: "Olivia Owner", alex: "Alex Advisory"})
	send := sender(Handler(opts))
	alexOpts := opts
	alexOpts.Authenticator = fixedAuthenticator{p: auth.Principal{ID: alex, Kind: auth.Human, Name: "Alex Advisory", Roles: []string{"advisory"}}}
	asAlex := sender(Handler(alexOpts))
	set := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
			t.Fatal(err)
		}
	}
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
	// The agent comes into service with its first review, as T9 would bring
	// it: no agent policy is active until plan P1-06 brings policies.
	id := uuid.New()
	set(`UPDATE whitetower.agents SET harness = '{"description": "A container."}', lifecycle_state = 'active',
		activated_at = '2026-10-19T09:00:00Z', version = version + 1 WHERE id = $1`, agent.Id)
	set(`INSERT INTO whitetower.reviews (id, agent_id, due_at, grace_ends_at, signoff_required, created_at)
		VALUES ($1, $2, '2027-01-01T00:00:00Z', '2027-01-15T00:00:00Z', true, '2026-10-19T09:00:00Z')`, id, agent.Id)
	path := "/reviews/" + id.String()
	review := func(res result, status int, etag string) gen.Review {
		t.Helper()
		var r gen.Review
		if res.status != status || res.header.Get("ETag") != etag || json.Unmarshal(res.body, &r) != nil {
			t.Fatalf("%d %s %s, want %d with the ETag %s", res.status, res.header.Get("ETag"), res.body, status, etag)
		}
		return r
	}

	r := review(send(http.MethodGet, path, olivia, "", nil), http.StatusOK, `"1"`)
	if r.Status != gen.ReviewStatusScheduled || r.AgentId != agent.Id || r.Overdue || !r.SignoffRequired || r.UnusedTooling == nil ||
		len(*r.UnusedTooling) != 0 || r.Attestation != nil || r.CompletedBy != nil {
		t.Errorf("getReview: %+v", r)
	}
	// decoded empties a list before a page is decoded into it, which would
	// otherwise keep a member that the page leaves out.
	var list gen.ReviewList
	decoded := func(l *gen.ReviewList) *gen.ReviewList { *l = gen.ReviewList{}; return l }
	for _, target := range []string{"/agents/" + agent.Id.String() + "/reviews", "/reviews?status=scheduled&overdue=false"} {
		if res = send(http.MethodGet, target, olivia, "", nil); res.status != http.StatusOK || json.Unmarshal(res.body, decoded(&list)) != nil ||
			len(list.Reviews) != 1 || list.Reviews[0].Id != id || list.Reviews[0].UnusedTooling != nil || list.NextCursor != nil {
			t.Errorf("%s: %d %s", target, res.status, res.body)
		}
	}
	problemOf(t, send(http.MethodGet, "/reviews?status=lost", olivia, "", nil), problem.BadRequest)
	problemOf(t, send(http.MethodGet, "/reviews/"+uuid.NewString(), olivia, "", nil), problem.NotFound)

	attestation := `{"stillNeeded":true,"ownerStillRight":true,"dataCategoriesCurrent":true,"policyAdequate":true,
		"toolingStillNeeded":true,"comment":"Still sorting invoices."}`
	completion := path + "/completion"
	problemOf(t, send(http.MethodPost, completion, olivia, attestation, nil), problem.PreconditionRequired)
	problemOf(t, send(http.MethodPost, completion, olivia, attestation, ifMatch(`"2"`)), problem.PreconditionFailed)
	problemOf(t, send(http.MethodPost, completion, olivia, strings.Replace(attestation, `"policyAdequate":true`, `"policyAdequate":false`, 1),
		ifMatch(`"1"`)), problem.BadRequest)
	problemOf(t, asAlex(http.MethodPost, completion, "", attestation, ifMatch(`"1"`)), problem.Forbidden)
	r = review(send(http.MethodPost, completion, olivia, attestation, ifMatch(`"1"`)), http.StatusOK, `"2"`)
	if r.Status != gen.ReviewStatusAwaitingSignoff || r.CompletedBy == nil || *r.CompletedBy.DisplayName != "Olivia Owner" ||
		r.Attestation == nil || *r.Attestation.Comment != "Still sorting invoices." || r.Attestation.KeptTooling == nil || r.CompletedAt == nil {
		t.Errorf("completeReview: %+v", r)
	}

	signOff := path + "/sign-off"
	problemOf(t, send(http.MethodPost, signOff, olivia, "", ifMatch(`"2"`)), problem.Forbidden)
	problemOf(t, asAlex(http.MethodPost, signOff, "", "", nil), problem.PreconditionRequired)
	r = review(asAlex(http.MethodPost, signOff, "", "", ifMatch(`"2"`)), http.StatusOK, `"3"`)
	if r.Status != gen.ReviewStatusCompleted || r.SignedOffBy == nil || r.SignedOffBy.Id.String() != alex || r.SignedOffAt == nil {
		t.Errorf("signOffReview: %+v", r)
	}
	problemOf(t, asAlex(http.MethodPost, signOff, "", "", ifMatch(`"3"`)), problem.Conflict)

	// The sign-off scheduled the next review, which the agent's list shows
	// first, a page at a time.
	reviews := "/agents/" + agent.Id.String() + "/reviews"
	if res = send(http.MethodGet, reviews+"?limit=1", olivia, "", nil); res.status != http.StatusOK || json.Unmarshal(res.body, decoded(&list)) != nil ||
		len(list.Reviews) != 1 || list.Reviews[0].Status != gen.ReviewStatusScheduled || list.NextCursor == nil {
		t.Fatalf("listAgentReviews: %d %s", res.status, res.body)
	}
	if res = send(http.MethodGet, reviews+"?limit=1&cursor="+*list.NextCursor, olivia, "", nil); res.status != http.StatusOK ||
		json.Unmarshal(res.body, decoded(&list)) != nil || len(list.Reviews) != 1 || list.Reviews[0].Id != id || list.NextCursor != nil {
		t.Fatalf("listAgentReviews, last page: %d %s", res.status, res.body)
	}
}
