package inventory_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/J466Y/WhiteTower/internal/inventory"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/db"
)

// act takes a lifecycle action on the agent, at the version given.
func (f *fixture) act(caller auth.Principal, a *inventory.Agent, action, comment string) (*inventory.Agent, error) {
	return f.inv.Transition(context.Background(), caller, a.ID, a.Version, action, comment)
}

// submitted proposes an agent as Olivia, with a use case of her own, and
// submits it.
func (f *fixture) submitted(t *testing.T, slug string) *inventory.Agent {
	t.Helper()
	a, err := f.act(f.olivia, f.propose(t, slug), "submit", "")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// scalar returns the one value that a query reads.
func scalar[T any](t *testing.T, f *fixture, sql string, args ...any) T {
	t.Helper()
	var v T
	if err := f.pool.QueryRow(context.Background(), sql, args...).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// useCaseStatus returns the status of the agent's use case.
func (f *fixture) useCaseStatus(t *testing.T, a *inventory.Agent) string {
	t.Helper()
	return scalar[string](t, f, `SELECT status FROM whitetower.use_cases WHERE id = $1`, a.UseCaseID)
}

// awaitingCommittee counts the open items of the advisory committee's inbox
// about the agent's proposal.
func (f *fixture) awaitingCommittee(t *testing.T, a *inventory.Agent) int {
	t.Helper()
	return scalar[int](t, f, `SELECT count(*) FROM whitetower.inbox_items WHERE role = 'advisory'
		AND kind = 'use_case_validation' AND subject_type = 'agent' AND subject_id = $1 AND resolved_at IS NULL`, a.ID)
}

func TestASubmittedProposalWaitsForTheAdvisoryCommittee(t *testing.T) {
	f := setup(t)
	draft := f.propose(t, "invoice-triage")
	a, err := f.act(f.olivia, draft, "submit", "")
	if err != nil {
		t.Fatal(err)
	}
	if a.LifecycleState != "proposed" || a.Version != draft.Version+1 {
		t.Fatalf("state %s at version %d", a.LifecycleState, a.Version)
	}
	if s := f.useCaseStatus(t, a); s != "submitted" {
		t.Errorf("use case %s, want submitted", s)
	}
	if n := f.awaitingCommittee(t, a); n != 1 {
		t.Errorf("%d items wait for the advisory committee, want 1", n)
	}

	// The governance state, the history and the event share one version.
	version := f.stateVersion(t, a.ID)
	if state := scalar[string](t, f, `SELECT lifecycle_state FROM whitetower.governance_state WHERE agent_id = $1`, a.ID); state != "proposed" {
		t.Errorf("governance state %s", state)
	}
	history, _, err := f.inv.Transitions(context.Background(), f.alex, a.ID, nil, 50)
	if err != nil || len(history) != 2 {
		t.Fatalf("history %+v, %v", history, err)
	}
	h := history[0]
	if h.Transition != "T2" || h.From != "draft" || h.To != "proposed" || h.Actor.Type != "human" ||
		h.Actor.ID.String() != f.olivia.ID || h.Actor.DisplayName != "Olivia Owner" || h.StateVersion != version || h.Comment != "" {
		t.Errorf("transition %+v", h)
	}
	if history[1].Transition != "T1" || history[1].From != "" {
		t.Errorf("the creation %+v", history[1])
	}
	changed := f.events(t, "whitetower.agent.lifecycle_changed.v1")
	if len(changed) != 1 || *changed[0].subject != a.ID || changed[0].data["transition"] != "T2" ||
		changed[0].data["state_version"] != float64(version) || changed[0].data["comment_given"] != false {
		t.Errorf("events %+v", changed)
	}
}

func TestTheAdvisoryCommitteeDecidesOnAProposal(t *testing.T) {
	for _, c := range []struct{ action, state, decision string }{
		{"request_changes", "draft", "changes_requested"},
		{"reject", "rejected", "rejected"},
		{"validate", "validated", "validated"},
	} {
		t.Run(c.action, func(t *testing.T) {
			f := setup(t)
			a, err := f.act(f.alex, f.submitted(t, "invoice-triage"), c.action, "Reviewed on 2026-10-19.")
			if err != nil {
				t.Fatal(err)
			}
			if a.LifecycleState != c.state || f.useCaseStatus(t, a) != c.decision || f.awaitingCommittee(t, a) != 0 {
				t.Errorf("state %s, use case %s, %d inbox items", a.LifecycleState, f.useCaseStatus(t, a), f.awaitingCommittee(t, a))
			}
			decisions, _, err := f.inv.Decisions(context.Background(), f.alex, a.UseCaseID, nil, 50)
			if err != nil || len(decisions) != 1 || decisions[0].Decision != c.decision || *decisions[0].AgentID != a.ID ||
				decisions[0].Comment != "Reviewed on 2026-10-19." || decisions[0].DecidedBy.ID.String() != f.alex.ID {
				t.Errorf("decisions %+v, %v", decisions, err)
			}
			history, _, err := f.inv.Transitions(context.Background(), f.alex, a.ID, nil, 1)
			if err != nil || history[0].Comment != "Reviewed on 2026-10-19." || history[0].Actor.ID.String() != f.alex.ID {
				t.Errorf("history %+v, %v", history, err)
			}
			changed := f.events(t, "whitetower.agent.lifecycle_changed.v1")
			if last := changed[len(changed)-1]; last.data["action"] != c.action || last.data["comment_given"] != true {
				t.Errorf("event %+v", last)
			}
		})
	}
}

func TestAWithdrawnProposalBecomesADraftAgain(t *testing.T) {
	f := setup(t)
	a := f.submitted(t, "invoice-triage")
	// Another agent that the same use case justifies waits for the committee.
	other, err := f.inv.Propose(context.Background(), f.olivia, proposal("invoice-sorter", a.UseCaseID))
	if err != nil {
		t.Fatal(err)
	}
	if other, err = f.act(f.olivia, other, "submit", ""); err != nil {
		t.Fatal(err)
	}

	if a, err = f.act(f.olivia, a, "withdraw", ""); err != nil {
		t.Fatal(err)
	}
	if a.LifecycleState != "draft" || f.awaitingCommittee(t, a) != 0 || f.useCaseStatus(t, a) != "submitted" {
		t.Errorf("state %s, %d inbox items, use case %s: the other agent still waits", a.LifecycleState, f.awaitingCommittee(t, a), f.useCaseStatus(t, a))
	}
	if _, err = f.act(f.olivia, other, "withdraw", ""); err != nil {
		t.Fatal(err)
	}
	if s := f.useCaseStatus(t, a); s != "draft" {
		t.Errorf("use case %s once no agent waits, want draft", s)
	}
}

// A validated or rejected use case never changes, because the other agents
// that it justifies rely on it: a later decision is recorded with its agent,
// and only the agent changes state.
func TestADecidedUseCaseNeverChanges(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	first := f.submitted(t, "invoice-triage")
	second, err := f.inv.Propose(ctx, f.olivia, proposal("invoice-sorter", first.UseCaseID))
	if err != nil {
		t.Fatal(err)
	}
	if second, err = f.act(f.olivia, second, "submit", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := f.act(f.alex, first, "validate", "Fine."); err != nil {
		t.Fatal(err)
	}
	if second, err = f.act(f.alex, second, "reject", "Not this one."); err != nil {
		t.Fatal(err)
	}
	if second.LifecycleState != "rejected" || f.useCaseStatus(t, second) != "validated" {
		t.Errorf("state %s, use case %s", second.LifecycleState, f.useCaseStatus(t, second))
	}
	if decisions, _, err := f.inv.Decisions(ctx, f.alex, first.UseCaseID, nil, 50); err != nil || len(decisions) != 2 ||
		decisions[0].Decision != "rejected" || *decisions[0].AgentID != second.ID {
		t.Errorf("decisions %+v, %v", decisions, err)
	}

	// While its use case is rejected, an agent is neither submitted nor
	// validated.
	rejected := f.submitted(t, "invoice-reader")
	waiting, err := f.inv.Propose(ctx, f.olivia, proposal("invoice-filer", rejected.UseCaseID))
	if err != nil {
		t.Fatal(err)
	}
	proposed, err := f.inv.Propose(ctx, f.olivia, proposal("invoice-keeper", rejected.UseCaseID))
	if err != nil {
		t.Fatal(err)
	}
	if proposed, err = f.act(f.olivia, proposed, "submit", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := f.act(f.alex, rejected, "reject", "Out of scope."); err != nil {
		t.Fatal(err)
	}
	_, err = f.act(f.olivia, waiting, "submit", "")
	refused(t, err, inventory.Conflict)
	_, err = f.act(f.alex, proposed, "validate", "Fine.")
	refused(t, err, inventory.Conflict)
	if proposed, err = f.act(f.alex, proposed, "request_changes", "Link another use case."); err != nil || f.useCaseStatus(t, proposed) != "rejected" {
		t.Fatalf("got %v; use case %s", err, f.useCaseStatus(t, proposed))
	}
}

// Security test ST-18: Nobody validates, rejects or asks changes of a proposal that they own, delegate for, ever did, or created, nor of one whose use case they created
func TestNobodyDecidesOnAProposalTheyOwnOwnedOrCreated(t *testing.T) {
	f := setup(t)
	ada := f.person(t, "Ada Advisory", "advisory")
	ada.Roles = []string{"advisory", "owner"}
	adaID := uuid.MustParse(ada.ID)
	assign := func(role, ended string) func(a *inventory.Agent) {
		return func(a *inventory.Agent) {
			f.set(t, `INSERT INTO whitetower.agent_owners (id, agent_id, principal_id, role, assigned_by, ended_at, ended_by, end_reason)
				VALUES ($1, $2, $3, $4, $3, `+ended+`)`, uuid.Must(uuid.NewV7()), a.ID, adaID, role)
		}
	}
	for name, relate := range map[string]func(a *inventory.Agent){
		"a delegate":        assign("delegate", "NULL, NULL, NULL"),
		"a former delegate": assign("delegate", "now(), $3, 'left the team'"),
		"the primary owner": func(a *inventory.Agent) {
			f.set(t, `UPDATE whitetower.agent_owners SET ended_at = now(), ended_by = $2, end_reason = 'left'
				WHERE agent_id = $1 AND role = 'primary'`, a.ID, adaID)
			assign("primary", "NULL, NULL, NULL")(a)
		},
		"the agent's creator": func(a *inventory.Agent) {
			f.set(t, `UPDATE whitetower.agents SET created_by = $2 WHERE id = $1`, a.ID, adaID)
		},
		"the use case's creator": func(a *inventory.Agent) {
			f.set(t, `UPDATE whitetower.use_cases SET created_by = $2 WHERE id = $1`, a.UseCaseID, adaID)
		},
	} {
		t.Run(name, func(t *testing.T) {
			a := f.submitted(t, "agent-"+uuid.NewString()[:8])
			relate(a)
			for _, action := range []string{"request_changes", "reject", "validate"} {
				_, err := f.act(ada, a, action, "Looks fine to me.")
				refused(t, err, inventory.Forbidden)
			}
		})
	}
}

// Each action needs its own permission, within its scope, besides seeing the
// agent.
func TestATransitionNeedsItsOwnPermission(t *testing.T) {
	f := setup(t)
	draft := f.propose(t, "invoice-triage")
	a := f.submitted(t, "invoice-sorter")
	bot := f.alex
	bot.Kind = auth.ServiceAccount
	breakglass := auth.Principal{ID: f.omar.ID, Kind: auth.Human, Roles: []string{"operator", "advisory"}, IsBreakglass: true}
	for _, c := range []struct {
		name   string
		caller auth.Principal
		agent  *inventory.Agent
		action string
		kind   inventory.RefusalKind
	}{
		{"another owner submits", f.otto, draft, "submit", inventory.Forbidden},
		{"an operator submits", f.omar, draft, "submit", inventory.Forbidden},
		{"the advisory committee withdraws", f.alex, a, "withdraw", inventory.Forbidden},
		{"an operator validates", f.omar, a, "validate", inventory.Forbidden},
		{"an owner validates", f.otto, a, "validate", inventory.Forbidden},
		{"a service account of the advisory committee validates", bot, a, "validate", inventory.Forbidden},
		{"a break-glass session validates", breakglass, a, "validate", inventory.Forbidden},
		{"a user, who sees only active agents, validates", f.uma, a, "validate", inventory.NotFound},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := f.act(c.caller, c.agent, c.action, "A comment.")
			refused(t, err, c.kind)
		})
	}
}

// Security test ST-19: an API token takes a lifecycle action only with the action's own permission among its scopes
func TestATokenWithoutTheActionsScopeTakesNoAction(t *testing.T) {
	f := setup(t)
	a := f.submitted(t, "invoice-triage")
	viewer := f.alex
	viewer.Scopes = []string{"inventory.view"}
	_, err := f.act(viewer, a, "validate", "Fine.")
	refused(t, err, inventory.Forbidden)

	scoped := f.alex
	scoped.Scopes = []string{"inventory.view", "usecase.validate"}
	if _, err := f.act(scoped, a, "validate", "Fine."); err != nil {
		t.Fatalf("a token with the action's scope: %v", err)
	}
}

func TestATransitionStartsFromTheVersionAndTheStateTheCallerRead(t *testing.T) {
	f := setup(t)
	a := f.submitted(t, "invoice-triage")
	stale := *a
	stale.Version--
	_, err := f.act(f.alex, &stale, "validate", "Fine.")
	refused(t, err, inventory.Stale)
	_, err = f.act(f.olivia, a, "submit", "")
	refused(t, err, inventory.Conflict)

	for action, kind := range map[string]inventory.RefusalKind{
		"dance":        inventory.Invalid,
		"create":       inventory.Invalid,
		"halt_suspend": inventory.Invalid,
		"activate":     inventory.NotBuilt,
		"retire":       inventory.NotBuilt,
	} {
		_, err := f.act(f.olivia, a, action, "A comment.")
		refused(t, err, kind)
	}

	rejected, err := f.act(f.alex, a, "reject", "No.")
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.act(f.olivia, rejected, "withdraw", "")
	refused(t, err, inventory.Conflict)
}

func TestRejectingAnAgentCancelsItsPendingTransfer(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a := f.submitted(t, "invoice-triage")
	transfer, err := f.inv.RequestTransfer(ctx, f.olivia, a.ID, uuid.MustParse(f.otto.ID))
	if err != nil {
		t.Fatal(err)
	}
	if a, err = f.inv.Get(ctx, f.olivia, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.act(f.alex, a, "reject", "Out of scope."); err != nil {
		t.Fatal(err)
	}
	if status := scalar[string](t, f, `SELECT status FROM whitetower.ownership_transfers WHERE id = $1`, transfer.ID); status != "cancelled" || //nolint:misspell // the schema's spelling
		f.openInboxItems(t, transfer.ID) != 0 {
		t.Errorf("transfer %s, %d inbox items", status, f.openInboxItems(t, transfer.ID))
	}
}

func TestTheHistoryListsTheNewestTransitionFirst(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a := f.submitted(t, "invoice-triage")
	if _, err := f.act(f.olivia, a, "withdraw", "Not ready yet."); err != nil {
		t.Fatal(err)
	}
	page, more, err := f.inv.Transitions(ctx, f.alex, a.ID, nil, 2)
	if err != nil || !more || len(page) != 2 || page[0].Action != "withdraw" || page[1].Action != "submit" {
		t.Fatalf("first page %+v, more %v, %v", page, more, err)
	}
	page, more, err = f.inv.Transitions(ctx, f.alex, a.ID, &page[1].ID, 2)
	if err != nil || more || len(page) != 1 || page[0].Action != "create" {
		t.Fatalf("last page %+v, more %v, %v", page, more, err)
	}
	_, _, err = f.inv.Transitions(ctx, f.uma, a.ID, nil, 2)
	refused(t, err, inventory.NotFound)
}

// Decisions on agents that one use case justifies happen one after the
// other: a decision waits for the one under way on the use case, then sees
// the status it left. Without the wait, an agent would be validated on a use
// case that a concurrent decision rejected.
func TestDecisionsOnOneUseCaseHappenOneAfterTheOther(t *testing.T) {
	f := setup(t)
	a := f.submitted(t, "invoice-triage")
	proceed, rejection := f.held(t,
		func(ctx context.Context, tx *db.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE whitetower.use_cases SET status = 'rejected' WHERE id = $1`, a.UseCaseID)
			return err
		},
		func(context.Context, *db.Tx) error { return nil })
	validated := make(chan error, 1)
	go func() {
		_, err := f.act(f.alex, a, "validate", "Fine.")
		validated <- err
	}()
	f.awaitLockWaits(t, 1) // the validation waits for the use case
	proceed()
	if err := <-rejection; err != nil {
		t.Fatal(err)
	}
	refused(t, <-validated, inventory.Conflict)
	if got, err := f.inv.Get(context.Background(), f.alex, a.ID); err != nil || got.LifecycleState != "proposed" {
		t.Fatalf("got %+v, %v: want the agent still proposed", got, err)
	}
}
