package inventory_test

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/J466Y/WhiteTower/internal/inventory"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
)

// model is what the lifecycle says of an agent with a use case of its own,
// written apart from the engine: its state, the state a suspension
// remembers, its use case's status, the facts that the rest of White Tower
// changes, and how many transitions its history holds.
type model struct {
	state, previous, useCase                                 string
	ownerActive, policy, harness, halted, overdue, activated bool
	history                                                  int
}

// caller is a principal, with the actions that their kind, roles and
// relationship to Olivia's agents let them take, and whether separation of
// duties refuses them the decisions on the agents and their reinstatement.
type caller struct {
	p          auth.Principal
	may        []string
	conflicted bool
}

// starts holds the states that each action that people take starts from,
// and commented the actions that need a comment.
var (
	starts = map[string][]string{
		"submit": {"draft"}, "withdraw": {"proposed"}, "request_changes": {"proposed"}, "reject": {"proposed"},
		"validate": {"proposed"}, "activate": {"ready"}, "suspend": {"validated", "ready", "active"},
		"reinstate": {"suspended"}, "retire": {"draft", "proposed", "validated", "ready", "active", "suspended"},
	}
	commented = []string{"request_changes", "reject", "validate", "suspend", "reinstate", "retire"}
	// duties are the actions that separation of duties refuses to whoever
	// owns the agent, ever did, or created it or its use case.
	duties = []string{"request_changes", "reject", "validate", "reinstate"}
	// further is the action that takes an agent in each state further.
	further = map[string]string{
		"draft": "submit", "proposed": "validate", "validated": "suspend", "ready": "activate", "active": "suspend", "suspended": "reinstate",
	}
)

// expect returns the refusal that the model expects when the caller asks for
// an action; or none, and the state it leads to.
func (m model) expect(c caller, action string, comment bool) (inventory.RefusalKind, string) {
	switch {
	case slices.Equal(c.p.Roles, []string{"user"}) && m.state != "active":
		return inventory.NotFound, ""
	case !slices.Contains(c.may, action), c.conflicted && slices.Contains(duties, action):
		return inventory.Forbidden, ""
	case !slices.Contains(starts[action], m.state):
		return inventory.Conflict, ""
	case slices.Contains(commented, action) && !comment:
		return inventory.Invalid, ""
	}
	holds, to := true, map[string]string{
		"submit": "proposed", "withdraw": "draft", "request_changes": "draft", "reject": "rejected", "validate": "validated",
		"activate": "active", "suspend": "suspended", "reinstate": m.previous, "retire": "retired",
	}[action]
	servable := m.useCase == "validated" && m.policy && m.harness
	switch action {
	case "submit", "validate":
		holds = m.ownerActive && m.useCase != "rejected"
	case "activate":
		holds = m.ownerActive && servable && !m.halted
	case "reinstate":
		holds = m.ownerActive && !m.overdue && !m.halted && (servable || (m.previous == "validated" && m.useCase == "validated"))
	}
	if !holds {
		return inventory.Conflict, ""
	}
	return 0, to
}

// apply moves the model along an action that it allowed.
func (m *model) apply(action, to string) {
	from := m.state
	m.state, m.history, m.previous = to, m.history+1, ""
	final := m.useCase == "validated" || m.useCase == "rejected"
	switch {
	case action == "suspend":
		m.previous = from
	case action == "activate":
		m.activated = true
	case final:
	case action == "submit":
		m.useCase = "submitted"
	case action == "withdraw" || action == "retire":
		if m.useCase == "submitted" {
			m.useCase = "draft"
		}
	case action == "request_changes":
		m.useCase = "changes_requested"
	case action == "reject" || action == "validate":
		m.useCase = to
	}
}

// agrees fails the test unless the database holds what the model says of the
// agent: its row, its use case, its governance state, its history, its audit
// events and the advisory committee's inbox. It returns the agent's version.
func (f *fixture) agrees(t *testing.T, id uuid.UUID, m model, step string) int64 {
	t.Helper()
	var state, previous, reason, useCase, published string
	var activated, retired bool
	var history, events, inbox int
	var version int64
	if err := f.pool.QueryRow(context.Background(), `
		SELECT a.version, a.lifecycle_state, coalesce(a.suspended_from, ''), coalesce(a.suspension_reason, ''), u.status,
		  a.activated_at IS NOT NULL, a.retired_at IS NOT NULL, g.lifecycle_state,
		  (SELECT count(*) FROM whitetower.lifecycle_transitions t WHERE t.agent_id = a.id),
		  (SELECT count(*) FROM whitetower.audit_events e WHERE e.subject_agent_id = a.id
		     AND e.type IN ('whitetower.agent.created.v1', 'whitetower.agent.lifecycle_changed.v1')),
		  (SELECT count(*) FROM whitetower.inbox_items i WHERE i.kind = 'use_case_validation' AND i.subject_id = a.id
		     AND i.resolved_at IS NULL)
		FROM whitetower.agents a
		JOIN whitetower.use_cases u ON u.id = a.use_case_id
		JOIN whitetower.governance_state g ON g.agent_id = a.id
		WHERE a.id = $1`, id).Scan(&version, &state, &previous, &reason, &useCase, &activated, &retired, &published, &history, &events, &inbox); err != nil {
		t.Fatal(err)
	}
	wantReason, wantInbox := "", 0
	if m.state == "suspended" {
		wantReason = "manual"
	}
	if m.state == "proposed" {
		wantInbox = 1
	}
	got := fmt.Sprint([]any{state, previous, reason, useCase, activated, retired, published, history, events, inbox})
	want := fmt.Sprint([]any{m.state, m.previous, wantReason, m.useCase, m.activated, m.state == "retired", m.state, m.history, m.history, wantInbox})
	if got != want {
		t.Fatalf("after %s, the database holds %s, the model %s", step, got, want)
	}
	return version
}

// Random sequences of the actions that people take, by random callers, while
// the owner, policies, halts, reviews and White Tower's own transitions
// change the facts from step to step, leave the database as a model of the
// lifecycle says, and each refusal is the one that the model expects.
func TestTheDatabaseFollowsAModelOfTheLifecycle(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	r := rand.New(rand.NewPCG(16, 11)) //nolint:gosec // G404: a fixed seed keeps the test deterministic
	// Olivia owns every agent and created its use case. operatorOlivia is
	// Olivia with the operator role as well, which grants agent.reinstate.
	operatorOlivia := f.olivia
	operatorOlivia.Name, operatorOlivia.Roles = "Olivia Operator", []string{"owner", "operator"}
	callers := []caller{
		{f.olivia, []string{"submit", "withdraw", "activate", "suspend", "retire"}, true},
		{operatorOlivia, []string{"submit", "withdraw", "activate", "suspend", "reinstate", "retire"}, true},
		{f.otto, nil, false},
		{f.alex, []string{"request_changes", "reject", "validate", "suspend", "reinstate", "retire"}, false},
		{f.omar, []string{"activate", "suspend", "reinstate", "retire"}, false},
		{f.uma, nil, false},
		{f.serviceAccount(t, "operator"), []string{"suspend"}, false},
	}
	actions := slices.Sorted(maps.Keys(starts))
	past := f.clk.Now().Add(-time.Hour)
	reached := map[string]int{}
	for i := range 200 {
		f.setStatus(t, f.olivia, "active")
		m := model{state: "draft", useCase: "draft", ownerActive: true, harness: r.IntN(2) == 0, history: 1}
		proposed := proposal(fmt.Sprintf("agent-%d", i), f.useCase(t, f.olivia).ID)
		if m.harness {
			proposed.Harness = &inventory.Harness{Description: "A container."}
		}
		a, err := f.inv.Propose(ctx, f.olivia, proposed)
		if err != nil {
			t.Fatal(err)
		}
		version := a.Version
		for step := range 10 {
			// The rest of White Tower changes the facts now and then.
			switch r.IntN(20) {
			case 0:
				m.ownerActive = !m.ownerActive
				f.setStatus(t, f.olivia, map[bool]string{true: "active", false: "inactive"}[m.ownerActive])
			case 1, 2, 3, 4:
				m.policy = !m.policy
				f.policies.set(a.ID, m.policy)
			case 5, 6:
				m.harness = true
				f.set(t, `UPDATE whitetower.agents SET harness = '{"description": "A container."}' WHERE id = $1`, a.ID)
			case 7:
				m.halted = !m.halted
				f.halt(t, a.ID, m.halted)
			case 8:
				m.overdue = !m.overdue
				if m.overdue {
					f.review(t, a.ID, &past)
				} else {
					f.review(t, a.ID, nil)
				}
			}
			// T7 and T8, which White Tower takes itself whenever it is asked,
			// and which move the agent only while their guards hold.
			for _, s := range []struct {
				action, from, to string
				holds            bool
			}{
				{"mark_ready", "validated", "ready", m.policy && m.harness},
				{"unmark_ready", "ready", "validated", !m.policy || !m.harness},
			} {
				want := m.state == s.from && s.holds
				if moved := f.system(t, a.ID, inventory.Cause{Action: s.action}); moved != want {
					t.Fatalf("%s at step %d: %s with %+v: moved %v", a.Slug, step, s.action, m, moved)
				}
				if want {
					m.state, m.history, version = s.to, m.history+1, version+1
				}
			}
			reached[m.state]++

			// Half the time the action that takes the agent further, a
			// quarter of the time another that its state allows, seldom a
			// retirement, which ends the sequence, and otherwise any action;
			// mostly by a caller who may take it.
			action, c := actions[r.IntN(len(actions))], callers[r.IntN(len(callers))]
			open := slices.DeleteFunc(slices.Clone(actions), func(x string) bool {
				return !slices.Contains(starts[x], m.state) || (x == "retire" && r.IntN(8) > 0)
			})
			switch n := r.IntN(4); {
			case n < 2 && further[m.state] != "":
				action = further[m.state]
			case n == 2 && len(open) > 0:
				action = open[r.IntN(len(open))]
			}
			if may := slices.DeleteFunc(slices.Clone(callers), func(x caller) bool {
				return !slices.Contains(x.may, action)
			}); len(may) > 0 && r.IntN(4) > 0 {
				c = may[r.IntN(len(may))]
			}
			comment := map[bool]string{true: "Because.", false: ""}[r.IntN(5) > 0]
			want, to := m.expect(c, action, comment != "")

			_, err := f.inv.Transition(ctx, c.p, a.ID, version, action, comment)
			var refusal *inventory.Refusal
			switch {
			case want == 0 && err != nil, want != 0 && (!errors.As(err, &refusal) || refusal.Kind != want):
				t.Fatalf("%s at step %d: %s by %s with %+v: got %v, want refusal %d", a.Slug, step, action, c.p.Name, m, err, want)
			case want == 0:
				m.apply(action, to)
			}
			version = f.agrees(t, a.ID, m, fmt.Sprintf("%s at step %d: %s by %s", a.Slug, step, action, c.p.Name))
		}
	}
	t.Logf("steps in each state %v", reached)
	for _, s := range []string{"draft", "proposed", "validated", "ready", "active", "suspended", "retired", "rejected"} {
		if reached[s] == 0 {
			t.Errorf("no sequence reached %s", s)
		}
	}
}
