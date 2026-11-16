package inventory

import (
	"errors"
	"maps"
	"math/rand/v2"
	"os"
	"slices"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/J466Y/WhiteTower/internal/authz"
)

// The engine's table is the lifecycle's machine-readable form,
// docs/architecture/agent-lifecycle.yaml: the same transitions, in the same
// order, with the same states, actors and guards, so that the two never
// diverge (the plan's notes for implementers).
func TestTheEngineFollowsTheLifecycleTable(t *testing.T) {
	raw, err := os.ReadFile("../../docs/architecture/agent-lifecycle.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Transitions []struct {
			ID     string   `yaml:"id"`
			Action string   `yaml:"action"`
			From   []string `yaml:"from"`
			To     string   `yaml:"to"`
			Actors []string `yaml:"actors"`
			Guards []string `yaml:"guards"`
		} `yaml:"transitions"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Transitions) != len(lifecycle) {
		t.Fatalf("the file has %d transitions, the engine %d", len(doc.Transitions), len(lifecycle))
	}
	for i, want := range doc.Transitions {
		got := lifecycle[i]
		if got.id != want.ID || got.action != want.Action || got.to != want.To || !slices.Equal(got.from, want.From) ||
			!slices.Equal(got.actors, want.Actors) || !slices.Equal(got.guards, want.Guards) {
			t.Errorf("the engine has %+v, the file %+v", got, want)
		}
	}
}

// Every guard of a transition that people can ask for is checked.
func TestEveryGuardOfABuiltTransitionIsChecked(t *testing.T) {
	for action := range permissions {
		tr, err := requested(action)
		if err != nil {
			t.Fatal(err)
		}
		for _, g := range tr.guards {
			if guards[g] == nil {
				t.Errorf("%s: nothing checks the guard %s", tr.id, g)
			}
		}
	}
}

// Random sequences of every action that people take never break the
// lifecycle's rules: an agent moves only along a transition of the table, by
// a caller whom its kind, roles and relationship allow, and only while every
// guard of the transition holds. The facts follow a model of the agent, its
// use case and the rest of White Tower from step to step, so that the
// sequences reach every state.
func TestRandomSequencesKeepTheLifecyclesRules(t *testing.T) {
	r := rand.New(rand.NewPCG(4, 23)) //nolint:gosec // G404: a fixed seed keeps the test deterministic
	actions := slices.Sorted(maps.Keys(permissions))
	// The callers: their roles, whether they are people, whether they own the
	// agent, and whether they had a part in its proposal.
	callers := []struct {
		roles                   []string
		person, own, conflicted bool
	}{
		{[]string{"owner"}, true, true, true},
		{[]string{"owner"}, true, false, false},
		{[]string{"advisory"}, true, false, false},
		{[]string{"advisory", "owner"}, true, true, true},
		{[]string{"operator"}, true, false, false},
		{[]string{"user"}, true, false, false},
		{[]string{"operator"}, false, false, false},
		{[]string{"advisory"}, false, false, false},
	}
	reached, taken := map[string]int{}, map[string]int{}
	for range 10_000 {
		a := Agent{LifecycleState: "draft", Version: 1}
		w := facts{metadataComplete: true, ownerActive: true, useCaseStatus: "draft", harnessDeclared: r.IntN(2) == 0}
		for range 24 {
			final := w.useCaseStatus == "validated" || w.useCaseStatus == "rejected"
			// The rest of White Tower changes the facts now and then: the
			// owner leaves or comes back, policies and halts come and go, a
			// harness is declared but never removed, a review lapses, and a
			// decision on another agent of the use case makes it final.
			switch r.IntN(20) {
			case 0:
				w.ownerActive = !w.ownerActive
			case 1, 2:
				w.policyActive = true
			case 3:
				w.policyActive = false
			case 4:
				w.harnessDeclared = true
			case 5:
				w.halted = !w.halted
			case 6:
				w.reviewOverdue = !w.reviewOverdue
			case 7:
				w.metadataComplete = !w.metadataComplete
			case 8:
				if !final {
					w.prohibited = !w.prohibited
				}
			case 9:
				if !final {
					w.useCaseStatus = []string{"validated", "rejected"}[r.IntN(2)]
				}
			}
			// T7 and T8, which White Tower takes itself (part 4c).
			switch {
			case a.LifecycleState == "validated" && w.policyActive && w.harnessDeclared && r.IntN(2) == 0:
				a.LifecycleState = "ready"
			case a.LifecycleState == "ready" && !w.policyActive:
				a.LifecycleState = "validated"
			}
			reached[a.LifecycleState]++

			// Mostly an action that the agent's state allows, seldom a
			// retirement, which ends the sequence; mostly by a caller whom the
			// action's permission allows.
			action := actions[r.IntN(len(actions))]
			if open := slices.DeleteFunc(slices.Clone(actions), func(x string) bool {
				tr, _ := requested(x)
				return !slices.Contains(tr.from, a.LifecycleState) || (x == "retire" && r.IntN(8) > 0)
			}); len(open) > 0 && r.IntN(4) > 0 {
				action = open[r.IntN(len(open))]
			}
			tr, err := requested(action)
			if err != nil {
				t.Fatal(err)
			}
			f := w
			for range 4 {
				c := callers[r.IntN(len(callers))]
				f.person, f.own, f.conflicted = c.person, c.own, c.conflicted
				f.permitted = authz.Allows(c.roles, permissions[action], authz.Relationship{IsOwner: c.own})
				if tr.allows(f) == nil {
					break
				}
			}
			f.commentGiven = r.IntN(4) > 0
			if a.Suspension != nil {
				f.previous = a.Suspension.From
			}
			if err = tr.allows(f); err == nil {
				err = tr.check(&a, a.Version, f)
			}
			var refusal *Refusal
			if err != nil && !errors.As(err, &refusal) {
				t.Fatal(err)
			}
			if err != nil {
				continue
			}
			b := tr.move(a, epoch)
			if rule := broken(tr, a, b, f); rule != "" {
				t.Fatalf("%s %s %s with %+v", tr.id, rule, a.LifecycleState, f)
			}
			a, b.Version = b, b.Version+1
			taken[tr.id]++
			// The use case follows the decisions on the proposal while none
			// has made it final.
			switch {
			case final:
			case action == "submit":
				w.useCaseStatus = "submitted"
			case (action == "withdraw" || action == "retire") && w.useCaseStatus == "submitted":
				w.useCaseStatus = "draft"
			case decisions[action] != "":
				w.useCaseStatus = decisions[action]
			}
		}
	}
	t.Logf("steps in each state %v; transitions taken %v", reached, taken)
	for _, s := range []string{"draft", "proposed", "validated", "ready", "active", "suspended", "retired", "rejected"} {
		if reached[s] == 0 {
			t.Errorf("no sequence reached %s", s)
		}
	}
	for _, tr := range lifecycle {
		if _, people := permissions[tr.action]; people && taken[tr.id] == 0 {
			t.Errorf("no sequence took %s", tr.id)
		}
	}
}

var epoch = time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)

// broken names the rule of the lifecycle that moving the agent from a to b
// along tr, with the facts given, breaks, if any.
func broken(tr transition, a, b Agent, f facts) string {
	from, to := a.LifecycleState, b.LifecycleState
	switch {
	case !slices.Contains(tr.from, from) || from == "retired" || from == "rejected":
		return "moved an agent that was"
	case !f.person && tr.action != "suspend":
		return "was taken by a service account on an agent that was"
	case !f.permitted || (tr.ownersOnly() && !f.own):
		return "was taken without the permission on an agent that was"
	case slices.Contains(tr.guards, "comment_given") && !f.commentGiven:
		return "was taken without a comment on an agent that was"
	case decisions[tr.action] != "" && f.conflicted:
		return "was decided by someone with a part in the proposal of an agent that was"
	case to == "proposed" && (!f.metadataComplete || !f.ownerActive || f.useCaseStatus == "rejected"):
		return "submitted an agent that was"
	case tr.action == "validate" && (f.prohibited || f.useCaseStatus == "rejected" || !f.ownerActive):
		return "validated an agent that was"
	case to == "active" && (!f.ownerActive || !useCaseValidated(f) || !f.policyActive || !f.harnessDeclared || f.halted):
		return "put into service, without the invariants of active, an agent that was"
	case (to == "suspended") != (b.Suspension != nil) || (b.Suspension != nil && (b.Suspension.From != from || b.Suspension.Reason != "manual")):
		return "suspended, without remembering where it was, an agent that was"
	case tr.action == "reinstate" && (to != a.Suspension.From || !f.ownerActive || f.reviewOverdue || f.halted):
		return "reinstated, elsewhere or without its conditions, an agent that was"
	case tr.action == "reinstate" && (!useCaseValidated(f) || (to != "validated" && (!f.policyActive || !f.harnessDeclared))):
		return "reinstated, without the invariants of where it returns, an agent that was"
	case (tr.action == "activate") != (b.ActivatedAt != a.ActivatedAt), (to == "retired") != (b.RetiredAt != nil):
		return "recorded the wrong times of an agent that was"
	}
	return ""
}
