package inventory

import (
	"errors"
	"maps"
	"math/rand/v2"
	"os"
	"slices"
	"testing"

	"go.yaml.in/yaml/v3"
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

// Random sequences of the proposal's actions, on random facts, never break
// the lifecycle's rules: an agent moves only along a transition of the table,
// never leaves a terminal state, reaches proposed only with complete metadata
// and an active owner, and is decided on only with a comment, by someone
// without a part in the proposal, and validated only on a use case that is
// neither rejected nor prohibited.
func TestTheProposalPhaseKeepsTheLifecyclesRules(t *testing.T) {
	r := rand.New(rand.NewPCG(4, 23)) //nolint:gosec // G404: a fixed seed keeps the test deterministic
	actions := slices.Sorted(maps.Keys(permissions))
	statuses := []string{"draft", "submitted", "changes_requested", "validated", "rejected"}
	for range 10_000 {
		a := &Agent{LifecycleState: "draft", Version: 1}
		for range 12 {
			tr, err := requested(actions[r.IntN(len(actions))])
			if err != nil {
				t.Fatal(err)
			}
			f := facts{
				metadataComplete: r.IntN(8) > 0, ownerActive: r.IntN(8) > 0, useCaseStatus: statuses[r.IntN(len(statuses))],
				prohibited: r.IntN(8) == 0, commentGiven: r.IntN(4) > 0, conflicted: r.IntN(8) == 0,
			}
			from := a.LifecycleState
			err = tr.check(a, a.Version, f)
			var refusal *Refusal
			if err != nil && !errors.As(err, &refusal) {
				t.Fatal(err)
			}
			if err != nil {
				continue
			}
			a.LifecycleState, a.Version = tr.to, a.Version+1
			decision := tr.action == "request_changes" || tr.action == "reject" || tr.action == "validate"
			switch {
			case !slices.Contains(tr.from, from):
				t.Fatalf("%s moved a %s agent", tr.action, from)
			case from == "rejected":
				t.Fatalf("%s moved a rejected agent", tr.action)
			case tr.to == "proposed" && (!f.metadataComplete || !f.ownerActive || f.useCaseStatus == "rejected"):
				t.Fatalf("submitted with %+v", f)
			case decision && (!f.commentGiven || f.conflicted):
				t.Fatalf("%s decided with %+v", tr.action, f)
			case tr.to == "validated" && (f.prohibited || f.useCaseStatus == "rejected" || !f.ownerActive):
				t.Fatalf("validated with %+v", f)
			}
		}
	}
}
