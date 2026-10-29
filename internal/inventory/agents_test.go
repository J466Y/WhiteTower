package inventory_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/J466Y/WhiteTower/internal/inventory"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
)

func TestAProposalBecomesADraftOwnedByItsProposer(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	uc := f.useCase(t, f.olivia)
	a, err := f.inv.Propose(ctx, f.olivia, proposal("invoice-triage", uc.ID))
	if err != nil {
		t.Fatal(err)
	}

	switch {
	case a.LifecycleState != "draft", a.Source != "registered", a.Version != 1:
		t.Errorf("state %s, source %s, version %d: want a registered draft at version 1", a.LifecycleState, a.Source, a.Version)
	case a.PrimaryOwner.ID.String() != f.olivia.ID || a.PrimaryOwner.DisplayName != "Olivia Owner" || a.PrimaryOwner.Status != "active":
		t.Errorf("primary owner %+v, want Olivia", a.PrimaryOwner)
	case len(a.Delegates) != 0, a.CreatedBy.ID.String() != f.olivia.ID:
		t.Errorf("delegates %v, created by %v", a.Delegates, a.CreatedBy)
	case a.AIActClassification != "not_assessed", a.HaltMode != "interrupt", a.DrillEligible:
		t.Errorf("classification %s, halt mode %s, drills %v: want the defaults", a.AIActClassification, a.HaltMode, a.DrillEligible)
	case a.Coverage != "C0", a.Halted, a.Labels["team"] != "finance", !a.CreatedAt.Equal(epoch):
		t.Errorf("coverage %s, halted %v, labels %v, created %v", a.Coverage, a.Halted, a.Labels, a.CreatedAt)
	}

	// The agent's governance state, at its first version: a draft, with the
	// lease of its risk tier and what policies see of it.
	var state string
	var lease int32
	var attrs []byte
	if err := f.pool.QueryRow(ctx, `SELECT lifecycle_state, lease_ttl_seconds, attributes
		FROM whitetower.governance_state WHERE agent_id = $1`, a.ID).Scan(&state, &lease, &attrs); err != nil {
		t.Fatal(err)
	}
	var seen map[string]any
	if err := json.Unmarshal(attrs, &seen); err != nil {
		t.Fatal(err)
	}
	if state != "draft" || lease != 30 || seen["owner_id"] != f.olivia.ID || seen["risk_tier"] != "high" || seen["slug"] != "invoice-triage" {
		t.Errorf("governance state %s, lease %d, attributes %v", state, lease, seen)
	}
	version := f.stateVersion(t, a.ID)

	// Transition T1, with the same state version as its event.
	var action, to, actorType string
	var from *string
	var transitionVersion int64
	if err := f.pool.QueryRow(ctx, `SELECT action, from_state, to_state, actor_type, state_version
		FROM whitetower.lifecycle_transitions WHERE agent_id = $1`, a.ID).Scan(&action, &from, &to, &actorType, &transitionVersion); err != nil {
		t.Fatal(err)
	}
	if action != "create" || from != nil || to != "draft" || actorType != "human" || transitionVersion != version {
		t.Errorf("transition %s %v→%s by %s at %d, want create →draft at %d", action, from, to, actorType, transitionVersion, version)
	}
	created := f.events(t, "whitetower.agent.created.v1")
	if len(created) != 1 || created[0].subject == nil || *created[0].subject != a.ID || created[0].actorID != f.olivia.ID {
		t.Fatalf("events %+v, want one about the agent, by Olivia", created)
	}
	if created[0].data["state_version"] != float64(version) || created[0].data["use_case_id"] != uc.ID.String() {
		t.Errorf("event data %v", created[0].data)
	}
}

func TestAProposalNeedsTheMetadataOfINV01(t *testing.T) {
	f := setup(t)
	uc := f.useCase(t, f.olivia)
	cases := map[string]func(*inventory.NewAgent){
		"a malformed slug":            func(p *inventory.NewAgent) { p.Slug = "Invoice_Triage" },
		"no name":                     func(p *inventory.NewAgent) { p.Name = " " },
		"no description":              func(p *inventory.NewAgent) { p.Description = "" },
		"an unknown kind":             func(p *inventory.NewAgent) { p.Kind = "outsourced" },
		"no vendor nor framework":     func(p *inventory.NewAgent) { p.Framework = "" },
		"no deployment location":      func(p *inventory.NewAgent) { p.DeploymentLocation = "" },
		"no environment":              func(p *inventory.NewAgent) { p.Environments = nil },
		"a malformed environment":     func(p *inventory.NewAgent) { p.Environments = []string{"Prod"} },
		"an environment listed twice": func(p *inventory.NewAgent) { p.Environments = []string{"prod", "prod"} },
		"an unknown risk tier":        func(p *inventory.NewAgent) { p.RiskTier = "extreme" },
		"an unknown classification":   func(p *inventory.NewAgent) { p.AIActClassification = "unsure" },
		"no data category":            func(p *inventory.NewAgent) { p.DataCategories = nil },
		"an unknown data category":    func(p *inventory.NewAgent) { p.DataCategories = []string{"gossip"} },
		"a malformed label key":       func(p *inventory.NewAgent) { p.Labels = map[string]string{"Team": "x"} },
		"an empty harness":            func(p *inventory.NewAgent) { p.Harness = &inventory.Harness{} },
		"an unknown halt mode":        func(p *inventory.NewAgent) { p.HaltMode = "pause" },
	}
	for name, spoil := range cases {
		t.Run(name, func(t *testing.T) {
			p := proposal("invoice-triage", uc.ID)
			spoil(&p)
			_, err := f.inv.Propose(context.Background(), f.olivia, p)
			refused(t, err, inventory.Invalid)
		})
	}
	tooMany := map[string]string{}
	for i := range 65 {
		tooMany[fmt.Sprintf("key-%d", i)] = "x"
	}
	p := proposal("invoice-triage", uc.ID)
	p.Labels = tooMany
	_, err := f.inv.Propose(context.Background(), f.olivia, p)
	refused(t, err, inventory.Invalid)
}

// Enforcement points build the subject of each decision request from the
// agent's labels, so the inventory takes only the label keys that the
// request's schema allows (CORE-17).
func TestLabelKeysHaveTheSyntaxOfTheDecisionRequest(t *testing.T) {
	f := setup(t)
	uc := f.useCase(t, f.olivia)
	cases := []struct {
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
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := proposal(fmt.Sprintf("agent-%d", i), uc.ID)
			p.Labels = map[string]string{tc.key: "finance"}
			a, err := f.inv.Propose(context.Background(), f.olivia, p)
			switch {
			case !tc.valid:
				refused(t, err, inventory.Invalid)
			case err != nil:
				t.Fatalf("refused, but the request's schema allows the key: %v", err)
			case a.Labels[tc.key] != "finance":
				t.Errorf("labels %v", a.Labels)
			}
		})
	}
}

// The subject of a decision request never holds an empty data category
// (CORE-17): the inventory refuses one, even from a setting that holds it.
func TestADataCategoryIsNeverEmpty(t *testing.T) {
	f := setup(t)
	f.set(t, `UPDATE whitetower.settings SET value = value || '[""]' WHERE key = 'inventory.data_categories'`)
	p := proposal("invoice-triage", f.useCase(t, f.olivia).ID)
	p.DataCategories = []string{""}
	_, err := f.inv.Propose(context.Background(), f.olivia, p)
	refused(t, err, inventory.Invalid)
}

func TestAProposalNeedsAUseCaseThatIsNotRejected(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	_, err := f.inv.Propose(ctx, f.olivia, proposal("invoice-triage", uuid.Must(uuid.NewV7())))
	refused(t, err, inventory.Invalid)

	uc := f.useCase(t, f.olivia)
	f.set(t, `UPDATE whitetower.use_cases SET status = 'rejected' WHERE id = $1`, uc.ID)
	_, err = f.inv.Propose(ctx, f.olivia, proposal("invoice-triage", uc.ID))
	refused(t, err, inventory.Conflict)
}

func TestASlugBelongsToOneAgent(t *testing.T) {
	f := setup(t)
	f.propose(t, "invoice-triage")
	_, err := f.inv.Propose(context.Background(), f.otto, proposal("invoice-triage", f.useCase(t, f.otto).ID))
	refused(t, err, inventory.Conflict)
}

func TestOnlyAPersonWithTheOwnerRoleProposesAnAgent(t *testing.T) {
	f := setup(t)
	uc := f.useCase(t, f.olivia)
	bot := f.olivia
	bot.Kind = auth.ServiceAccount
	scoped := f.olivia
	scoped.Scopes = []string{"inventory.view"}
	for name, caller := range map[string]auth.Principal{
		"the advisory role":            f.alex,
		"an operator":                  f.omar,
		"a service account":            bot,
		"a token without the scope":    scoped,
		"a session of the user role":   f.uma,
		"a break-glass session":        {ID: f.omar.ID, Kind: auth.Human, Roles: []string{"operator"}, IsBreakglass: true},
		"a principal with no role":     {ID: f.olivia.ID, Kind: auth.Human},
		"another role, with the scope": {ID: f.alex.ID, Kind: auth.Human, Roles: []string{"advisory"}, Scopes: []string{"agent.propose"}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := f.inv.Propose(context.Background(), caller, proposal("invoice-triage", uc.ID))
			refused(t, err, inventory.Forbidden)
		})
	}
}

func TestWhoeverSeesOnlyActiveAgentsSeesNoOther(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a := f.propose(t, "invoice-triage")
	_, err := f.inv.Get(ctx, f.uma, a.ID)
	refused(t, err, inventory.NotFound)
	if list, _, err := f.inv.List(ctx, f.uma, "", 50); err != nil || len(list) != 0 {
		t.Fatalf("got %v, %v; want no agent", list, err)
	}

	f.set(t, `UPDATE whitetower.agents SET lifecycle_state = 'active', harness = '{"description": "a container"}' WHERE id = $1`, a.ID)
	if _, err := f.inv.Get(ctx, f.uma, a.ID); err != nil {
		t.Fatalf("an active agent: %v", err)
	}
	if list, _, err := f.inv.List(ctx, f.uma, "", 50); err != nil || len(list) != 1 {
		t.Fatalf("got %v, %v; want the active agent", list, err)
	}
	if _, err := f.inv.Get(ctx, f.alex, uuid.Must(uuid.NewV7())); err == nil {
		t.Fatal("an agent that does not exist was found")
	}
}

func TestAgentsAreListedBySlugOnePageAtATime(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	for _, slug := range []string{"c-agent", "a-agent", "b-agent"} {
		f.propose(t, slug)
	}
	page, more, err := f.inv.List(ctx, f.alex, "", 2)
	if err != nil || !more || len(page) != 2 || page[0].Slug != "a-agent" || page[1].Slug != "b-agent" {
		t.Fatalf("first page %v, more %v, %v", page, more, err)
	}
	page, more, err = f.inv.List(ctx, f.alex, page[1].Slug, 2)
	if err != nil || more || len(page) != 1 || page[0].Slug != "c-agent" {
		t.Fatalf("last page %v, more %v, %v", page, more, err)
	}
}

func TestAnEditChangesTheVersionTheCallerRead(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a := f.propose(t, "invoice-triage")
	stateVersion := f.stateVersion(t, a.ID)
	name := "Invoice sorter"
	description := "Sorts every invoice."

	edited, err := f.inv.Edit(ctx, f.olivia, a.ID, a.Version, inventory.AgentChanges{Name: &name, Description: &description})
	if err != nil {
		t.Fatal(err)
	}
	if edited.Name != name || edited.Description != description || edited.Version != a.Version+1 {
		t.Fatalf("got %q, %q at version %d", edited.Name, edited.Description, edited.Version)
	}
	// Enforcement points see neither the name nor the description.
	if v := f.stateVersion(t, a.ID); v != stateVersion {
		t.Errorf("state version %d, want %d", v, stateVersion)
	}
	updated := f.events(t, "whitetower.agent.updated.v1")
	if len(updated) != 1 || *updated[0].subject != a.ID {
		t.Fatalf("events %+v", updated)
	}
	data := updated[0].data
	if _, copied := data["after"].(map[string]any)["description"]; copied || data["state_version"] != nil {
		t.Errorf("event data %v: the description is named, never copied, and no state version is taken", data)
	}
	if changed := data["changed"].([]any); len(changed) != 2 || changed[0] != "name" || changed[1] != "description" {
		t.Errorf("changed %v", changed)
	}

	_, err = f.inv.Edit(ctx, f.olivia, a.ID, a.Version, inventory.AgentChanges{Name: &name})
	refused(t, err, inventory.Stale)

	// An edit that changes nothing takes no new version.
	same, err := f.inv.Edit(ctx, f.olivia, a.ID, edited.Version, inventory.AgentChanges{Name: &name})
	if err != nil || same.Version != edited.Version {
		t.Fatalf("got version %d, %v; want %d", same.Version, err, edited.Version)
	}
	if n := len(f.events(t, "whitetower.agent.updated.v1")); n != 1 {
		t.Errorf("%d events, want 1", n)
	}
}

func TestAnEditOfWhatPoliciesSeeTakesAStateVersion(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a := f.propose(t, "invoice-triage")
	before := f.stateVersion(t, a.ID)
	critical := "critical"
	edited, err := f.inv.Edit(ctx, f.olivia, a.ID, a.Version, inventory.AgentChanges{RiskTier: &critical})
	if err != nil {
		t.Fatal(err)
	}
	after := f.stateVersion(t, a.ID)
	var lease int32
	if err := f.pool.QueryRow(ctx, `SELECT lease_ttl_seconds FROM whitetower.governance_state WHERE agent_id = $1`, a.ID).Scan(&lease); err != nil {
		t.Fatal(err)
	}
	if edited.RiskTier != "critical" || after <= before || lease != 15 {
		t.Fatalf("risk tier %s, state version %d after %d, lease %d", edited.RiskTier, after, before, lease)
	}
	updated := f.events(t, "whitetower.agent.updated.v1")
	data := updated[0].data
	if data["state_version"] != float64(after) || data["before"].(map[string]any)["risk_tier"] != "high" || data["after"].(map[string]any)["risk_tier"] != "critical" {
		t.Errorf("event data %v", data)
	}
}

func TestOwnersAndOperatorsEditAnAgent(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a := f.propose(t, "invoice-triage")
	name := "Invoice sorter"
	for caller, p := range map[string]auth.Principal{"another owner": f.otto, "the advisory committee": f.alex, "a user": f.uma} {
		t.Run(caller, func(t *testing.T) {
			_, err := f.inv.Edit(ctx, p, a.ID, a.Version, inventory.AgentChanges{Name: &name})
			refused(t, err, inventory.Forbidden)
		})
	}
	if _, err := f.inv.Edit(ctx, f.omar, a.ID, a.Version, inventory.AgentChanges{Name: &name}); err != nil {
		t.Fatalf("an operator: %v", err)
	}
}

func TestAnEditKeepsTheRulesOfTheAgent(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a := f.propose(t, "invoice-triage")
	empty := ""
	_, err := f.inv.Edit(ctx, f.olivia, a.ID, a.Version, inventory.AgentChanges{Framework: &empty})
	refused(t, err, inventory.Invalid)

	gossip := []string{"gossip"}
	_, err = f.inv.Edit(ctx, f.olivia, a.ID, a.Version, inventory.AgentChanges{DataCategories: &gossip})
	refused(t, err, inventory.Invalid)

	// The use case changes only while the agent is a draft, and never to a
	// rejected one.
	rejected := f.useCase(t, f.olivia)
	f.set(t, `UPDATE whitetower.use_cases SET status = 'rejected' WHERE id = $1`, rejected.ID)
	_, err = f.inv.Edit(ctx, f.olivia, a.ID, a.Version, inventory.AgentChanges{UseCaseID: &rejected.ID})
	refused(t, err, inventory.Conflict)
	other := f.useCase(t, f.olivia)
	f.set(t, `UPDATE whitetower.agents SET lifecycle_state = 'proposed' WHERE id = $1`, a.ID)
	_, err = f.inv.Edit(ctx, f.olivia, a.ID, a.Version, inventory.AgentChanges{UseCaseID: &other.ID})
	refused(t, err, inventory.Conflict)

	f.set(t, `UPDATE whitetower.agents SET lifecycle_state = 'retired', retired_at = now() WHERE id = $1`, a.ID)
	name := "Invoice sorter"
	_, err = f.inv.Edit(ctx, f.olivia, a.ID, a.Version, inventory.AgentChanges{Name: &name})
	refused(t, err, inventory.Conflict)
}

func TestOwnersAreThePrimaryOwnerAndTheDelegates(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a := f.propose(t, "invoice-triage")
	f.set(t, `INSERT INTO whitetower.agent_owners (id, agent_id, principal_id, role, assigned_by, assigned_at)
		VALUES ($1, $2, $3, 'delegate', $4, now())`, uuid.Must(uuid.NewV7()), a.ID, uuid.MustParse(f.otto.ID), uuid.MustParse(f.olivia.ID))
	for name, c := range map[string]struct {
		who  auth.Principal
		owns bool
	}{
		"the primary owner": {f.olivia, true},
		"a delegate":        {f.otto, true},
		"someone else":      {f.omar, false},
	} {
		owns, err := f.inv.IsOwner(ctx, a.ID, uuid.MustParse(c.who.ID))
		if err != nil || owns != c.owns {
			t.Errorf("%s: got %v, %v", name, owns, err)
		}
	}
	got, err := f.inv.Get(ctx, f.alex, a.ID)
	if err != nil || len(got.Delegates) != 1 || got.Delegates[0].ID.String() != f.otto.ID {
		t.Fatalf("delegates %v, %v", got.Delegates, err)
	}

	f.set(t, `UPDATE whitetower.agent_owners SET ended_at = now(), ended_by = $2, end_reason = 'left the team'
		WHERE agent_id = $1 AND role = 'delegate'`, a.ID, uuid.MustParse(f.olivia.ID))
	if owns, err := f.inv.IsOwner(ctx, a.ID, uuid.MustParse(f.otto.ID)); err != nil || owns {
		t.Errorf("an ended delegate: got %v, %v", owns, err)
	}
}

func TestAHaltOfTheFleetHaltsEveryAgent(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a := f.propose(t, "invoice-triage")
	f.set(t, `UPDATE whitetower.fleet_state SET run_state = 'halted', halt_ids = ARRAY[$1::uuid],
		state_version = whitetower.next_governance_version()`, uuid.Must(uuid.NewV7()))
	got, err := f.inv.Get(ctx, f.alex, a.ID)
	if err != nil || !got.Halted {
		t.Fatalf("halted %v, %v", got.Halted, err)
	}
}
