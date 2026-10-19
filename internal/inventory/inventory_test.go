package inventory_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/J466Y/WhiteTower/api/events"
	"github.com/J466Y/WhiteTower/internal/audit"
	"github.com/J466Y/WhiteTower/internal/authz"
	"github.com/J466Y/WhiteTower/internal/inventory"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/clock/clocktest"
	"github.com/J466Y/WhiteTower/internal/platform/db"
	"github.com/J466Y/WhiteTower/internal/platform/db/dbtest"
)

var epoch = time.Date(2026, 10, 19, 9, 0, 0, 0, time.UTC)

// fixture is an inventory on a database of its own, with people who hold the
// roles that the tests need.
type fixture struct {
	pool *db.DB
	inv  *inventory.Inventory
	clk  *clocktest.Fake
	// olivia and otto are owners, alex is on the advisory committee, omar is
	// an operator and uma a user.
	olivia, otto, alex, omar, uma auth.Principal
}

func setup(t *testing.T) *fixture {
	t.Helper()
	pool := dbtest.New(t).Open(t)
	catalog, err := audit.LoadCatalog(events.Files)
	if err != nil {
		t.Fatal(err)
	}
	clk := clocktest.New(epoch)
	f := &fixture{
		pool: pool,
		clk:  clk,
		inv: inventory.New(inventory.Options{
			DB:         pool,
			Clock:      clk,
			Writer:     audit.NewWriter(catalog, clk),
			Authorizer: authz.NewAuthorizer(),
			Versions:   inventory.SequenceVersions{},
			RoleMapping: map[string]string{
				"wt-owner": "owner", "wt-advisory": "advisory", "wt-operator": "operator", "wt-user": "user",
			},
		}),
	}
	f.olivia = f.person(t, "Olivia Owner", "owner")
	f.otto = f.person(t, "Otto Owner", "owner")
	f.alex = f.person(t, "Alex Advisory", "advisory")
	f.omar = f.person(t, "Omar Operator", "operator")
	f.uma = f.person(t, "Uma User", "user")
	return f
}

// person stores a human principal in the IdP group of the role given, and
// returns it as an API caller with that role.
func (f *fixture) person(t *testing.T, name, role string) auth.Principal {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	if _, err := f.pool.Exec(context.Background(),
		`INSERT INTO whitetower.principals (id, kind, issuer, subject, display_name, idp_groups)
		 VALUES ($1, 'human', 'https://idp.example.com', $2, $3, $4)`, id, id.String(), name, []string{"wt-" + role}); err != nil {
		t.Fatal(err)
	}
	return auth.Principal{ID: id.String(), Kind: auth.Human, Name: name, Roles: []string{role}}
}

// useCase creates a use case as the person given.
func (f *fixture) useCase(t *testing.T, by auth.Principal) *inventory.UseCase {
	t.Helper()
	uc, err := f.inv.CreateUseCase(context.Background(), by, inventory.NewUseCase{
		Title:                 "Invoice triage",
		Description:           "Sorts the invoices that suppliers send.",
		BusinessJustification: "Saves the finance team a day a week.",
		DataCategories:        []string{"financial_data"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return uc
}

// proposal is a complete proposal of an agent that the use case justifies.
func proposal(slug string, useCase uuid.UUID) inventory.NewAgent {
	return inventory.NewAgent{
		Slug:               slug,
		Name:               "Invoice triage",
		Description:        "Sorts the invoices that suppliers send.",
		Kind:               "in_house",
		Framework:          "langgraph",
		DeploymentLocation: "eu-west-1",
		Environments:       []string{"production"},
		RiskTier:           "high",
		DataCategories:     []string{"financial_data"},
		UseCaseID:          useCase,
		Labels:             map[string]string{"team": "finance"},
	}
}

// propose proposes an agent as olivia.
func (f *fixture) propose(t *testing.T, slug string) *inventory.Agent {
	t.Helper()
	a, err := f.inv.Propose(context.Background(), f.olivia, proposal(slug, f.useCase(t, f.olivia).ID))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// set changes a row the way a later step of the lifecycle would.
func (f *fixture) set(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatal(err)
	}
}

// refused fails the test unless err is a refusal of the kind given.
func refused(t *testing.T, err error, kind inventory.RefusalKind) {
	t.Helper()
	var r *inventory.Refusal
	if !errors.As(err, &r) || r.Kind != kind {
		t.Fatalf("got %v, want a refusal of kind %d", err, kind)
	}
}

// event is an audit event as the log stores it.
type event struct {
	subject   *uuid.UUID
	actorType string
	actorID   string
	data      map[string]any
}

// events returns the audit events of the type given, oldest first.
func (f *fixture) events(t *testing.T, eventType string) []event {
	t.Helper()
	rows, err := f.pool.Query(context.Background(),
		`SELECT subject_agent_id, actor_type, coalesce(actor_id, ''), canonical
		 FROM whitetower.audit_events WHERE type = $1 ORDER BY id`, eventType)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var found []event
	for rows.Next() {
		var e event
		var canonical []byte
		if err := rows.Scan(&e.subject, &e.actorType, &e.actorID, &canonical); err != nil {
			t.Fatal(err)
		}
		var envelope struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(canonical, &envelope); err != nil {
			t.Fatal(err)
		}
		e.data = envelope.Data
		found = append(found, e)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return found
}

// stateVersion returns the governance state version of an agent.
func (f *fixture) stateVersion(t *testing.T, agent uuid.UUID) int64 {
	t.Helper()
	var v int64
	if err := f.pool.QueryRow(context.Background(),
		`SELECT state_version FROM whitetower.governance_state WHERE agent_id = $1`, agent).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestDataCategoriesComeFromTheSetting(t *testing.T) {
	f := setup(t)
	categories, err := f.inv.DataCategories(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(categories) != 10 || categories[0] != "public_data" {
		t.Fatalf("got %v, want the ten categories of the setting inventory.data_categories", categories)
	}
}
