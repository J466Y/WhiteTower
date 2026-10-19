package inventory_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/J466Y/WhiteTower/internal/inventory"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
)

func TestAUseCaseIsCreatedAsADraft(t *testing.T) {
	f := setup(t)
	uc := f.useCase(t, f.olivia)
	if uc.Status != "draft" || uc.AIActClassification != "not_assessed" || uc.CreatedBy.ID.String() != f.olivia.ID || uc.Version != 1 {
		t.Fatalf("got %+v", uc)
	}
	created := f.events(t, "whitetower.use_case.created.v1")
	if len(created) != 1 || created[0].subject != nil || created[0].data["use_case_id"] != uc.ID.String() {
		t.Fatalf("events %+v, want one without a subject, about the use case", created)
	}

	bot := f.olivia
	bot.Kind = auth.ServiceAccount
	for name, caller := range map[string]auth.Principal{"a service account": bot, "the advisory committee": f.alex, "a user": f.uma} {
		t.Run(name, func(t *testing.T) {
			_, err := f.inv.CreateUseCase(context.Background(), caller, inventory.NewUseCase{
				Title: "t", Description: "d", BusinessJustification: "b", DataCategories: []string{"public_data"},
			})
			refused(t, err, inventory.Forbidden)
		})
	}
	_, err := f.inv.CreateUseCase(context.Background(), f.olivia, inventory.NewUseCase{
		Title: "t", Description: "d", BusinessJustification: "", DataCategories: []string{"public_data"},
	})
	refused(t, err, inventory.Invalid)
}

func TestOnlyItsCreatorEditsAUseCase(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	uc := f.useCase(t, f.olivia)
	conditions := "A person checks every payment."
	for name, caller := range map[string]auth.Principal{"another owner": f.otto, "an operator": f.omar} {
		t.Run(name, func(t *testing.T) {
			_, err := f.inv.EditUseCase(ctx, caller, uc.ID, uc.Version, inventory.UseCaseChanges{Conditions: &conditions})
			refused(t, err, inventory.Forbidden)
		})
	}

	classification := "limited"
	edited, err := f.inv.EditUseCase(ctx, f.olivia, uc.ID, uc.Version, inventory.UseCaseChanges{
		Conditions: &conditions, AIActClassification: &classification,
	})
	if err != nil || edited.Conditions != conditions || edited.Version != uc.Version+1 {
		t.Fatalf("got %+v, %v", edited, err)
	}
	updated := f.events(t, "whitetower.use_case.updated.v1")
	if len(updated) != 1 {
		t.Fatalf("events %+v", updated)
	}
	data := updated[0].data
	if _, copied := data["after"].(map[string]any)["conditions"]; copied || data["after"].(map[string]any)["ai_act_classification"] != "limited" {
		t.Errorf("event data %v: the conditions are named, never copied", data)
	}
	_, err = f.inv.EditUseCase(ctx, f.olivia, uc.ID, uc.Version, inventory.UseCaseChanges{Conditions: &conditions})
	refused(t, err, inventory.Stale)
}

func TestAUseCaseUnderReviewOrDecidedNeverChanges(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	title := "Invoice sorting"
	for _, status := range []string{"submitted", "validated", "rejected"} {
		t.Run(status, func(t *testing.T) {
			uc := f.useCase(t, f.olivia)
			f.set(t, `UPDATE whitetower.use_cases SET status = $2 WHERE id = $1`, uc.ID, status)
			_, err := f.inv.EditUseCase(ctx, f.olivia, uc.ID, uc.Version, inventory.UseCaseChanges{Title: &title})
			refused(t, err, inventory.Conflict)
		})
	}
	t.Run("an agent it justifies waits for a decision", func(t *testing.T) {
		uc := f.useCase(t, f.olivia)
		a, err := f.inv.Propose(ctx, f.olivia, proposal("invoice-triage", uc.ID))
		if err != nil {
			t.Fatal(err)
		}
		f.set(t, `UPDATE whitetower.agents SET lifecycle_state = 'proposed' WHERE id = $1`, a.ID)
		_, err = f.inv.EditUseCase(ctx, f.olivia, uc.ID, uc.Version, inventory.UseCaseChanges{Title: &title})
		refused(t, err, inventory.Conflict)
	})
	t.Run("changes were requested", func(t *testing.T) {
		uc := f.useCase(t, f.olivia)
		f.set(t, `UPDATE whitetower.use_cases SET status = 'changes_requested' WHERE id = $1`, uc.ID)
		if _, err := f.inv.EditUseCase(ctx, f.olivia, uc.ID, uc.Version, inventory.UseCaseChanges{Title: &title}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestUsersSeeOnlyTheUseCasesOfActiveAgents(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a := f.propose(t, "invoice-triage")
	_, err := f.inv.GetUseCase(ctx, f.uma, a.UseCaseID)
	refused(t, err, inventory.NotFound)
	if list, _, err := f.inv.ListUseCases(ctx, f.uma, nil, 50); err != nil || len(list) != 0 {
		t.Fatalf("got %v, %v; want no use case", list, err)
	}
	f.set(t, `UPDATE whitetower.agents SET lifecycle_state = 'active', harness = '{"description": "a container"}' WHERE id = $1`, a.ID)
	if _, err := f.inv.GetUseCase(ctx, f.uma, a.UseCaseID); err != nil {
		t.Fatalf("the use case of an active agent: %v", err)
	}
	if list, _, err := f.inv.ListUseCases(ctx, f.uma, nil, 50); err != nil || len(list) != 1 {
		t.Fatalf("got %v, %v; want the use case of the active agent", list, err)
	}
}

func TestUseCasesAndTheirDecisionsAreListedNewestFirst(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	first, second, third := f.useCase(t, f.olivia), f.useCase(t, f.olivia), f.useCase(t, f.otto)
	page, more, err := f.inv.ListUseCases(ctx, f.alex, nil, 2)
	if err != nil || !more || len(page) != 2 || page[0].ID != third.ID || page[1].ID != second.ID {
		t.Fatalf("first page %v, more %v, %v", page, more, err)
	}
	page, more, err = f.inv.ListUseCases(ctx, f.alex, &page[1].ID, 2)
	if err != nil || more || len(page) != 1 || page[0].ID != first.ID {
		t.Fatalf("last page %v, more %v, %v", page, more, err)
	}

	alex := uuid.MustParse(f.alex.ID)
	for _, decision := range []string{"changes_requested", "validated"} {
		f.set(t, `INSERT INTO whitetower.use_case_decisions (id, use_case_id, decision, comment, decided_by)
			VALUES ($1, $2, $3, 'reviewed', $4)`, uuid.Must(uuid.NewV7()), first.ID, decision, alex)
	}
	decisions, more, err := f.inv.Decisions(ctx, f.alex, first.ID, nil, 50)
	if err != nil || more || len(decisions) != 2 || decisions[0].Decision != "validated" || decisions[0].DecidedBy.DisplayName != "Alex Advisory" {
		t.Fatalf("decisions %+v, more %v, %v", decisions, more, err)
	}
	_, _, err = f.inv.Decisions(ctx, f.uma, first.ID, nil, 50)
	refused(t, err, inventory.NotFound)
}
