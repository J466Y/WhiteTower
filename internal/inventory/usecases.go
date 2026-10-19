package inventory

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/J466Y/WhiteTower/internal/audit"
	"github.com/J466Y/WhiteTower/internal/authz"
	"github.com/J466Y/WhiteTower/internal/inventory/inventorydb"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/db"
)

// UseCase is the business purpose that justifies one or more agents
// (INV-03). Its conditions are those under which the agents it justifies may
// run, which the advisory committee validates with it.
type UseCase struct {
	ID                    uuid.UUID
	Title                 string
	Description           string
	BusinessJustification string
	DataCategories        []string
	AffectedPersons       string // empty when not given
	AIActClassification   string
	Conditions            string // empty when not given
	Status                string
	CreatedBy             Person
	CreatedAt             time.Time
	UpdatedAt             time.Time
	// Version is the version of the use case's row, which its ETag carries
	// (API-03).
	Version int64
}

// NewUseCase is a use case to create.
type NewUseCase struct {
	Title                 string
	Description           string
	BusinessJustification string
	DataCategories        []string
	AffectedPersons       string
	AIActClassification   string // not_assessed when empty
	Conditions            string
}

// UseCaseChanges are the members of a use case to change; a nil member keeps
// its value, and an empty text clears an optional one.
type UseCaseChanges struct {
	Title                 *string
	Description           *string
	BusinessJustification *string
	DataCategories        *[]string
	AffectedPersons       *string
	AIActClassification   *string
	Conditions            *string
}

// Decision is a decision of the advisory committee on a use case, made on an
// agent's proposal.
type Decision struct {
	ID        uuid.UUID
	Decision  string
	Comment   string
	AgentID   *uuid.UUID
	DecidedBy Person
	DecidedAt time.Time
}

// CreateUseCase creates a use case as a draft. Owners create them, and only
// people: whoever creates a use case never decides on it (HUM-04).
func (inv *Inventory) CreateUseCase(ctx context.Context, caller auth.Principal, in NewUseCase) (*UseCase, error) {
	if caller.Kind != auth.Human {
		return nil, refuse(Forbidden, "only a person can create a use case")
	}
	if err := inv.authorize(ctx, caller, authz.PermissionAgentPropose, authz.Relationship{}); err != nil {
		return nil, err
	}
	creator, err := uuid.Parse(caller.ID)
	if err != nil {
		return nil, fmt.Errorf("the caller's ID %q: %w", caller.ID, err)
	}
	uc := UseCase{
		Title: in.Title, Description: in.Description, BusinessJustification: in.BusinessJustification,
		DataCategories: in.DataCategories, AffectedPersons: in.AffectedPersons,
		AIActClassification: in.AIActClassification, Conditions: in.Conditions,
	}
	if uc.AIActClassification == "" {
		uc.AIActClassification = "not_assessed"
	}
	if err := uc.validate(); err != nil {
		return nil, err
	}
	var id uuid.UUID
	err = inv.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := inventorydb.New(tx)
		if err := checkCategories(ctx, q, uc.DataCategories); err != nil {
			return err
		}
		if id, err = uuid.NewV7(); err != nil {
			return fmt.Errorf("generating the use case's ID: %w", err)
		}
		if err := q.CreateUseCase(ctx, inventorydb.CreateUseCaseParams{
			ID:                    id,
			Title:                 uc.Title,
			Description:           uc.Description,
			BusinessJustification: uc.BusinessJustification,
			DataCategories:        uc.DataCategories,
			AffectedPersons:       nonEmpty(uc.AffectedPersons),
			AiActClassification:   uc.AIActClassification,
			Conditions:            nonEmpty(uc.Conditions),
			CreatedBy:             creator,
			CreatedAt:             inv.clk.Now().UTC(),
		}); err != nil {
			return fmt.Errorf("inserting the use case: %w", err)
		}
		if err := inv.writer.Record(ctx, tx, audit.Event{
			Type: "whitetower.use_case.created.v1",
			Data: map[string]any{
				"use_case_id":           id.String(),
				"ai_act_classification": uc.AIActClassification,
				"data_categories":       uc.DataCategories,
				"actor":                 actorOf(caller),
			},
		}); err != nil {
			return fmt.Errorf("recording the use case's creation: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return inv.loadUseCase(ctx, inventorydb.New(inv.db), id)
}

// GetUseCase returns a use case. Whoever may see only active agents sees only
// the use cases of active agents.
func (inv *Inventory) GetUseCase(ctx context.Context, caller auth.Principal, id uuid.UUID) (*UseCase, error) {
	q := inventorydb.New(inv.db)
	uc, err := inv.loadUseCase(ctx, q, id)
	if err != nil {
		return nil, err
	}
	if !seesAll(caller) {
		active, err := q.UseCaseJustifiesActiveAgent(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("reading the use case's agents: %w", err)
		}
		if !active {
			return nil, refuse(NotFound, "no use case has this ID")
		}
	}
	return uc, nil
}

// ListUseCases returns a page of at most size use cases, newest first, before
// the one given, and whether more follow. Whoever may see only active agents
// sees only the use cases of active agents.
func (inv *Inventory) ListUseCases(ctx context.Context, caller auth.Principal, before *uuid.UUID, size int) ([]UseCase, bool, error) {
	if size < 1 || size > maxPage {
		return nil, false, fmt.Errorf("a page of %d use cases: want 1 to %d", size, maxPage)
	}
	q := inventorydb.New(inv.db)
	rows, err := q.ListUseCases(ctx, inventorydb.ListUseCasesParams{
		Before:     before,
		ActiveOnly: !seesAll(caller),
		PageLimit:  int32(size + 1), //nolint:gosec // G115: size is at most maxPage
	})
	if err != nil {
		return nil, false, fmt.Errorf("listing use cases: %w", err)
	}
	more := len(rows) > size
	if more {
		rows = rows[:size]
	}
	useCases, err := assembleUseCases(ctx, q, rows)
	return useCases, more, err
}

// EditUseCase changes a use case, if it is still at the version the caller
// read (API-03). Only its creator edits it, while it is a draft or changes
// were requested, and no agent it justifies waits for a decision: the
// committee decides on what it read. A validated or rejected use case never
// changes, because the agents it justifies rely on it.
func (inv *Inventory) EditUseCase(ctx context.Context, caller auth.Principal, id uuid.UUID, version int64, ch UseCaseChanges) (*UseCase, error) {
	err := inv.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := inventorydb.New(tx)
		before, err := inv.loadUseCase(ctx, q, id)
		if err != nil {
			return err
		}
		if before.CreatedBy.ID.String() != caller.ID {
			return refuse(Forbidden, "only the use case's creator edits it")
		}
		if err := inv.authorize(ctx, caller, authz.PermissionAgentPropose, authz.Relationship{}); err != nil {
			return err
		}
		if before.Version != version {
			return refuse(Stale, "the use case changed since you read it: read it again, then retry")
		}
		switch before.Status {
		case "validated", "rejected":
			return refuse(Conflict, "a %s use case never changes: create another one", before.Status)
		case "submitted":
			return refuse(Conflict, "the advisory committee is deciding on the use case: withdraw the proposal to edit it")
		}
		awaits, err := q.UseCaseAwaitsDecision(ctx, id)
		if err != nil {
			return fmt.Errorf("reading the use case's agents: %w", err)
		}
		if awaits {
			return refuse(Conflict, "the advisory committee is deciding on the use case: withdraw the proposal to edit it")
		}
		after := ch.applyTo(before)
		if err := after.validate(); err != nil {
			return err
		}
		if ch.DataCategories != nil {
			if err := checkCategories(ctx, q, after.DataCategories); err != nil {
				return err
			}
		}
		cs := compareUseCases(before, after)
		if len(cs.names) == 0 {
			return nil
		}
		n, err := q.UpdateUseCase(ctx, inventorydb.UpdateUseCaseParams{
			Title:                 after.Title,
			Description:           after.Description,
			BusinessJustification: after.BusinessJustification,
			DataCategories:        after.DataCategories,
			AffectedPersons:       nonEmpty(after.AffectedPersons),
			AiActClassification:   after.AIActClassification,
			Conditions:            nonEmpty(after.Conditions),
			UpdatedAt:             inv.clk.Now().UTC(),
			ID:                    id,
			Version:               version,
		})
		if err != nil {
			return fmt.Errorf("updating the use case: %w", err)
		}
		if n == 0 {
			return refuse(Stale, "the use case changed since you read it: read it again, then retry")
		}
		data := map[string]any{"use_case_id": id.String(), "changed": cs.names, "actor": actorOf(caller)}
		if len(cs.before) > 0 {
			data["before"], data["after"] = cs.before, cs.after
		}
		if err := inv.writer.Record(ctx, tx, audit.Event{Type: "whitetower.use_case.updated.v1", Data: data}); err != nil {
			return fmt.Errorf("recording the use case's change: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return inv.loadUseCase(ctx, inventorydb.New(inv.db), id)
}

// Decisions returns a page of at most size decisions on a use case that the
// caller may see, newest first, before the one given, and whether more
// follow.
func (inv *Inventory) Decisions(ctx context.Context, caller auth.Principal, useCaseID uuid.UUID, before *uuid.UUID, size int) ([]Decision, bool, error) {
	if size < 1 || size > maxPage {
		return nil, false, fmt.Errorf("a page of %d decisions: want 1 to %d", size, maxPage)
	}
	if _, err := inv.GetUseCase(ctx, caller, useCaseID); err != nil {
		return nil, false, err
	}
	q := inventorydb.New(inv.db)
	rows, err := q.ListUseCaseDecisions(ctx, inventorydb.ListUseCaseDecisionsParams{
		UseCaseID: useCaseID,
		Before:    before,
		PageLimit: int32(size + 1), //nolint:gosec // G115: size is at most maxPage
	})
	if err != nil {
		return nil, false, fmt.Errorf("listing the use case's decisions: %w", err)
	}
	more := len(rows) > size
	if more {
		rows = rows[:size]
	}
	deciders := make([]uuid.UUID, len(rows))
	for i, r := range rows {
		deciders[i] = r.DecidedBy
	}
	who, err := people(ctx, q, deciders)
	if err != nil {
		return nil, false, err
	}
	decisions := make([]Decision, len(rows))
	for i, r := range rows {
		decisions[i] = Decision{
			ID: r.ID, Decision: r.Decision, Comment: r.Comment, AgentID: r.AgentID,
			DecidedBy: who[r.DecidedBy], DecidedAt: r.DecidedAt,
		}
	}
	return decisions, more, nil
}

// validate checks the members of a use case that the inventory is about to
// store, against the bounds of the API.
func (uc *UseCase) validate() error {
	for _, err := range []error{
		required("title", uc.Title, 200),
		required("description", uc.Description, 4000),
		required("businessJustification", uc.BusinessJustification, 4000),
		dataCategories(uc.DataCategories),
		optional("affectedPersons", uc.AffectedPersons, 2000),
		oneOf("aiActClassification", uc.AIActClassification, classifications),
		optional("conditions", uc.Conditions, 4000),
	} {
		if err != nil {
			return err
		}
	}
	return nil
}

// applyTo returns a copy of uc with the changes applied.
func (ch UseCaseChanges) applyTo(uc *UseCase) *UseCase {
	b := *uc
	set := func(dst *string, src *string) {
		if src != nil {
			*dst = *src
		}
	}
	set(&b.Title, ch.Title)
	set(&b.Description, ch.Description)
	set(&b.BusinessJustification, ch.BusinessJustification)
	set(&b.AffectedPersons, ch.AffectedPersons)
	set(&b.AIActClassification, ch.AIActClassification)
	set(&b.Conditions, ch.Conditions)
	if ch.DataCategories != nil {
		b.DataCategories = slices.Clone(*ch.DataCategories)
	}
	return &b
}

// compareUseCases compares a use case before and after an edit. Its texts
// are written by people: the event names them as changed, and copies only the
// classification and the data categories.
func compareUseCases(a, b *UseCase) changeSet {
	d := changeSet{before: map[string]any{}, after: map[string]any{}}
	text := func(name, x, y string) {
		if x != y {
			d.names = append(d.names, name)
		}
	}
	text("title", a.Title, b.Title)
	text("description", a.Description, b.Description)
	text("business_justification", a.BusinessJustification, b.BusinessJustification)
	if !slices.Equal(a.DataCategories, b.DataCategories) {
		d.names = append(d.names, "data_categories")
		d.before["data_categories"], d.after["data_categories"] = a.DataCategories, b.DataCategories
	}
	text("affected_persons", a.AffectedPersons, b.AffectedPersons)
	if a.AIActClassification != b.AIActClassification {
		d.names = append(d.names, "ai_act_classification")
		d.before["ai_act_classification"], d.after["ai_act_classification"] = a.AIActClassification, b.AIActClassification
	}
	text("conditions", a.Conditions, b.Conditions)
	return d
}

// loadUseCase reads a use case.
func (inv *Inventory) loadUseCase(ctx context.Context, q *inventorydb.Queries, id uuid.UUID) (*UseCase, error) {
	row, err := q.GetUseCase(ctx, id)
	if err != nil {
		return nil, notFound(err, "use case")
	}
	useCases, err := assembleUseCases(ctx, q, []inventorydb.WhitetowerUseCase{row})
	if err != nil {
		return nil, err
	}
	return &useCases[0], nil
}

// assembleUseCases completes the rows of use cases with the people who
// created them.
func assembleUseCases(ctx context.Context, q *inventorydb.Queries, rows []inventorydb.WhitetowerUseCase) ([]UseCase, error) {
	creators := make([]uuid.UUID, len(rows))
	for i, r := range rows {
		creators[i] = r.CreatedBy
	}
	who, err := people(ctx, q, creators)
	if err != nil {
		return nil, err
	}
	useCases := make([]UseCase, len(rows))
	for i, r := range rows {
		useCases[i] = UseCase{
			ID: r.ID, Title: r.Title, Description: r.Description,
			BusinessJustification: r.BusinessJustification, DataCategories: r.DataCategories,
			AffectedPersons: deref(r.AffectedPersons), AIActClassification: r.AiActClassification,
			Conditions: deref(r.Conditions), Status: r.Status, CreatedBy: who[r.CreatedBy],
			CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, Version: r.Version,
		}
	}
	return useCases, nil
}
