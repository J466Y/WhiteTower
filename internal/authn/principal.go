package authn

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/J466Y/WhiteTower/internal/audit"
	"github.com/J466Y/WhiteTower/internal/authn/authndb"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/clock"
	"github.com/J466Y/WhiteTower/internal/platform/db"
)

// ErrPrincipalNotFound is returned when no principal matches the query.
var ErrPrincipalNotFound = errors.New("principal not found")

// Principal represents a human user or service account in White Tower.
type Principal struct {
	ID                     uuid.UUID
	Kind                   string
	Issuer                 *string
	Subject                *string
	DisplayName            string
	Email                  *string
	Status                 string
	StatusChangedAt        *time.Time
	StatusReason           *string
	IDPGroups              []string
	LastLoginAt            *time.Time
	ResponsiblePrincipalID *uuid.UUID
	CreatedAt              time.Time
	UpdatedAt              time.Time
	Version                int64
}

// PrincipalStore manages principal records and status transitions.
type PrincipalStore struct {
	database     *db.DB
	clk          clock.Clock
	writer       *audit.Writer
	sessionStore *SessionStore
}

// NewPrincipalStore returns an initialized PrincipalStore.
func NewPrincipalStore(database *db.DB, clk clock.Clock, writer *audit.Writer, sessionStore *SessionStore) *PrincipalStore {
	return &PrincipalStore{
		database:     database,
		clk:          clk,
		writer:       writer,
		sessionStore: sessionStore,
	}
}

// UpsertHuman creates or updates a human principal record from IdP authentication claims.
func (ps *PrincipalStore) UpsertHuman(ctx context.Context, issuer, subject, displayName string, email *string, idpGroups []string) (*Principal, error) {
	if issuer == "" || subject == "" || displayName == "" {
		return nil, errors.New("issuer, subject, and displayName are required")
	}
	if idpGroups == nil {
		idpGroups = []string{}
	}

	newID, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("generating principal UUID: %w", err)
	}

	now := ps.clk.Now().UTC()
	q := authndb.New(ps.database)
	row, err := q.UpsertHumanPrincipal(ctx, authndb.UpsertHumanPrincipalParams{
		ID:          newID,
		Issuer:      &issuer,
		Subject:     &subject,
		DisplayName: displayName,
		Email:       email,
		IdpGroups:   idpGroups,
		LastLoginAt: &now,
	})
	if err != nil {
		return nil, fmt.Errorf("upserting principal: %w", err)
	}

	return fromDBModel(row), nil
}

// GetByID returns the principal with the given UUID.
func (ps *PrincipalStore) GetByID(ctx context.Context, id uuid.UUID) (*Principal, error) {
	q := authndb.New(ps.database)
	row, err := q.GetPrincipalByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrPrincipalNotFound
		}
		return nil, fmt.Errorf("querying principal by ID: %w", err)
	}
	return fromDBModel(row), nil
}

// GetByIdentity returns the human principal matching the IdP issuer and subject.
func (ps *PrincipalStore) GetByIdentity(ctx context.Context, issuer, subject string) (*Principal, error) {
	q := authndb.New(ps.database)
	row, err := q.GetHumanPrincipalByIdentity(ctx, authndb.GetHumanPrincipalByIdentityParams{
		Issuer:  &issuer,
		Subject: &subject,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrPrincipalNotFound
		}
		return nil, fmt.Errorf("querying principal by identity: %w", err)
	}
	return fromDBModel(row), nil
}

// Deactivate sets a principal's status to inactive, revokes all of their active sessions,
// and records an audited whitetower.principal.deactivated.v1 event (HUM-05, ST-14, ST-21).
func (ps *PrincipalStore) Deactivate(ctx context.Context, id uuid.UUID, actor auth.Principal, reason string) error {
	return ps.database.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := authndb.New(tx)
		p, err := q.GetPrincipalByID(ctx, id)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrPrincipalNotFound
			}
			return fmt.Errorf("reading principal: %w", err)
		}
		if p.Status == "inactive" {
			return nil
		}

		now := ps.clk.Now().UTC()
		if err := q.UpdatePrincipalStatus(ctx, authndb.UpdatePrincipalStatusParams{
			ID:              id,
			Status:          "inactive",
			StatusChangedAt: &now,
			StatusReason:    &reason,
		}); err != nil {
			return fmt.Errorf("updating principal status: %w", err)
		}

		// Revoke all sessions within the transaction.
		if err := ps.sessionStore.RevokeAllForPrincipalTx(ctx, tx, id); err != nil {
			return fmt.Errorf("revoking sessions for deactivated principal: %w", err)
		}

		// Record audit event in the same transaction.
		var actorType string
		switch actor.Kind {
		case auth.ServiceAccount:
			actorType = "service_account"
		case "":
			actorType = "system"
		default:
			actorType = "human"
		}

		actorPayload := map[string]any{
			"type": actorType,
		}
		if actor.ID != "" {
			actorPayload["id"] = actor.ID
		}

		if err := ps.writer.Record(ctx, tx, audit.Event{
			Type:    "whitetower.principal.deactivated.v1",
			Subject: id.String(),
			Data: map[string]any{
				"principal_id": id.String(),
				"actor":        actorPayload,
				"reason":       reason,
			},
		}); err != nil {
			return fmt.Errorf("recording deactivation audit event: %w", err)
		}

		return nil
	})
}

// Reactivate sets a principal's status back to active and records an audited event (HUM-05).
func (ps *PrincipalStore) Reactivate(ctx context.Context, id uuid.UUID, actor auth.Principal, reason string) error {
	return ps.database.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := authndb.New(tx)
		p, err := q.GetPrincipalByID(ctx, id)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrPrincipalNotFound
			}
			return fmt.Errorf("reading principal: %w", err)
		}
		if p.Status == "active" {
			return nil
		}

		now := ps.clk.Now().UTC()
		if err := q.UpdatePrincipalStatus(ctx, authndb.UpdatePrincipalStatusParams{
			ID:              id,
			Status:          "active",
			StatusChangedAt: &now,
			StatusReason:    &reason,
		}); err != nil {
			return fmt.Errorf("updating principal status: %w", err)
		}

		var actorType string
		switch actor.Kind {
		case auth.ServiceAccount:
			actorType = "service_account"
		case "":
			actorType = "system"
		default:
			actorType = "human"
		}

		actorPayload := map[string]any{
			"type": actorType,
		}
		if actor.ID != "" {
			actorPayload["id"] = actor.ID
		}

		if err := ps.writer.Record(ctx, tx, audit.Event{
			Type:    "whitetower.principal.reactivated.v1",
			Subject: id.String(),
			Data: map[string]any{
				"principal_id": id.String(),
				"actor":        actorPayload,
				"reason":       reason,
			},
		}); err != nil {
			return fmt.Errorf("recording reactivation audit event: %w", err)
		}

		return nil
	})
}

func fromDBModel(r authndb.WhitetowerPrincipal) *Principal {
	return &Principal{
		ID:                     r.ID,
		Kind:                   r.Kind,
		Issuer:                 r.Issuer,
		Subject:                r.Subject,
		DisplayName:            r.DisplayName,
		Email:                  r.Email,
		Status:                 r.Status,
		StatusChangedAt:        r.StatusChangedAt,
		StatusReason:           r.StatusReason,
		IDPGroups:              append([]string{}, r.IdpGroups...),
		LastLoginAt:            r.LastLoginAt,
		ResponsiblePrincipalID: r.ResponsiblePrincipalID,
		CreatedAt:              r.CreatedAt,
		UpdatedAt:              r.UpdatedAt,
		Version:                r.Version,
	}
}
