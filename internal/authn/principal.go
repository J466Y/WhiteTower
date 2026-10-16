package authn

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/J466Y/WhiteTower/internal/audit"
	"github.com/J466Y/WhiteTower/internal/authn/authndb"
	"github.com/J466Y/WhiteTower/internal/authz"
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
	tokenStore   *TokenStore
}

// NewPrincipalStore returns an initialized PrincipalStore.
func NewPrincipalStore(database *db.DB, clk clock.Clock, writer *audit.Writer, sessionStore *SessionStore, tokenStore *TokenStore) *PrincipalStore {
	return &PrincipalStore{
		database:     database,
		clk:          clk,
		writer:       writer,
		sessionStore: sessionStore,
		tokenStore:   tokenStore,
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

// GetBySubjectOrEmail returns the human principal matching the given subject or email.
func (ps *PrincipalStore) GetBySubjectOrEmail(ctx context.Context, identifier string) (*Principal, error) {
	q := authndb.New(ps.database)
	row, err := q.GetHumanPrincipalBySubjectOrEmail(ctx, &identifier)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrPrincipalNotFound
		}
		return nil, fmt.Errorf("querying principal by subject or email: %w", err)
	}
	return fromDBModel(row), nil
}

// GetByEmail returns the human principal matching the given email address.
func (ps *PrincipalStore) GetByEmail(ctx context.Context, email string) (*Principal, error) {
	q := authndb.New(ps.database)
	row, err := q.GetHumanPrincipalByEmail(ctx, &email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrPrincipalNotFound
		}
		return nil, fmt.Errorf("querying principal by email: %w", err)
	}
	return fromDBModel(row), nil
}

// ListHumans returns a paginated list of human principals and the total count.
func (ps *PrincipalStore) ListHumans(ctx context.Context, limit, offset int32) ([]*Principal, int64, error) {
	q := authndb.New(ps.database)
	count, err := q.CountHumanPrincipals(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("counting human principals: %w", err)
	}
	rows, err := q.ListHumanPrincipals(ctx, authndb.ListHumanPrincipalsParams{
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("listing human principals: %w", err)
	}
	principals := make([]*Principal, len(rows))
	for i, r := range rows {
		principals[i] = fromDBModel(r)
	}
	return principals, count, nil
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

		// Revoke all API tokens within the transaction (ST-19).
		if ps.tokenStore != nil {
			if err := ps.tokenStore.RevokeAllForPrincipalTx(ctx, tx, id); err != nil {
				return fmt.Errorf("revoking api tokens for deactivated principal: %w", err)
			}
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

// CreateServiceAccount creates a new service account principal with a designated responsible human principal.
func (ps *PrincipalStore) CreateServiceAccount(
	ctx context.Context,
	displayName string,
	email *string,
	responsiblePrincipalID uuid.UUID,
	roles []string,
	grantedBy uuid.UUID,
) (*Principal, error) {
	displayName = strings.TrimSpace(displayName)
	if len(displayName) < 1 || len(displayName) > 200 {
		return nil, errors.New("service account display name must be between 1 and 200 characters")
	}

	newID, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("generating service account UUID: %w", err)
	}

	now := ps.clk.Now().UTC()
	var created *Principal

	err = ps.database.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := authndb.New(tx)
		// Verify responsible principal exists and is active
		resp, err := q.GetPrincipalByID(ctx, responsiblePrincipalID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("verifying responsible principal: %w", ErrPrincipalNotFound)
			}
			return fmt.Errorf("verifying responsible principal: %w", err)
		}
		if resp.Status != "active" {
			return fmt.Errorf("verifying responsible principal: %w", ErrPrincipalInactive)
		}

		row, err := q.CreateServiceAccountPrincipal(ctx, authndb.CreateServiceAccountPrincipalParams{
			ID:                     newID,
			DisplayName:            displayName,
			Email:                  email,
			ResponsiblePrincipalID: &responsiblePrincipalID,
			CreatedAt:              now,
		})
		if err != nil {
			return fmt.Errorf("inserting service account principal: %w", err)
		}

		// Bind initial roles
		for _, rStr := range roles {
			if !authz.IsValidRole(authz.Role(rStr)) {
				return fmt.Errorf("invalid role %q", rStr)
			}
			bindingID, err := uuid.NewV7()
			if err != nil {
				return fmt.Errorf("generating role binding UUID: %w", err)
			}
			if err := q.AddRoleBinding(ctx, authndb.AddRoleBindingParams{
				ID:          bindingID,
				PrincipalID: newID,
				Role:        rStr,
				Reason:      "initial service account provisioning",
				GrantedBy:   grantedBy,
				GrantedAt:   now,
			}); err != nil {
				return fmt.Errorf("adding role binding %q: %w", rStr, err)
			}
		}

		created = fromDBModel(row)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return created, nil
}

// ListServiceAccounts returns service accounts, optionally filtered by responsiblePrincipalID.
func (ps *PrincipalStore) ListServiceAccounts(ctx context.Context, responsiblePrincipalID *uuid.UUID) ([]*Principal, error) {
	q := authndb.New(ps.database)
	if responsiblePrincipalID != nil {
		rows, err := q.ListServiceAccountsByResponsiblePrincipal(ctx, responsiblePrincipalID)
		if err != nil {
			return nil, fmt.Errorf("querying service accounts: %w", err)
		}
		result := make([]*Principal, len(rows))
		for i, r := range rows {
			result[i] = fromDBModel(r)
		}
		return result, nil
	}

	rows, err := q.ListAllServiceAccounts(ctx)
	if err != nil {
		return nil, fmt.Errorf("querying all service accounts: %w", err)
	}
	result := make([]*Principal, len(rows))
	for i, r := range rows {
		result[i] = fromDBModel(r)
	}
	return result, nil
}

// GetRoles returns all active roles for the given principal ID.
func (ps *PrincipalStore) GetRoles(ctx context.Context, principalID uuid.UUID) ([]string, error) {
	q := authndb.New(ps.database)
	return q.ListActiveRoleBindings(ctx, principalID)
}
