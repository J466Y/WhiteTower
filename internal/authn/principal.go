package authn

import (
	"context"
	"errors"
	"fmt"
	"slices"
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

// ErrPrincipalExists is returned when SCIM would create a principal with the
// issuer and subject of one that exists.
var ErrPrincipalExists = errors.New("a principal with this issuer and subject exists")

var (
	// ErrResponsibleNotHuman is returned when a principal that is not a human
	// would be responsible for a service account.
	ErrResponsibleNotHuman = errors.New("a service account needs a human responsible for it")

	// ErrRoleNotHeld is returned when a service account would get a role that
	// its responsible principal does not hold.
	ErrRoleNotHeld = errors.New("the responsible principal does not hold the role")
)

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

// Identity is what an identity provider says of a person at a sign-in, or
// what SCIM provisions: the issuer and subject that name them, their name and
// email address, and the groups from which their roles come.
type Identity struct {
	Issuer      string
	Subject     string
	DisplayName string
	Email       *string
	Groups      []string
}

// SignIn creates the principal of the person whom id names, or updates the
// one with its issuer and subject, at a sign-in through method: "oidc" from a
// browser, or "token_exchange" from the CLI. In the same transaction it
// records what changed (AUD-01): whitetower.principal.created.v1 for a new
// principal, and whitetower.principal.groups_changed.v1 when the groups,
// compared as sets, are not those the principal had. Then, still in that
// transaction, it runs then, when not nil, for the rest of the sign-in: its
// session or its token. An inactive principal is refused with
// ErrPrincipalInactive, and nothing is written: neither its record nor an
// event.
func (ps *PrincipalStore) SignIn(ctx context.Context, method string, id Identity, then func(ctx context.Context, tx *db.Tx, p *Principal) error) (*Principal, error) {
	if id.Issuer == "" || id.Subject == "" || id.DisplayName == "" {
		return nil, errors.New("issuer, subject, and displayName are required")
	}
	newID, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("generating principal UUID: %w", err)
	}
	var signedIn *Principal
	err = ps.database.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		p, err := signInHuman(ctx, tx, ps.writer, ps.clk.Now().UTC(), newID, method, id)
		if err != nil {
			return err
		}
		if p.Status != "active" {
			return ErrPrincipalInactive
		}
		if then != nil {
			if err := then(ctx, tx, p); err != nil {
				return err
			}
		}
		signedIn = p
		return nil
	})
	if err != nil {
		return nil, err
	}
	return signedIn, nil
}

// signInHuman creates the principal of id in tx, with newID, or updates the
// one with its issuer and subject, at a sign-in through method, and records
// what changed. It locks the principal's row before it reads the groups, so
// that two sign-ins of one person at once, on one replica or two, create one
// principal and record one creation, and the second records its change from
// the groups that the first wrote. Under READ COMMITTED, an insert that meets
// a principal that another transaction created waits for that transaction,
// and once it commits inserts nothing: the next lock, a new statement, finds
// the principal.
func signInHuman(ctx context.Context, tx *db.Tx, writer *audit.Writer, now time.Time, newID uuid.UUID, method string, id Identity) (*Principal, error) {
	q := authndb.New(tx)
	groups := groupSet(id.Groups)
	for attempt := 1; ; attempt++ {
		held, err := q.LockHumanPrincipalByIdentity(ctx, authndb.LockHumanPrincipalByIdentityParams{Issuer: &id.Issuer, Subject: &id.Subject})
		if err == nil {
			row, err := q.UpdateHumanPrincipalAtSignIn(ctx, authndb.UpdateHumanPrincipalAtSignInParams{
				ID:          held.ID,
				DisplayName: id.DisplayName,
				Email:       id.Email,
				IdpGroups:   groups,
				LastLoginAt: &now,
			})
			if err != nil {
				return nil, fmt.Errorf("updating principal: %w", err)
			}
			if before := groupSet(held.IdpGroups); !slices.Equal(before, groups) {
				if err := writer.Record(ctx, tx, audit.Event{
					Type:    "whitetower.principal.groups_changed.v1",
					Subject: held.ID.String(),
					Data: map[string]any{
						"principal_id": held.ID.String(),
						"actor":        actorOf(method, held.ID),
						"method":       method,
						"before":       before,
						"after":        groups,
					},
				}); err != nil {
					return nil, fmt.Errorf("recording the change of the principal's groups: %w", err)
				}
			}
			return fromDBModel(row), nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("locking principal: %w", err)
		}
		if attempt > 1 {
			return nil, errors.New("the principal that another sign-in created is gone")
		}
		created, err := createHuman(ctx, tx, writer, now, newID, method, id, &now)
		if err == nil {
			return created, nil
		}
		if !errors.Is(err, ErrPrincipalExists) {
			return nil, err
		}
		// Another sign-in created the principal since the lock found none,
		// and has committed.
	}
}

// ProvisionHuman creates the principal of the person whom id names, as SCIM
// provisions it, and records whitetower.principal.created.v1 in the same
// transaction, with SCIM's service account as actor. A principal with the
// issuer and subject exists already: ErrPrincipalExists, and nothing is
// written. SCIM is never a sign-in, so the principal has no last login.
func (ps *PrincipalStore) ProvisionHuman(ctx context.Context, id Identity) (*Principal, error) {
	if id.Issuer == "" || id.Subject == "" || id.DisplayName == "" {
		return nil, errors.New("issuer, subject, and displayName are required")
	}
	newID, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("generating principal UUID: %w", err)
	}
	var created *Principal
	err = ps.database.InTx(ctx, func(ctx context.Context, tx *db.Tx) (err error) {
		created, err = createHuman(ctx, tx, ps.writer, ps.clk.Now().UTC(), newID, "scim", id, nil)
		return err
	})
	if err != nil {
		return nil, err
	}
	return created, nil
}

// createHuman inserts the principal of id in tx, with newID, and records its
// creation through method. A principal with the issuer and subject exists, or
// another transaction created one that committed: ErrPrincipalExists.
func createHuman(ctx context.Context, tx *db.Tx, writer *audit.Writer, now time.Time, newID uuid.UUID, method string, id Identity, lastLogin *time.Time) (*Principal, error) {
	groups := groupSet(id.Groups)
	row, err := authndb.New(tx).InsertHumanPrincipal(ctx, authndb.InsertHumanPrincipalParams{
		ID:          newID,
		Issuer:      &id.Issuer,
		Subject:     &id.Subject,
		DisplayName: id.DisplayName,
		Email:       id.Email,
		IdpGroups:   groups,
		LastLoginAt: lastLogin,
		CreatedAt:   now,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrPrincipalExists
	}
	if err != nil {
		return nil, fmt.Errorf("creating principal: %w", err)
	}
	if err := writer.Record(ctx, tx, audit.Event{
		Type:    "whitetower.principal.created.v1",
		Subject: row.ID.String(),
		Data: map[string]any{
			"principal_id": row.ID.String(),
			"actor":        actorOf(method, row.ID),
			"method":       method,
			"idp_groups":   groups,
		},
	}); err != nil {
		return nil, fmt.Errorf("recording the principal's creation: %w", err)
	}
	return fromDBModel(row), nil
}

// groupSet returns groups sorted, each once, and never nil: the form in which
// principals keep their groups and events record them, so that the same
// groups in another order are the same groups.
func groupSet(groups []string) []string {
	set := append([]string{}, groups...)
	slices.Sort(set)
	return slices.Compact(set)
}

// actorOf returns the audit actor of a change to the principal id, or to its
// session, made through method: SCIM's service account for a provisioning,
// the break-glass custodian, or the person who signs in or out.
func actorOf(method string, id uuid.UUID) map[string]any {
	switch method {
	case "scim":
		return map[string]any{"type": "service_account", "id": SCIMPrincipalID.String()}
	case "breakglass":
		return map[string]any{"type": "breakglass", "id": id.String()}
	default:
		return map[string]any{"type": "human", "id": id.String()}
	}
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

// CreateServiceAccount creates a service account that the responsible human
// creates for their own automation, and binds it the roles given. Each must
// be one that the responsible principal holds: a service account acts for its
// responsible principal, never with more (plan P1-03, step 6), and nobody
// gets a role through it that they do not hold (HUM-02, DC-4).
func (ps *PrincipalStore) CreateServiceAccount(
	ctx context.Context,
	displayName string,
	email *string,
	roles []string,
	responsible auth.Principal,
) (*Principal, error) {
	displayName = strings.TrimSpace(displayName)
	if len(displayName) < 1 || len(displayName) > 200 {
		return nil, errors.New("service account display name must be between 1 and 200 characters")
	}
	if responsible.Kind != auth.Human {
		return nil, ErrResponsibleNotHuman
	}
	responsiblePrincipalID, err := uuid.Parse(responsible.ID)
	if err != nil {
		return nil, fmt.Errorf("responsible principal ID %q: %w", responsible.ID, err)
	}
	for _, rStr := range roles {
		if !authz.IsValidRole(authz.Role(rStr)) {
			return nil, fmt.Errorf("invalid role %q", rStr)
		}
		if !slices.Contains(responsible.Roles, rStr) {
			return nil, fmt.Errorf("%w: %s", ErrRoleNotHeld, rStr)
		}
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
		if resp.Kind != "human" {
			return ErrResponsibleNotHuman
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
			bindingID, err := uuid.NewV7()
			if err != nil {
				return fmt.Errorf("generating role binding UUID: %w", err)
			}
			if err := q.AddRoleBinding(ctx, authndb.AddRoleBindingParams{
				ID:          bindingID,
				PrincipalID: newID,
				Role:        rStr,
				Reason:      "initial service account provisioning",
				GrantedBy:   responsiblePrincipalID,
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
