package authn

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

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
// issuer and subject of one that exists, or with a userName that differs from
// one SCIM gave only in case.
var ErrPrincipalExists = errors.New("a principal with this issuer and subject exists")

var (
	// ErrExternalIDExists is returned when SCIM would provision a person
	// whose external ID is that of a principal SCIM already manages.
	ErrExternalIDExists = errors.New("SCIM already manages the principal with this external ID")

	// ErrExternalIDConflict is returned when a sign-in finds no principal by
	// its external ID, and the principal with its issuer and subject holds
	// another external ID.
	ErrExternalIDConflict = errors.New("the principal with the sign-in's issuer and subject holds another external ID")

	// ErrInvalidExternalID is returned for an external ID that is empty,
	// blank or longer than MaxExternalIDLength characters.
	ErrInvalidExternalID = fmt.Errorf("an external ID is a string of 1 to %d characters, not blank", MaxExternalIDLength)
)

// MaxExternalIDLength is the longest external ID, in characters, as the
// database bounds it: an identity provider's IDs, such as a UUID or Entra
// ID's object ID, are far shorter.
const MaxExternalIDLength = 255

// scimIssuer is the issuer of the principals that SCIM manages, whose subject
// is the userName that SCIM gave them.
const scimIssuer = "scim"

// systemPrincipalIDs are the principals that White Tower itself acts as: the
// break-glass custodian, and SCIM's service account, which audit events name
// as actor. They are nobody's, so SCIM never reaches them (KIL-08, HUM-06).
var systemPrincipalIDs = []uuid.UUID{BreakglassPrincipalID, SCIMPrincipalID}

// checkExternalID returns ErrInvalidExternalID unless v can be an external
// ID: the identity provider's ID of a person, which a sign-in and SCIM
// compare exactly, so it is stored as given.
func checkExternalID(v string) error {
	if strings.TrimSpace(v) == "" || utf8.RuneCountInString(v) > MaxExternalIDLength {
		return ErrInvalidExternalID
	}
	return nil
}

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
	ExternalID             *string
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
// what SCIM provisions: the issuer and subject that name them, their external
// ID, their name and email address, and the groups from which their roles
// come.
type Identity struct {
	Issuer      string
	Subject     string
	DisplayName string
	Email       *string
	Groups      []string
	// ExternalID is the identity provider's ID of the person, which it sends
	// as externalId through SCIM, and in a claim of its ID tokens
	// (auth.oidc.external_id_claim): a sign-in finds the principal by it.
	ExternalID string
}

// SignIn creates the principal of the person whom id names, or updates the
// one it finds, at a sign-in through method: "oidc" from a browser, or
// "token_exchange" from the CLI. It finds the principal with the external ID
// of id, which SCIM may have provisioned, else the one with its issuer and
// subject that has no external ID yet, which it then gives the external ID:
// a principal that a sign-in created before external IDs existed. In the same
// transaction it records what changed (AUD-01):
// whitetower.principal.created.v1 for a new principal, and
// whitetower.principal.groups_changed.v1 when the groups, compared as sets,
// are not those the principal had. A change of groups also revokes every
// session of the principal, whose roles came from the groups before (ST-14).
// Then, still in that transaction, it runs then, when not nil, for the rest
// of the sign-in: its session, which is thus the only one left after a change
// of groups, or its token.
// An inactive principal is refused with ErrPrincipalInactive, and a principal
// with the issuer and subject but another external ID with
// ErrExternalIDConflict, each in an error that names the principal; nothing
// is written then: neither a record nor an event.
func (ps *PrincipalStore) SignIn(ctx context.Context, method string, id Identity, then func(ctx context.Context, tx *db.Tx, p *Principal) error) (*Principal, error) {
	if id.Issuer == "" || id.Subject == "" || id.DisplayName == "" {
		return nil, errors.New("issuer, subject, and displayName are required")
	}
	if err := checkExternalID(id.ExternalID); err != nil {
		return nil, err
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
			return &refusedPrincipal{id: p.ID, err: ErrPrincipalInactive}
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
// one that lockAtSignIn finds, at a sign-in through method, and records what
// changed. It locks the principal's row before it reads the groups, so that
// two sign-ins of one person at once, on one replica or two, create one
// principal and record one creation, and the second records its change from
// the groups that the first wrote. Under READ COMMITTED, an insert that meets
// a principal that another transaction created, with the external ID or the
// issuer and subject, waits for that transaction, and once it commits inserts
// nothing: the next lock, a new statement, finds the principal. Break-glass
// signs in with no external ID: its custodian has none, and is found by its
// issuer and subject alone.
func signInHuman(ctx context.Context, tx *db.Tx, writer *audit.Writer, now time.Time, newID uuid.UUID, method string, id Identity) (*Principal, error) {
	q := authndb.New(tx)
	groups := groupSet(id.Groups)
	for attempt := 1; ; attempt++ {
		held, err := lockAtSignIn(ctx, q, id)
		if err == nil {
			row, err := q.UpdateHumanPrincipalAtSignIn(ctx, authndb.UpdateHumanPrincipalAtSignInParams{
				ID:          held.ID,
				ExternalID:  externalID(id),
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
				// A session keeps the roles of its sign-in, and roles come
				// from groups: every session of the principal ends, so that
				// none keeps the roles of the groups before (ST-14). The
				// sign-in's own session, if any, comes after, and the event
				// above records the revocations, as a deactivation's does.
				if err := q.RevokeSessionsForPrincipal(ctx, authndb.RevokeSessionsForPrincipalParams{PrincipalID: held.ID, RevokedAt: &now}); err != nil {
					return nil, fmt.Errorf("revoking the sessions of the groups before: %w", err)
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

// lockAtSignIn locks the principal that a sign-in of id finds: the one with
// its external ID, else the one with its issuer and subject, which the
// sign-in links when it has no external ID yet. A principal with the issuer
// and subject but another external ID is ErrExternalIDConflict: the identity
// provider now names the person by another value than their principal holds,
// as after auth.oidc.external_id_claim changed, and the sign-in neither
// changes that external ID, by which SCIM may know the principal, nor creates
// a second principal with the same issuer and subject. None: pgx.ErrNoRows.
func lockAtSignIn(ctx context.Context, q *authndb.Queries, id Identity) (authndb.WhitetowerPrincipal, error) {
	if id.ExternalID != "" {
		held, err := q.LockHumanPrincipalByExternalID(ctx, &id.ExternalID)
		if !errors.Is(err, pgx.ErrNoRows) {
			return held, err
		}
	}
	held, err := q.LockHumanPrincipalByIdentity(ctx, authndb.LockHumanPrincipalByIdentityParams{Issuer: &id.Issuer, Subject: &id.Subject})
	// A sign-in of the same person that linked the principal while this
	// lock waited for it leaves the principal with this external ID.
	if err == nil && held.ExternalID != nil && *held.ExternalID != id.ExternalID {
		return held, &refusedPrincipal{id: held.ID, err: ErrExternalIDConflict}
	}
	return held, err
}

// externalID returns the external ID of id, or nil for none.
func externalID(id Identity) *string {
	if id.ExternalID == "" {
		return nil
	}
	return &id.ExternalID
}

// ProvisionHuman provisions the person whom id names, as SCIM does: their
// principal takes SCIM's issuer, scim, and their userName, in id.Subject, as
// its subject, so that SCIM finds it by its userName, and the external ID of
// id, by which the person's sign-ins find it. In the same transaction it
// records what it did, with SCIM's service account as actor:
//
//   - a person who never signed in gets a new principal, and
//     whitetower.principal.created.v1;
//   - a person who signed in before SCIM provisioned them has the principal
//     that their first sign-in created, with the same external ID: SCIM
//     adopts that principal rather than creating a second one, sets its
//     userName, name and email address on it, and records
//     whitetower.principal.adopted.v1. Its ID, status, groups and last login
//     stay as they are.
//
// When active is false, the same transaction then deactivates the principal,
// as Deactivate does, so that SCIM never answers with a user that is active
// against its request, and never leaves one so.
//
// A principal with the userName exists already, compared without regard to
// case, as RFC 7643 compares userNames: ErrPrincipalExists. One that SCIM
// manages has the external ID: ErrExternalIDExists. Nothing is written then.
// SCIM is never a sign-in, so it gives no principal a last login.
func (ps *PrincipalStore) ProvisionHuman(ctx context.Context, id Identity, active bool) (*Principal, error) {
	id.Issuer = scimIssuer
	if id.Subject == "" || id.DisplayName == "" {
		return nil, errors.New("userName and displayName are required")
	}
	if err := checkExternalID(id.ExternalID); err != nil {
		return nil, err
	}
	newID, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("generating principal UUID: %w", err)
	}
	now := ps.clk.Now().UTC()
	var provisioned *Principal
	err = ps.database.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := authndb.New(tx)
		_, err := q.GetPrincipalBySCIMUserName(ctx, id.Subject)
		if err == nil {
			return ErrPrincipalExists
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("reading the principal with the userName: %w", err)
		}
		if provisioned, err = provisionHuman(ctx, tx, ps.writer, now, newID, id); err != nil || active {
			return err
		}
		if err := ps.deactivateTx(ctx, tx, provisioned.ID, SCIMPrincipal, "SCIM initial provisioning as inactive"); err != nil {
			return err
		}
		row, err := q.GetPrincipalByID(ctx, provisioned.ID)
		if err != nil {
			return fmt.Errorf("reading the principal provisioned inactive: %w", err)
		}
		provisioned = fromDBModel(row)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return provisioned, nil
}

// provisionHuman creates the principal of id in tx, with newID, or adopts the
// one with its external ID that a sign-in created, as ProvisionHuman says.
func provisionHuman(ctx context.Context, tx *db.Tx, writer *audit.Writer, now time.Time, newID uuid.UUID, id Identity) (*Principal, error) {
	q := authndb.New(tx)
	for attempt := 1; ; attempt++ {
		held, err := q.LockHumanPrincipalByExternalID(ctx, &id.ExternalID)
		switch {
		case err == nil && held.Issuer != nil && *held.Issuer == scimIssuer:
			return nil, ErrExternalIDExists
		case err == nil:
			return adoptHuman(ctx, tx, writer, now, held.ID, id)
		case !errors.Is(err, pgx.ErrNoRows):
			return nil, fmt.Errorf("locking principal: %w", err)
		case attempt > 1:
			// The creation met a principal with the userName, which
			// another transaction created since ProvisionHuman checked.
			return nil, ErrPrincipalExists
		}
		created, err := createHuman(ctx, tx, writer, now, newID, "scim", id, nil)
		if !errors.Is(err, ErrPrincipalExists) {
			return created, err
		}
		// Another transaction created a principal with the userName or the
		// external ID since the lock found none, and has committed: the next
		// lock tells which.
	}
}

// adoptHuman gives the principal with the ID given, which a sign-in created,
// SCIM's issuer and the userName, name and email address of id, in tx, and
// records the adoption. Another transaction created a principal with the
// userName, compared without regard to case, since ProvisionHuman checked:
// ErrPrincipalExists.
func adoptHuman(ctx context.Context, tx *db.Tx, writer *audit.Writer, now time.Time, principalID uuid.UUID, id Identity) (*Principal, error) {
	row, err := authndb.New(tx).AdoptHumanPrincipal(ctx, authndb.AdoptHumanPrincipalParams{
		ID:          principalID,
		Issuer:      &id.Issuer,
		Subject:     &id.Subject,
		DisplayName: id.DisplayName,
		Email:       id.Email,
		UpdatedAt:   now,
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" &&
		(pgErr.ConstraintName == "principals_idp_identity" || pgErr.ConstraintName == "principals_scim_user_name") {
		return nil, ErrPrincipalExists
	}
	if err != nil {
		return nil, fmt.Errorf("adopting principal: %w", err)
	}
	if err := writer.Record(ctx, tx, audit.Event{
		Type:    "whitetower.principal.adopted.v1",
		Subject: row.ID.String(),
		Data: map[string]any{
			"principal_id": row.ID.String(),
			"actor":        actorOf("scim", row.ID),
		},
	}); err != nil {
		return nil, fmt.Errorf("recording the principal's adoption: %w", err)
	}
	return fromDBModel(row), nil
}

// createHuman inserts the principal of id in tx, with newID, and records its
// creation through method. A principal with the issuer and subject or the
// external ID exists, or another transaction created one that committed:
// ErrPrincipalExists.
func createHuman(ctx context.Context, tx *db.Tx, writer *audit.Writer, now time.Time, newID uuid.UUID, method string, id Identity, lastLogin *time.Time) (*Principal, error) {
	groups := groupSet(id.Groups)
	row, err := authndb.New(tx).InsertHumanPrincipal(ctx, authndb.InsertHumanPrincipalParams{
		ID:          newID,
		Issuer:      &id.Issuer,
		Subject:     &id.Subject,
		ExternalID:  externalID(id),
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

// GetPerson returns the principal with the given UUID when it is a person's:
// a human principal that is not one White Tower acts as, such as the
// break-glass custodian. Any other principal is ErrPrincipalNotFound, so that
// SCIM, which reaches people only, cannot tell it from one that does not
// exist.
func (ps *PrincipalStore) GetPerson(ctx context.Context, id uuid.UUID) (*Principal, error) {
	q := authndb.New(ps.database)
	row, err := q.GetPerson(ctx, authndb.GetPersonParams{ID: id, SystemIds: systemPrincipalIDs})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrPrincipalNotFound
		}
		return nil, fmt.Errorf("querying person by ID: %w", err)
	}
	return fromDBModel(row), nil
}

// GetBySCIMUserName returns the principal that SCIM provisioned, or adopted,
// with the userName given, compared without regard to case, as RFC 7643
// compares userNames.
func (ps *PrincipalStore) GetBySCIMUserName(ctx context.Context, userName string) (*Principal, error) {
	row, err := authndb.New(ps.database).GetPrincipalBySCIMUserName(ctx, userName)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrPrincipalNotFound
		}
		return nil, fmt.Errorf("querying principal by SCIM userName: %w", err)
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

// ListPeople returns a page of the principals that GetPerson returns, newest
// first, and how many there are.
func (ps *PrincipalStore) ListPeople(ctx context.Context, limit, offset int32) ([]*Principal, int64, error) {
	q := authndb.New(ps.database)
	count, err := q.CountPeople(ctx, systemPrincipalIDs)
	if err != nil {
		return nil, 0, fmt.Errorf("counting people: %w", err)
	}
	rows, err := q.ListPeople(ctx, authndb.ListPeopleParams{
		Limit:     limit,
		Offset:    offset,
		SystemIds: systemPrincipalIDs,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("listing people: %w", err)
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
		return ps.deactivateTx(ctx, tx, id, actor, reason)
	})
}

// deactivateTx is Deactivate in tx, for a provisioning that deactivates the
// principal it creates in its own transaction.
func (ps *PrincipalStore) deactivateTx(ctx context.Context, tx *db.Tx, id uuid.UUID, actor auth.Principal, reason string) error {
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
		ExternalID:             r.ExternalID,
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
// gets a role through it that they do not hold (HUM-02, DC-4). In the same
// transaction it records whitetower.service_account.created.v1, with the
// roles bound (AUD-01).
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

		// The roles bound, sorted, and never null: the bindings' unique index
		// has refused a role given twice.
		bound := append([]string{}, roles...)
		slices.Sort(bound)
		if err := ps.writer.Record(ctx, tx, audit.Event{
			Type:    "whitetower.service_account.created.v1",
			Subject: newID.String(),
			Data: map[string]any{
				"principal_id":             newID.String(),
				"actor":                    map[string]any{"type": "human", "id": responsiblePrincipalID.String()},
				"responsible_principal_id": responsiblePrincipalID.String(),
				"roles":                    bound,
			},
		}); err != nil {
			return fmt.Errorf("recording the service account's creation: %w", err)
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
