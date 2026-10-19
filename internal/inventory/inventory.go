// Package inventory is the registry of agents (plan P1-04): the agents, their
// owners and the use cases that justify them, and their lifecycle
// (docs/architecture/lifecycle.md). Every change commits with its audit event
// (AUD-01), and every change that enforcement points see takes a governance
// state version.
package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/J466Y/WhiteTower/internal/audit"
	"github.com/J466Y/WhiteTower/internal/authz"
	"github.com/J466Y/WhiteTower/internal/inventory/inventorydb"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/clock"
	"github.com/J466Y/WhiteTower/internal/platform/db"
)

// Options are what the inventory needs from the rest of the core.
type Options struct {
	// DB holds the inventory.
	DB *db.DB
	// Clock dates every change: the times that the lifecycle compares later
	// come from it, never from the database.
	Clock clock.Clock
	// Writer records the audit event of every change.
	Writer *audit.Writer
	// Authorizer decides what each caller may do on each agent.
	Authorizer auth.Authorizer
	// Versions numbers the changes of the governance state.
	Versions StateVersions
}

// Inventory keeps the agents and the use cases that justify them.
type Inventory struct {
	db         *db.DB
	clk        clock.Clock
	writer     *audit.Writer
	authorizer auth.Authorizer
	versions   StateVersions
}

// New returns the inventory.
func New(opts Options) *Inventory {
	return &Inventory{
		db:         opts.DB,
		clk:        opts.Clock,
		writer:     opts.Writer,
		authorizer: opts.Authorizer,
		versions:   opts.Versions,
	}
}

// RefusalKind says why the inventory refuses a request, so that each API
// maps it to its own codes.
type RefusalKind int

const (
	// Invalid is a request that is malformed or incomplete.
	Invalid RefusalKind = iota + 1
	// NotFound names a resource that does not exist, or that the caller may
	// not see.
	NotFound
	// Forbidden is a request that the caller may not make.
	Forbidden
	// Conflict is a request that the resource's state does not allow.
	Conflict
	// Stale is a change to a version of the resource that is no longer
	// current.
	Stale
)

// Refusal is a request that the inventory refuses. Its detail tells the
// client why, and names nothing internal.
type Refusal struct {
	Kind   RefusalKind
	Detail string
}

func (r *Refusal) Error() string { return r.Detail }

func refuse(kind RefusalKind, format string, args ...any) *Refusal {
	return &Refusal{Kind: kind, Detail: fmt.Sprintf(format, args...)}
}

// Person is a principal as the inventory shows it: never more than its
// pseudonymous ID, its display name and whether it is active.
type Person struct {
	ID          uuid.UUID
	DisplayName string
	Status      string
}

// people returns the principals with the given IDs.
func people(ctx context.Context, q *inventorydb.Queries, ids []uuid.UUID) (map[uuid.UUID]Person, error) {
	rows, err := q.PrincipalRefs(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("reading principals: %w", err)
	}
	found := make(map[uuid.UUID]Person, len(rows))
	for _, r := range rows {
		found[r.ID] = Person{ID: r.ID, DisplayName: r.DisplayName, Status: r.Status}
	}
	return found, nil
}

// authorize checks that the caller may use perm on a resource it relates to
// as rel. It goes through the Authorizer, which also applies the scopes of an
// API token and the limits of a break-glass session.
func (inv *Inventory) authorize(ctx context.Context, caller auth.Principal, perm authz.Permission, rel authz.Relationship) error {
	if err := inv.authorizer.Authorize(authz.ContextWithRelationship(ctx, rel), &caller, string(perm)); err != nil {
		return refuse(Forbidden, "your roles do not permit this")
	}
	return nil
}

// seesAll reports whether the caller may see every agent, not only the active
// ones (the user role sees only those).
func seesAll(caller auth.Principal) bool {
	return authz.Allows(caller.Roles, authz.PermissionInventoryView, authz.Relationship{})
}

// actorOf names the caller in an audit event, by pseudonymous ID.
func actorOf(caller auth.Principal) map[string]any {
	switch {
	case caller.IsBreakglass:
		return map[string]any{"type": "breakglass", "id": caller.ID}
	case caller.Kind == auth.ServiceAccount:
		return map[string]any{"type": "service_account", "id": caller.ID}
	default:
		return map[string]any{"type": "human", "id": caller.ID}
	}
}

// setting decodes the value of a setting (domain model, section 5) into v.
func setting(ctx context.Context, q *inventorydb.Queries, key string, v any) error {
	raw, err := q.GetSetting(ctx, key)
	if err != nil {
		return fmt.Errorf("reading the setting %s: %w", key, err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("decoding the setting %s: %w", key, err)
	}
	return nil
}

// DataCategories returns the categories of data that agents and use cases may
// name: the setting inventory.data_categories, which administrators edit.
func (inv *Inventory) DataCategories(ctx context.Context) ([]string, error) {
	var categories []string
	if err := setting(ctx, inventorydb.New(inv.db), "inventory.data_categories", &categories); err != nil {
		return nil, err
	}
	return categories, nil
}

// checkCategories refuses data categories that the setting does not hold.
func checkCategories(ctx context.Context, q *inventorydb.Queries, categories []string) error {
	var known []string
	if err := setting(ctx, q, "inventory.data_categories", &known); err != nil {
		return err
	}
	for _, c := range categories {
		if !contains(known, c) {
			return refuse(Invalid, "%q is not a data category of the setting inventory.data_categories", c)
		}
	}
	return nil
}

// notFound turns a missing row into a refusal, and wraps any other error.
func notFound(err error, what string) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return refuse(NotFound, "no %s has this ID", what)
	}
	return fmt.Errorf("reading the %s: %w", what, err)
}
