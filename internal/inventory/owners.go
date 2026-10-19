package inventory

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/J466Y/WhiteTower/internal/audit"
	"github.com/J466Y/WhiteTower/internal/authn"
	"github.com/J466Y/WhiteTower/internal/authz"
	"github.com/J466Y/WhiteTower/internal/inventory/inventorydb"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/db"
)

// Assignment is a principal's assignment as an agent's primary owner or
// delegate (INV-02). An ended one says who ended it, and why.
type Assignment struct {
	ID         uuid.UUID
	Principal  Person
	Role       string
	AssignedBy Person
	AssignedAt time.Time
	EndedBy    *Person
	EndedAt    *time.Time
	EndReason  string
}

// Transfer is an offer of an agent's primary ownership, from its primary owner
// to another person, who accepts or declines it.
type Transfer struct {
	ID          uuid.UUID
	AgentID     uuid.UUID
	From        Person
	To          Person
	RequestedBy Person
	RequestedAt time.Time
	Status      string
	DecidedAt   *time.Time
}

// The reason recorded for the end of a primary owner's assignment when the
// new owner accepts a transfer, and of a delegate's when they become the
// primary owner.
const (
	transferredReason = "ownership transferred"
	promotedReason    = "became the primary owner"
)

// Owners returns a page of at most size of the agent's owner assignments:
// the current ones first, then those that ended, each the latest assigned
// first; after names the last assignment of the previous page, and ended
// whether it had ended.
func (inv *Inventory) Owners(ctx context.Context, caller auth.Principal, agentID uuid.UUID, after *uuid.UUID, ended bool, size int) ([]Assignment, bool, error) {
	if size < 1 || size > maxPage {
		return nil, false, fmt.Errorf("a page of %d owner assignments: want 1 to %d", size, maxPage)
	}
	if _, err := inv.Get(ctx, caller, agentID); err != nil {
		return nil, false, err
	}
	q := inventorydb.New(inv.db)
	rows, err := q.ListAssignments(ctx, inventorydb.ListAssignmentsParams{
		AgentID:    agentID,
		AfterID:    after,
		AfterEnded: ended,
		PageLimit:  int32(size + 1), //nolint:gosec // G115: size is at most maxPage
	})
	if err != nil {
		return nil, false, fmt.Errorf("listing the agent's owners: %w", err)
	}
	more := len(rows) > size
	if more {
		rows = rows[:size]
	}
	var ids []uuid.UUID
	for _, r := range rows {
		ids = append(ids, r.AssignedBy)
		if r.EndedBy != nil {
			ids = append(ids, *r.EndedBy)
		}
	}
	who, err := people(ctx, q, ids)
	if err != nil {
		return nil, false, err
	}
	assignments := make([]Assignment, len(rows))
	for i, r := range rows {
		assignments[i] = Assignment{
			ID:         r.ID,
			Principal:  Person{ID: r.PrincipalID, DisplayName: r.DisplayName, Status: r.Status},
			Role:       r.Role,
			AssignedBy: who[r.AssignedBy],
			AssignedAt: r.AssignedAt,
			EndedAt:    r.EndedAt,
			EndReason:  deref(r.EndReason),
		}
		if r.EndedBy != nil {
			p := who[*r.EndedBy]
			assignments[i].EndedBy = &p
		}
	}
	return assignments, more, nil
}

// Reassign makes another person the agent's primary owner at once, for a
// reason, if the agent is still at the version the caller read: the advisory
// committee and operators do it, for example after an owner left (INV-02).
// The former owner's assignment ends, the new owner stops being a delegate,
// and a pending transfer is canceled. Policies see the owner, so the agent
// takes a new governance state version.
func (inv *Inventory) Reassign(ctx context.Context, caller auth.Principal, agentID uuid.UUID, version int64, newOwner uuid.UUID, reason string) (*Agent, error) {
	if err := required("reason", reason, 1000); err != nil {
		return nil, err
	}
	actor, err := uuid.Parse(caller.ID)
	if err != nil {
		return nil, fmt.Errorf("the caller's ID %q: %w", caller.ID, err)
	}
	err = inv.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := inventorydb.New(tx)
		a, err := inv.lockAgent(ctx, q, agentID)
		if err != nil {
			return err
		}
		if err := inv.authorize(ctx, caller, authz.PermissionAgentOwnershipReassign, authz.Relationship{}); err != nil {
			return err
		}
		if a.Version != version {
			return refuse(Stale, "the agent changed since you read it: read it again, then retry")
		}
		if err := stillChanges(a); err != nil {
			return err
		}
		if a.PrimaryOwner.ID == newOwner {
			return refuse(Conflict, "the principal is already the agent's primary owner")
		}
		if err := inv.canOwn(ctx, q, newOwner); err != nil {
			return err
		}
		now := inv.clk.Now().UTC()
		if err := makePrimary(ctx, q, agentID, newOwner, actor, reason, now); err != nil {
			return err
		}
		if err := cancelTransfers(ctx, q, agentID, now); err != nil {
			return err
		}
		v := version
		if err := touch(ctx, q, agentID, &v, now); err != nil {
			return err
		}
		stateVersion, err := inv.republish(ctx, tx, agentID, now)
		if err != nil {
			return err
		}
		return inv.recordOwnership(ctx, tx, agentID, map[string]any{
			"change":        "owner_reassigned",
			"principal_id":  newOwner.String(),
			"former_owner":  a.PrimaryOwner.ID.String(),
			"actor":         actorOf(caller),
			"state_version": stateVersion,
		})
	})
	if err != nil {
		return nil, err
	}
	return inv.load(ctx, inventorydb.New(inv.db), agentID)
}

// AddDelegate makes a person with the owner role a delegate of the agent: the
// owner role's grants of scope own then let them act for its owner (INV-02).
// The agent's owners and operators manage its delegates.
func (inv *Inventory) AddDelegate(ctx context.Context, caller auth.Principal, agentID, principalID uuid.UUID) (*Assignment, error) {
	actor, err := uuid.Parse(caller.ID)
	if err != nil {
		return nil, fmt.Errorf("the caller's ID %q: %w", caller.ID, err)
	}
	var assignment uuid.UUID
	now := inv.clk.Now().UTC()
	err = inv.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := inventorydb.New(tx)
		if err := inv.mayEditOwners(ctx, q, caller, actor, agentID); err != nil {
			return err
		}
		if err := inv.canOwn(ctx, q, principalID); err != nil {
			return err
		}
		if assignment, err = uuid.NewV7(); err != nil {
			return fmt.Errorf("generating the assignment's ID: %w", err)
		}
		if err := q.AddOwner(ctx, inventorydb.AddOwnerParams{
			ID: assignment, AgentID: agentID, PrincipalID: principalID, Role: "delegate", AssignedBy: actor, AssignedAt: now,
		}); err != nil {
			if isUniqueViolation(err, "agent_owners_one_assignment") {
				return refuse(Conflict, "the principal is already an owner or a delegate of the agent")
			}
			return fmt.Errorf("adding the delegate: %w", err)
		}
		if err := touch(ctx, q, agentID, nil, now); err != nil {
			return err
		}
		return inv.recordOwnership(ctx, tx, agentID, map[string]any{
			"change": "delegate_added", "principal_id": principalID.String(), "actor": actorOf(caller),
		})
	})
	if err != nil {
		return nil, err
	}
	who, err := people(ctx, inventorydb.New(inv.db), []uuid.UUID{principalID, actor})
	if err != nil {
		return nil, err
	}
	return &Assignment{
		ID: assignment, Principal: who[principalID], Role: "delegate", AssignedBy: who[actor], AssignedAt: now,
	}, nil
}

// RemoveDelegate ends a delegate's assignment, for a reason; the history
// keeps it. The agent's owners and operators manage its delegates.
func (inv *Inventory) RemoveDelegate(ctx context.Context, caller auth.Principal, agentID, principalID uuid.UUID, reason string) error {
	if err := required("reason", reason, 1000); err != nil {
		return err
	}
	actor, err := uuid.Parse(caller.ID)
	if err != nil {
		return fmt.Errorf("the caller's ID %q: %w", caller.ID, err)
	}
	return inv.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := inventorydb.New(tx)
		if err := inv.mayEditOwners(ctx, q, caller, actor, agentID); err != nil {
			return err
		}
		current, err := q.CurrentAssignment(ctx, inventorydb.CurrentAssignmentParams{AgentID: agentID, PrincipalID: principalID})
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && current.Role != "delegate") {
			return refuse(NotFound, "the principal is not a delegate of the agent")
		}
		if err != nil {
			return fmt.Errorf("reading the delegate's assignment: %w", err)
		}
		now := inv.clk.Now().UTC()
		if err := q.EndAssignment(ctx, inventorydb.EndAssignmentParams{ID: current.ID, EndedBy: &actor, EndedAt: &now, EndReason: &reason}); err != nil {
			return fmt.Errorf("ending the delegate's assignment: %w", err)
		}
		if err := touch(ctx, q, agentID, nil, now); err != nil {
			return err
		}
		return inv.recordOwnership(ctx, tx, agentID, map[string]any{
			"change": "delegate_removed", "principal_id": principalID.String(), "actor": actorOf(caller),
		})
	})
}

// RequestTransfer offers the agent's primary ownership to another person with
// the owner role, who must accept it; the offer waits in their inbox. Only
// the primary owner offers it, and an agent has one pending transfer at most.
func (inv *Inventory) RequestTransfer(ctx context.Context, caller auth.Principal, agentID, to uuid.UUID) (*Transfer, error) {
	actor, err := uuid.Parse(caller.ID)
	if err != nil {
		return nil, fmt.Errorf("the caller's ID %q: %w", caller.ID, err)
	}
	var id uuid.UUID
	err = inv.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := inventorydb.New(tx)
		a, err := inv.lockAgent(ctx, q, agentID)
		if err != nil {
			return err
		}
		if err := inv.authorize(ctx, caller, authz.PermissionAgentMetadataEdit, authz.Relationship{IsOwner: a.PrimaryOwner.ID == actor}); err != nil {
			return err
		}
		if a.PrimaryOwner.ID != actor {
			return refuse(Forbidden, "only the agent's primary owner offers its ownership")
		}
		if err := stillChanges(a); err != nil {
			return err
		}
		if to == actor {
			return refuse(Invalid, "the transfer must name someone else")
		}
		if err := inv.canOwn(ctx, q, to); err != nil {
			return err
		}
		now := inv.clk.Now().UTC()
		if id, err = uuid.NewV7(); err != nil {
			return fmt.Errorf("generating the transfer's ID: %w", err)
		}
		if err := q.CreateTransfer(ctx, inventorydb.CreateTransferParams{
			ID: id, AgentID: agentID, FromPrincipalID: actor, ToPrincipalID: to, RequestedBy: actor, RequestedAt: now,
		}); err != nil {
			if isUniqueViolation(err, "ownership_transfers_one_pending") {
				return refuse(Conflict, "the agent already has a pending ownership transfer")
			}
			return fmt.Errorf("inserting the transfer: %w", err)
		}
		item, err := uuid.NewV7()
		if err != nil {
			return fmt.Errorf("generating the inbox item's ID: %w", err)
		}
		if err := q.AddInboxItem(ctx, inventorydb.AddInboxItemParams{
			ID: item, PrincipalID: &to, Kind: "ownership_transfer", SubjectType: "ownership_transfer", SubjectID: id, CreatedAt: now,
		}); err != nil {
			return fmt.Errorf("adding the transfer to its recipient's inbox: %w", err)
		}
		if err := touch(ctx, q, agentID, nil, now); err != nil {
			return err
		}
		return inv.recordOwnership(ctx, tx, agentID, map[string]any{
			"change": "transfer_requested", "principal_id": to.String(), "transfer_id": id.String(), "actor": actorOf(caller),
		})
	})
	if err != nil {
		return nil, err
	}
	return inv.loadTransfer(ctx, inventorydb.New(inv.db), agentID, id)
}

// CancelTransfer cancels a pending transfer. The primary owner who offered
// it, or an operator, cancels it.
func (inv *Inventory) CancelTransfer(ctx context.Context, caller auth.Principal, agentID, transferID uuid.UUID) error {
	return inv.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := inventorydb.New(tx)
		t, err := lockedTransfer(ctx, q, agentID, transferID)
		if err != nil {
			return err
		}
		requester := t.RequestedBy.String() == caller.ID
		if err := inv.authorize(ctx, caller, authz.PermissionAgentMetadataEdit, authz.Relationship{IsOwner: requester}); err != nil {
			return err
		}
		return inv.closeTransfer(ctx, tx, caller, t, "cancelled", "transfer_cancelled") //nolint:misspell // the schema's spelling
	})
}

// AcceptTransfer makes the person that a pending transfer names the agent's
// primary owner; they need the owner role. The former owner's assignment
// ends, and the agent takes a new governance state version.
func (inv *Inventory) AcceptTransfer(ctx context.Context, caller auth.Principal, agentID, transferID uuid.UUID) (*Transfer, error) {
	err := inv.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := inventorydb.New(tx)
		t, err := inv.transferFor(ctx, q, caller, agentID, transferID)
		if err != nil {
			return err
		}
		if err := inv.authorize(ctx, caller, authz.PermissionAgentPropose, authz.Relationship{}); err != nil {
			return err
		}
		a, err := inv.load(ctx, q, agentID)
		if err != nil {
			return err
		}
		if err := stillChanges(a); err != nil {
			return err
		}
		if a.PrimaryOwner.ID != t.FromPrincipalID {
			return refuse(Conflict, "the agent's primary owner changed since the transfer was offered")
		}
		if err := inv.canOwn(ctx, q, t.ToPrincipalID); err != nil {
			return err
		}
		now := inv.clk.Now().UTC()
		if err := makePrimary(ctx, q, agentID, t.ToPrincipalID, t.ToPrincipalID, transferredReason, now); err != nil {
			return err
		}
		if err := inv.closeTransfer(ctx, tx, caller, t, "accepted", ""); err != nil {
			return err
		}
		stateVersion, err := inv.republish(ctx, tx, agentID, now)
		if err != nil {
			return err
		}
		return inv.recordOwnership(ctx, tx, agentID, map[string]any{
			"change":        "transfer_accepted",
			"principal_id":  t.ToPrincipalID.String(),
			"former_owner":  t.FromPrincipalID.String(),
			"transfer_id":   t.ID.String(),
			"actor":         actorOf(caller),
			"state_version": stateVersion,
		})
	})
	if err != nil {
		return nil, err
	}
	return inv.loadTransfer(ctx, inventorydb.New(inv.db), agentID, transferID)
}

// DeclineTransfer declines a pending transfer, as the person it names; the
// agent keeps its primary owner.
func (inv *Inventory) DeclineTransfer(ctx context.Context, caller auth.Principal, agentID, transferID uuid.UUID) (*Transfer, error) {
	err := inv.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := inventorydb.New(tx)
		t, err := inv.transferFor(ctx, q, caller, agentID, transferID)
		if err != nil {
			return err
		}
		return inv.closeTransfer(ctx, tx, caller, t, "declined", "transfer_declined")
	})
	if err != nil {
		return nil, err
	}
	return inv.loadTransfer(ctx, inventorydb.New(inv.db), agentID, transferID)
}

// transferFor returns a transfer of the agent that names the caller, under
// the agent's lock.
func (inv *Inventory) transferFor(ctx context.Context, q *inventorydb.Queries, caller auth.Principal, agentID, transferID uuid.UUID) (inventorydb.WhitetowerOwnershipTransfer, error) {
	t, err := lockedTransfer(ctx, q, agentID, transferID)
	if err != nil {
		return t, err
	}
	if t.ToPrincipalID.String() != caller.ID {
		return t, refuse(Forbidden, "only the principal that the transfer names accepts or declines it")
	}
	return t, nil
}

// closeTransfer closes a pending transfer with the status given, takes it out
// of its recipient's inbox, and changes the agent's ETag. With an event
// change, it records the event; the caller records the others.
func (inv *Inventory) closeTransfer(ctx context.Context, tx *db.Tx, caller auth.Principal, t inventorydb.WhitetowerOwnershipTransfer, status, change string) error {
	q := inventorydb.New(tx)
	if t.Status != "pending" {
		return refuse(Conflict, "the transfer is %s, no longer pending", t.Status)
	}
	now := inv.clk.Now().UTC()
	n, err := q.DecideTransfer(ctx, inventorydb.DecideTransferParams{Status: status, DecidedAt: &now, ID: t.ID})
	if err != nil {
		return fmt.Errorf("closing the transfer: %w", err)
	}
	if n == 0 {
		return refuse(Conflict, "the transfer is no longer pending")
	}
	if err := q.ResolveInboxItems(ctx, inventorydb.ResolveInboxItemsParams{
		ResolvedAt: &now, SubjectType: "ownership_transfer", SubjectID: t.ID,
	}); err != nil {
		return fmt.Errorf("taking the transfer out of the inbox: %w", err)
	}
	if err := touch(ctx, q, t.AgentID, nil, now); err != nil {
		return err
	}
	if change == "" {
		return nil
	}
	return inv.recordOwnership(ctx, tx, t.AgentID, map[string]any{
		"change": change, "principal_id": t.ToPrincipalID.String(), "transfer_id": t.ID.String(), "actor": actorOf(caller),
	})
}

// mayEditOwners checks that the caller may manage the agent's delegates: one
// of its owners, or an operator, while the agent still changes.
func (inv *Inventory) mayEditOwners(ctx context.Context, q *inventorydb.Queries, caller auth.Principal, actor, agentID uuid.UUID) error {
	a, err := inv.lockAgent(ctx, q, agentID)
	if err != nil {
		return err
	}
	own, err := q.IsOwner(ctx, inventorydb.IsOwnerParams{AgentID: agentID, PrincipalID: actor})
	if err != nil {
		return fmt.Errorf("reading the agent's owners: %w", err)
	}
	if err := inv.authorize(ctx, caller, authz.PermissionAgentMetadataEdit, authz.Relationship{IsOwner: own}); err != nil {
		return err
	}
	return stillChanges(a)
}

// lockAgent locks the agent's row until the transaction ends, then reads the
// agent. Every change of an agent's owners or transfers takes the lock first,
// so that they happen one after the other and each sees what the one before
// it committed: two reassignments at the same version, or a reassignment and
// an accepted transfer, would otherwise both pass their checks.
func (inv *Inventory) lockAgent(ctx context.Context, q *inventorydb.Queries, agentID uuid.UUID) (*Agent, error) {
	if _, err := q.LockAgent(ctx, agentID); err != nil {
		return nil, notFound(err, "agent")
	}
	return inv.load(ctx, q, agentID)
}

// lockedTransfer locks the agent, as lockAgent does, then reads its
// transfer. A caller who names an agent that does not exist learns no more
// than with a transfer that does not.
func lockedTransfer(ctx context.Context, q *inventorydb.Queries, agentID, transferID uuid.UUID) (inventorydb.WhitetowerOwnershipTransfer, error) {
	if _, err := q.LockAgent(ctx, agentID); err != nil {
		return inventorydb.WhitetowerOwnershipTransfer{}, notFound(err, "ownership transfer of the agent")
	}
	t, err := q.GetTransfer(ctx, inventorydb.GetTransferParams{ID: transferID, AgentID: agentID})
	if err != nil {
		return t, notFound(err, "ownership transfer of the agent")
	}
	return t, nil
}

// canOwn refuses a principal that may not own agents: someone who is not an
// active person with the owner role, from IdP groups or local bindings.
func (inv *Inventory) canOwn(ctx context.Context, q *inventorydb.Queries, id uuid.UUID) error {
	p, err := q.PrincipalForOwnership(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return refuse(Invalid, "no principal has the ID %s", id)
	}
	if err != nil {
		return fmt.Errorf("reading the principal: %w", err)
	}
	switch {
	case p.Kind != "human":
		return refuse(Invalid, "only a person can own an agent or be a delegate")
	case p.Status != "active":
		return refuse(Invalid, "the principal is inactive")
	case !slices.Contains(authn.ResolveEffectiveRoles(p.IdpGroups, inv.roleMapping, p.BoundRoles), string(authz.RoleOwner)):
		return refuse(Invalid, "the principal does not hold the owner role")
	}
	return nil
}

// stillChanges refuses a change to a retired or rejected agent.
func stillChanges(a *Agent) error {
	if a.LifecycleState == "retired" || a.LifecycleState == "rejected" {
		return refuse(Conflict, "a %s agent no longer changes", a.LifecycleState)
	}
	return nil
}

// makePrimary ends the agent's primary owner's assignment, and the new
// owner's assignment as a delegate if they have one, then makes them the
// primary owner. The unique indexes on assignments are not deferrable, which
// is why the ends come first.
func makePrimary(ctx context.Context, q *inventorydb.Queries, agentID, newOwner, by uuid.UUID, reason string, now time.Time) error {
	end := func(id uuid.UUID, reason string) error {
		if err := q.EndAssignment(ctx, inventorydb.EndAssignmentParams{ID: id, EndedBy: &by, EndedAt: &now, EndReason: &reason}); err != nil {
			return fmt.Errorf("ending an owner assignment: %w", err)
		}
		return nil
	}
	primary, err := q.PrimaryAssignment(ctx, agentID)
	switch {
	case err == nil:
		if err := end(primary.ID, reason); err != nil {
			return err
		}
	case !errors.Is(err, pgx.ErrNoRows):
		return fmt.Errorf("reading the primary owner's assignment: %w", err)
	}
	delegate, err := q.CurrentAssignment(ctx, inventorydb.CurrentAssignmentParams{AgentID: agentID, PrincipalID: newOwner})
	switch {
	case err == nil:
		if err := end(delegate.ID, promotedReason); err != nil {
			return err
		}
	case !errors.Is(err, pgx.ErrNoRows):
		return fmt.Errorf("reading the new owner's assignment: %w", err)
	}
	id, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("generating the assignment's ID: %w", err)
	}
	if err := q.AddOwner(ctx, inventorydb.AddOwnerParams{
		ID: id, AgentID: agentID, PrincipalID: newOwner, Role: "primary", AssignedBy: by, AssignedAt: now,
	}); err != nil {
		return fmt.Errorf("assigning the primary owner: %w", err)
	}
	return nil
}

// cancelTransfers cancels the agent's pending transfer, and takes it out of
// its recipient's inbox.
func cancelTransfers(ctx context.Context, q *inventorydb.Queries, agentID uuid.UUID, now time.Time) error {
	ids, err := q.CancelPendingTransfers(ctx, inventorydb.CancelPendingTransfersParams{DecidedAt: &now, AgentID: agentID})
	if err != nil {
		return fmt.Errorf("canceling the pending transfer: %w", err)
	}
	for _, id := range ids {
		if err := q.ResolveInboxItems(ctx, inventorydb.ResolveInboxItemsParams{
			ResolvedAt: &now, SubjectType: "ownership_transfer", SubjectID: id,
		}); err != nil {
			return fmt.Errorf("taking the transfer out of the inbox: %w", err)
		}
	}
	return nil
}

// touch gives the agent a new version, so that its ETag changes with its
// owners; with a version, only if the agent is still at it.
func touch(ctx context.Context, q *inventorydb.Queries, agentID uuid.UUID, version *int64, now time.Time) error {
	n, err := q.TouchAgent(ctx, inventorydb.TouchAgentParams{UpdatedAt: now, ID: agentID, Version: version})
	if err != nil {
		return fmt.Errorf("changing the agent's version: %w", err)
	}
	if n == 0 {
		return refuse(Stale, "the agent changed since you read it: read it again, then retry")
	}
	return nil
}

// republish writes the agent's governance state again, once its owner
// changed, and returns its new version.
func (inv *Inventory) republish(ctx context.Context, tx *db.Tx, agentID uuid.UUID, now time.Time) (int64, error) {
	a, err := inv.load(ctx, inventorydb.New(tx), agentID)
	if err != nil {
		return 0, err
	}
	return inv.publishState(ctx, tx, a, now)
}

// recordOwnership records a change of the agent's owners or of one of its
// transfers.
func (inv *Inventory) recordOwnership(ctx context.Context, tx *db.Tx, agentID uuid.UUID, data map[string]any) error {
	if err := inv.writer.Record(ctx, tx, audit.Event{
		Type: "whitetower.agent.ownership_changed.v1", Subject: agentID.String(), Data: data,
	}); err != nil {
		return fmt.Errorf("recording the change of the agent's owners: %w", err)
	}
	return nil
}

// loadTransfer reads a transfer of the agent.
func (inv *Inventory) loadTransfer(ctx context.Context, q *inventorydb.Queries, agentID, id uuid.UUID) (*Transfer, error) {
	t, err := q.GetTransfer(ctx, inventorydb.GetTransferParams{ID: id, AgentID: agentID})
	if err != nil {
		return nil, notFound(err, "ownership transfer of the agent")
	}
	transfers, err := assembleTransfers(ctx, q, []inventorydb.WhitetowerOwnershipTransfer{t})
	if err != nil {
		return nil, err
	}
	return &transfers[0], nil
}

// assembleTransfers completes the rows of transfers with the people they
// name.
func assembleTransfers(ctx context.Context, q *inventorydb.Queries, rows []inventorydb.WhitetowerOwnershipTransfer) ([]Transfer, error) {
	var ids []uuid.UUID
	for _, r := range rows {
		ids = append(ids, r.FromPrincipalID, r.ToPrincipalID, r.RequestedBy)
	}
	who, err := people(ctx, q, ids)
	if err != nil {
		return nil, err
	}
	transfers := make([]Transfer, len(rows))
	for i, r := range rows {
		transfers[i] = Transfer{
			ID: r.ID, AgentID: r.AgentID, From: who[r.FromPrincipalID], To: who[r.ToPrincipalID],
			RequestedBy: who[r.RequestedBy], RequestedAt: r.RequestedAt, Status: r.Status, DecidedAt: r.DecidedAt,
		}
	}
	return transfers, nil
}
