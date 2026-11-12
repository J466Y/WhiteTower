package inventory

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/J466Y/WhiteTower/internal/audit"
	"github.com/J466Y/WhiteTower/internal/authz"
	"github.com/J466Y/WhiteTower/internal/inventory/inventorydb"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/db"
)

// transition is a transition of the lifecycle, as
// docs/architecture/agent-lifecycle.yaml defines it; a test keeps the two
// the same. The code of each transition does what its effects say.
type transition struct {
	id     string
	action string
	from   []string // none for the creation
	to     string   // previousState for a reinstatement
	actors []string
	guards []string
}

// previousState is where a reinstatement goes: the state the agent was
// suspended from.
const previousState = "previous_state"

// lifecycle holds the transitions of the lifecycle, in the order of
// agent-lifecycle.yaml.
var lifecycle = []transition{
	{
		id: "T1", action: "create", to: "draft", actors: []string{"owner"},
		guards: []string{"metadata_complete", "use_case_linked"},
	},
	{
		id: "T2", action: "submit", from: []string{"draft"}, to: "proposed", actors: []string{"primary_owner", "delegate"},
		guards: []string{"metadata_complete", "owner_active", "use_case_not_rejected"},
	},
	{id: "T3", action: "withdraw", from: []string{"proposed"}, to: "draft", actors: []string{"primary_owner", "delegate"}},
	{
		id: "T4", action: "request_changes", from: []string{"proposed"}, to: "draft", actors: []string{"advisory"},
		guards: []string{"not_owner_or_creator", "comment_given"},
	},
	{
		id: "T5", action: "reject", from: []string{"proposed"}, to: "rejected", actors: []string{"advisory"},
		guards: []string{"not_owner_or_creator", "comment_given"},
	},
	{
		id: "T6", action: "validate", from: []string{"proposed"}, to: "validated", actors: []string{"advisory"},
		guards: []string{"not_owner_or_creator", "use_case_not_prohibited", "use_case_not_rejected", "owner_active", "comment_given"},
	},
	{
		id: "T7", action: "mark_ready", from: []string{"validated"}, to: "ready", actors: []string{"system"},
		guards: []string{"agent_policy_active", "harness_declared"},
	},
	{
		id: "T8", action: "unmark_ready", from: []string{"ready"}, to: "validated", actors: []string{"system"},
		guards: []string{"agent_policy_or_harness_missing"},
	},
	{
		id: "T9", action: "activate", from: []string{"ready"}, to: "active", actors: []string{"primary_owner", "delegate", "operator"},
		guards: []string{"owner_active", "use_case_validated", "agent_policy_active", "harness_declared", "not_halted"},
	},
	{
		id: "T10", action: "suspend", from: []string{"validated", "ready", "active"}, to: "suspended",
		actors: []string{"primary_owner", "delegate", "advisory", "operator"}, guards: []string{"comment_given"},
	},
	{
		id: "T11", action: "auto_suspend", from: []string{"validated", "ready", "active"}, to: "suspended",
		actors: []string{"system"}, guards: []string{"owner_inactive_or_review_overdue"},
	},
	{
		id: "T12", action: "halt_suspend", from: []string{"validated", "ready", "active"}, to: "suspended",
		actors: []string{"system"}, guards: []string{"agent_halt_issued"},
	},
	{
		id: "T13", action: "reinstate", from: []string{"suspended"}, to: previousState, actors: []string{"advisory", "operator"},
		guards: []string{"comment_given", "owner_active", "review_not_overdue", "not_halted", "previous_state_invariants_hold"},
	},
	{
		id: "T14", action: "retire", from: []string{"draft", "proposed", "validated", "ready", "active", "suspended"}, to: "retired",
		actors: []string{"primary_owner", "delegate", "advisory", "operator"}, guards: []string{"comment_given"},
	},
}

// permissions are what each action that people take needs besides
// inventory.view, which the API checks (the description of transitionAgent).
// Part 4b of plan P1-04 builds activate, suspend, reinstate and retire.
var permissions = map[string]authz.Permission{
	"submit":          authz.PermissionAgentPropose,
	"withdraw":        authz.PermissionAgentPropose,
	"request_changes": authz.PermissionUsecaseValidate,
	"reject":          authz.PermissionUsecaseValidate,
	"validate":        authz.PermissionUsecaseValidate,
}

// decisions are the use case decisions that the advisory committee's actions
// record.
var decisions = map[string]string{
	"request_changes": "changes_requested",
	"reject":          "rejected",
	"validate":        "validated",
}

// facts are what the guards read of an agent, its use case and the caller.
type facts struct {
	metadataComplete bool
	ownerActive      bool
	useCaseStatus    string
	prohibited       bool // the use case's EU AI Act classification
	commentGiven     bool
	// conflicted is true when the caller created the agent or its use case,
	// or is or ever was its primary owner or one of its delegates.
	conflicted bool
}

// guards tells whether each guard that the built transitions read holds
// (docs/architecture/lifecycle.md, section 4).
var guards = map[string]func(facts) bool{
	"metadata_complete":       func(f facts) bool { return f.metadataComplete },
	"owner_active":            func(f facts) bool { return f.ownerActive },
	"use_case_not_rejected":   func(f facts) bool { return f.useCaseStatus != "rejected" },
	"use_case_not_prohibited": func(f facts) bool { return !f.prohibited },
	"not_owner_or_creator":    func(f facts) bool { return !f.conflicted },
	"comment_given":           func(f facts) bool { return f.commentGiven },
}

// unmet returns the guards of t that do not hold, in the table's order.
func (t transition) unmet(f facts) []string {
	var failed []string
	for _, g := range t.guards {
		if !guards[g](f) {
			failed = append(failed, g)
		}
	}
	return failed
}

// ownersOnly reports whether only the agent's primary owner and its delegates
// take t. The owner role's grant of the permission covers every agent, so
// the inventory checks the relationship itself.
func (t transition) ownersOnly() bool {
	return !slices.ContainsFunc(t.actors, func(a string) bool { return a != "primary_owner" && a != "delegate" })
}

// requested returns the transition of an action that people take.
func requested(action string) (transition, error) {
	i := slices.IndexFunc(lifecycle, func(t transition) bool { return t.action == action })
	switch {
	case i < 0 || lifecycle[i].id == "T1":
		return transition{}, refuse(Invalid, "%q is not a lifecycle action that people take", action)
	case slices.Contains(lifecycle[i].actors, "system"):
		return transition{}, refuse(Invalid, "White Tower takes the action %s itself", action)
	}
	if _, built := permissions[action]; !built {
		return transition{}, refuse(NotBuilt, "the action %s is agreed but not built yet", action)
	}
	return lifecycle[i], nil
}

// Transition takes a lifecycle action on an agent, if it is still at the
// version the caller read (INV-04, API-03): the caller's roles and the
// separation of duties must allow it, and every guard of its transition must
// hold. The agent's use case follows the decisions on its proposal while no
// decision has made it final. The agent takes a new governance state version.
func (inv *Inventory) Transition(ctx context.Context, caller auth.Principal, agentID uuid.UUID, version int64, action, comment string) (*Agent, error) {
	t, err := requested(action)
	if err != nil {
		return nil, err
	}
	if err := optional("comment", comment, 2000); err != nil {
		return nil, err
	}
	if strings.TrimSpace(comment) == "" {
		comment = ""
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
		if !seesAll(caller) && a.LifecycleState != "active" {
			return refuse(NotFound, "no agent has this ID")
		}
		// Service accounts take no action but suspend (T10), the maintainer's
		// decision of 2026-11-12: people decide on proposals (HUM-04), and an
		// automation never puts an agent into service or retires it. The kind
		// is judged, not the principal, so that a person's own service account
		// is refused too.
		if caller.Kind != auth.Human && t.action != "suspend" {
			return refuse(Forbidden, "only a person may %s an agent", t.action)
		}
		own, err := q.IsOwner(ctx, inventorydb.IsOwnerParams{AgentID: agentID, PrincipalID: actor})
		if err != nil {
			return fmt.Errorf("reading the agent's owners: %w", err)
		}
		if err := inv.authorize(ctx, caller, permissions[t.action], authz.Relationship{IsOwner: own}); err != nil {
			return err
		}
		if t.ownersOnly() && !own {
			return refuse(Forbidden, "only the agent's primary owner and its delegates may %s it", t.action)
		}
		uc, err := q.LockUseCase(ctx, a.UseCaseID)
		if err != nil {
			return fmt.Errorf("reading the agent's use case: %w", err)
		}
		ever, err := q.EverAssigned(ctx, inventorydb.EverAssignedParams{AgentID: agentID, PrincipalID: actor})
		if err != nil {
			return fmt.Errorf("reading the agent's owners: %w", err)
		}
		f := facts{
			metadataComplete: a.validate() == nil,
			ownerActive:      a.PrimaryOwner.Status == "active",
			useCaseStatus:    uc.Status,
			prohibited:       uc.AiActClassification == "prohibited",
			commentGiven:     comment != "",
			conflicted:       ever || a.CreatedBy.ID == actor || uc.CreatedBy == actor,
		}
		if err := t.check(a, version, f); err != nil {
			return err
		}
		return inv.apply(ctx, tx, caller, actor, t, a, uc, comment)
	})
	if err != nil {
		return nil, err
	}
	return inv.load(ctx, inventorydb.New(inv.db), agentID)
}

// TransitionRecord is one transition of an agent's lifecycle, as its history
// shows it (INV-04).
type TransitionRecord struct {
	ID uuid.UUID
	// Transition is the transition's ID in the lifecycle, T1 to T14.
	Transition string
	Action     string
	From       string // empty for the creation
	To         string
	Actor      Actor
	Reason     string // empty but for a suspension
	Comment    string // empty when none was given
	// StateVersion is the governance state version that the transition took.
	StateVersion int64
	OccurredAt   time.Time
}

// Actor is who took a transition: a person, a service account or a
// break-glass session, with its ID and display name, or the system, which
// has neither.
type Actor struct {
	Type        string
	ID          *uuid.UUID
	DisplayName string
}

// Transitions returns a page of at most size of the transitions of an agent
// that the caller may see, newest first, before the one given, and whether
// more follow.
func (inv *Inventory) Transitions(ctx context.Context, caller auth.Principal, agentID uuid.UUID, before *uuid.UUID, size int) ([]TransitionRecord, bool, error) {
	if size < 1 || size > maxPage {
		return nil, false, fmt.Errorf("a page of %d transitions: want 1 to %d", size, maxPage)
	}
	if _, err := inv.Get(ctx, caller, agentID); err != nil {
		return nil, false, err
	}
	rows, err := inventorydb.New(inv.db).ListTransitions(ctx, inventorydb.ListTransitionsParams{
		AgentID:   agentID,
		Before:    before,
		PageLimit: int32(size + 1), //nolint:gosec // G115: size is at most maxPage
	})
	if err != nil {
		return nil, false, fmt.Errorf("listing the agent's transitions: %w", err)
	}
	more := len(rows) > size
	if more {
		rows = rows[:size]
	}
	records := make([]TransitionRecord, len(rows))
	for i, r := range rows {
		records[i] = TransitionRecord{
			ID: r.ID, Action: r.Action, From: deref(r.FromState), To: r.ToState,
			Actor:  Actor{Type: r.ActorType, ID: r.ActorID, DisplayName: deref(r.DisplayName)},
			Reason: deref(r.Reason), Comment: deref(r.Comment), StateVersion: r.StateVersion, OccurredAt: r.OccurredAt,
		}
		if j := slices.IndexFunc(lifecycle, func(t transition) bool { return t.action == r.Action }); j >= 0 {
			records[i].Transition = lifecycle[j].id
		}
	}
	return records, more, nil
}

// check refuses t on the agent, at the version the caller read, with the
// facts given: separation of duties first, then a stale version, a state that
// t does not start from, a missing comment and the other guards, which the
// refusal names.
func (t transition) check(a *Agent, version int64, f facts) error {
	failed := t.unmet(f)
	switch {
	case slices.Contains(failed, "not_owner_or_creator"):
		return refuse(Forbidden, "separation of duties: nobody decides on a proposal they own, delegate for, ever did, or created, nor on one whose use case they created (HUM-04)")
	case a.Version != version:
		return refuse(Stale, "the agent changed since you read it: read it again, then retry")
	case !slices.Contains(t.from, a.LifecycleState):
		return refuse(Conflict, "a %s agent cannot %s: it must be %s", a.LifecycleState, t.action, strings.Join(t.from, " or "))
	case slices.Contains(failed, "comment_given"):
		return refuse(Invalid, "a comment is required to %s an agent", t.action)
	case len(failed) > 0:
		return refuse(Conflict, "the lifecycle refuses to %s the agent, since these guards do not hold: %s", t.action, strings.Join(failed, ", "))
	}
	return nil
}

// apply moves the agent along t, with its effects on the use case, the
// decisions and the inbox, and records the transition at the agent's new
// governance state version.
func (inv *Inventory) apply(ctx context.Context, tx *db.Tx, caller auth.Principal, actor uuid.UUID, t transition, a *Agent, uc inventorydb.WhitetowerUseCase, comment string) error {
	q := inventorydb.New(tx)
	now := inv.clk.Now().UTC()
	from := a.LifecycleState
	n, err := q.SetLifecycleState(ctx, inventorydb.SetLifecycleStateParams{LifecycleState: t.to, UpdatedAt: now, ID: a.ID, Version: a.Version})
	if err != nil {
		return fmt.Errorf("moving the agent: %w", err)
	}
	if n == 0 {
		return refuse(Stale, "the agent changed since you read it: read it again, then retry")
	}
	a.LifecycleState = t.to
	if err := affectUseCase(ctx, q, t.action, uc, now); err != nil {
		return err
	}
	if decision, ok := decisions[t.action]; ok {
		id, err := uuid.NewV7()
		if err != nil {
			return fmt.Errorf("generating the decision's ID: %w", err)
		}
		if err := q.RecordDecision(ctx, inventorydb.RecordDecisionParams{
			ID: id, UseCaseID: uc.ID, AgentID: &a.ID, Decision: decision, Comment: comment, DecidedBy: actor, DecidedAt: now,
		}); err != nil {
			return fmt.Errorf("recording the decision on the use case: %w", err)
		}
	}
	if err := affectInbox(ctx, q, t.action, a.ID, now); err != nil {
		return err
	}
	// A rejected agent no longer changes, so its pending ownership transfer
	// could never be accepted.
	if t.to == "rejected" {
		if err := cancelTransfers(ctx, q, a.ID, now); err != nil {
			return err
		}
	}
	version, err := inv.publishState(ctx, tx, a, now)
	if err != nil {
		return err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("generating the transition's ID: %w", err)
	}
	if err := q.RecordTransition(ctx, inventorydb.RecordTransitionParams{
		ID: id, AgentID: a.ID, Action: t.action, FromState: &from, ToState: t.to,
		ActorType: actorType(caller), ActorID: &actor, Comment: nonEmpty(comment), StateVersion: version, OccurredAt: now,
	}); err != nil {
		return fmt.Errorf("recording the transition: %w", err)
	}
	if err := inv.writer.Record(ctx, tx, audit.Event{
		Type:    "whitetower.agent.lifecycle_changed.v1",
		Subject: a.ID.String(),
		Data: map[string]any{
			"transition":    t.id,
			"action":        t.action,
			"from":          from,
			"to":            t.to,
			"comment_given": comment != "",
			"actor":         actorOf(caller),
			"state_version": version,
		},
	}); err != nil {
		return fmt.Errorf("recording the agent's transition: %w", err)
	}
	return nil
}

// affectUseCase applies the effect of a decision on a proposal to its use
// case, which a decision has not made final: submitting it, withdrawing it
// once no agent that it justifies waits for the committee, or deciding on it.
func affectUseCase(ctx context.Context, q *inventorydb.Queries, action string, uc inventorydb.WhitetowerUseCase, now time.Time) error {
	if uc.Status == "validated" || uc.Status == "rejected" {
		return nil
	}
	status := uc.Status
	switch action {
	case "submit":
		status = "submitted"
	case "withdraw":
		awaits, err := q.UseCaseAwaitsDecision(ctx, uc.ID)
		if err != nil {
			return fmt.Errorf("reading the use case's agents: %w", err)
		}
		if uc.Status == "submitted" && !awaits {
			status = "draft"
		}
	default:
		if decision, ok := decisions[action]; ok {
			status = decision
		}
	}
	if status == uc.Status {
		return nil
	}
	if err := q.SetUseCaseStatus(ctx, inventorydb.SetUseCaseStatusParams{Status: status, UpdatedAt: now, ID: uc.ID}); err != nil {
		return fmt.Errorf("changing the use case's status: %w", err)
	}
	return nil
}

// affectInbox puts a submitted proposal in the advisory committee's inbox,
// and takes it out once it is withdrawn or decided on.
func affectInbox(ctx context.Context, q *inventorydb.Queries, action string, agentID uuid.UUID, now time.Time) error {
	const kind, subject = "use_case_validation", "agent"
	switch action {
	case "submit":
		id, err := uuid.NewV7()
		if err != nil {
			return fmt.Errorf("generating the inbox item's ID: %w", err)
		}
		advisory := string(authz.RoleAdvisory)
		if err := q.AddInboxItem(ctx, inventorydb.AddInboxItemParams{
			ID: id, Role: &advisory, Kind: kind, SubjectType: subject, SubjectID: agentID, CreatedAt: now,
		}); err != nil {
			return fmt.Errorf("adding the proposal to the advisory committee's inbox: %w", err)
		}
	case "withdraw", "request_changes", "reject", "validate":
		if err := q.ResolveInboxItems(ctx, inventorydb.ResolveInboxItemsParams{
			ResolvedAt: &now, Kind: kind, SubjectType: subject, SubjectID: agentID,
		}); err != nil {
			return fmt.Errorf("taking the proposal out of the inbox: %w", err)
		}
	}
	return nil
}
