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
var permissions = map[string]authz.Permission{
	"submit":          authz.PermissionAgentPropose,
	"withdraw":        authz.PermissionAgentPropose,
	"request_changes": authz.PermissionUsecaseValidate,
	"reject":          authz.PermissionUsecaseValidate,
	"validate":        authz.PermissionUsecaseValidate,
	"activate":        authz.PermissionAgentActivate,
	"suspend":         authz.PermissionAgentSuspend,
	"reinstate":       authz.PermissionAgentReinstate,
	"retire":          authz.PermissionAgentRetire,
}

// decisions are the use case decisions that the advisory committee's actions
// record.
var decisions = map[string]string{
	"request_changes": "changes_requested",
	"reject":          "rejected",
	"validate":        "validated",
}

// facts are what a decision reads of an agent, its use case and the caller.
type facts struct {
	metadataComplete bool
	ownerActive      bool
	useCaseStatus    string
	prohibited       bool // the use case's EU AI Act classification
	commentGiven     bool
	// conflicted is true when the caller created the agent or its use case,
	// or is or ever was its primary owner or one of its delegates.
	conflicted      bool
	policyActive    bool // an agent-specific policy has an active version
	harnessDeclared bool
	halted          bool // the effective run state
	reviewOverdue   bool // an open review is past its grace period
	// previous is the state that a suspended agent returns to.
	previous string
	// person is false for a service account; permitted is true when the
	// caller's roles grant the action's permission on the agent, within
	// their token's scopes; own is true for the agent's primary owner and
	// its delegates.
	person, permitted, own bool
}

// guards tells whether each guard that the transitions people take read
// holds (docs/architecture/lifecycle.md, section 4).
var guards = map[string]func(facts) bool{
	"metadata_complete":              func(f facts) bool { return f.metadataComplete },
	"owner_active":                   func(f facts) bool { return f.ownerActive },
	"use_case_not_rejected":          func(f facts) bool { return f.useCaseStatus != "rejected" },
	"use_case_not_prohibited":        func(f facts) bool { return !f.prohibited },
	"use_case_validated":             useCaseValidated,
	"not_owner_or_creator":           func(f facts) bool { return !f.conflicted },
	"comment_given":                  func(f facts) bool { return f.commentGiven },
	"agent_policy_active":            func(f facts) bool { return f.policyActive },
	"harness_declared":               func(f facts) bool { return f.harnessDeclared },
	"not_halted":                     func(f facts) bool { return !f.halted },
	"review_not_overdue":             func(f facts) bool { return !f.reviewOverdue },
	"previous_state_invariants_hold": func(f facts) bool { holds, ok := invariants[f.previous]; return ok && holds(f) },
}

// invariants tell whether an agent meets what each state that a suspension
// remembers needs, so that a reinstatement keeps it (the lifecycle, sections
// 1, 5 and 6): a validated use case, and for ready and active also an active
// agent-specific policy and a declared harness. T13 checks the owner and the
// run state itself.
var invariants = map[string]func(facts) bool{
	"validated": useCaseValidated,
	"ready":     servable,
	"active":    servable,
}

func useCaseValidated(f facts) bool { return f.useCaseStatus == "validated" }

func servable(f facts) bool { return useCaseValidated(f) && f.policyActive && f.harnessDeclared }

// allows refuses the caller an action that the facts say they may not take:
// only a person takes an action other than suspend (HUM-04, the maintainer's
// decision of 2026-11-12), with the action's permission within its scope,
// and only the agent's owners take the actions that only they take. The
// principal's kind decides, so that a person's own service account is
// refused too: an automation never puts an agent into service, nor retires
// it.
func (t transition) allows(f facts) error {
	switch {
	case !f.person && t.action != "suspend":
		return refuse(Forbidden, "only a person may %s an agent", t.action)
	case !f.permitted:
		return refuse(Forbidden, "your roles do not permit this")
	case t.ownersOnly() && !f.own:
		return refuse(Forbidden, "only the agent's primary owner and its delegates may %s it", t.action)
	}
	return nil
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
		// The agent's row, then its governance state, as every writer of what
		// enforcement points see locks them before it takes its version (the
		// design of the halt path, section 2). The run state that the guards
		// read holds until the transition commits: an agent or selector halt,
		// which locks the state of the agents it covers, either committed
		// before and shows, or waits.
		if _, err := q.LockAgent(ctx, agentID); err != nil {
			return notFound(err, "agent")
		}
		if err := lockState(ctx, q, agentID); err != nil {
			return err
		}
		a, err := inv.load(ctx, q, agentID)
		if err != nil {
			return err
		}
		if !seesAll(caller) && a.LifecycleState != "active" {
			return refuse(NotFound, "no agent has this ID")
		}
		own, err := q.IsOwner(ctx, inventorydb.IsOwnerParams{AgentID: agentID, PrincipalID: actor})
		if err != nil {
			return fmt.Errorf("reading the agent's owners: %w", err)
		}
		f := facts{person: caller.Kind == auth.Human, own: own, permitted: inv.permits(ctx, caller, t.action, own)}
		if err := t.allows(f); err != nil {
			return err
		}
		uc, err := q.LockUseCase(ctx, a.UseCaseID)
		if err != nil {
			return fmt.Errorf("reading the agent's use case: %w", err)
		}
		if err := inv.readFacts(ctx, tx, &f, actor, a, uc); err != nil {
			return err
		}
		f.commentGiven = comment != ""
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

// Action is a lifecycle action that an agent's state allows, as the caller
// may take it now.
type Action struct {
	Action string
	// Transition is the transition's ID in the lifecycle, T2 to T14.
	Transition      string
	CommentRequired bool
	// RefusedBy names what refuses the action to the caller, empty when they
	// may take it: permission, when their kind, roles or scopes do not allow
	// it, then each guard of the lifecycle that does not hold.
	RefusedBy []string
}

// Actions returns the lifecycle state of an agent that the caller may see,
// and the actions that people take which that state allows, in the order of
// the lifecycle, each with what refuses it to the caller now (UI-03, the
// console's disabled actions). Transition checks everything again.
func (inv *Inventory) Actions(ctx context.Context, caller auth.Principal, agentID uuid.UUID) (string, []Action, error) {
	actor, err := uuid.Parse(caller.ID)
	if err != nil {
		return "", nil, fmt.Errorf("the caller's ID %q: %w", caller.ID, err)
	}
	var state string
	var actions []Action
	err = inv.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := inventorydb.New(tx)
		a, err := inv.load(ctx, q, agentID)
		if err != nil {
			return err
		}
		if !seesAll(caller) && a.LifecycleState != "active" {
			return refuse(NotFound, "no agent has this ID")
		}
		own, err := q.IsOwner(ctx, inventorydb.IsOwnerParams{AgentID: agentID, PrincipalID: actor})
		if err != nil {
			return fmt.Errorf("reading the agent's owners: %w", err)
		}
		uc, err := q.GetUseCase(ctx, a.UseCaseID)
		if err != nil {
			return fmt.Errorf("reading the agent's use case: %w", err)
		}
		f := facts{person: caller.Kind == auth.Human, own: own}
		if err := inv.readFacts(ctx, tx, &f, actor, a, uc); err != nil {
			return err
		}
		state, actions = a.LifecycleState, []Action{}
		for _, t := range lifecycle {
			if _, people := permissions[t.action]; !people || !slices.Contains(t.from, a.LifecycleState) {
				continue
			}
			f.permitted = inv.permits(ctx, caller, t.action, own)
			actions = append(actions, Action{
				Action: t.action, Transition: t.id, CommentRequired: slices.Contains(t.guards, "comment_given"), RefusedBy: t.refusals(f),
			})
		}
		return nil
	})
	if err != nil {
		return "", nil, err
	}
	return state, actions, nil
}

// permits reports whether the caller's roles grant the action's permission on
// an agent that they own or not. The Authorizer also applies the scopes of an
// API token (ST-19) and the limits of a break-glass session.
func (inv *Inventory) permits(ctx context.Context, caller auth.Principal, action string, own bool) bool {
	return inv.authorize(ctx, caller, permissions[action], authz.Relationship{IsOwner: own}) == nil
}

// readFacts adds to f what the guards read of the agent and its use case, in
// tx, as they concern the caller.
func (inv *Inventory) readFacts(ctx context.Context, tx *db.Tx, f *facts, actor uuid.UUID, a *Agent, uc inventorydb.WhitetowerUseCase) error {
	q := inventorydb.New(tx)
	ever, err := q.EverAssigned(ctx, inventorydb.EverAssignedParams{AgentID: a.ID, PrincipalID: actor})
	if err != nil {
		return fmt.Errorf("reading the agent's owners: %w", err)
	}
	if f.policyActive, err = inv.policies.Active(ctx, tx, a.ID); err != nil {
		return fmt.Errorf("reading the agent's policies: %w", err)
	}
	if f.reviewOverdue, err = q.ReviewOverdue(ctx, inventorydb.ReviewOverdueParams{AgentID: a.ID, Now: inv.clk.Now().UTC()}); err != nil {
		return fmt.Errorf("reading the agent's reviews: %w", err)
	}
	f.metadataComplete = a.validate() == nil
	f.ownerActive = a.PrimaryOwner.Status == "active"
	f.useCaseStatus = uc.Status
	f.prohibited = uc.AiActClassification == "prohibited"
	f.conflicted = ever || a.CreatedBy.ID == actor || uc.CreatedBy == actor
	f.harnessDeclared = a.Harness != nil
	f.halted = a.Halted
	if a.Suspension != nil {
		f.previous = a.Suspension.From
	}
	return nil
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

// refusals names what refuses t to the caller, as getAgentActions tells it
// beforehand: permission, then each guard that does not hold but the
// comment, which only the request brings.
func (t transition) refusals(f facts) []string {
	refused := []string{}
	if t.allows(f) != nil {
		refused = append(refused, "permission")
	}
	for _, g := range t.unmet(f) {
		if g != "comment_given" {
			refused = append(refused, g)
		}
	}
	return refused
}

// move returns the agent as t leaves it at the time given: in its new state,
// suspended with the state it came from, back in that state once reinstated,
// and with the times of its activation and of its retirement. People suspend
// an agent only by hand (T10).
func (t transition) move(a Agent, now time.Time) Agent {
	b := a
	b.LifecycleState, b.Suspension = t.to, nil
	switch t.to {
	case previousState:
		b.LifecycleState = a.Suspension.From
	case "suspended":
		b.Suspension = &Suspension{From: a.LifecycleState, Reason: "manual", At: now}
	case "active":
		b.ActivatedAt = &now
	case "retired":
		b.RetiredAt = &now
	}
	return b
}

// apply moves the agent along t, with its effects on the use case, the
// decisions, the inbox and the pending ownership transfer, and records the
// transition at the agent's new governance state version.
func (inv *Inventory) apply(ctx context.Context, tx *db.Tx, caller auth.Principal, actor uuid.UUID, t transition, a *Agent, uc inventorydb.WhitetowerUseCase, comment string) error {
	q := inventorydb.New(tx)
	now := inv.clk.Now().UTC()
	from := a.LifecycleState
	moved := t.move(*a, now)
	set := inventorydb.SetLifecycleStateParams{
		LifecycleState: moved.LifecycleState, ActivatedAt: moved.ActivatedAt, RetiredAt: moved.RetiredAt,
		UpdatedAt: now, ID: a.ID, Version: a.Version,
	}
	if s := moved.Suspension; s != nil {
		set.SuspendedFrom, set.SuspensionReason, set.SuspendedAt = &s.From, &s.Reason, &s.At
	}
	n, err := q.SetLifecycleState(ctx, set)
	if err != nil {
		return fmt.Errorf("moving the agent: %w", err)
	}
	if n == 0 {
		return refuse(Stale, "the agent changed since you read it: read it again, then retry")
	}
	*a = moved
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
	// A rejected or retired agent no longer changes, so its pending ownership
	// transfer could never be accepted.
	if t.to == "rejected" || t.to == "retired" {
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
		ID: id, AgentID: a.ID, Action: t.action, FromState: &from, ToState: a.LifecycleState, ActorType: actorType(caller),
		ActorID: &actor, Reason: set.SuspensionReason, Comment: nonEmpty(comment), StateVersion: version, OccurredAt: now,
	}); err != nil {
		return fmt.Errorf("recording the transition: %w", err)
	}
	data := map[string]any{
		"transition":    t.id,
		"action":        t.action,
		"from":          from,
		"to":            a.LifecycleState,
		"comment_given": comment != "",
		"actor":         actorOf(caller),
		"state_version": version,
	}
	if a.Suspension != nil {
		data["suspension_reason"] = a.Suspension.Reason
	}
	if err := inv.writer.Record(ctx, tx, audit.Event{Type: "whitetower.agent.lifecycle_changed.v1", Subject: a.ID.String(), Data: data}); err != nil {
		return fmt.Errorf("recording the agent's transition: %w", err)
	}
	return nil
}

// affectUseCase applies the effect of a decision on a proposal to its use
// case, which a decision has not made final: submitting it, withdrawing it
// once no agent that it justifies waits for the committee, or deciding on it.
// The lifecycle does not say what retiring a proposal does to its use case,
// so the retirement withdraws it, as T3 does.
func affectUseCase(ctx context.Context, q *inventorydb.Queries, action string, uc inventorydb.WhitetowerUseCase, now time.Time) error {
	if uc.Status == "validated" || uc.Status == "rejected" {
		return nil
	}
	status := uc.Status
	switch action {
	case "submit":
		status = "submitted"
	case "withdraw", "retire":
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
// and takes it out once it is withdrawn, decided on or retired.
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
	case "withdraw", "request_changes", "reject", "validate", "retire":
		if err := q.ResolveInboxItems(ctx, inventorydb.ResolveInboxItemsParams{
			ResolvedAt: &now, Kind: kind, SubjectType: subject, SubjectID: agentID,
		}); err != nil {
			return fmt.Errorf("taking the proposal out of the inbox: %w", err)
		}
	}
	return nil
}
