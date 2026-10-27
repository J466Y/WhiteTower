package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/J466Y/WhiteTower/internal/audit"
	"github.com/J466Y/WhiteTower/internal/authz"
	"github.com/J466Y/WhiteTower/internal/inventory/inventorydb"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/db"
)

// Agent is an agent of the inventory, in-house or third-party (INV-01).
type Agent struct {
	ID                  uuid.UUID
	Slug                string
	Name                string
	Description         string
	Kind                string
	Source              string
	Vendor              string // empty when not given
	Framework           string // empty when not given
	DeploymentLocation  string
	Environments        []string
	RiskTier            string
	AIActClassification string
	DataCategories      []string
	UseCaseID           uuid.UUID
	LifecycleState      string
	Suspension          *Suspension
	// Halted is the run state: an agent halt or a fleet halt stops the
	// agent, whatever its lifecycle state.
	Halted bool
	// Coverage is how deeply White Tower governs the agent, C0 to C3
	// (INV-08).
	Coverage      string
	Harness       *Harness
	Labels        map[string]string
	HaltMode      string
	DrillEligible bool
	PrimaryOwner  Person
	Delegates     []Person
	// PendingTransfer is the agent's ownership transfer that waits for its
	// recipient, if there is one.
	PendingTransfer *Transfer
	CreatedBy       Person
	CreatedAt       time.Time
	UpdatedAt       time.Time
	ActivatedAt     *time.Time
	RetiredAt       *time.Time
	// Version is the version of the agent's row, which its ETag carries
	// (API-03).
	Version int64
}

// Suspension says why and since when an agent is suspended, and the state
// that reinstating it returns to.
type Suspension struct {
	From   string
	Reason string
	At     time.Time
}

// Harness is the declaration of what confines an agent where it runs. The
// MVP records it; Phase 2 enforces it.
type Harness struct {
	Description string `json:"description"`
}

// NewAgent is a proposal of an agent: the mandatory metadata of INV-01, and
// its options.
type NewAgent struct {
	Slug                string
	Name                string
	Description         string
	Kind                string
	Vendor              string
	Framework           string
	DeploymentLocation  string
	Environments        []string
	RiskTier            string
	AIActClassification string // not_assessed when empty
	DataCategories      []string
	UseCaseID           uuid.UUID
	Labels              map[string]string
	Harness             *Harness
	HaltMode            string // interrupt when empty
	DrillEligible       bool
}

// AgentChanges are the members of an agent to change; a nil member keeps its
// value, and an empty vendor or framework clears it.
type AgentChanges struct {
	Name                *string
	Description         *string
	Vendor              *string
	Framework           *string
	DeploymentLocation  *string
	Environments        *[]string
	RiskTier            *string
	AIActClassification *string
	DataCategories      *[]string
	UseCaseID           *uuid.UUID
	Labels              *map[string]string
	Harness             *Harness
	HaltMode            *string
	DrillEligible       *bool
}

// Propose registers an agent as a draft, transition T1 of the lifecycle. The
// caller, a person with the owner role, becomes its primary owner (INV-02),
// and a use case that is not rejected justifies it (INV-03). The agent gets
// its first governance state version.
func (inv *Inventory) Propose(ctx context.Context, caller auth.Principal, in NewAgent) (*Agent, error) {
	if caller.Kind != auth.Human {
		return nil, refuse(Forbidden, "only a person can propose an agent, and own it")
	}
	if err := inv.authorize(ctx, caller, authz.PermissionAgentPropose, authz.Relationship{}); err != nil {
		return nil, err
	}
	owner, err := uuid.Parse(caller.ID)
	if err != nil {
		return nil, fmt.Errorf("the caller's ID %q: %w", caller.ID, err)
	}
	draft := Agent{
		Slug: in.Slug, Name: in.Name, Description: in.Description, Kind: in.Kind,
		Vendor: in.Vendor, Framework: in.Framework, DeploymentLocation: in.DeploymentLocation,
		Environments: in.Environments, RiskTier: in.RiskTier, AIActClassification: in.AIActClassification,
		DataCategories: in.DataCategories, UseCaseID: in.UseCaseID, Labels: in.Labels,
		Harness: in.Harness, HaltMode: in.HaltMode, DrillEligible: in.DrillEligible,
	}
	if draft.AIActClassification == "" {
		draft.AIActClassification = "not_assessed"
	}
	if draft.HaltMode == "" {
		draft.HaltMode = "interrupt"
	}
	if draft.Labels == nil {
		draft.Labels = map[string]string{}
	}
	if !slugPattern.MatchString(draft.Slug) {
		return nil, refuse(Invalid, "slug must have 1 to 63 lowercase letters, digits and inner hyphens")
	}
	if err := oneOf("kind", draft.Kind, agentKinds); err != nil {
		return nil, err
	}
	if err := draft.validate(); err != nil {
		return nil, err
	}

	var id uuid.UUID
	err = inv.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := inventorydb.New(tx)
		if err := checkCategories(ctx, q, draft.DataCategories); err != nil {
			return err
		}
		if err := checkUseCase(ctx, q, draft.UseCaseID); err != nil {
			return err
		}
		now := inv.clk.Now().UTC()
		if id, err = uuid.NewV7(); err != nil {
			return fmt.Errorf("generating the agent's ID: %w", err)
		}
		labelsJSON, harnessJSON, err := encode(&draft)
		if err != nil {
			return err
		}
		if err := q.CreateAgent(ctx, inventorydb.CreateAgentParams{
			ID:                  id,
			Slug:                draft.Slug,
			Name:                draft.Name,
			Description:         draft.Description,
			Kind:                draft.Kind,
			Vendor:              nonEmpty(draft.Vendor),
			Framework:           nonEmpty(draft.Framework),
			DeploymentLocation:  &draft.DeploymentLocation,
			Environments:        draft.Environments,
			RiskTier:            draft.RiskTier,
			AiActClassification: draft.AIActClassification,
			DataCategories:      draft.DataCategories,
			UseCaseID:           draft.UseCaseID,
			Harness:             harnessJSON,
			HaltMode:            draft.HaltMode,
			DrillEligible:       draft.DrillEligible,
			Labels:              labelsJSON,
			CreatedBy:           owner,
			CreatedAt:           now,
		}); err != nil {
			if isUniqueViolation(err, "agents_slug_key") {
				return refuse(Conflict, "the slug %s is taken", draft.Slug)
			}
			return fmt.Errorf("inserting the agent: %w", err)
		}
		assignment, err := uuid.NewV7()
		if err != nil {
			return fmt.Errorf("generating the owner assignment's ID: %w", err)
		}
		if err := q.AddOwner(ctx, inventorydb.AddOwnerParams{
			ID: assignment, AgentID: id, PrincipalID: owner, Role: "primary", AssignedBy: owner, AssignedAt: now,
		}); err != nil {
			return fmt.Errorf("assigning the primary owner: %w", err)
		}
		created, err := inv.load(ctx, q, id)
		if err != nil {
			return err
		}
		// T1 creates the agent's governance state, which every later change
		// writes again. P1-08 folds the active selector halts into it here,
		// once selector halts exist.
		version, err := inv.putState(ctx, tx, created, now)
		if err != nil {
			return err
		}
		transition, err := uuid.NewV7()
		if err != nil {
			return fmt.Errorf("generating the transition's ID: %w", err)
		}
		if err := q.RecordTransition(ctx, inventorydb.RecordTransitionParams{
			ID: transition, AgentID: id, Action: "create", ToState: "draft",
			ActorType: "human", ActorID: &owner, StateVersion: version, OccurredAt: now,
		}); err != nil {
			return fmt.Errorf("recording the transition: %w", err)
		}
		if err := inv.writer.Record(ctx, tx, audit.Event{
			Type:    "whitetower.agent.created.v1",
			Subject: id.String(),
			Data: map[string]any{
				"slug":          draft.Slug,
				"kind":          draft.Kind,
				"risk_tier":     draft.RiskTier,
				"use_case_id":   draft.UseCaseID.String(),
				"primary_owner": owner.String(),
				"actor":         actorOf(caller),
				"state_version": version,
			},
		}); err != nil {
			return fmt.Errorf("recording the agent's creation: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return inv.load(ctx, inventorydb.New(inv.db), id)
}

// Get returns an agent. Whoever may see only active agents finds no other.
func (inv *Inventory) Get(ctx context.Context, caller auth.Principal, id uuid.UUID) (*Agent, error) {
	a, err := inv.load(ctx, inventorydb.New(inv.db), id)
	if err != nil {
		return nil, err
	}
	if !seesAll(caller) && a.LifecycleState != "active" {
		return nil, refuse(NotFound, "no agent has this ID")
	}
	return a, nil
}

// List returns a page of at most size agents, by slug, after the slug given,
// and whether more follow. Whoever may see only active agents sees only
// those.
func (inv *Inventory) List(ctx context.Context, caller auth.Principal, after string, size int) ([]Agent, bool, error) {
	if size < 1 || size > maxPage {
		return nil, false, fmt.Errorf("a page of %d agents: want 1 to %d", size, maxPage)
	}
	var from *string
	if after != "" {
		from = &after
	}
	q := inventorydb.New(inv.db)
	rows, err := q.ListAgents(ctx, inventorydb.ListAgentsParams{
		After:      from,
		ActiveOnly: !seesAll(caller),
		PageLimit:  int32(size + 1), //nolint:gosec // G115: size is at most maxPage
	})
	if err != nil {
		return nil, false, fmt.Errorf("listing agents: %w", err)
	}
	more := len(rows) > size
	if more {
		rows = rows[:size]
	}
	agents, err := inv.assemble(ctx, q, rows)
	return agents, more, err
}

// Edit changes an agent's metadata (INV-01), if it is still at the version
// the caller read (API-03). The agent's owners edit it, and operators any
// agent. A change to what policies see of the agent, or to its halt mode,
// takes a new governance state version.
func (inv *Inventory) Edit(ctx context.Context, caller auth.Principal, id uuid.UUID, version int64, ch AgentChanges) (*Agent, error) {
	callerID, err := uuid.Parse(caller.ID)
	if err != nil {
		return nil, fmt.Errorf("the caller's ID %q: %w", caller.ID, err)
	}
	err = inv.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := inventorydb.New(tx)
		before, err := inv.load(ctx, q, id)
		if err != nil {
			return err
		}
		own, err := q.IsOwner(ctx, inventorydb.IsOwnerParams{AgentID: id, PrincipalID: callerID})
		if err != nil {
			return fmt.Errorf("reading the agent's owners: %w", err)
		}
		if err := inv.authorize(ctx, caller, authz.PermissionAgentMetadataEdit, authz.Relationship{IsOwner: own}); err != nil {
			return err
		}
		if before.Version != version {
			return refuse(Stale, "the agent changed since you read it: read it again, then retry")
		}
		if before.LifecycleState == "retired" || before.LifecycleState == "rejected" {
			return refuse(Conflict, "a %s agent no longer changes", before.LifecycleState)
		}
		after := ch.applyTo(before)
		if err := after.validate(); err != nil {
			return err
		}
		if after.UseCaseID != before.UseCaseID {
			if before.LifecycleState != "draft" {
				return refuse(Conflict, "an agent's use case changes only while the agent is a draft")
			}
			if err := checkUseCase(ctx, q, after.UseCaseID); err != nil {
				return err
			}
		}
		if ch.DataCategories != nil {
			if err := checkCategories(ctx, q, after.DataCategories); err != nil {
				return err
			}
		}
		cs := compare(before, after)
		if len(cs.names) == 0 {
			return nil
		}
		now := inv.clk.Now().UTC()
		labelsJSON, harnessJSON, err := encode(after)
		if err != nil {
			return err
		}
		n, err := q.UpdateAgent(ctx, inventorydb.UpdateAgentParams{
			Name:                after.Name,
			Description:         after.Description,
			Vendor:              nonEmpty(after.Vendor),
			Framework:           nonEmpty(after.Framework),
			DeploymentLocation:  &after.DeploymentLocation,
			Environments:        after.Environments,
			RiskTier:            after.RiskTier,
			AiActClassification: after.AIActClassification,
			DataCategories:      after.DataCategories,
			UseCaseID:           after.UseCaseID,
			Harness:             harnessJSON,
			HaltMode:            after.HaltMode,
			DrillEligible:       after.DrillEligible,
			Labels:              labelsJSON,
			UpdatedAt:           now,
			ID:                  id,
			Version:             version,
		})
		if err != nil {
			return fmt.Errorf("updating the agent: %w", err)
		}
		if n == 0 {
			return refuse(Stale, "the agent changed since you read it: read it again, then retry")
		}
		data := map[string]any{"changed": cs.names, "actor": actorOf(caller)}
		if len(cs.before) > 0 {
			data["before"], data["after"] = cs.before, cs.after
		}
		if cs.governs {
			v, err := inv.publishState(ctx, tx, after, now)
			if err != nil {
				return err
			}
			data["state_version"] = v
		}
		if err := inv.writer.Record(ctx, tx, audit.Event{Type: "whitetower.agent.updated.v1", Subject: id.String(), Data: data}); err != nil {
			return fmt.Errorf("recording the agent's change: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return inv.load(ctx, inventorydb.New(inv.db), id)
}

// IsOwner reports whether the principal is the agent's primary owner or one of
// its delegates: the `own` scope of the permission matrix. The domains that
// act on agents check ownership with it (plan P1-16).
func (inv *Inventory) IsOwner(ctx context.Context, agentID, principalID uuid.UUID) (bool, error) {
	own, err := inventorydb.New(inv.db).IsOwner(ctx, inventorydb.IsOwnerParams{AgentID: agentID, PrincipalID: principalID})
	if err != nil {
		return false, fmt.Errorf("reading the agent's owners: %w", err)
	}
	return own, nil
}

// maxPage bounds a page of a list, as the public API does.
const maxPage = 200

// validate checks the metadata of an agent that the inventory is about to
// store: what INV-01 requires, and the bounds of the API.
func (a *Agent) validate() error {
	checks := []error{
		required("name", a.Name, 200),
		required("description", a.Description, 4000),
		optional("vendor", a.Vendor, 200),
		optional("framework", a.Framework, 200),
		required("deploymentLocation", a.DeploymentLocation, 200),
		environments(a.Environments),
		oneOf("riskTier", a.RiskTier, riskTiers),
		oneOf("aiActClassification", a.AIActClassification, classifications),
		dataCategories(a.DataCategories),
		labels(a.Labels),
		oneOf("haltMode", a.HaltMode, haltModes),
	}
	if a.Vendor == "" && a.Framework == "" {
		checks = append(checks, refuse(Invalid, "a vendor or a framework is required (INV-01)"))
	}
	if a.Harness != nil {
		checks = append(checks, required("harness.description", a.Harness.Description, 4000))
	}
	for _, err := range checks {
		if err != nil {
			return err
		}
	}
	return nil
}

// applyTo returns a copy of a with the changes applied.
func (ch AgentChanges) applyTo(a *Agent) *Agent {
	b := *a
	set := func(dst *string, src *string) {
		if src != nil {
			*dst = *src
		}
	}
	set(&b.Name, ch.Name)
	set(&b.Description, ch.Description)
	set(&b.Vendor, ch.Vendor)
	set(&b.Framework, ch.Framework)
	set(&b.DeploymentLocation, ch.DeploymentLocation)
	set(&b.RiskTier, ch.RiskTier)
	set(&b.AIActClassification, ch.AIActClassification)
	set(&b.HaltMode, ch.HaltMode)
	if ch.Environments != nil {
		b.Environments = slices.Clone(*ch.Environments)
	}
	if ch.DataCategories != nil {
		b.DataCategories = slices.Clone(*ch.DataCategories)
	}
	if ch.UseCaseID != nil {
		b.UseCaseID = *ch.UseCaseID
	}
	if ch.Labels != nil {
		b.Labels = maps.Clone(*ch.Labels)
		if b.Labels == nil {
			b.Labels = map[string]string{}
		}
	}
	if ch.Harness != nil {
		h := *ch.Harness
		b.Harness = &h
	}
	if ch.DrillEligible != nil {
		b.DrillEligible = *ch.DrillEligible
	}
	return &b
}

// changeSet is what an edit changed, as its audit event records it.
type changeSet struct {
	names         []string
	before, after map[string]any
	// governs is true when the change reaches the governance state: what
	// policies see of the agent, its lease or its halt mode.
	governs bool
}

// compare compares an agent before and after an edit. The description and
// the harness are free text that people write: the event names them as
// changed, but copies only the other members.
func compare(a, b *Agent) changeSet {
	d := changeSet{before: map[string]any{}, after: map[string]any{}}
	values := func(name string, x, y any, governs bool) {
		d.names = append(d.names, name)
		d.before[name], d.after[name] = x, y
		d.governs = d.governs || governs
	}
	if a.Name != b.Name {
		values("name", a.Name, b.Name, false)
	}
	if a.Description != b.Description {
		d.names = append(d.names, "description")
	}
	if a.Vendor != b.Vendor {
		values("vendor", a.Vendor, b.Vendor, false)
	}
	if a.Framework != b.Framework {
		values("framework", a.Framework, b.Framework, false)
	}
	if a.DeploymentLocation != b.DeploymentLocation {
		values("deployment_location", a.DeploymentLocation, b.DeploymentLocation, false)
	}
	if !slices.Equal(a.Environments, b.Environments) {
		values("environments", a.Environments, b.Environments, false)
	}
	if a.RiskTier != b.RiskTier {
		values("risk_tier", a.RiskTier, b.RiskTier, true)
	}
	if a.AIActClassification != b.AIActClassification {
		values("ai_act_classification", a.AIActClassification, b.AIActClassification, false)
	}
	if !slices.Equal(a.DataCategories, b.DataCategories) {
		values("data_categories", a.DataCategories, b.DataCategories, true)
	}
	if a.UseCaseID != b.UseCaseID {
		values("use_case_id", a.UseCaseID.String(), b.UseCaseID.String(), false)
	}
	if !maps.Equal(a.Labels, b.Labels) {
		values("labels", a.Labels, b.Labels, true)
	}
	if (a.Harness == nil) != (b.Harness == nil) || (a.Harness != nil && *a.Harness != *b.Harness) {
		d.names = append(d.names, "harness")
	}
	if a.HaltMode != b.HaltMode {
		values("halt_mode", a.HaltMode, b.HaltMode, true)
	}
	if a.DrillEligible != b.DrillEligible {
		values("drill_eligible", a.DrillEligible, b.DrillEligible, false)
	}
	return d
}

// checkUseCase refuses a use case that does not exist, or that was rejected:
// a rejected use case justifies no agent.
func checkUseCase(ctx context.Context, q *inventorydb.Queries, id uuid.UUID) error {
	uc, err := q.GetUseCase(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return refuse(Invalid, "no use case has the ID %s", id)
	}
	if err != nil {
		return fmt.Errorf("reading the use case: %w", err)
	}
	if uc.Status == "rejected" {
		return refuse(Conflict, "the use case was rejected: link another one")
	}
	return nil
}

// load reads an agent with its owners and run state.
func (inv *Inventory) load(ctx context.Context, q *inventorydb.Queries, id uuid.UUID) (*Agent, error) {
	row, err := q.GetAgent(ctx, id)
	if err != nil {
		return nil, notFound(err, "agent")
	}
	agents, err := inv.assemble(ctx, q, []inventorydb.WhitetowerAgent{row})
	if err != nil {
		return nil, err
	}
	return &agents[0], nil
}

// assemble completes the rows of agents with their owners, the people who
// created them and their run state.
func (inv *Inventory) assemble(ctx context.Context, q *inventorydb.Queries, rows []inventorydb.WhitetowerAgent) ([]Agent, error) {
	ids := make([]uuid.UUID, len(rows))
	creators := make([]uuid.UUID, len(rows))
	for i, r := range rows {
		ids[i], creators[i] = r.ID, r.CreatedBy
	}
	owners, err := q.CurrentOwners(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("reading the agents' owners: %w", err)
	}
	halted, err := q.HaltedAgents(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("reading the agents' run state: %w", err)
	}
	fleetHalted, err := q.FleetHalted(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading the fleet's run state: %w", err)
	}
	creatorOf, err := people(ctx, q, creators)
	if err != nil {
		return nil, err
	}
	pendingRows, err := q.PendingTransfers(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("reading the agents' pending transfers: %w", err)
	}
	pending, err := assembleTransfers(ctx, q, pendingRows)
	if err != nil {
		return nil, err
	}
	agents := make([]Agent, len(rows))
	for i, r := range rows {
		a := Agent{
			ID: r.ID, Slug: r.Slug, Name: r.Name, Description: r.Description, Kind: r.Kind,
			Source: r.Source, Vendor: deref(r.Vendor), Framework: deref(r.Framework),
			DeploymentLocation: deref(r.DeploymentLocation), Environments: r.Environments,
			RiskTier: r.RiskTier, AIActClassification: r.AiActClassification,
			DataCategories: r.DataCategories, UseCaseID: r.UseCaseID, LifecycleState: r.LifecycleState,
			Halted: fleetHalted || slices.Contains(halted, r.ID),
			// Step 8 computes coverage (pull request 6). Until P1-05, P1-07 and
			// P1-08 record credentials, instances and drills, every agent is
			// at C0.
			Coverage: "C0", HaltMode: r.HaltMode, DrillEligible: r.DrillEligible,
			Delegates: []Person{}, CreatedBy: creatorOf[r.CreatedBy], CreatedAt: r.CreatedAt,
			UpdatedAt: r.UpdatedAt, ActivatedAt: r.ActivatedAt, RetiredAt: r.RetiredAt, Version: r.Version,
		}
		if r.SuspendedFrom != nil && r.SuspensionReason != nil && r.SuspendedAt != nil {
			a.Suspension = &Suspension{From: *r.SuspendedFrom, Reason: *r.SuspensionReason, At: *r.SuspendedAt}
		}
		if err := json.Unmarshal(r.Labels, &a.Labels); err != nil {
			return nil, fmt.Errorf("decoding the labels of agent %s: %w", r.ID, err)
		}
		if r.Harness != nil {
			a.Harness = &Harness{}
			if err := json.Unmarshal(r.Harness, a.Harness); err != nil {
				return nil, fmt.Errorf("decoding the harness of agent %s: %w", r.ID, err)
			}
		}
		for j := range pending {
			if pending[j].AgentID == r.ID {
				a.PendingTransfer = &pending[j]
			}
		}
		for _, o := range owners {
			if o.AgentID != r.ID {
				continue
			}
			p := Person{ID: o.PrincipalID, DisplayName: o.DisplayName, Status: o.Status}
			if o.Role == "primary" {
				a.PrimaryOwner = p
			} else {
				a.Delegates = append(a.Delegates, p)
			}
		}
		agents[i] = a
	}
	return agents, nil
}

// encode returns the agent's labels and harness as the database stores them.
func encode(a *Agent) (labelsJSON, harnessJSON []byte, err error) {
	if labelsJSON, err = json.Marshal(a.Labels); err != nil {
		return nil, nil, fmt.Errorf("encoding the labels: %w", err)
	}
	if a.Harness != nil {
		if harnessJSON, err = json.Marshal(a.Harness); err != nil {
			return nil, nil, fmt.Errorf("encoding the harness: %w", err)
		}
	}
	return labelsJSON, harnessJSON, nil
}

// isUniqueViolation reports whether err is a violation of the named unique
// constraint.
func isUniqueViolation(err error, constraint string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == constraint
}

func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
