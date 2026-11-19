package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/J466Y/WhiteTower/internal/audit"
	"github.com/J466Y/WhiteTower/internal/authz"
	"github.com/J466Y/WhiteTower/internal/inventory/inventorydb"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/db"
)

// Review is a periodic review of an agent (INV-06; docs/architecture/
// lifecycle.md, section 8). T9 schedules the first one, and each completed
// review the next.
type Review struct {
	ID      uuid.UUID
	AgentID uuid.UUID
	// Status is scheduled until the owner completes the review, then
	// awaiting_signoff while it waits for a sign-off, then completed; or
	// canceled, when the agent is retired.
	Status      string
	DueAt       time.Time
	GraceEndsAt time.Time
	// Overdue is true while the review is open past its due date, by the
	// inventory's clock.
	Overdue bool
	// SignoffRequired was set when the review was scheduled, from the setting
	// lifecycle.review_signoff_risk_tiers.
	SignoffRequired bool
	Attestation     *Attestation
	CompletedBy     *Person
	CompletedAt     *time.Time
	SignedOffBy     *Person
	SignedOffAt     *time.Time
	// UnusedTooling holds, for an open review read on its own, its candidates
	// to disable (CAT-09); it is nil otherwise, and for a caller who may not
	// view agents' tooling.
	UnusedTooling []UnusedTool
	CreatedAt     time.Time
	// Version is the version of the review's row, which its ETag carries.
	Version int64
}

// Attestation is the owner's attestation of a review (INV-06): five
// statements, which must all be true, the keys of the candidates to disable
// that the owner keeps, and a comment.
type Attestation struct {
	StillNeeded           bool `json:"still_needed"`
	OwnerStillRight       bool `json:"owner_still_right"`
	DataCategoriesCurrent bool `json:"data_categories_current"`
	PolicyAdequate        bool `json:"policy_adequate"`
	ToolingStillNeeded    bool `json:"tooling_still_needed"`
	// KeptTooling is nil when it is read by a caller who may not view
	// agents' tooling.
	KeptTooling []string `json:"kept_tooling"`
	Comment     string   `json:"comment,omitempty"`
}

// UnusedTool is a tool or model enabled for an agent that the agent has not
// used recently: a candidate to disable (CAT-09).
type UnusedTool struct {
	// Key is its key in the catalog (RFC-0002, section 3).
	Key string
	// Kind is tool or model.
	Kind string
	// LastUsedAt is nil when the agent never used it.
	LastUsedAt *time.Time
}

// Tooling lists the candidates to disable that a review shows (CAT-09).
// Plan P1-16 implements it from agent_tooling.last_used_at.
type Tooling interface {
	// Unused returns the tools and models enabled for the agent that it has
	// not used within the setting lifecycle.review_unused_tooling_days, which
	// the implementation reads, as tx sees them. A completion asks it under
	// the agent's row lock, so it is a plain read that waits for no lock.
	Unused(ctx context.Context, tx *db.Tx, agentID uuid.UUID) ([]UnusedTool, error)
}

// NoTooling answers that no agent has enabled tooling, until plan P1-16
// brings it: a review then lists no candidate to disable.
type NoTooling struct{}

// Unused implements Tooling.
func (NoTooling) Unused(context.Context, *db.Tx, uuid.UUID) ([]UnusedTool, error) { return nil, nil }

// The bounds of an attestation, as the API's schema gives them.
const (
	maxKeptTooling   = 500
	maxToolingKey    = 255
	maxReviewComment = 2000
)

// reviewStatuses are the statuses of a review; the first two are open.
var reviewStatuses = []string{"scheduled", "awaiting_signoff", "completed", "cancelled"} //nolint:misspell // the schema's spelling

// reviewItems are the kinds of inbox items about a review: its reminders,
// which the lifecycle guard job sends (pull request 5b), and its sign-off.
var reviewItems = []string{"review_due", "review_signoff"}

func isOpen(status string) bool { return status == "scheduled" || status == "awaiting_signoff" }

// seesTooling reports whether the caller may view agents' tooling
// (catalog.view; the permission matrix, "View the catalog and agents'
// tooling"). The Authorizer applies a token's scopes and refuses it to a
// break-glass session. It decides only whether a review shows tooling, and
// never refuses the review.
func (inv *Inventory) seesTooling(ctx context.Context, caller auth.Principal) bool {
	return inv.authorize(ctx, caller, authz.PermissionCatalogView, authz.Relationship{}) == nil
}

// GetReview returns a review of an agent that the caller may see, with its
// candidates to disable while it is open, to a caller who may view them.
func (inv *Inventory) GetReview(ctx context.Context, caller auth.Principal, id uuid.UUID) (*Review, error) {
	var review *Review
	err := inv.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := inventorydb.New(tx)
		r, err := q.GetReview(ctx, id)
		if err != nil {
			return notFound(err, "review")
		}
		agent, err := q.GetAgent(ctx, r.AgentID)
		if err != nil {
			return fmt.Errorf("reading the review's agent: %w", err)
		}
		if !seesAll(caller) && agent.LifecycleState != "active" {
			return refuse(NotFound, "no review has this ID")
		}
		reviews, err := inv.reviewsOf(ctx, q, caller, []inventorydb.WhitetowerReview{r})
		if err != nil {
			return err
		}
		review = &reviews[0]
		if isOpen(r.Status) && inv.seesTooling(ctx, caller) {
			if review.UnusedTooling, err = inv.tooling.Unused(ctx, tx, r.AgentID); err != nil {
				return fmt.Errorf("reading the agent's unused tooling: %w", err)
			}
			if review.UnusedTooling == nil {
				review.UnusedTooling = []UnusedTool{}
			}
		}
		return nil
	})
	return review, err
}

// ReviewPosition is where a page of reviews starts: next to the review with
// this due date and ID.
type ReviewPosition struct {
	DueAt time.Time
	ID    uuid.UUID
}

// AgentReviews returns a page of at most size of the reviews of an agent that
// the caller may see, the latest due first, before the position given, and
// whether more follow.
func (inv *Inventory) AgentReviews(ctx context.Context, caller auth.Principal, agentID uuid.UUID, before *ReviewPosition, size int) ([]Review, bool, error) {
	if size < 1 || size > maxPage {
		return nil, false, fmt.Errorf("a page of %d reviews: want 1 to %d", size, maxPage)
	}
	if _, err := inv.Get(ctx, caller, agentID); err != nil {
		return nil, false, err
	}
	params := inventorydb.ListAgentReviewsParams{AgentID: agentID, PageLimit: int32(size + 1)} //nolint:gosec // G115: size is at most maxPage
	if before != nil {
		params.BeforeDue, params.BeforeID = &before.DueAt, &before.ID
	}
	q := inventorydb.New(inv.db)
	rows, err := q.ListAgentReviews(ctx, params)
	if err != nil {
		return nil, false, fmt.Errorf("listing the agent's reviews: %w", err)
	}
	return inv.reviewPage(ctx, q, caller, rows, size)
}

// ReviewFilter selects reviews: those in any of the statuses given, or in any
// status when none is, and, with Overdue, only the open reviews past their
// due date, or only the others.
type ReviewFilter struct {
	Statuses []string
	Overdue  *bool
}

// ListReviews returns a page of at most size of the reviews that the filter
// selects, of every agent the caller may see, the earliest due first, after
// the position given, and whether more follow.
func (inv *Inventory) ListReviews(ctx context.Context, caller auth.Principal, filter ReviewFilter, after *ReviewPosition, size int) ([]Review, bool, error) {
	if size < 1 || size > maxPage {
		return nil, false, fmt.Errorf("a page of %d reviews: want 1 to %d", size, maxPage)
	}
	if len(filter.Statuses) > len(reviewStatuses) {
		return nil, false, refuse(Invalid, "status takes at most %d values", len(reviewStatuses))
	}
	for _, s := range filter.Statuses {
		if err := oneOf("status", s, reviewStatuses); err != nil {
			return nil, false, err
		}
	}
	// The statuses go as an empty array, never as NULL, which would select
	// nothing.
	params := inventorydb.ListReviewsParams{
		ActiveOnly: !seesAll(caller),
		Statuses:   append([]string{}, filter.Statuses...),
		Overdue:    filter.Overdue,
		Now:        inv.clk.Now().UTC(),
		PageLimit:  int32(size + 1), //nolint:gosec // G115: size is at most maxPage
	}
	if after != nil {
		params.AfterDue, params.AfterID = &after.DueAt, &after.ID
	}
	q := inventorydb.New(inv.db)
	rows, err := q.ListReviews(ctx, params)
	if err != nil {
		return nil, false, fmt.Errorf("listing reviews: %w", err)
	}
	return inv.reviewPage(ctx, q, caller, rows, size)
}

// reviewPage returns the reviews of a page whose rows hold one more than
// size when more follow.
func (inv *Inventory) reviewPage(ctx context.Context, q *inventorydb.Queries, caller auth.Principal, rows []inventorydb.WhitetowerReview, size int) ([]Review, bool, error) {
	more := len(rows) > size
	if more {
		rows = rows[:size]
	}
	reviews, err := inv.reviewsOf(ctx, q, caller, rows)
	return reviews, more, err
}

// CompleteReview records the owner's attestation of a scheduled review
// (INV-06), if it is still at the version the caller read. Every statement
// must be true, and the tooling that the owner keeps must be among the
// review's candidates to disable now. Only a person who is the agent's
// primary owner or one of its delegates completes it, while the agent is in
// service or suspended: completing an overdue review lets the advisory
// committee reinstate an agent that White Tower suspended for it. A review
// that needs a sign-off then waits for one in the advisory committee's inbox;
// any other is completed, and the agent's next review is scheduled.
func (inv *Inventory) CompleteReview(ctx context.Context, caller auth.Principal, id uuid.UUID, version int64, in Attestation) (*Review, error) {
	att, err := in.normalized()
	if err != nil {
		return nil, err
	}
	actor, err := uuid.Parse(caller.ID)
	if err != nil {
		return nil, fmt.Errorf("the caller's ID %q: %w", caller.ID, err)
	}
	err = inv.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := inventorydb.New(tx)
		_, a, err := inv.readReview(ctx, q, caller, id)
		if err != nil {
			return err
		}
		if err := inv.mayComplete(ctx, q, caller, actor, a.ID); err != nil {
			return err
		}
		r, a, err := inv.lockReview(ctx, q, id)
		if err != nil {
			return err
		}
		// The agent's owners may have changed before the lock.
		if err := inv.mayComplete(ctx, q, caller, actor, a.ID); err != nil {
			return err
		}
		if err := reviewable(r, a, version, "scheduled"); err != nil {
			return err
		}
		candidates, err := inv.tooling.Unused(ctx, tx, a.ID)
		if err != nil {
			return fmt.Errorf("reading the agent's unused tooling: %w", err)
		}
		for _, k := range att.KeptTooling {
			if !slices.ContainsFunc(candidates, func(c UnusedTool) bool { return c.Key == k }) {
				return refuse(Invalid, "%q is not a candidate to disable of this review", k)
			}
		}
		stored, err := json.Marshal(att)
		if err != nil {
			return fmt.Errorf("encoding the attestation: %w", err)
		}
		now := inv.clk.Now().UTC()
		status := "completed"
		if r.SignoffRequired {
			status = "awaiting_signoff"
		}
		n, err := q.CompleteReview(ctx, inventorydb.CompleteReviewParams{
			Status: status, Attestation: stored, CompletedBy: &actor, CompletedAt: &now, ID: id, Version: version,
		})
		if err != nil {
			return fmt.Errorf("completing the review: %w", err)
		}
		if n == 0 {
			return refuse(Stale, "the review changed since you read it: read it again, then retry")
		}
		if err := resolveReviewItems(ctx, q, id, now); err != nil {
			return err
		}
		if r.SignoffRequired {
			item, err := uuid.NewV7()
			if err != nil {
				return fmt.Errorf("generating the inbox item's ID: %w", err)
			}
			advisory := string(authz.RoleAdvisory)
			if err := q.AddInboxItem(ctx, inventorydb.AddInboxItemParams{
				ID: item, Role: &advisory, Kind: "review_signoff", SubjectType: "review", SubjectID: id, CreatedAt: now,
			}); err != nil {
				return fmt.Errorf("adding the review to the advisory committee's inbox: %w", err)
			}
		}
		if err := inv.recordReview(ctx, tx, a.ID, map[string]any{
			"change": "completed", "review_id": id.String(), "status": status, "actor": actorOf(caller),
			"attestation": map[string]any{
				"still_needed": true, "owner_still_right": true, "data_categories_current": true,
				"policy_adequate": true, "tooling_still_needed": true, "kept_tooling": att.KeptTooling,
			},
		}); err != nil {
			return err
		}
		if r.SignoffRequired {
			return nil
		}
		return inv.scheduleReview(ctx, tx, a.ID, a.RiskTier, actorOf(caller), now)
	})
	if err != nil {
		return nil, err
	}
	return inv.GetReview(ctx, caller, id)
}

// SignOffReview completes a review that waits for the advisory committee's
// sign-off (the lifecycle, section 8), if it is still at the version the
// caller read, and schedules the agent's next review. The review's
// SignoffRequired, which the setting lifecycle.review_signoff_risk_tiers set
// when it was scheduled, decides whether the committee's grant reaches it,
// not the agent's risk tier now. Only a person signs it off, and nobody who
// is or ever was the agent's primary owner or one of its delegates, who
// created the agent or its use case, or who completed the review (HUM-04);
// the database refuses the same (reject_review_signoff_by_party).
func (inv *Inventory) SignOffReview(ctx context.Context, caller auth.Principal, id uuid.UUID, version int64) (*Review, error) {
	actor, err := uuid.Parse(caller.ID)
	if err != nil {
		return nil, fmt.Errorf("the caller's ID %q: %w", caller.ID, err)
	}
	err = inv.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := inventorydb.New(tx)
		r, a, err := inv.readReview(ctx, q, caller, id)
		if err != nil {
			return err
		}
		if err := inv.maySignOff(ctx, q, caller, actor, r, a); err != nil {
			return err
		}
		if r, a, err = inv.lockReview(ctx, q, id); err != nil {
			return err
		}
		// The agent's owners, and whoever completed the review, may have
		// changed before the lock.
		if err := inv.maySignOff(ctx, q, caller, actor, r, a); err != nil {
			return err
		}
		if err := reviewable(r, a, version, "awaiting_signoff"); err != nil {
			return err
		}
		now := inv.clk.Now().UTC()
		n, err := q.SignOffReview(ctx, inventorydb.SignOffReviewParams{SignedOffBy: &actor, SignedOffAt: &now, ID: id, Version: version})
		if err != nil {
			return fmt.Errorf("signing off the review: %w", err)
		}
		if n == 0 {
			return refuse(Stale, "the review changed since you read it: read it again, then retry")
		}
		if err := resolveReviewItems(ctx, q, id, now); err != nil {
			return err
		}
		if err := inv.recordReview(ctx, tx, a.ID, map[string]any{
			"change": "signed_off", "review_id": id.String(), "actor": actorOf(caller),
		}); err != nil {
			return err
		}
		return inv.scheduleReview(ctx, tx, a.ID, a.RiskTier, actorOf(caller), now)
	})
	if err != nil {
		return nil, err
	}
	return inv.GetReview(ctx, caller, id)
}

// readReview reads a review and its agent without a lock, so that a caller
// whom a completion or a sign-off refuses takes no lock at all. Whoever may
// not see the agent finds no review.
func (inv *Inventory) readReview(ctx context.Context, q *inventorydb.Queries, caller auth.Principal, id uuid.UUID) (inventorydb.WhitetowerReview, *Agent, error) {
	r, err := q.GetReview(ctx, id)
	if err != nil {
		return r, nil, notFound(err, "review")
	}
	a, err := inv.load(ctx, q, r.AgentID)
	if err != nil {
		return r, nil, err
	}
	if !seesAll(caller) && a.LifecycleState != "active" {
		return r, nil, refuse(NotFound, "no review has this ID")
	}
	return r, a, nil
}

// lockReview locks a review's agent, then the review, and reads both again,
// once the caller is known to be allowed. A completion and a sign-off of the
// agent's review therefore happen one after the other, and before or after
// the agent's automatic suspension, which locks the agent's row too. They
// take no governance state version, since enforcement points see nothing of
// a review, and wait for nothing outside the database: an agent halt, which
// locks the agent's row before it takes the version counter, waits at most
// for one such short transaction of an allowed caller, as it does for an
// edit, and never for a refused one.
func (inv *Inventory) lockReview(ctx context.Context, q *inventorydb.Queries, id uuid.UUID) (inventorydb.WhitetowerReview, *Agent, error) {
	r, err := q.GetReview(ctx, id)
	if err != nil {
		return r, nil, fmt.Errorf("reading the review: %w", err)
	}
	if _, err := q.LockAgent(ctx, r.AgentID); err != nil {
		return r, nil, fmt.Errorf("locking the review's agent: %w", err)
	}
	if r, err = q.LockReview(ctx, id); err != nil {
		return r, nil, fmt.Errorf("locking the review: %w", err)
	}
	a, err := inv.load(ctx, q, r.AgentID)
	return r, a, err
}

// mayComplete refuses a completion to anyone but a person who is the agent's
// primary owner or one of its delegates, with agent.review within their
// token's scopes.
func (inv *Inventory) mayComplete(ctx context.Context, q *inventorydb.Queries, caller auth.Principal, actor, agentID uuid.UUID) error {
	if caller.Kind != auth.Human {
		return refuse(Forbidden, "only a person attests for an agent and completes its review")
	}
	own, err := q.IsOwner(ctx, inventorydb.IsOwnerParams{AgentID: agentID, PrincipalID: actor})
	if err != nil {
		return fmt.Errorf("reading the agent's owners: %w", err)
	}
	if err := inv.authorize(ctx, caller, authz.PermissionAgentReview, authz.Relationship{IsOwner: own}); err != nil {
		return err
	}
	if !own {
		return refuse(Forbidden, "only the agent's primary owner and its delegates complete its review")
	}
	return nil
}

// maySignOff refuses a sign-off to anyone but a person whose grant reaches
// the review, and to whoever separation of duties refuses (HUM-04).
func (inv *Inventory) maySignOff(ctx context.Context, q *inventorydb.Queries, caller auth.Principal, actor uuid.UUID, r inventorydb.WhitetowerReview, a *Agent) error {
	if caller.Kind != auth.Human {
		return refuse(Forbidden, "only a person signs off a review (HUM-04)")
	}
	// The scope sign_off of the advisory committee's grant covers the
	// reviews that need a sign-off: the setting holds high and critical
	// always, and the tiers that administrators add. The owner role's grant
	// of scope own never applies, since IsOwner stays false.
	if err := inv.authorize(ctx, caller, authz.PermissionAgentReview, authz.Relationship{IsHighOrCriticalRisk: r.SignoffRequired}); err != nil {
		return err
	}
	ever, err := q.EverAssigned(ctx, inventorydb.EverAssignedParams{AgentID: a.ID, PrincipalID: actor})
	if err != nil {
		return fmt.Errorf("reading the agent's owners: %w", err)
	}
	uc, err := q.GetUseCase(ctx, a.UseCaseID)
	if err != nil {
		return fmt.Errorf("reading the agent's use case: %w", err)
	}
	if ever || a.CreatedBy.ID == actor || uc.CreatedBy == actor || (r.CompletedBy != nil && *r.CompletedBy == actor) {
		return refuse(Forbidden, "separation of duties: nobody signs off the review of an agent they own, delegate for, ever did, or created, nor of one whose use case they created, nor a review they completed (HUM-04)")
	}
	return nil
}

// reviewable refuses a change of a review that is no longer at the version
// the caller read, of an agent that has no open review, or of a review that
// is not in the status that the change starts from. Only an agent in service,
// or suspended, has an open review: T9 schedules it, and T14 cancels it.
func reviewable(r inventorydb.WhitetowerReview, a *Agent, version int64, status string) error {
	switch {
	case r.Version != version:
		return refuse(Stale, "the review changed since you read it: read it again, then retry")
	case a.LifecycleState != "active" && a.LifecycleState != "suspended":
		return refuse(Conflict, "a %s agent has no open review", a.LifecycleState)
	case r.Status != status:
		return refuse(Conflict, "the review is %s: it must be %s", r.Status, status)
	}
	return nil
}

// normalized checks an attestation as the API's schema bounds it, and
// returns it with a blank comment left out and the kept tooling never nil.
// Every statement must be true: an agent no longer needed is retired instead,
// an agent whose owner is no longer right gets another one, and its data
// categories, its policy and its tooling are brought up to date first.
func (in Attestation) normalized() (Attestation, error) {
	for _, s := range []struct {
		name  string
		holds bool
	}{
		{"stillNeeded", in.StillNeeded},
		{"ownerStillRight", in.OwnerStillRight},
		{"dataCategoriesCurrent", in.DataCategoriesCurrent},
		{"policyAdequate", in.PolicyAdequate},
		{"toolingStillNeeded", in.ToolingStillNeeded},
	} {
		if !s.holds {
			return in, refuse(Invalid, "every statement of the attestation must be true, and %s is not: bring the agent up to date, or retire it, first", s.name)
		}
	}
	if len(in.KeptTooling) > maxKeptTooling {
		return in, refuse(Invalid, "keptTooling has more than %d entries", maxKeptTooling)
	}
	for i, k := range in.KeptTooling {
		if n := utf8.RuneCountInString(k); n == 0 || n > maxToolingKey {
			return in, refuse(Invalid, "a key of keptTooling must have 1 to %d characters", maxToolingKey)
		}
		if slices.Contains(in.KeptTooling[:i], k) {
			return in, refuse(Invalid, "keptTooling lists %q twice", k)
		}
	}
	if err := optional("comment", in.Comment, maxReviewComment); err != nil {
		return in, err
	}
	out := in
	out.KeptTooling = append([]string{}, in.KeptTooling...)
	if strings.TrimSpace(in.Comment) == "" {
		out.Comment = ""
	}
	return out, nil
}

// scheduleReview schedules the agent's next review from the time given,
// unless the agent has an open review: at activation (T9), and once a review
// is completed (the lifecycle, section 8). The review stores its due date,
// the end of its grace period and whether it needs a sign-off, from the
// settings as they are now, so that a later change of them applies to the
// reviews scheduled after it. A review takes no governance state version, so
// T9 calls it before it takes its own: the settings and the review's row are
// never read or written under the version counter (the design of the halt
// path, section 2).
func (inv *Inventory) scheduleReview(ctx context.Context, tx *db.Tx, agentID uuid.UUID, riskTier string, actor map[string]any, now time.Time) error {
	q := inventorydb.New(tx)
	terms, err := reviewTermsOf(ctx, q, riskTier, now)
	if err != nil {
		return err
	}
	scheduled, err := q.HasOpenReview(ctx, agentID)
	if err != nil {
		return fmt.Errorf("reading the agent's open review: %w", err)
	}
	if scheduled {
		return nil
	}
	id, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("generating the review's ID: %w", err)
	}
	if err := q.ScheduleReview(ctx, inventorydb.ScheduleReviewParams{
		ID: id, AgentID: agentID, DueAt: terms.dueAt, GraceEndsAt: terms.graceEndsAt, SignoffRequired: terms.signoff, CreatedAt: now,
	}); err != nil {
		return fmt.Errorf("scheduling the agent's review: %w", err)
	}
	return inv.recordReview(ctx, tx, agentID, map[string]any{
		"change": "scheduled", "review_id": id.String(), "actor": actor,
		"due_at": timestamp(terms.dueAt), "grace_ends_at": timestamp(terms.graceEndsAt), "signoff_required": terms.signoff,
	})
}

// cancelReviews cancels the agent's open review, which a retired agent no
// longer needs (T14), and takes it out of every inbox.
func (inv *Inventory) cancelReviews(ctx context.Context, tx *db.Tx, agentID uuid.UUID, actor map[string]any, now time.Time) error {
	q := inventorydb.New(tx)
	ids, err := q.CancelOpenReviews(ctx, agentID)
	if err != nil {
		return fmt.Errorf("canceling the agent's open review: %w", err)
	}
	for _, id := range ids {
		if err := resolveReviewItems(ctx, q, id, now); err != nil {
			return err
		}
		if err := inv.recordReview(ctx, tx, agentID, map[string]any{
			"change": "cancelled", "review_id": id.String(), "actor": actor, //nolint:misspell // the schema's spelling
		}); err != nil {
			return err
		}
	}
	return nil
}

// resolveReviewItems takes every item about the review out of every inbox.
func resolveReviewItems(ctx context.Context, q *inventorydb.Queries, reviewID uuid.UUID, now time.Time) error {
	for _, kind := range reviewItems {
		if err := q.ResolveInboxItems(ctx, inventorydb.ResolveInboxItemsParams{
			ResolvedAt: &now, Kind: kind, SubjectType: "review", SubjectID: reviewID,
		}); err != nil {
			return fmt.Errorf("taking the review out of the inbox: %w", err)
		}
	}
	return nil
}

// recordReview records a change of one of the agent's reviews.
func (inv *Inventory) recordReview(ctx context.Context, tx *db.Tx, agentID uuid.UUID, data map[string]any) error {
	if err := inv.writer.Record(ctx, tx, audit.Event{
		Type: "whitetower.review.changed.v1", Subject: agentID.String(), Data: data,
	}); err != nil {
		return fmt.Errorf("recording the change of the agent's review: %w", err)
	}
	return nil
}

// reviewTerms are what a review stores when it is scheduled.
type reviewTerms struct {
	dueAt, graceEndsAt time.Time
	signoff            bool
}

// reviewTermsOf returns the terms of a review, scheduled at the time given,
// of an agent of the risk tier given, from the settings
// lifecycle.review_interval_days, lifecycle.review_grace_days and
// lifecycle.review_signoff_risk_tiers, read at use. A setting outside the
// rules that P1-17 registers for it (the plan's progress notes of 2026-10-21)
// fails the transaction: no default stands in for it, so that a broken
// setting never makes reviews rarer or drops a sign-off.
func reviewTermsOf(ctx context.Context, q *inventorydb.Queries, riskTier string, now time.Time) (reviewTerms, error) {
	var intervals map[string]int
	if err := setting(ctx, q, "lifecycle.review_interval_days", &intervals); err != nil {
		return reviewTerms{}, err
	}
	if len(intervals) != len(riskTiers) {
		return reviewTerms{}, fmt.Errorf("the setting lifecycle.review_interval_days must hold the four risk tiers and no other")
	}
	for _, tier := range riskTiers {
		if days, ok := intervals[tier]; !ok || days < 1 || days > 730 {
			return reviewTerms{}, fmt.Errorf("the setting lifecycle.review_interval_days must give the risk tier %s 1 to 730 days", tier)
		}
	}
	var grace *int
	if err := setting(ctx, q, "lifecycle.review_grace_days", &grace); err != nil {
		return reviewTerms{}, err
	}
	if grace == nil || *grace < 0 || *grace > 90 {
		return reviewTerms{}, fmt.Errorf("the setting lifecycle.review_grace_days must be 0 to 90 days")
	}
	var tiers []string
	if err := setting(ctx, q, "lifecycle.review_signoff_risk_tiers", &tiers); err != nil {
		return reviewTerms{}, err
	}
	for i, tier := range tiers {
		if !slices.Contains(riskTiers, tier) || slices.Contains(tiers[:i], tier) {
			return reviewTerms{}, fmt.Errorf("the setting lifecycle.review_signoff_risk_tiers must hold distinct risk tiers")
		}
	}
	if !slices.Contains(tiers, "high") || !slices.Contains(tiers, "critical") {
		return reviewTerms{}, fmt.Errorf("the setting lifecycle.review_signoff_risk_tiers must hold high and critical")
	}
	due := now.AddDate(0, 0, intervals[riskTier])
	return reviewTerms{dueAt: due, graceEndsAt: due.AddDate(0, 0, *grace), signoff: slices.Contains(tiers, riskTier)}, nil
}

// reviewsOf completes the rows of reviews with the people who completed and
// signed them off, as the caller may see them: the tooling that an owner
// kept only to a caller who may view agents' tooling.
func (inv *Inventory) reviewsOf(ctx context.Context, q *inventorydb.Queries, caller auth.Principal, rows []inventorydb.WhitetowerReview) ([]Review, error) {
	var ids []uuid.UUID
	for _, r := range rows {
		for _, p := range []*uuid.UUID{r.CompletedBy, r.SignedOffBy} {
			if p != nil {
				ids = append(ids, *p)
			}
		}
	}
	who, err := people(ctx, q, ids)
	if err != nil {
		return nil, err
	}
	person := func(id *uuid.UUID) *Person {
		if id == nil {
			return nil
		}
		p := who[*id]
		return &p
	}
	tooling := inv.seesTooling(ctx, caller)
	now := inv.clk.Now().UTC()
	reviews := make([]Review, len(rows))
	for i, r := range rows {
		reviews[i] = Review{
			ID: r.ID, AgentID: r.AgentID, Status: r.Status, DueAt: r.DueAt, GraceEndsAt: r.GraceEndsAt,
			Overdue: isOpen(r.Status) && r.DueAt.Before(now), SignoffRequired: r.SignoffRequired,
			CompletedBy: person(r.CompletedBy), CompletedAt: r.CompletedAt,
			SignedOffBy: person(r.SignedOffBy), SignedOffAt: r.SignedOffAt,
			CreatedAt: r.CreatedAt, Version: r.Version,
		}
		if r.Attestation != nil {
			att := &Attestation{}
			if err := json.Unmarshal(r.Attestation, att); err != nil {
				return nil, fmt.Errorf("decoding the attestation of review %s: %w", r.ID, err)
			}
			switch {
			case !tooling:
				att.KeptTooling = nil
			case att.KeptTooling == nil:
				att.KeptTooling = []string{}
			}
			reviews[i].Attestation = att
		}
	}
	return reviews, nil
}

// timestamp formats a time as the event schemas do.
func timestamp(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }
