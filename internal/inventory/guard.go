package inventory

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/J466Y/WhiteTower/internal/audit"
	"github.com/J466Y/WhiteTower/internal/authz"
	"github.com/J466Y/WhiteTower/internal/inventory/inventorydb"
	"github.com/J466Y/WhiteTower/internal/platform/db"
	"github.com/J466Y/WhiteTower/internal/platform/jobs"
	"github.com/J466Y/WhiteTower/internal/platform/logging"
)

// guardInterval is how often the lifecycle guard runs: an agent whose owner
// leaves, or whose review lapses past its grace period, is suspended within a
// minute (INV-05).
const guardInterval = time.Minute

// GuardJob returns the lifecycle guard (plan P1-04, step 7), a background job
// that one replica runs at a time. Each run suspends, as White Tower (T11),
// every agent whose primary owner is no longer an active principal and every
// agent whose open review is past its grace period (INV-05), then sends the
// reminders of the reviews that wait for their owner (INV-06).
//
// It suspends one agent per transaction, and reminds one review per
// transaction, so that an agent halt waits at most for one short transaction
// of one agent: it finds them with a read that takes no lock, and each
// transaction checks again, under its lock, that its reason still holds. A
// run that stops halfway leaves every agent and every review as it was or as
// the guard left it, and the next run goes on from there. One that fails is
// logged, and the others go on; the run then fails, so that the record of
// the job says so.
func (inv *Inventory) GuardJob(logger *slog.Logger) jobs.Job {
	return jobs.Job{
		Name:     "lifecycle-guard",
		Schedule: jobs.Every(guardInterval),
		Run:      func(ctx context.Context) error { return inv.runGuard(ctx, logger) },
	}
}

// runGuard runs the lifecycle guard once. The suspensions come first, and read
// no setting: a broken setting of the reminders never keeps an agent in
// service. The reminders go out even when a suspension failed.
func (inv *Inventory) runGuard(ctx context.Context, logger *slog.Logger) error {
	failedSuspensions, err := inv.suspendLapsed(ctx, logger)
	if ctx.Err() != nil {
		return err
	}
	failedReminders, remindErr := inv.remind(ctx, logger)
	err = errors.Join(err, remindErr)
	if failedSuspensions > 0 || failedReminders > 0 {
		err = errors.Join(err, fmt.Errorf("the lifecycle guard ran with failures, which the log names: suspensions %d, reminders %d",
			failedSuspensions, failedReminders))
	}
	return err
}

// suspendLapsed suspends each agent whose primary owner is no longer active,
// or whose open review is past its grace period, and returns how many of
// them it failed to suspend.
func (inv *Inventory) suspendLapsed(ctx context.Context, logger *slog.Logger) (int, error) {
	t := lifecycle[slices.IndexFunc(lifecycle, func(t transition) bool { return t.action == "auto_suspend" })]
	lapsed, err := inventorydb.New(inv.db).AgentsToSuspend(ctx, inventorydb.AgentsToSuspendParams{
		Now: inv.clk.Now().UTC(), States: t.from,
	})
	if err != nil {
		return 0, fmt.Errorf("finding the agents to suspend: %w", err)
	}
	failed := 0
	for _, a := range lapsed {
		if err := ctx.Err(); err != nil {
			return failed, err
		}
		var reasons []string
		if a.OwnerInactive {
			reasons = append(reasons, "owner_inactive")
		}
		if a.ReviewOverdue {
			reasons = append(reasons, "review_overdue")
		}
		switch reason, err := inv.autoSuspend(ctx, a.ID, reasons); {
		case err != nil:
			failed++
			logger.ErrorContext(ctx, "lifecycle guard: suspending an agent failed",
				"agent_id", a.ID.String(), "error", logging.Sanitize(err.Error()))
		case reason != "":
			logger.InfoContext(ctx, "lifecycle guard: suspended an agent", "agent_id", a.ID.String(), "reason", reason)
		}
	}
	return failed, nil
}

// autoSuspend suspends the agent as White Tower (T11), in a transaction of
// its own, for the first of the reasons given that still holds under the
// agent's lock, and returns it. It returns no reason when none holds any
// longer, or when the agent has left the states that T11 starts from: the
// suspension records only a reason that holds, and the guard never moves an
// agent out of a suspension.
func (inv *Inventory) autoSuspend(ctx context.Context, agentID uuid.UUID, reasons []string) (string, error) {
	var suspended string
	err := inv.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		suspended = ""
		for _, reason := range reasons {
			moved, err := inv.SystemTransition(ctx, tx, agentID, Cause{Action: "auto_suspend", Reason: reason})
			if err != nil {
				return err
			}
			if moved {
				suspended = reason
				return nil
			}
		}
		return nil
	})
	return suspended, err
}

// remind sends the reminders that are due, and returns how many reviews it
// failed to remind (the lifecycle, section 8). A scheduled review reminds
// whoever is the agent's primary owner at each number of days before its due
// date that the setting lifecycle.review_reminder_days gives, and each
// reminder takes the one before it out of the inbox; once past its due date,
// it reminds the advisory committee, once, and the owner's last reminder
// stays. A review that waits for its sign-off is in the advisory committee's
// inbox already, and the owner has nothing left to do. When several
// reminders fell due since the last run, only the latest is sent.
func (inv *Inventory) remind(ctx context.Context, logger *slog.Logger) (int, error) {
	q := inventorydb.New(inv.db)
	days, err := reminderDaysOf(ctx, q)
	if err != nil {
		return 0, err
	}
	now := inv.clk.Now().UTC()
	due, err := q.ReviewsToRemind(ctx, inventorydb.ReviewsToRemindParams{Days: days, Now: now})
	if err != nil {
		return 0, fmt.Errorf("finding the reviews to remind: %w", err)
	}
	failed := 0
	for _, r := range due {
		if err := ctx.Err(); err != nil {
			return failed, err
		}
		if err := inv.remindReview(ctx, r, now); err != nil {
			failed++
			logger.ErrorContext(ctx, "lifecycle guard: reminding a review failed",
				"review_id", r.ID.String(), "agent_id", r.AgentID.String(), "error", logging.Sanitize(err.Error()))
		}
	}
	return failed, nil
}

// remindReview sends one reminder of a review, at the time given, in a
// transaction of its own. Recording the reminder locks the review's row and
// checks again that the reminder is due; it locks neither the agent's row
// nor its governance state, and takes no governance state version, since
// enforcement points see nothing of a review, so that no halt ever waits for
// a reminder. It records whitetower.review.reminded.v1, as the system: a
// reminder changes nothing that the review shows.
func (inv *Inventory) remindReview(ctx context.Context, r inventorydb.ReviewsToRemindRow, now time.Time) error {
	return inv.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := inventorydb.New(tx)
		point := r.DueAt.Add(-time.Duration(r.DaysBeforeDue) * 24 * time.Hour)
		n, err := q.RecordReminder(ctx, inventorydb.RecordReminderParams{RemindedAt: now, ID: r.ID, Point: point})
		if err != nil {
			return fmt.Errorf("recording the reminder: %w", err)
		}
		if n == 0 {
			return nil // reminded since, or no longer scheduled
		}
		id, err := uuid.NewV7()
		if err != nil {
			return fmt.Errorf("generating the inbox item's ID: %w", err)
		}
		item := inventorydb.AddInboxItemParams{ID: id, Kind: "review_due", SubjectType: "review", SubjectID: r.ID, CreatedAt: now}
		var reminder map[string]any
		if r.DaysBeforeDue > 0 {
			if err := q.ResolveInboxItems(ctx, inventorydb.ResolveInboxItemsParams{
				ResolvedAt: &now, Kind: "review_due", SubjectType: "review", SubjectID: r.ID,
			}); err != nil {
				return fmt.Errorf("taking the last reminder out of the inbox: %w", err)
			}
			owner, err := q.PrimaryAssignment(ctx, r.AgentID)
			if err != nil {
				return fmt.Errorf("reading the agent's primary owner: %w", err)
			}
			item.PrincipalID = &owner.PrincipalID
			reminder = map[string]any{"days_before_due": r.DaysBeforeDue, "principal_id": owner.PrincipalID.String()}
		} else {
			advisory := string(authz.RoleAdvisory)
			item.Role = &advisory
			reminder = map[string]any{"role": advisory}
		}
		if err := q.AddInboxItem(ctx, item); err != nil {
			return fmt.Errorf("adding the reminder to the inbox: %w", err)
		}
		if err := inv.writer.Record(ctx, tx, audit.Event{
			Type: "whitetower.review.reminded.v1", Subject: r.AgentID.String(),
			Data: map[string]any{"review_id": r.ID.String(), "reminder": reminder, "actor": map[string]any{"type": "system"}},
		}); err != nil {
			return fmt.Errorf("recording the reminder of the agent's review: %w", err)
		}
		return nil
	})
}

// reminderDaysOf returns the numbers of days before a review's due date at
// which its owner is reminded, from the setting lifecycle.review_reminder_days,
// read at use. A setting outside the rules that P1-17 registers for it (the
// plan's progress notes of 2026-10-21), 1 to 10 distinct numbers of 1 to 365
// days, fails the reminders: no default stands in for it.
func reminderDaysOf(ctx context.Context, q *inventorydb.Queries) ([]int32, error) {
	var days []int32
	if err := setting(ctx, q, "lifecycle.review_reminder_days", &days); err != nil {
		return nil, err
	}
	if len(days) < 1 || len(days) > 10 {
		return nil, errors.New("the setting lifecycle.review_reminder_days must hold 1 to 10 numbers of days")
	}
	for i, d := range days {
		if d < 1 || d > 365 || slices.Contains(days[:i], d) {
			return nil, errors.New("the setting lifecycle.review_reminder_days must hold distinct numbers of 1 to 365 days")
		}
	}
	return days, nil
}
