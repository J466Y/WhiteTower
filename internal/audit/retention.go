package audit

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/J466Y/WhiteTower/internal/audit/auditdb"
	"github.com/J466Y/WhiteTower/internal/platform/clock"
	"github.com/J466Y/WhiteTower/internal/platform/db"
	"github.com/J466Y/WhiteTower/internal/platform/jobs"
	"github.com/J466Y/WhiteTower/internal/platform/metrics"
)

// RetentionOptions configures the audit retention job.
type RetentionOptions struct {
	DB      *db.DB
	Writer  *Writer
	Days    int
	Clock   clock.Clock
	Logger  *slog.Logger
	Metrics *metrics.Audit
}

// RetentionJob returns the background job that drops expired monthly audit
// partitions (plan P1-02, step 9).
func RetentionJob(opts RetentionOptions) jobs.Job {
	return jobs.Job{
		Name:     "audit-retention",
		Schedule: jobs.Every(24 * time.Hour),
		Run: func(ctx context.Context) error {
			_, err := DropExpiredPartitions(ctx, opts)
			return err
		},
	}
}

// DropExpiredPartitions drops audit partitions older than opts.Days.
// It records an audited event for each dropped partition, records its
// leaf range in audit_pruned_ranges, and drops the partition tables.
func DropExpiredPartitions(ctx context.Context, opts RetentionOptions) (int, error) {
	if opts.Days <= 0 {
		return 0, nil
	}

	var partitions []string
	err := opts.DB.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var err error
		partitions, err = auditdb.New(tx).ListAuditPartitions(ctx)
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("audit.retention: list partitions: %w", err)
	}

	now := opts.Clock.Now().UTC()
	cutoff := now.AddDate(0, 0, -opts.Days)
	dropped := 0

	for _, p := range partitions {
		if !strings.HasPrefix(p, "audit_events_") {
			continue
		}
		suffix := strings.TrimPrefix(p, "audit_events_")
		monthStart, err := time.Parse("2006_01", suffix)
		if err != nil {
			opts.Logger.WarnContext(ctx, "audit.retention: invalid partition suffix", "partition", p, "err", err)
			continue
		}
		monthEnd := monthStart.AddDate(0, 1, 0)
		if monthEnd.After(cutoff) {
			continue
		}

		var leafCount int64
		err = opts.DB.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
			q := auditdb.New(tx)
			bounds, err := q.PartitionLeafBounds(ctx, auditdb.PartitionLeafBoundsParams{
				IngestedAt:   monthStart,
				IngestedAt_2: monthEnd,
			})
			if err != nil {
				return fmt.Errorf("query leaf bounds: %w", err)
			}
			leafCount = bounds.LeafCount

			data := map[string]any{
				"partition":      p,
				"from_time":      monthStart.Format(time.RFC3339Nano),
				"to_time":        monthEnd.Format(time.RFC3339Nano),
				"retention_days": opts.Days,
				"reason":         "retention policy threshold elapsed",
			}
			if bounds.LeafCount > 0 {
				data["from_leaf_index"] = bounds.MinLeafIndex
				data["to_leaf_index"] = bounds.MaxLeafIndex + 1
				data["events_count"] = bounds.LeafCount
			}
			if err := opts.Writer.Record(ctx, tx, Event{
				Type: "whitetower.audit.partition_dropped.v1",
				Data: data,
			}); err != nil {
				return fmt.Errorf("record partition_dropped event: %w", err)
			}

			if bounds.LeafCount > 0 {
				err = q.RecordPrunedRange(ctx, auditdb.RecordPrunedRangeParams{
					FromLeafIndex: bounds.MinLeafIndex,
					ToLeafIndex:   bounds.MaxLeafIndex + 1,
					PartitionName: p,
				})
				if err != nil {
					return fmt.Errorf("record pruned range: %w", err)
				}
			}

			if err := q.DropAuditPartition(ctx, suffix); err != nil {
				return fmt.Errorf("drop partition: %w", err)
			}

			return nil
		})
		if err != nil {
			return dropped, fmt.Errorf("audit.retention: %s: %w", p, err)
		}

		dropped++
		if opts.Metrics != nil {
			opts.Metrics.PartitionDropped(leafCount)
		}
		opts.Logger.InfoContext(ctx, "audit partition dropped by retention", "partition", p, "leaves", leafCount)
	}

	return dropped, nil
}
