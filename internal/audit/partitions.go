package audit

import (
	"context"
	"time"

	"github.com/J466Y/WhiteTower/internal/audit/auditdb"
	"github.com/J466Y/WhiteTower/internal/platform/db"
	"github.com/J466Y/WhiteTower/internal/platform/jobs"
)

// MonthsAhead is how many months ahead the audit tables have partitions, so
// that an event never lacks one (plan P1-02, step 2).
const MonthsAhead = 3

// PartitionsJob creates the audit tables' partitions of this month and of
// the next MonthsAhead, every hour: a month added once a day would do, and
// an hour is how long a new partition may wait after a failover.
func PartitionsJob(d *db.DB) jobs.Job {
	return jobs.Job{
		Name:     "audit-partitions",
		Schedule: jobs.Every(time.Hour),
		Run: func(ctx context.Context) error {
			return d.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
				return auditdb.New(tx).EnsurePartitions(ctx, MonthsAhead)
			})
		},
	}
}
