package authn

import (
	"context"
	"time"

	"github.com/J466Y/WhiteTower/internal/platform/jobs"
)

// CleanupSessionsJob returns a background job that periodically purges expired
// and revoked sessions from PostgreSQL (plan P1-03, step 2).
func CleanupSessionsJob(store *SessionStore) jobs.Job {
	return jobs.Job{
		Name:     "auth-sessions-cleanup",
		Schedule: jobs.Every(time.Hour),
		Run: func(ctx context.Context) error {
			_, err := store.DeleteExpired(ctx)
			return err
		},
	}
}
