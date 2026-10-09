package jobs

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/J466Y/WhiteTower/internal/platform/db"
	"github.com/J466Y/WhiteTower/internal/platform/db/gen"
	"github.com/J466Y/WhiteTower/internal/platform/logging"
)

// checkTimeout bounds a check-in on the lock connection.
const checkTimeout = 5 * time.Second

// postgresLocks takes the locks on a session of the runtime role.
type postgresLocks struct {
	db   *db.DB
	idle time.Duration
}

func (l postgresLocks) open(ctx context.Context) (session, error) {
	conn, err := l.db.Connect(ctx, "jobs", l.idle)
	if err != nil {
		return nil, err
	}
	return postgresSession{conn}, nil
}

type postgresSession struct{ conn *pgx.Conn }

func (s postgresSession) tryLock(ctx context.Context, key int32) (bool, error) {
	var locked bool
	err := s.conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1, $2)", lockClass, key).Scan(&locked)
	return locked, err
}

func (s postgresSession) check(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	return s.conn.Ping(ctx)
}

func (s postgresSession) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.conn.Close(ctx)
}

// postgresHistory records the runs in job_state.
type postgresHistory struct{ q *gen.Queries }

func newPostgresHistory(d *db.DB) postgresHistory { return postgresHistory{gen.New(d)} }

func (h postgresHistory) lastStarted(ctx context.Context, job string) (time.Time, error) {
	at, err := h.q.JobLastStarted(ctx, job)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return time.Time{}, nil
	case err != nil:
		return time.Time{}, err
	case at == nil:
		return time.Time{}, nil
	}
	return *at, nil
}

func (h postgresHistory) started(ctx context.Context, job, replica string, at time.Time) error {
	return h.q.RecordJobStarted(ctx, gen.RecordJobStartedParams{Name: job, StartedAt: &at, Runner: &replica})
}

func (h postgresHistory) finished(ctx context.Context, job string, at time.Time, err error) error {
	status := "success"
	var message *string
	if err != nil {
		status = "failure"
		m := logging.Sanitize(err.Error())
		message = &m
	}
	return h.q.RecordJobFinished(ctx, gen.RecordJobFinishedParams{
		Name: job, FinishedAt: &at, Status: &status, LastError: message,
	})
}
