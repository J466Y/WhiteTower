package govstate

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/J466Y/WhiteTower/internal/govstate/govstatedb"
	"github.com/J466Y/WhiteTower/internal/platform/db"
	"github.com/J466Y/WhiteTower/internal/platform/notify"
)

// channel carries the version of each change of the governance state once it
// has committed. The hub of every replica listens on it (plan P1-07.1, step
// 5).
const channel = "governance"

// announceTimeout bounds how long the caller of a change waits for its
// notification: the hubs read every second anyway.
const announceTimeout = time.Second

// Versions numbers the changes of the governance state from the version
// counter (the design of the halt path, section 2). It implements the
// StateVersions interface that each domain writing the governance state
// declares, and cmd/whitetower/main.go gives every such domain the same
// Versions.
type Versions struct {
	bus    notify.Bus
	logger *slog.Logger
}

// NewVersions returns the versions, which announce each change on bus.
func NewVersions(bus notify.Bus, logger *slog.Logger) *Versions {
	return &Versions{bus: bus, logger: logger}
}

// Next returns the version of the change that tx makes. Its first call in a
// transaction moves the head, whose lock tx then holds until it ends, so that
// transactions commit in the order of their versions; a later call returns
// the same version, so that every record tx changes carries it. A writer
// calls Next once its checks pass and it holds every row lock it needs, and
// waits for no lock afterwards. The first call also has the change announced
// to the replicas once tx commits, in a statement of its own: a notification
// sent in tx would make its commit wait for PostgreSQL's notification lock
// while it holds the head, and fail when the queue of notifications is full
// (the design of the halt path, section 3).
func (v *Versions) Next(ctx context.Context, tx *db.Tx) (int64, error) {
	taken, err := govstatedb.New(tx).NextVersion(ctx)
	if err != nil {
		return 0, fmt.Errorf("taking a governance state version: %w", err)
	}
	if taken.First {
		tx.AfterCommit(func(ctx context.Context) { v.announce(ctx, taken.Version) })
	}
	return taken.Version, nil
}

// announce tells the replicas that a version has committed. A notification
// only asks their hubs to read sooner, so a failure leaves the change as it
// is: the hubs read it within a second.
func (v *Versions) announce(ctx context.Context, version int64) {
	ctx, cancel := context.WithTimeout(ctx, announceTimeout)
	defer cancel()
	if err := v.bus.PublishCommitted(ctx, channel, strconv.FormatInt(version, 10)); err != nil {
		v.logger.WarnContext(ctx, "governance state: announcing a change failed; the replicas read it within a second",
			"state_version", version, "error", err.Error())
	}
}
