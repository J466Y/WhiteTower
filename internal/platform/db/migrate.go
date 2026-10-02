package db

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"

	"github.com/J466Y/WhiteTower/internal/platform/config"
)

// migrationLockID marks White Tower's migrations among the advisory locks of
// the database: "WhiteTwr" in ASCII.
const migrationLockID int64 = 0x5768697465547772

// Migrate applies the pending migrations as the migration role. Concurrent
// runs, such as the init containers of several replicas, take turns on an
// advisory lock: one migrates while the others wait, up to 30 minutes, then
// find nothing left to do. It also lets the runtime role read the version
// table, through which the server checks the schema.
func Migrate(ctx context.Context, cfg config.Migration, logger *slog.Logger) error {
	if cfg.URL == "" {
		return errors.New("database.migration.url: required to migrate")
	}
	cc, err := pgx.ParseConfig(cfg.URL)
	if err != nil {
		return fmt.Errorf("database.migration.url: %w", err)
	}
	if err := setPassword(cc, cfg.PasswordFile, "database.migration.password_file"); err != nil {
		return err
	}
	setApplicationName(cc, "whitetower migrate")

	locker, err := lock.NewPostgresSessionLocker(lock.WithLockID(migrationLockID), lock.WithLockTimeout(2, 900))
	if err != nil {
		return err
	}
	sqlDB := stdlib.OpenDB(*cc)
	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, migrations(),
		goose.WithSessionLocker(locker), goose.WithDisableGlobalRegistry(true), goose.WithSlog(logger))
	if err != nil {
		_ = sqlDB.Close()
		return err
	}
	defer provider.Close() // closes sqlDB too

	logger.InfoContext(ctx, "migrating the database", "target_version", ExpectedVersion())
	results, err := provider.Up(ctx)
	if err != nil {
		return fmt.Errorf("migrating the database: %w", err)
	}
	for _, r := range results {
		logger.InfoContext(ctx, "applied a migration", "version", r.Source.Version, "file", r.Source.Path,
			"took", r.Duration.String())
	}
	if _, err := sqlDB.ExecContext(ctx, "GRANT SELECT ON goose_db_version TO whitetower_runtime"); err != nil {
		return fmt.Errorf("letting the runtime role read the schema version: %w", err)
	}
	version, err := provider.GetDBVersion(ctx)
	if err != nil {
		return err
	}
	logger.InfoContext(ctx, "the database schema is current", "version", version, "applied", len(results))
	return nil
}
