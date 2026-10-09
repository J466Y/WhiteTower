// Package db is the core's access to PostgreSQL (ADR-0003): a pool of the
// runtime role's connections, transactions with commit hooks, the check of
// the schema version, and the migrations, which only whitetower migrate
// applies, as the migration role (threat model, DC-3).
package db

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/J466Y/WhiteTower/internal/platform/config"
)

// DB is a pool of the runtime role's connections. Its Exec, Query and
// QueryRow run outside any transaction; with them, DB serves the code that
// sqlc generates, as Tx does.
type DB struct {
	pool *pgxpool.Pool
}

// Open prepares a pool of the runtime role's connections. It connects only
// when a connection is needed: a database that is down fails the readiness
// check, not the startup.
func Open(cfg config.Database) (*DB, error) {
	if cfg.URL == "" {
		return nil, errors.New("database.url: required to serve")
	}
	pc, err := pgxpool.ParseConfig(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("database.url: %w", err)
	}
	if err := setPassword(pc.ConnConfig, cfg.PasswordFile, "database.password_file"); err != nil {
		return nil, err
	}
	setApplicationName(pc.ConnConfig, "whitetower")
	pc.MaxConns = int32(min(cfg.MaxConnections, 1000)) //nolint:gosec // G115: at most 1000, as the configuration checks
	pool, err := pgxpool.NewWithConfig(context.Background(), pc)
	if err != nil {
		return nil, err
	}
	return &DB{pool: pool}, nil
}

// Close closes every connection of the pool.
func (db *DB) Close() { db.pool.Close() }

// Connect opens a session of the runtime role outside the pool, for work
// that holds a session: the notification listener and the locks of the
// background jobs. pg_stat_activity names it after the pool's connections and
// its purpose. The database ends the session once it has run no statement for
// idle, so that a replica cut off from the database neither holds locks nor
// holds back notifications for longer: the caller checks in more often.
// Closing the connection ends the session, and with it its locks and listens.
func (db *DB) Connect(ctx context.Context, purpose string, idle time.Duration) (*pgx.Conn, error) {
	cc := db.pool.Config().ConnConfig
	cc.RuntimeParams["application_name"] += " " + purpose
	conn, err := pgx.ConnectConfig(ctx, cc)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Exec(ctx, "SELECT set_config('idle_session_timeout', $1, false)",
		strconv.FormatInt(idle.Milliseconds(), 10)); err != nil {
		_ = conn.Close(ctx)
		return nil, err
	}
	return conn, nil
}

// Ping checks that the database answers. It is the readiness check
// "database".
func (db *DB) Ping(ctx context.Context) error { return db.pool.Ping(ctx) }

// Exec runs a statement outside any transaction.
func (db *DB) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return db.pool.Exec(ctx, sql, args...)
}

// Query runs a query outside any transaction.
func (db *DB) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return db.pool.Query(ctx, sql, args...)
}

// QueryRow runs a query that returns at most one row, outside any
// transaction.
func (db *DB) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return db.pool.QueryRow(ctx, sql, args...)
}

// setPassword takes the password from the configured file and nowhere else:
// pgx would also read PGPASSWORD, .pgpass and service files, and secrets come
// only from the files the configuration names (requirement OPS-04).
func setPassword(cc *pgx.ConnConfig, file, key string) error {
	cc.Password = ""
	if file == "" {
		return nil
	}
	b, err := os.ReadFile(file) //nolint:gosec // G304: the operator chooses the file
	if err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	cc.Password = strings.TrimRight(string(b), "\r\n")
	return nil
}

// setApplicationName names the connections in pg_stat_activity, unless the
// URL already does.
func setApplicationName(cc *pgx.ConnConfig, name string) {
	if _, ok := cc.RuntimeParams["application_name"]; !ok {
		cc.RuntimeParams["application_name"] = name
	}
}
