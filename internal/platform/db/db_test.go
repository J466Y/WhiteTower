package db_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/J466Y/WhiteTower/internal/platform/config"
	"github.com/J466Y/WhiteTower/internal/platform/db"
	"github.com/J466Y/WhiteTower/internal/platform/db/dbtest"
)

var discard = slog.New(slog.DiscardHandler)

func migrations(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

// Two replicas migrate an empty database at once, as their init containers
// would: one applies every migration while the other waits, then finds
// nothing left to do (plan P1-01, step 4).
func TestConcurrentMigrationsApplyOnce(t *testing.T) {
	ctx := context.Background()
	d := dbtest.Empty(t)
	logs := []*bytes.Buffer{{}, {}}
	errs := make(chan error, len(logs))
	for _, buf := range logs {
		go func() { errs <- db.Migrate(ctx, d.Config.Migration, slog.New(slog.NewJSONHandler(buf, nil))) }()
	}
	for range logs {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}

	var applied []float64
	for _, buf := range logs {
		for line := range strings.Lines(buf.String()) {
			var r struct {
				Msg     string  `json:"msg"`
				Applied float64 `json:"applied"`
			}
			if json.Unmarshal([]byte(line), &r) == nil && r.Msg == "the database schema is current" {
				applied = append(applied, r.Applied)
			}
		}
	}
	want := float64(migrations(t))
	if len(applied) != 2 || applied[0]+applied[1] != want || (applied[0] != 0 && applied[1] != 0) {
		t.Fatalf("migrations applied by each run: %v, want %v by one and 0 by the other", applied, want)
	}
	var rows int
	if err := d.Superuser(t).QueryRow(ctx, "SELECT count(*) FROM goose_db_version WHERE version_id > 0").Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != migrations(t) {
		t.Fatalf("%d migrations recorded, want %d", rows, migrations(t))
	}
	if err := d.Open(t).CheckSchema(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestCheckSchema(t *testing.T) {
	ctx := context.Background()
	d := dbtest.Empty(t)
	pool := d.Open(t)
	if err := pool.CheckSchema(ctx); !errors.Is(err, db.ErrSchemaBehind) {
		t.Fatalf("before any migration: %v, want ErrSchemaBehind", err)
	}
	if err := db.Migrate(ctx, d.Config.Migration, discard); err != nil {
		t.Fatal(err)
	}
	if err := pool.CheckSchema(ctx); err != nil {
		t.Fatalf("after migrating: %v", err)
	}
	// A newer release migrated the database further.
	if _, err := d.Superuser(t).Exec(ctx, "INSERT INTO goose_db_version (version_id, is_applied) VALUES ($1, true)",
		db.ExpectedVersion()+1); err != nil {
		t.Fatal(err)
	}
	if err := pool.CheckSchema(ctx); !errors.Is(err, db.ErrSchemaAhead) {
		t.Fatalf("on a newer schema: %v, want ErrSchemaAhead", err)
	}
}

// The runtime role cannot change the schema, so a compromised server cannot
// drop the append-only triggers or rewrite the schema's history (threat
// model, T-54 and DC-3).
func TestTheRuntimeRoleCannotChangeTheSchema(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.New(t).Open(t)
	for _, stmt := range []string{
		"DROP TRIGGER audit_events_append_only ON whitetower.audit_events",
		"ALTER TABLE whitetower.audit_events DISABLE TRIGGER audit_events_append_only",
		"CREATE TABLE whitetower.backdoor (id int)",
		"CREATE TABLE public.backdoor (id int)",
		"DELETE FROM goose_db_version",
		"UPDATE goose_db_version SET version_id = 0",
	} {
		_, err := pool.Exec(ctx, stmt)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Errorf("%s: %v, want insufficient_privilege", stmt, err)
		}
	}

	// Nor can it migrate a database.
	d := dbtest.Empty(t)
	runtimeAsMigration := config.Migration{URL: d.Config.URL, PasswordFile: d.Config.PasswordFile}
	if err := db.Migrate(ctx, runtimeAsMigration, discard); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("the runtime role migrating a database: %v, want permission denied", err)
	}
}

// PGPASSWORD and the like are ignored: the password comes from the file the
// configuration names (requirement OPS-04).
func TestThePasswordComesOnlyFromItsFile(t *testing.T) {
	ctx := context.Background()
	d := dbtest.New(t)
	password, err := os.ReadFile(d.Config.PasswordFile)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PGPASSWORD", strings.TrimSpace(string(password)))
	cfg := d.Config
	cfg.PasswordFile = ""
	pool, err := db.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err == nil {
		t.Fatal("connected with PGPASSWORD")
	}
	if err := d.Open(t).Ping(ctx); err != nil {
		t.Fatalf("with the password file: %v", err)
	}
}

// The invariants the database itself enforces (plan P0-02, step 7), checked
// on the schema as whitetower migrate applies it.
func TestSchemaChecks(t *testing.T) {
	script, err := os.ReadFile("../../../hack/db/schema_checks.sql")
	if err != nil {
		t.Fatal(err)
	}
	var sql strings.Builder
	for line := range strings.Lines(string(script)) {
		if !strings.HasPrefix(strings.TrimSpace(line), `\`) { // psql meta-commands
			sql.WriteString(line)
		}
	}
	conn := dbtest.New(t).Superuser(t)
	if _, err := conn.Exec(context.Background(), sql.String()); err != nil {
		t.Fatal(err)
	}
}

func jobExists(t *testing.T, pool *db.DB, name string) bool {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), "SELECT count(*) FROM whitetower.job_state WHERE name = $1", name).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

func insertJob(ctx context.Context, tx *db.Tx, name string) error {
	_, err := tx.Exec(ctx, "INSERT INTO whitetower.job_state (name) VALUES ($1)", name)
	return err
}

func TestInTx(t *testing.T) {
	pool := dbtest.New(t).Open(t)

	t.Run("commits, then runs the hooks in order", func(t *testing.T) {
		var calls []string
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		err := pool.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
			tx.BeforeCommit(func(context.Context) error { calls = append(calls, "before"); return nil })
			tx.AfterCommit(func(ctx context.Context) {
				cancel() // the caller goes away: the hook's context lives on
				calls = append(calls, "after:"+errString(ctx.Err()))
			})
			return insertJob(ctx, tx, "committed")
		})
		if err != nil {
			t.Fatal(err)
		}
		if !jobExists(t, pool, "committed") || strings.Join(calls, ",") != "before,after:<nil>" {
			t.Fatalf("committed %v, hooks %v", jobExists(t, pool, "committed"), calls)
		}
	})

	for _, tt := range []struct {
		name string
		fn   func(ctx context.Context, tx *db.Tx) error
	}{
		{"an error rolls back", func(ctx context.Context, tx *db.Tx) error {
			if err := insertJob(ctx, tx, "fn failed"); err != nil {
				return err
			}
			return errors.New("domain error")
		}},
		{"a failing BeforeCommit hook rolls back", func(ctx context.Context, tx *db.Tx) error {
			tx.BeforeCommit(func(context.Context) error { return errors.New("audit write failed") })
			return insertJob(ctx, tx, "hook failed")
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			afterCommit := false
			err := pool.InTx(context.Background(), func(ctx context.Context, tx *db.Tx) error {
				tx.AfterCommit(func(context.Context) { afterCommit = true })
				return tt.fn(ctx, tx)
			})
			if err == nil || jobExists(t, pool, "fn failed") || jobExists(t, pool, "hook failed") || afterCommit {
				t.Fatalf("error %v, AfterCommit ran %v: want the transaction rolled back", err, afterCommit)
			}
		})
	}

	t.Run("a panic rolls back and goes on", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Error("the panic was swallowed")
			}
			if jobExists(t, pool, "panicked") {
				t.Error("the transaction committed")
			}
		}()
		_ = pool.InTx(context.Background(), func(ctx context.Context, tx *db.Tx) error {
			if err := insertJob(ctx, tx, "panicked"); err != nil {
				return err
			}
			panic("boom")
		})
	})

	t.Run("a serialization failure runs the transaction again", func(t *testing.T) {
		attempts, afterCommits := 0, 0
		err := pool.InTx(context.Background(), func(ctx context.Context, tx *db.Tx) error {
			attempts++
			tx.AfterCommit(func(context.Context) { afterCommits++ })
			if err := insertJob(ctx, tx, "retried"); err != nil {
				return err
			}
			if attempts == 1 {
				return &pgconn.PgError{Code: "40001", Message: "could not serialize access"}
			}
			return nil
		})
		if err != nil || attempts != 2 || afterCommits != 1 || !jobExists(t, pool, "retried") {
			t.Fatalf("error %v after %d attempts, %d AfterCommit runs", err, attempts, afterCommits)
		}
	})

	t.Run("other errors are not retried", func(t *testing.T) {
		attempts := 0
		err := pool.InTx(context.Background(), func(ctx context.Context, tx *db.Tx) error {
			attempts++
			return insertJob(ctx, tx, "committed") // duplicate key
		})
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23505" || attempts != 1 {
			t.Fatalf("error %v after %d attempts", err, attempts)
		}
	})
}

func errString(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}

// sqlc's generated code takes a DB or a Tx alike.
var _ = []interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}{(*db.DB)(nil), (*db.Tx)(nil)}
