// Package dbtest gives integration tests a PostgreSQL database set up as in a
// deployment: a migration role that owns the schema, and a runtime role,
// member of whitetower_runtime, for the server.
//
// One container serves each test binary. It starts on first use, and
// testcontainers' reaper removes it when the binary exits. Each test gets a
// database of its own, copied from a template that the real migrations
// prepared once, so a test costs a copy rather than a migration. Without
// Docker the tests skip, except in CI (the CI variable is set), where they
// fail.
package dbtest

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"
	tclog "github.com/testcontainers/testcontainers-go/log"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/J466Y/WhiteTower/internal/platform/config"
	"github.com/J466Y/WhiteTower/internal/platform/db"
)

// Image is the PostgreSQL image of the tests. WT_TEST_POSTGRES_IMAGE
// overrides it, for example to test PostgreSQL 16.
const Image = "postgres:17-alpine"

// The login roles, as an operator creates them.
const (
	MigrationRole = "whitetower_migrator"
	RuntimeRole   = "whitetower_app"
)

// Passwords of the throwaway test container.
//
//nolint:gosec // G101: not credentials of anything that outlives a test
const (
	superuserPassword = "superuser-test-only"
	migrationPassword = "migrator-test-only"
	runtimePassword   = "app-test-only"
)

const template = "whitetower_template"

// server is the container of the test binary.
type server struct {
	hostPort string
	err      error
}

var (
	start = sync.OnceValue(startServer)
	// Databases are created one at a time: a copy of the template must not
	// overlap with another session on it.
	creating sync.Mutex
	sequence atomic.Int64
)

func startServer() server {
	ctx := context.Background()
	tclog.SetDefault(tclog.NewNoopLogger())
	c, err := testcontainers.Run(ctx, cmp.Or(os.Getenv("WT_TEST_POSTGRES_IMAGE"), Image),
		testcontainers.WithEnv(map[string]string{"POSTGRES_PASSWORD": superuserPassword}),
		testcontainers.WithExposedPorts("5432/tcp"),
		// Tests need no durability, which costs time.
		testcontainers.WithCmd("postgres", "-c", "fsync=off", "-c", "synchronous_commit=off", "-c", "full_page_writes=off"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(2*time.Minute),
			wait.ForListeningPort("5432/tcp"),
		),
	)
	if err != nil {
		return server{err: err}
	}
	host, err := c.Host(ctx)
	if err != nil {
		return server{err: err}
	}
	port, err := c.MappedPort(ctx, "5432/tcp")
	if err != nil {
		return server{err: err}
	}
	s := server{hostPort: net.JoinHostPort(host, port.Port())}
	s.err = s.bootstrap(ctx)
	return s
}

// bootstrap creates the roles and a template with the binary's schema, as an
// operator and whitetower migrate would.
func (s server) bootstrap(ctx context.Context) error {
	conn, err := pgx.Connect(ctx, s.superuserURL("postgres"))
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	for _, stmt := range []string{
		"CREATE ROLE " + MigrationRole + " LOGIN PASSWORD '" + migrationPassword + "'",
		"CREATE ROLE whitetower_runtime NOLOGIN",
		"CREATE ROLE " + RuntimeRole + " LOGIN PASSWORD '" + runtimePassword + "' IN ROLE whitetower_runtime",
		"CREATE DATABASE " + template + " OWNER " + MigrationRole,
	} {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", stmt, err)
		}
	}
	dir, err := os.MkdirTemp("", "whitetower-dbtest-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	cfg, err := s.config(dir, template)
	if err != nil {
		return err
	}
	return db.Migrate(ctx, cfg.Migration, slog.New(slog.DiscardHandler))
}

func (s server) superuserURL(database string) string {
	return "postgres://postgres:" + superuserPassword + "@" + s.hostPort + "/" + database + "?sslmode=disable"
}

// config returns the configuration of both roles for a database, with their
// password files written in dir.
func (s server) config(dir, database string) (config.Database, error) {
	runtimeFile := filepath.Join(dir, "runtime-password")
	migrationFile := filepath.Join(dir, "migration-password")
	if err := os.WriteFile(runtimeFile, []byte(runtimePassword+"\n"), 0o600); err != nil {
		return config.Database{}, err
	}
	if err := os.WriteFile(migrationFile, []byte(migrationPassword+"\n"), 0o600); err != nil {
		return config.Database{}, err
	}
	return config.Database{
		URL:            "postgres://" + RuntimeRole + "@" + s.hostPort + "/" + database + "?sslmode=disable",
		PasswordFile:   runtimeFile,
		MaxConnections: 4,
		Migration: config.Migration{
			URL:          "postgres://" + MigrationRole + "@" + s.hostPort + "/" + database + "?sslmode=disable",
			PasswordFile: migrationFile,
		},
	}, nil
}

// Database is the database of one test.
type Database struct {
	// Name is the database's name.
	Name string
	// Config holds the connections of the runtime and migration roles, with
	// their password files, as the server and whitetower migrate read them.
	Config config.Database

	server server
}

// New returns a database with the binary's schema, dropped when the test
// ends.
func New(t testing.TB) *Database {
	t.Helper()
	return newDatabase(t, template)
}

// Empty returns a database where nothing is migrated yet, owned by the
// migration role, as an operator prepares it for the first whitetower
// migrate. It is dropped when the test ends.
func Empty(t testing.TB) *Database {
	t.Helper()
	return newDatabase(t, "template0")
}

func newDatabase(t testing.TB, from string) *Database {
	t.Helper()
	s := start()
	if s.err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("PostgreSQL in Docker: %v", s.err)
		}
		t.Skipf("PostgreSQL in Docker is not available: %v", s.err)
	}
	name := fmt.Sprintf("whitetower_test_%d", sequence.Add(1))
	s.exec(t, "CREATE DATABASE "+name+" TEMPLATE "+from+" OWNER "+MigrationRole)
	t.Cleanup(func() { s.exec(t, "DROP DATABASE "+name+" WITH (FORCE)") })
	cfg, err := s.config(t.TempDir(), name)
	if err != nil {
		t.Fatal(err)
	}
	return &Database{Name: name, Config: cfg, server: s}
}

// exec runs a statement as the superuser, outside any test database.
func (s server) exec(t testing.TB, stmt string) {
	t.Helper()
	creating.Lock()
	defer creating.Unlock()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, s.superuserURL("postgres"))
	if err != nil {
		t.Errorf("%s: %v", stmt, err)
		return
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, stmt); err != nil {
		t.Errorf("%s: %v", stmt, err)
	}
}

// Open returns a pool of the runtime role's connections, as the server opens
// it, closed when the test ends.
func (d *Database) Open(t testing.TB) *db.DB {
	t.Helper()
	pool, err := db.Open(d.Config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// OpenReplica returns a pool of the runtime role's connections as another
// replica of the server opens it, closed when the test ends. pg_stat_activity
// names its sessions after the replica: "<replica>", or "<replica> <purpose>"
// for those that db.Connect opens.
func (d *Database) OpenReplica(t testing.TB, replica string) *db.DB {
	t.Helper()
	cfg := d.Config
	cfg.URL += "&application_name=" + url.QueryEscape(replica)
	pool, err := db.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// Terminate ends the sessions that pg_stat_activity names application, as a
// failure of the database or of the network would, and returns how many it
// ended.
func (d *Database) Terminate(t testing.TB, application string) int {
	t.Helper()
	var n int
	if err := d.Superuser(t).QueryRow(context.Background(),
		"SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE datname = $1 AND application_name = $2",
		d.Name, application).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Superuser connects to the test's database as the superuser, for checks
// that need more than the roles of the deployment. The connection closes
// when the test ends.
func (d *Database) Superuser(t testing.TB) *pgx.Conn {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, d.server.superuserURL(d.Name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(ctx) })
	return conn
}
