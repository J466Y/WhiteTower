package main

import (
	"bytes"
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/J466Y/WhiteTower/internal/platform/db"
	"github.com/J466Y/WhiteTower/internal/platform/db/dbtest"
)

func TestServeAndMigrateNameWhatTheyMiss(t *testing.T) {
	for _, tt := range []struct {
		command, want string
	}{
		{"serve", "database.url"},
		{"migrate", "database.migration.url"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run([]string{tt.command}, devEnv, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), tt.want) {
			t.Errorf("%s: exit code %d, stderr %q, want 1 naming %s", tt.command, code, stderr.String(), tt.want)
		}
	}
}

// The criterion of plan P1-01, step 4: two replicas start against an empty
// database. Both run whitetower migrate at once: one migrates while the other
// waits. Then both servers start, and both become ready.
func TestTwoReplicasMigrateThenServe(t *testing.T) {
	d := dbtest.Empty(t)
	type result struct {
		code           int
		stdout, stderr string
	}
	results := make(chan result, 2)
	for range 2 {
		go func() {
			var stdout, stderr bytes.Buffer
			code := run([]string{"migrate"}, migrationEnv(d), &stdout, &stderr)
			results <- result{code, stdout.String(), stderr.String()}
		}()
	}
	applying := 0
	for range 2 {
		r := <-results
		if r.code != 0 {
			t.Fatalf("migrate: exit code %d, stderr %q", r.code, r.stderr)
		}
		if strings.Contains(r.stdout, `"msg":"applied a migration"`) {
			applying++
		}
	}
	if applying != 1 {
		t.Fatalf("%d runs applied migrations, want exactly 1", applying)
	}
	for _, s := range []*serving{startServeOn(t, d), startServeOn(t, d)} {
		if status, body := s.readiness(t); status != http.StatusOK {
			t.Fatalf("readyz: %d %q", status, body)
		}
	}
}

// Before whitetower migrate has run, the server starts but is not ready; it
// becomes ready once the schema is there, without a restart.
func TestServeWaitsForMigrations(t *testing.T) {
	d := dbtest.Empty(t)
	s := startServeOn(t, d)
	if status, body := s.readiness(t); status != http.StatusServiceUnavailable || body != "not ready: schema\n" {
		t.Fatalf("readyz before migrating: %d %q", status, body)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"migrate"}, migrationEnv(d), &stdout, &stderr); code != 0 {
		t.Fatalf("migrate: exit code %d, stderr %q", code, stderr.String())
	}
	if status, body := s.readiness(t); status != http.StatusOK {
		t.Fatalf("readyz after migrating: %d %q", status, body)
	}
}

// A server whose binary is older than the schema refuses to start: the
// migrations are forward-only.
func TestServeRefusesANewerSchema(t *testing.T) {
	d := dbtest.New(t)
	if _, err := d.Superuser(t).Exec(context.Background(),
		"INSERT INTO goose_db_version (version_id, is_applied) VALUES ($1, true)", db.ExpectedVersion()+1); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	start := time.Now()
	code := run([]string{"serve"}, append(databaseEnv(d), devEnv...), &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "newer than this binary") {
		t.Fatalf("exit code %d, stderr %q", code, stderr.String())
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Fatalf("refusing took %s", took)
	}
}

// The server holds only the runtime role's credentials: it starts and is
// ready with the migration role's password file missing (threat model, DC-3).
func TestServeNeverReadsTheMigrationRole(t *testing.T) {
	d := dbtest.New(t)
	s := startServeOn(t, d,
		"WT_DATABASE_MIGRATION_URL="+d.Config.Migration.URL,
		"WT_DATABASE_MIGRATION_PASSWORD_FILE="+filepath.Join(t.TempDir(), "not-mounted-here"),
	)
	if status, body := s.readiness(t); status != http.StatusOK {
		t.Fatalf("readyz: %d %q", status, body)
	}
}
