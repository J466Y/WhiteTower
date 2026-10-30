// Package packaging validates deployment artifacts: Dockerfiles, Compose profiles,
// and seed data (OPS-01, P1-12.1).
package packaging

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/J466Y/WhiteTower/internal/govstate"
	"github.com/J466Y/WhiteTower/internal/platform/db/dbtest"
)

const root = "../.."

// composeConfig holds the minimal Compose schema fields we validate.
type composeConfig struct {
	Services map[string]struct {
		Image       string            `yaml:"image"`
		ReadOnly    bool              `yaml:"read_only"`
		Tmpfs       []string          `yaml:"tmpfs"`
		SecurityOpt []string          `yaml:"security_opt"`
		CapDrop     []string          `yaml:"cap_drop"`
		Environment map[string]string `yaml:"environment"`
		Secrets     []string          `yaml:"secrets"`
		Ports       []string          `yaml:"ports"`
		DependsOn   map[string]struct {
			Condition string `yaml:"condition"`
		} `yaml:"depends_on"`
		Healthcheck *struct {
			Test []string `yaml:"test"`
		} `yaml:"healthcheck"`
	} `yaml:"services"`
	Secrets map[string]struct {
		File string `yaml:"file"`
	} `yaml:"secrets"`
}

func loadCompose(t *testing.T, path string) composeConfig {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var cfg composeConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	return cfg
}

func TestDockerfilesComplyWithHardeningAndMetadataStandards(t *testing.T) {
	dockerfiles := []string{
		root + "/deploy/docker/Dockerfile",
		root + "/deploy/docker/goreleaser.Dockerfile",
		root + "/deploy/docker/mock-module.Dockerfile",
		root + "/deploy/docker/demo-agent.Dockerfile",
	}

	for _, path := range dockerfiles {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("reading %s: %v", path, err)
			}
			content := string(data)

			// OCI Annotations
			if !strings.Contains(content, "org.opencontainers.image.title") {
				t.Errorf("%s missing org.opencontainers.image.title", path)
			}
			if !strings.Contains(content, "org.opencontainers.image.licenses") {
				t.Errorf("%s missing org.opencontainers.image.licenses", path)
			}
			if !strings.Contains(content, "org.opencontainers.image.source") {
				t.Errorf("%s missing org.opencontainers.image.source", path)
			}

			// Non-root user execution
			if !strings.Contains(content, "USER nonroot:nonroot") && !strings.Contains(content, "USER app:app") {
				t.Errorf("%s does not specify a non-root user", path)
			}
		})
	}
}

func TestComposeProfilesComplyWithHardeningStandards(t *testing.T) {
	profiles := []string{
		root + "/deploy/compose/dev/compose.yaml",
		root + "/deploy/compose/eval/compose.yaml",
	}

	for _, path := range profiles {
		t.Run(filepath.Base(filepath.Dir(path)), func(t *testing.T) {
			cfg := loadCompose(t, path)

			core, ok := cfg.Services["whitetower"]
			if !ok {
				t.Fatalf("%s missing whitetower service", path)
			}

			// Read-only root filesystem
			if !core.ReadOnly {
				t.Errorf("%s: whitetower service must set read_only: true", path)
			}

			// tmpfs mount for /tmp
			hasTmpfs := false
			for _, m := range core.Tmpfs {
				if strings.HasPrefix(m, "/tmp") {
					hasTmpfs = true
					break
				}
			}
			if !hasTmpfs {
				t.Errorf("%s: whitetower service must mount tmpfs on /tmp", path)
			}

			// Security opts: no-new-privileges
			hasNoNewPrivs := false
			for _, opt := range core.SecurityOpt {
				if opt == "no-new-privileges:true" {
					hasNoNewPrivs = true
					break
				}
			}
			if !hasNoNewPrivs {
				t.Errorf("%s: whitetower service must set security_opt no-new-privileges:true", path)
			}

			// Capabilities: drop all
			hasCapDropAll := false
			for _, cap := range core.CapDrop {
				if cap == "ALL" {
					hasCapDropAll = true
					break
				}
			}
			if !hasCapDropAll {
				t.Errorf("%s: whitetower service must set cap_drop ALL", path)
			}

			// Secrets mounted as files, not passed as inline passwords in environment
			if len(core.Secrets) == 0 {
				t.Errorf("%s: whitetower service must declare secret mounts", path)
			}
			for secretName, secretDef := range cfg.Secrets {
				if secretDef.File == "" {
					t.Errorf("%s: secret %s must be mounted from file", path, secretName)
				}
			}

			// Healthcheck must be defined
			if core.Healthcheck == nil || len(core.Healthcheck.Test) == 0 {
				t.Errorf("%s: whitetower service must have a healthcheck defined", path)
			}
		})
	}
}

func TestEvaluationSeedScriptExecutesCleanly(t *testing.T) {
	d := dbtest.New(t)
	pool := d.Open(t)
	ctx := context.Background()

	seedSQLPath := root + "/deploy/compose/eval/seed/seed.sql"
	sqlBytes, err := os.ReadFile(seedSQLPath)
	if err != nil {
		t.Fatalf("reading seed.sql: %v", err)
	}

	// Execute seed script as migrator on migrated database
	su := d.Superuser(t)
	if _, err := su.Exec(ctx, string(sqlBytes)); err != nil {
		t.Fatalf("executing seed.sql: %v", err)
	}

	// Verify sample principals exist
	var principalCount int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM whitetower.principals WHERE status = 'active'").Scan(&principalCount); err != nil {
		t.Fatal(err)
	}
	if principalCount < 7 {
		t.Errorf("expected at least 7 active principals, got %d", principalCount)
	}

	// Verify sample use cases exist
	var useCaseCount int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM whitetower.use_cases").Scan(&useCaseCount); err != nil {
		t.Fatal(err)
	}
	if useCaseCount < 2 {
		t.Errorf("expected at least 2 use cases, got %d", useCaseCount)
	}

	// Verify sample agents in different lifecycle states exist
	var activeCount, proposedCount, suspendedCount int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM whitetower.agents WHERE lifecycle_state = 'active'").Scan(&activeCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM whitetower.agents WHERE lifecycle_state = 'proposed'").Scan(&proposedCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM whitetower.agents WHERE lifecycle_state = 'suspended'").Scan(&suspendedCount); err != nil {
		t.Fatal(err)
	}

	if activeCount != 1 {
		t.Errorf("expected 1 active agent, got %d", activeCount)
	}
	if proposedCount != 1 {
		t.Errorf("expected 1 proposed agent, got %d", proposedCount)
	}
	if suspendedCount != 1 {
		t.Errorf("expected 1 suspended agent, got %d", suspendedCount)
	}

	// Verify agent owners exist
	var ownerCount int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM whitetower.agent_owners WHERE role = 'primary'").Scan(&ownerCount); err != nil {
		t.Fatal(err)
	}
	if ownerCount < 3 {
		t.Errorf("expected at least 3 agent primary owners, got %d", ownerCount)
	}

	// Every agent has its governance state, as T1 writes it: the lease of its
	// risk tier and the attributes of govstate.Attributes, at a version from
	// the version counter.
	rows, err := pool.Query(ctx, `SELECT a.slug, g.lease_ttl_seconds, g.attributes FROM whitetower.agents a
		JOIN whitetower.governance_state g ON g.agent_id = a.id
		JOIN whitetower.governance_head h ON h.version = g.state_version`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	leases := map[string]int32{"doc-indexer": 60, "portfolio-analyst-v1": 30, "support-bot-alpha": 60}
	for rows.Next() {
		var slug string
		var lease int32
		var raw []byte
		if err := rows.Scan(&slug, &lease, &raw); err != nil {
			t.Fatal(err)
		}
		var attrs govstate.Attributes
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&attrs); err != nil || lease != leases[slug] || attrs.Slug != slug ||
			attrs.OwnerID.String() != "00000000-0000-7000-8000-000000000001" {
			t.Errorf("%s: lease %d, attributes %s (%v)", slug, lease, raw, err)
		}
		delete(leases, slug)
	}
	if err := rows.Err(); err != nil || len(leases) != 0 {
		t.Errorf("agents without a governance state at the head's version: %v (%v)", leases, err)
	}
}
