package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// notifyChannel carries the new state version after every governance change.
const notifyChannel = "whitetower_governance"

// governanceLock serializes the transactions that change governance state.
// nextval hands out versions when called, not when transactions commit; if
// two writers commit out of order, a replica that reads "every change since
// version V" can skip the one that commits late. Holding this lock until
// commit makes commit order equal version order. (Finding for P1-07 and
// P1-08.)
const governanceLock = 7319_2026

const (
	operatorID  = "0192f1c2-7a3b-7c4d-8e5f-0000000000a3"
	advisoryID  = "0192f1c2-7a3b-7c4d-8e5f-0000000000a2"
	useCaseID   = "0192f1c2-7a3b-7c4d-8e5f-000000000010"
	moduleID    = "0192f1c2-7a3b-7c4d-8e5f-000000000050"
	runtimeRole = "wt_s2"
)

// instance is one enforcement point: its instance and the agent it serves.
type instance struct {
	InstanceID string `json:"instance_id"`
	AgentID    string `json:"agent_id"`
}

// setupDB recreates the White Tower schema from the real migration, creates a
// login role in whitetower_runtime, and seeds n active agents with one
// enforcement point instance each. It returns the instances and the URL the
// core replicas connect with.
func setupDB(ctx context.Context, adminURL, migrationFile string, n, ttlSeconds int) ([]instance, string, error) {
	migration, err := os.ReadFile(migrationFile) //nolint:gosec // G304: the spike reads the migration named by its own flag
	if err != nil {
		return nil, "", err
	}
	conn, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = conn.Close(ctx) }()

	steps := []string{
		`DROP SCHEMA IF EXISTS whitetower CASCADE`,
		string(migration),
		`DO $$ BEGIN
		   IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'wt_s2') THEN
		     CREATE ROLE wt_s2 LOGIN PASSWORD 'spike' IN ROLE whitetower_runtime;
		   END IF;
		 END $$`,
	}
	for _, sql := range steps {
		if _, err := conn.Exec(ctx, sql); err != nil {
			return nil, "", fmt.Errorf("schema: %w", err)
		}
	}
	seed := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO whitetower.principals (id, kind, issuer, subject, display_name) VALUES
		    ($1, 'human', 'http://idp', 'omar', 'Omar Operator'),
		    ($2, 'human', 'http://idp', 'alex', 'Alex Advisory')`, []any{operatorID, advisoryID}},
		{`INSERT INTO whitetower.use_cases (id, title, description, business_justification, status, created_by)
		  VALUES ($1, 'S2 spike', 'Load test', 'Measurements', 'validated', $2)`, []any{useCaseID, operatorID}},
		{`INSERT INTO whitetower.agents (id, slug, name, description, kind, risk_tier, use_case_id, lifecycle_state,
		                                 harness, created_by, activated_at)
		  SELECT gen_random_uuid(), 'agent-' || lpad(i::text, 5, '0'), 'Agent ' || i, 'S2 spike agent', 'in_house',
		         'critical', $1, 'active', '{}'::jsonb, $2, now()
		  FROM generate_series(1, $3) AS i`, []any{useCaseID, operatorID, n}},
		{`INSERT INTO whitetower.governance_state (agent_id, lifecycle_state, lease_ttl_seconds, halt_mode, attributes, state_version)
		  SELECT id, 'active', $1, 'interrupt', jsonb_build_object('slug', slug, 'kind', kind, 'risk_tier', risk_tier),
		         nextval('whitetower.governance_state_version_seq')
		  FROM whitetower.agents ORDER BY slug`, []any{ttlSeconds}},
		{`INSERT INTO whitetower.modules (id, slug, name, vendor, module_version, manifest, manifest_sha256, capabilities,
		                                  contract_versions, status, registered_by, approved_by, approved_at)
		  VALUES ($1, 'ep-python', 'Python enforcement point', 'White Tower', '0.1.0', '{}', sha256(convert_to('{}', 'UTF8')),
		          '{enforcement-point,policy-engine}', '{v1alpha1}', 'approved', $2, $3, now())`, []any{moduleID, operatorID, advisoryID}},
		{`INSERT INTO whitetower.module_instances (id, module_id, instance_key, identity_kind, identity_agent_id,
		                                           module_version, contract_version, status, lease_ttl_seconds,
		                                           connected_at, last_seen_at)
		  SELECT gen_random_uuid(), $1, 'ep-' || slug, 'agent', id, '0.1.0', 'v1alpha1', 'disconnected', $2, now(), now()
		  FROM whitetower.agents`, []any{moduleID, ttlSeconds}},
	}
	for _, s := range seed {
		if _, err := conn.Exec(ctx, s.sql, s.args...); err != nil {
			return nil, "", fmt.Errorf("seed: %w", err)
		}
	}
	rows, err := conn.Query(ctx, `SELECT id::text, identity_agent_id::text FROM whitetower.module_instances ORDER BY instance_key`)
	if err != nil {
		return nil, "", err
	}
	instances, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (instance, error) {
		var in instance
		err := r.Scan(&in.InstanceID, &in.AgentID)
		return in, err
	})
	if err != nil {
		return nil, "", err
	}

	u, err := url.Parse(adminURL)
	if err != nil {
		return nil, "", err
	}
	u.User = url.UserPassword(runtimeRole, "spike")
	return instances, u.String(), nil
}

// haltRow is a halt as governance state carries it.
type haltRow struct {
	ID       string    `json:"id"`
	Scope    string    `json:"scope"`
	IssuedAt time.Time `json:"issued_at"`
	Drill    bool      `json:"drill"`
}

// agentRow is one agent's governance state.
type agentRow struct {
	AgentID        string
	LifecycleState string
	LeaseTTL       int
	HaltMode       string
	Version        uint64
	Halts          []haltRow
}

const haltsJSON = `coalesce((SELECT json_agg(json_build_object('id', h.id, 'scope', h.scope, 'issued_at', h.issued_at, 'drill', h.drill))
                             FROM whitetower.halts h WHERE h.id = ANY (%s)), '[]'::json)`

var agentColumns = `g.agent_id::text, g.lifecycle_state, g.lease_ttl_seconds, g.halt_mode, g.state_version, ` +
	fmt.Sprintf(haltsJSON, "g.agent_halt_ids")

func scanAgent(r pgx.CollectableRow) (agentRow, error) {
	var a agentRow
	var halts []byte
	if err := r.Scan(&a.AgentID, &a.LifecycleState, &a.LeaseTTL, &a.HaltMode, &a.Version, &halts); err != nil {
		return a, err
	}
	return a, json.Unmarshal(halts, &a.Halts)
}

// loadAgent reads one agent's governance state.
func loadAgent(ctx context.Context, pool *pgxpool.Pool, agentID string) (agentRow, error) {
	rows, err := pool.Query(ctx, `SELECT `+agentColumns+` FROM whitetower.governance_state g WHERE g.agent_id = $1`, agentID)
	if err != nil {
		return agentRow{}, err
	}
	return pgx.CollectExactlyOneRow(rows, scanAgent)
}

// changedAgents reads every agent whose state changed after a version, in
// version order.
func changedAgents(ctx context.Context, pool *pgxpool.Pool, since uint64) ([]agentRow, error) {
	rows, err := pool.Query(ctx, `SELECT `+agentColumns+` FROM whitetower.governance_state g
	                              WHERE g.state_version > $1 ORDER BY g.state_version`, since)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanAgent)
}

// loadFleet reads the fleet state.
func loadFleet(ctx context.Context, pool *pgxpool.Pool) (uint64, []haltRow, error) {
	var version uint64
	var halts []byte
	err := pool.QueryRow(ctx, `SELECT f.state_version, `+fmt.Sprintf(haltsJSON, "f.halt_ids")+` FROM whitetower.fleet_state f`).
		Scan(&version, &halts)
	if err != nil {
		return 0, nil, err
	}
	var hs []haltRow
	return version, hs, json.Unmarshal(halts, &hs)
}

// governanceTx runs fn in a transaction holding the governance lock, with a
// new state version, and notifies the replicas after fn.
func governanceTx(ctx context.Context, pool *pgxpool.Pool, fn func(tx pgx.Tx, version int64) error) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, governanceLock); err != nil {
		return err
	}
	var version int64
	if err := tx.QueryRow(ctx, `SELECT nextval('whitetower.governance_state_version_seq')`).Scan(&version); err != nil {
		return err
	}
	if err := fn(tx, version); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_notify($1, $2)`, notifyChannel, strconv.FormatInt(version, 10)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// issueHalt halts one agent (scope "agent") or the fleet (scope "fleet").
func issueHalt(ctx context.Context, pool *pgxpool.Pool, scope, agentID string) (string, time.Time, error) {
	haltID := newUUID()
	var issuedAt time.Time
	var agent any
	if scope == "agent" {
		agent = agentID
	}
	err := governanceTx(ctx, pool, func(tx pgx.Tx, version int64) error {
		err := tx.QueryRow(ctx, `INSERT INTO whitetower.halts (id, scope, agent_id, reason, issued_by_type, issued_by, state_version, issued_at)
		                         VALUES ($1, $2, $3, 'S2 spike', 'human', $4, $5, clock_timestamp()) RETURNING issued_at`,
			haltID, scope, agent, operatorID, version).Scan(&issuedAt)
		if err != nil {
			return err
		}
		if scope == "agent" {
			ct, err := tx.Exec(ctx, `UPDATE whitetower.governance_state
			                         SET agent_halt_ids = array_append(agent_halt_ids, $1), run_state = 'halted',
			                             state_version = $2, updated_at = now()
			                         WHERE agent_id = $3`, haltID, version, agentID)
			if err == nil && ct.RowsAffected() != 1 {
				err = fmt.Errorf("no governance state for agent %s", agentID)
			}
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE whitetower.fleet_state
		                       SET halt_ids = array_append(halt_ids, $1), run_state = 'halted', state_version = $2, updated_at = now()`,
			haltID, version)
		return err
	})
	return haltID, issuedAt, err
}

// releaseHalt releases a halt the way the core must: a release request by one
// person, approved by another (KIL-05), then the halt and the state.
func releaseHalt(ctx context.Context, pool *pgxpool.Pool, haltID string) error {
	err := governanceTx(ctx, pool, func(tx pgx.Tx, version int64) error {
		if _, err := tx.Exec(ctx, `INSERT INTO whitetower.halt_release_requests (id, halt_id, reason, requested_by, status, decided_by, decided_at)
		                           VALUES ($1, $2, 'S2 spike', $3, 'approved', $4, now())`,
			newUUID(), haltID, operatorID, advisoryID); err != nil {
			return err
		}
		var scope string
		var agentID *string
		if err := tx.QueryRow(ctx, `UPDATE whitetower.halts SET status = 'released', released_at = clock_timestamp()
		                            WHERE id = $1 RETURNING scope, agent_id::text`, haltID).Scan(&scope, &agentID); err != nil {
			return err
		}
		switch {
		case scope == "fleet":
			_, err := tx.Exec(ctx, `UPDATE whitetower.fleet_state
			                        SET halt_ids = array_remove(halt_ids, $1),
			                            run_state = CASE WHEN cardinality(array_remove(halt_ids, $1)) > 0 THEN 'halted' ELSE 'running' END,
			                            state_version = $2, updated_at = now()`, haltID, version)
			return err
		case agentID != nil:
			_, err := tx.Exec(ctx, `UPDATE whitetower.governance_state
			                        SET agent_halt_ids = array_remove(agent_halt_ids, $1),
			                            run_state = CASE WHEN cardinality(array_remove(agent_halt_ids, $1)) > 0 THEN 'halted' ELSE 'running' END,
			                            state_version = $2, updated_at = now()
			                        WHERE agent_id = $3`, haltID, version, *agentID)
			return err
		default:
			return errors.New("halt without a target")
		}
	})
	return err
}

// ackLatencies returns, for one halt, the time from issue to each recorded
// acknowledgement, both taken from the database clock.
func ackLatencies(ctx context.Context, pool *pgxpool.Pool, haltID string) ([]time.Duration, error) {
	rows, err := pool.Query(ctx, `SELECT extract(epoch FROM a.acknowledged_at - h.issued_at)::float8 FROM whitetower.halt_acks a
	                              JOIN whitetower.halts h ON h.id = a.halt_id WHERE a.halt_id = $1`, haltID)
	if err != nil {
		return nil, err
	}
	seconds, err := pgx.CollectRows(rows, pgx.RowTo[float64])
	if err != nil {
		return nil, err
	}
	out := make([]time.Duration, len(seconds))
	for i, s := range seconds {
		out[i] = time.Duration(s * float64(time.Second))
	}
	return out, nil
}
