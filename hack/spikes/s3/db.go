package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/mod/sumdb/note"
)

const runtimeRole = "wt_s3"

// setupDB recreates the White Tower schema from the real migration, adds the
// spike's queue of unsealed events, creates a login role in
// whitetower_runtime, registers the checkpoint key, and creates the
// partitions of a past month for the retention test. It returns the runtime
// role's URL.
func setupDB(ctx context.Context, adminURL, migrationFile string, pastMonth time.Time, vkey ed25519.PublicKey, keyID string) (string, error) {
	migration, err := os.ReadFile(migrationFile) //nolint:gosec // G304: the spike reads the migration named by its own flag
	if err != nil {
		return "", err
	}
	conn, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close(ctx) }()

	next := pastMonth.AddDate(0, 1, 0)
	suffix := pastMonth.Format("2006_01")
	jwk := fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q}`, base64.RawURLEncoding.EncodeToString(vkey))
	steps := []struct {
		sql  string
		args []any
	}{
		{sql: `DROP SCHEMA IF EXISTS whitetower CASCADE`},
		{sql: string(migration)},
		{sql: `DO $$ BEGIN
		         IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'wt_s3') THEN
		           CREATE ROLE wt_s3 LOGIN PASSWORD 'spike' IN ROLE whitetower_runtime;
		         END IF;
		       END $$`},
		// The queue the sealer drains: ingestion adds each event here in its
		// own transaction, so an event that commits late is never skipped.
		{sql: `CREATE TABLE whitetower.audit_unsealed (
		         audit_id    uuid PRIMARY KEY,
		         ingested_at timestamptz NOT NULL
		       )`},
		{sql: `CREATE INDEX audit_unsealed_order ON whitetower.audit_unsealed (ingested_at, audit_id)`},
		// No UPDATE: the sealer claims events without row locks (see sealBatch).
		{sql: `GRANT SELECT, INSERT, DELETE ON whitetower.audit_unsealed TO whitetower_runtime`},
		{sql: fmt.Sprintf(`CREATE TABLE whitetower.audit_events_%s PARTITION OF whitetower.audit_events FOR VALUES FROM (%s) TO (%s)`,
			suffix, quote(pastMonth.Format(time.RFC3339)), quote(next.Format(time.RFC3339)))},
		{sql: fmt.Sprintf(`CREATE TABLE whitetower.audit_event_ids_%s PARTITION OF whitetower.audit_event_ids FOR VALUES FROM (%s) TO (%s)`,
			suffix, quote(pastMonth.Format(time.DateOnly)), quote(next.Format(time.DateOnly)))},
		{sql: `INSERT INTO whitetower.signing_keys (key_id, purpose, algorithm, public_jwk, status, activated_at)
		       VALUES ($1, 'checkpoint', 'EdDSA', $2::jsonb, 'active', now())`, args: []any{keyID, jwk}},
	}
	for _, s := range steps {
		if _, err := conn.Exec(ctx, s.sql, s.args...); err != nil {
			return "", fmt.Errorf("setup: %w", err)
		}
	}
	u, err := url.Parse(adminURL)
	if err != nil {
		return "", err
	}
	u.User = url.UserPassword(runtimeRole, "spike")
	return u.String(), nil
}

func quote(s string) string { return "'" + s + "'" }

// dropMonth drops the audit partitions of one month, as the retention job
// does: the events go, the leaves and tree hashes stay.
func dropMonth(ctx context.Context, adminURL string, month time.Time) (time.Duration, error) {
	conn, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		return 0, err
	}
	defer func() { _ = conn.Close(ctx) }()
	suffix := month.Format("2006_01")
	start := time.Now()
	_, err = conn.Exec(ctx, fmt.Sprintf(`DROP TABLE whitetower.audit_events_%s; DROP TABLE whitetower.audit_event_ids_%s`, suffix, suffix))
	return time.Since(start), err
}

// tableSizes returns the total size, indexes included, of the audit tables.
func tableSizes(ctx context.Context, adminURL string) (map[string]int64, error) {
	conn, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close(ctx) }()
	sizes := map[string]int64{}
	for _, t := range []string{"audit_events", "audit_event_ids", "audit_leaves", "audit_tree_hashes", "audit_checkpoints", "audit_unsealed"} {
		var size int64
		// Partitioned tables: sum their partitions.
		err := conn.QueryRow(ctx, `SELECT coalesce(sum(pg_total_relation_size(c.oid)), 0)::bigint
		                           FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		                           WHERE n.nspname = 'whitetower' AND (c.relname = $1 OR c.oid IN (
		                             SELECT inhrelid FROM pg_inherits WHERE inhparent = ('whitetower.' || $1)::regclass))`, t).Scan(&size)
		if err != nil {
			return nil, err
		}
		sizes[t] = size
	}
	return sizes, nil
}

// checkpointKey creates the Ed25519 key that signs checkpoints, as a signed
// note key (C2SP signed-note), and returns its public half for the key
// registry.
func checkpointKey(origin string) (note.Signer, note.Verifier, ed25519.PublicKey, error) {
	skey, vkey, err := note.GenerateKey(rand.Reader, origin)
	if err != nil {
		return nil, nil, nil, err
	}
	signer, err := note.NewSigner(skey)
	if err != nil {
		return nil, nil, nil, err
	}
	verifier, err := note.NewVerifier(vkey)
	if err != nil {
		return nil, nil, nil, err
	}
	// A verifier key is <name>+<hash>+<base64 of the algorithm byte and the
	// key>; the name has no "+", but the base64 may.
	parts := strings.SplitN(vkey, "+", 3)
	if len(parts) != 3 {
		return nil, nil, nil, fmt.Errorf("unexpected verifier key %q", vkey)
	}
	raw, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || len(raw) != 1+ed25519.PublicKeySize {
		return nil, nil, nil, fmt.Errorf("unexpected verifier key %q", vkey)
	}
	return signer, verifier, ed25519.PublicKey(raw[1:]), nil
}
