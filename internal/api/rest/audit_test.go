package rest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/J466Y/WhiteTower/api/events"
	"github.com/J466Y/WhiteTower/internal/api/rest/gen"
	"github.com/J466Y/WhiteTower/internal/audit"
	"github.com/J466Y/WhiteTower/internal/authz"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/clock/clocktest"
	"github.com/J466Y/WhiteTower/internal/platform/db"
	"github.com/J466Y/WhiteTower/internal/platform/db/dbtest"
	"github.com/J466Y/WhiteTower/internal/platform/keys"
	"github.com/J466Y/WhiteTower/internal/platform/metrics"
	"github.com/J466Y/WhiteTower/internal/platform/ratelimit"
	"github.com/J466Y/WhiteTower/pkg/auditverify"
)

type auditTestAuthenticator struct{}

func (auditTestAuthenticator) Authenticate(r *http.Request) (*auth.Principal, error) {
	switch role := r.Header.Get("X-Test-Role"); role {
	case "auditor":
		return &auth.Principal{ID: "00000000-0000-7000-8000-000000000002", Kind: auth.Human, Name: "Alice Auditor", Roles: []string{"auditor"}}, nil
	case "steering":
		return &auth.Principal{ID: "00000000-0000-7000-8000-000000000003", Kind: auth.Human, Name: "Steve Steering", Roles: []string{"steering"}}, nil
	case "operator":
		return &auth.Principal{ID: "00000000-0000-7000-8000-000000000004", Kind: auth.Human, Name: "Omar Operator", Roles: []string{"operator"}}, nil
	case "advisory":
		return &auth.Principal{ID: "00000000-0000-7000-8000-000000000005", Kind: auth.Human, Name: "Alex Advisory", Roles: []string{"advisory"}}, nil
	case "owner":
		return &auth.Principal{ID: "00000000-0000-7000-8000-000000000001", Kind: auth.Human, Name: "Olivia Owner", Roles: []string{"owner"}}, nil
	case "user":
		return &auth.Principal{ID: "00000000-0000-7000-8000-000000000006", Kind: auth.Human, Name: "Ursula User", Roles: []string{"user"}}, nil
	case "admin":
		return &auth.Principal{ID: "00000000-0000-7000-8000-000000000007", Kind: auth.Human, Name: "Arthur Admin", Roles: []string{"admin"}}, nil
	default:
		return nil, nil
	}
}

func newAuditTestKey(t *testing.T) keys.Ed25519 {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return keys.NewEd25519(private)
}

func setupAuditTestServer(t *testing.T, auditLog *audit.Log) http.Handler {
	t.Helper()
	authorizer := authz.NewAuthorizer()
	return Handler(Options{
		Logger:        slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Authenticator: auditTestAuthenticator{},
		Authorizer:    authorizer,
		Limiter:       ratelimit.New(10000, 10000),
		AuditLog:      auditLog,
	})
}

// Security test ST-12: Reads of the audit log are themselves audited (AUD-09)
func TestAuditQueryEndpoints(t *testing.T) {
	d := dbtest.New(t)
	pool := d.Open(t)
	ctx := context.Background()

	clk := clocktest.New(time.Date(2026, 10, 16, 10, 0, 0, 0, time.UTC))
	catalog, err := audit.LoadCatalog(events.Files)
	if err != nil {
		t.Fatal(err)
	}
	writer := audit.NewWriter(catalog, clk)
	key := newAuditTestKey(t)
	origin := "whitetower.test/audit"
	sealer := audit.NewSealer(audit.SealerOptions{
		DB:       pool,
		Writer:   writer,
		Key:      key,
		Origin:   origin,
		Interval: time.Minute,
		Clock:    clk,
		Logger:   slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Metrics:  metrics.NewAudit(prometheus.NewRegistry()),
	})

	// Seed database with principals, use case, agents and ownership.
	oliviaID := "00000000-0000-7000-8000-000000000001"
	auditorID := "00000000-0000-7000-8000-000000000002"
	useCaseID := "00000000-0000-7000-8000-000000000010"
	agent1ID := "00000000-0000-7000-8000-000000000021"
	agent2ID := "00000000-0000-7000-8000-000000000022"

	su := d.Superuser(t)
	for _, stmt := range []string{
		fmt.Sprintf("INSERT INTO whitetower.principals (id, kind, issuer, subject, display_name, email) VALUES ('%s', 'human', 'http://idp', 'olivia', 'Olivia Owner', 'owner@example.test')", oliviaID),
		fmt.Sprintf("INSERT INTO whitetower.principals (id, kind, issuer, subject, display_name, email) VALUES ('%s', 'human', 'http://idp', 'alice', 'Alice Auditor', 'auditor@example.test')", auditorID),
		fmt.Sprintf("INSERT INTO whitetower.use_cases (id, title, description, business_justification, created_by) VALUES ('%s', 'UC1', 'desc', 'just', '%s')", useCaseID, oliviaID),
		fmt.Sprintf("INSERT INTO whitetower.agents (id, slug, name, description, kind, risk_tier, use_case_id, created_by) VALUES ('%s', 'agent-1', 'Agent One', 'desc', 'in_house', 'high', '%s', '%s')", agent1ID, useCaseID, oliviaID),
		fmt.Sprintf("INSERT INTO whitetower.agents (id, slug, name, description, kind, risk_tier, use_case_id, created_by) VALUES ('%s', 'agent-2', 'Agent Two', 'desc', 'in_house', 'high', '%s', '%s')", agent2ID, useCaseID, auditorID),
		fmt.Sprintf("INSERT INTO whitetower.agent_owners (id, agent_id, principal_id, role, assigned_by) VALUES (gen_random_uuid(), '%s', '%s', 'primary', '%s')", agent1ID, oliviaID, oliviaID),
		fmt.Sprintf("INSERT INTO whitetower.agent_owners (id, agent_id, principal_id, role, assigned_by) VALUES (gen_random_uuid(), '%s', '%s', 'primary', '%s')", agent2ID, auditorID, auditorID),
	} {
		if _, err := su.Exec(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}

	// Record test events.
	var eventIDs []uuid.UUID
	for i := 0; i < 4; i++ {
		clk.Advance(time.Second)
		var e audit.Event
		switch i {
		case 0:
			e = audit.Event{
				Type:    "whitetower.agent.created.v1",
				Subject: agent1ID,
				Data: map[string]any{
					"slug":          "agent-1",
					"kind":          "in_house",
					"risk_tier":     "high",
					"use_case_id":   useCaseID,
					"primary_owner": oliviaID,
					"actor":         map[string]any{"type": "human", "id": oliviaID},
					"state_version": 1,
				},
			}
		case 1:
			e = audit.Event{
				Type:    "whitetower.token.created.v1",
				Subject: oliviaID,
				Data: map[string]any{
					"token_id":     uuid.New().String(),
					"principal_id": oliviaID,
					"token_prefix": "wt_pat_test1",
					"scopes":       []string{"inventory.view"},
					"actor":        map[string]any{"type": "human", "id": oliviaID},
				},
			}
		case 2:
			e = audit.Event{
				Type:    "whitetower.agent.created.v1",
				Subject: agent2ID,
				Data: map[string]any{
					"slug":          "agent-2",
					"kind":          "in_house",
					"risk_tier":     "high",
					"use_case_id":   useCaseID,
					"primary_owner": auditorID,
					"actor":         map[string]any{"type": "human", "id": auditorID},
					"state_version": 1,
				},
			}
		case 3:
			e = audit.Event{
				Type: "whitetower.breakglass.used.v1",
				Data: map[string]any{
					"actor":      map[string]any{"type": "breakglass", "id": "00000000-0000-0000-0000-000000000001"},
					"expires_at": clk.Now().Add(time.Hour).Format("2006-01-02T15:04:05.000Z"),
				},
			}
		}

		err := pool.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
			return writer.Record(ctx, tx, e)
		})
		if err != nil {
			t.Fatalf("recording event %d: %v", i, err)
		}
	}

	// Read recorded event IDs from database.
	rows, err := su.Query(ctx, "SELECT id FROM whitetower.audit_events ORDER BY event_time ASC")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		eventIDs = append(eventIDs, id)
	}
	rows.Close()

	if len(eventIDs) != 4 {
		t.Fatalf("expected 4 events recorded, got %d", len(eventIDs))
	}

	// Advance clock past checkpoint interval and seal batch into Merkle tree.
	clk.Advance(2 * time.Minute)
	if err := sealer.Round(ctx); err != nil {
		t.Fatalf("sealer round: %v", err)
	}

	// Record an unsealed event (5th event).
	clk.Advance(time.Second)
	unsealedEvent := audit.Event{
		Type:    "whitetower.token.created.v1",
		Subject: oliviaID,
		Data: map[string]any{
			"token_id":     uuid.New().String(),
			"principal_id": oliviaID,
			"token_prefix": "wt_pat_unsealed",
			"scopes":       []string{"inventory.view"},
			"actor":        map[string]any{"type": "human", "id": oliviaID},
		},
	}
	if err := pool.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		return writer.Record(ctx, tx, unsealedEvent)
	}); err != nil {
		t.Fatalf("recording unsealed event: %v", err)
	}

	var unsealedID uuid.UUID
	if err := su.QueryRow(ctx, "SELECT id FROM whitetower.audit_events WHERE canonical LIKE '%wt_pat_unsealed%'").Scan(&unsealedID); err != nil {
		t.Fatalf("finding unsealed event ID: %v", err)
	}

	auditLog := audit.NewLog(pool).WithWriter(writer)
	handler := setupAuditTestServer(t, auditLog)

	t.Run("QueryEventsAsAuditorWithPaginationAndFilters", func(t *testing.T) {
		// List all events (should return 5 total: 4 sealed + 1 unsealed).
		res := callWithRole(handler, "/api/v1/audit/events", "auditor")
		if res.status != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", res.status, res.body)
		}

		var list gen.AuditEventList
		if err := json.Unmarshal(res.body, &list); err != nil {
			t.Fatalf("decoding response: %v", err)
		}
		if len(list.Events) < 5 {
			t.Fatalf("expected at least 5 events, got %d", len(list.Events))
		}

		// Keyset cursor pagination with limit 2.
		res1 := callWithRole(handler, "/api/v1/audit/events?limit=2", "auditor")
		if res1.status != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", res1.status, res1.body)
		}
		var page1 gen.AuditEventList
		if err := json.Unmarshal(res1.body, &page1); err != nil {
			t.Fatal(err)
		}
		if len(page1.Events) != 2 {
			t.Fatalf("expected 2 events on page 1, got %d", len(page1.Events))
		}
		if page1.NextCursor == nil || *page1.NextCursor == "" {
			t.Fatal("expected nextCursor on page 1")
		}

		// Page 2 with cursor.
		urlPage2 := fmt.Sprintf("/api/v1/audit/events?limit=2&cursor=%s", *page1.NextCursor)
		res2 := callWithRole(handler, urlPage2, "auditor")
		if res2.status != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", res2.status, res2.body)
		}
		var page2 gen.AuditEventList
		if err := json.Unmarshal(res2.body, &page2); err != nil {
			t.Fatal(err)
		}
		if len(page2.Events) != 2 {
			t.Fatalf("expected 2 events on page 2, got %d", len(page2.Events))
		}
		if page2.Events[0].Id == page1.Events[0].Id || page2.Events[0].Id == page1.Events[1].Id {
			t.Fatal("page 2 contains duplicates from page 1")
		}

		// Filter by agentId.
		urlAgent := fmt.Sprintf("/api/v1/audit/events?agentId=%s", agent1ID)
		resAgent := callWithRole(handler, urlAgent, "auditor")
		if resAgent.status != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", resAgent.status, resAgent.body)
		}
		var agentEvents gen.AuditEventList
		if err := json.Unmarshal(resAgent.body, &agentEvents); err != nil {
			t.Fatal(err)
		}
		for _, ev := range agentEvents.Events {
			if ev.Subject == nil || *ev.Subject != agent1ID {
				t.Errorf("expected subject %s, got %v", agent1ID, ev.Subject)
			}
		}

		// Filter by event type.
		resType := callWithRole(handler, "/api/v1/audit/events?type=whitetower.token.created.v1", "auditor")
		if resType.status != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", resType.status, resType.body)
		}
		var typeEvents gen.AuditEventList
		if err := json.Unmarshal(resType.body, &typeEvents); err != nil {
			t.Fatal(err)
		}
		for _, ev := range typeEvents.Events {
			if ev.Type != "whitetower.token.created.v1" {
				t.Errorf("expected token.created type, got %s", ev.Type)
			}
		}
	})

	t.Run("QueryEventsRoleScopedPermissions", func(t *testing.T) {
		// Steering, advisory, operator can see everything.
		for _, role := range []string{"steering", "advisory", "operator"} {
			res := callWithRole(handler, "/api/v1/audit/events", role)
			if res.status != http.StatusOK {
				t.Errorf("expected 200 for %s, got %d", role, res.status)
			}
		}

		// Owner querying without agentId sees only events for owned agent1, NOT agent2.
		resOwner := callWithRole(handler, "/api/v1/audit/events", "owner")
		if resOwner.status != http.StatusOK {
			t.Fatalf("expected 200 for owner, got %d: %s", resOwner.status, resOwner.body)
		}
		var ownerList gen.AuditEventList
		if err := json.Unmarshal(resOwner.body, &ownerList); err != nil {
			t.Fatal(err)
		}
		for _, ev := range ownerList.Events {
			if ev.Subject == nil || *ev.Subject != agent1ID {
				t.Errorf("owner saw event for unowned subject %v", ev.Subject)
			}
		}

		// Owner querying for owned agent1 -> 200 OK.
		resOwned := callWithRole(handler, fmt.Sprintf("/api/v1/audit/events?agentId=%s", agent1ID), "owner")
		if resOwned.status != http.StatusOK {
			t.Errorf("expected 200 for owner on owned agent, got %d", resOwned.status)
		}

		// Owner querying for unowned agent2 -> 403 Forbidden.
		resUnowned := callWithRole(handler, fmt.Sprintf("/api/v1/audit/events?agentId=%s", agent2ID), "owner")
		if resUnowned.status != http.StatusForbidden {
			t.Errorf("expected 403 for owner on unowned agent, got %d", resUnowned.status)
		}

		// User and Admin denied by default.
		for _, role := range []string{"user", "admin"} {
			res := callWithRole(handler, "/api/v1/audit/events", role)
			if res.status != http.StatusForbidden {
				t.Errorf("expected 403 for %s, got %d", role, res.status)
			}
		}

		// Anonymous -> 401 Unauthenticated.
		resAnon := callWithRole(handler, "/api/v1/audit/events", "")
		if resAnon.status != http.StatusUnauthorized {
			t.Errorf("expected 401 for anonymous, got %d", resAnon.status)
		}
	})

	t.Run("GetAuditEventWithInclusionProofAndVerification", func(t *testing.T) {
		// Event 0 is sealed in the checkpoint.
		sealedID := eventIDs[0]
		urlEvent := fmt.Sprintf("/api/v1/audit/events/%s", sealedID)
		res := callWithRole(handler, urlEvent, "auditor")
		if res.status != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", res.status, res.body)
		}

		var detail gen.AuditEventDetail
		if err := json.Unmarshal(res.body, &detail); err != nil {
			t.Fatalf("decoding detail: %v", err)
		}
		if detail.Event.Id != sealedID {
			t.Fatalf("expected event ID %s, got %s", sealedID, detail.Event.Id)
		}
		if detail.Proof == nil {
			t.Fatal("expected non-nil inclusion proof for sealed event")
		}

		// Cryptographically verify inclusion proof using pkg/auditverify.
		rawKeys, err := auditLog.CheckpointKeys(ctx)
		if err != nil {
			t.Fatalf("reading checkpoint keys: %v", err)
		}
		pubKey, err := auditverify.ParseJWK(rawKeys[0])
		if err != nil {
			t.Fatalf("parsing JWK: %v", err)
		}
		verifierKeys, err := auditverify.NewKeys(origin, pubKey)
		if err != nil {
			t.Fatalf("creating auditverify.Keys: %v", err)
		}

		cp, err := auditverify.OpenCheckpoint([]byte(detail.Proof.Checkpoint), verifierKeys)
		if err != nil {
			t.Fatalf("verifying checkpoint signed note: %v", err)
		}

		proofHashes := make([]auditverify.Hash, len(detail.Proof.Hashes))
		for i, hStr := range detail.Proof.Hashes {
			b, err := base64.StdEncoding.DecodeString(hStr)
			if err != nil {
				t.Fatalf("decoding proof hash %d: %v", i, err)
			}
			copy(proofHashes[i][:], b)
		}

		err = auditverify.CheckInclusion(proofHashes, cp, detail.Proof.LeafIndex, []byte(detail.Event.Canonical))
		if err != nil {
			t.Fatalf("CheckInclusion failed: %v", err)
		}

		// Event that is unsealed -> proof is null.
		resUnsealed := callWithRole(handler, fmt.Sprintf("/api/v1/audit/events/%s", unsealedID), "auditor")
		if resUnsealed.status != http.StatusOK {
			t.Fatalf("expected 200, got %d", resUnsealed.status)
		}
		var unsealedDetail gen.AuditEventDetail
		if err := json.Unmarshal(resUnsealed.body, &unsealedDetail); err != nil {
			t.Fatal(err)
		}
		if unsealedDetail.Proof != nil {
			t.Errorf("expected nil proof for unsealed event, got %+v", unsealedDetail.Proof)
		}

		// Non-existent event -> 404.
		resMissing := callWithRole(handler, fmt.Sprintf("/api/v1/audit/events/%s", uuid.New()), "auditor")
		if resMissing.status != http.StatusNotFound {
			t.Errorf("expected 404 for missing event, got %d", resMissing.status)
		}

		// Owner permissions on single event:
		// Event 0 belongs to agent1 (owned) -> 200.
		resOwnerOwned := callWithRole(handler, urlEvent, "owner")
		if resOwnerOwned.status != http.StatusOK {
			t.Errorf("expected 200 for owner on owned event, got %d", resOwnerOwned.status)
		}
		// Event 2 belongs to agent2 (not owned) -> 403.
		resOwnerUnowned := callWithRole(handler, fmt.Sprintf("/api/v1/audit/events/%s", eventIDs[2]), "owner")
		if resOwnerUnowned.status != http.StatusForbidden {
			t.Errorf("expected 403 for owner on unowned event, got %d", resOwnerUnowned.status)
		}
		// Event 3 has no agent -> 403.
		resOwnerNoAgent := callWithRole(handler, fmt.Sprintf("/api/v1/audit/events/%s", eventIDs[3]), "owner")
		if resOwnerNoAgent.status != http.StatusForbidden {
			t.Errorf("expected 403 for owner on event with no agent, got %d", resOwnerNoAgent.status)
		}
	})

	t.Run("GetAuditCheckpointsAndKeys", func(t *testing.T) {
		// Auditor can view checkpoints.
		resCP := callWithRole(handler, "/api/v1/audit/checkpoints", "auditor")
		if resCP.status != http.StatusOK {
			t.Fatalf("expected 200 for checkpoints, got %d: %s", resCP.status, resCP.body)
		}
		var checkpoints []gen.AuditCheckpoint
		if err := json.Unmarshal(resCP.body, &checkpoints); err != nil {
			t.Fatal(err)
		}
		if len(checkpoints) == 0 {
			t.Fatal("expected at least 1 checkpoint")
		}
		if checkpoints[0].TreeSize <= 0 {
			t.Errorf("invalid checkpoint treeSize: %d", checkpoints[0].TreeSize)
		}

		// Owner cannot view checkpoints (no audit.verify permission).
		resOwnerCP := callWithRole(handler, "/api/v1/audit/checkpoints", "owner")
		if resOwnerCP.status != http.StatusForbidden {
			t.Errorf("expected 403 for owner on checkpoints, got %d", resOwnerCP.status)
		}

		// Auditor can view keys.
		resKeys := callWithRole(handler, "/api/v1/audit/keys", "auditor")
		if resKeys.status != http.StatusOK {
			t.Fatalf("expected 200 for keys, got %d: %s", resKeys.status, resKeys.body)
		}
		var jwks []map[string]any
		if err := json.Unmarshal(resKeys.body, &jwks); err != nil {
			t.Fatal(err)
		}
		if len(jwks) == 0 {
			t.Fatal("expected at least 1 JWK")
		}
		if jwks[0]["kty"] != "OKP" || jwks[0]["crv"] != "Ed25519" {
			t.Errorf("unexpected JWK: %+v", jwks[0])
		}

		// Owner cannot view keys.
		resOwnerKeys := callWithRole(handler, "/api/v1/audit/keys", "owner")
		if resOwnerKeys.status != http.StatusForbidden {
			t.Errorf("expected 403 for owner on keys, got %d", resOwnerKeys.status)
		}
	})

	t.Run("SecurityTestST12_ReadsAreAudited", func(t *testing.T) {
		// Security test ST-12: Reads of the audit log are themselves audited (AUD-09)
		// Clear or record current count of read events.
		var initialCount int
		if err := su.QueryRow(ctx, "SELECT count(*) FROM whitetower.audit_events WHERE type = 'whitetower.audit.read.v1'").Scan(&initialCount); err != nil {
			t.Fatal(err)
		}

		// Perform a query read as auditor.
		clk.Advance(time.Minute)
		res := callWithRole(handler, fmt.Sprintf("/api/v1/audit/events?agentId=%s", agent1ID), "auditor")
		if res.status != http.StatusOK {
			t.Fatalf("query failed: %d %s", res.status, res.body)
		}

		// Check that a read event was recorded in the database.
		var newCount int
		if err := su.QueryRow(ctx, "SELECT count(*) FROM whitetower.audit_events WHERE type = 'whitetower.audit.read.v1'").Scan(&newCount); err != nil {
			t.Fatal(err)
		}
		if newCount <= initialCount {
			t.Fatalf("expected read audit event to be written; initial=%d, new=%d", initialCount, newCount)
		}

		// Inspect the latest recorded read event.
		var canonical []byte
		var actorID, actorType, action, outcome string
		err := su.QueryRow(ctx, `
			SELECT actor_id, actor_type, action, outcome, canonical
			FROM whitetower.audit_events
			WHERE type = 'whitetower.audit.read.v1'
			ORDER BY event_time DESC, id DESC LIMIT 1
		`).Scan(&actorID, &actorType, &action, &outcome, &canonical)
		if err != nil {
			t.Fatalf("reading latest audit.read event: %v", err)
		}

		if actorID != auditorID {
			t.Errorf("expected actor_id %s, got %s", auditorID, actorID)
		}
		if actorType != "human" {
			t.Errorf("expected actor_type human, got %s", actorType)
		}
		if outcome != "success" {
			t.Errorf("expected outcome success, got %s", outcome)
		}

		var eventData struct {
			Data struct {
				Operation string         `json:"operation"`
				Query     map[string]any `json:"query"`
			} `json:"data"`
		}
		if err := json.Unmarshal(canonical, &eventData); err != nil {
			t.Fatalf("parsing read event JSON: %v", err)
		}
		if eventData.Data.Operation != "query" {
			t.Errorf("expected operation query, got %s", eventData.Data.Operation)
		}
		if eventData.Data.Query["agent_id"] != agent1ID {
			t.Errorf("expected query.agent_id %s, got %v", agent1ID, eventData.Data.Query["agent_id"])
		}
	})
}

func callWithRole(h http.Handler, target, role string) result {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	if role != "" {
		r.Header.Set("X-Test-Role", role)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return result{rec.Code, rec.Header(), rec.Body.Bytes()}
}
