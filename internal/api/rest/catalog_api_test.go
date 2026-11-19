package rest_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/J466Y/WhiteTower/api/events"
	"github.com/J466Y/WhiteTower/internal/api/rest"
	"github.com/J466Y/WhiteTower/internal/api/rest/resttest"
	"github.com/J466Y/WhiteTower/internal/audit"
	"github.com/J466Y/WhiteTower/internal/authn"
	"github.com/J466Y/WhiteTower/internal/authz"
	"github.com/J466Y/WhiteTower/internal/catalog"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/clock/clocktest"
	"github.com/J466Y/WhiteTower/internal/platform/db/dbtest"
	"github.com/J466Y/WhiteTower/pkg/apiclient"
)

// The callers of the catalog's reads: an auditor's session, which may view
// the catalog; an auditor's API tokens with and without catalog.view among
// their scopes; and a break-glass session, which may not.
var (
	auditor = auth.Principal{ID: "0192f2c4-8d1e-7c3a-9b2f-5e1d2c3b4a70", Kind: auth.Human, Roles: []string{"auditor"}}
	scoped  = auth.Principal{
		ID: auditor.ID, Kind: auth.Human, Roles: auditor.Roles,
		Scopes: []string{string(authz.PermissionInventoryView), string(authz.PermissionCatalogView)},
	}
	unscoped = auth.Principal{
		ID: auditor.ID, Kind: auth.Human, Roles: auditor.Roles, Scopes: []string{string(authz.PermissionInventoryView)},
	}
	custodian = auth.Principal{
		ID: authn.BreakglassPrincipalID.String(), Kind: auth.Human, Roles: []string{string(authz.RoleOperator)},
		Scopes: authn.BreakglassScopes, IsBreakglass: true,
	}
)

// The definition that the catalog stores has an integer beyond 2^53, which
// encoding it again would round.
const storedDefinition = `{"inputSchema":{"properties":{"id":{"maximum":18446744073709551615,"type":"integer"}},"type":"object"},"name":"create_issue"}`

// catalogAPI serves the public API, with the real authorizer, over a catalog
// that one agent's report filled, and returns it with the stored
// definition's hash.
func catalogAPI(t *testing.T) (*resttest.Server, string) {
	t.Helper()
	ctx := context.Background()
	pool := dbtest.New(t).Open(t)
	eventCatalog, err := audit.LoadCatalog(events.Files)
	if err != nil {
		t.Fatal(err)
	}
	clk := clocktest.New(time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC))
	person, useCase, agent := uuid.New(), uuid.New(), uuid.New()
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO whitetower.principals (id, kind, issuer, subject, display_name) VALUES ($1, 'human', 'https://idp.example.com', $2, 'Olivia Owner')`, []any{person, person.String()}},
		{`INSERT INTO whitetower.use_cases (id, title, description, business_justification, created_by) VALUES ($1, 'Use', 'Use.', 'Use.', $2)`, []any{useCase, person}},
		{`INSERT INTO whitetower.agents (id, slug, name, description, kind, risk_tier, use_case_id, created_by)
		  VALUES ($1, 'invoice-triage', 'Invoice triage', 'An agent.', 'in_house', 'low', $2, $3)`, []any{agent, useCase, person}},
	} {
		if _, err := pool.Exec(ctx, stmt.sql, stmt.args...); err != nil {
			t.Fatal(err)
		}
	}
	sum := sha256.Sum256([]byte(storedDefinition))
	hash := hex.EncodeToString(sum[:])
	if _, err := pool.Exec(ctx, `INSERT INTO whitetower.catalog_tool_definitions (definition_sha256, canonical, stored_at) VALUES ($1, $2, $3)`,
		sum[:], []byte(storedDefinition), clk.Now()); err != nil {
		t.Fatal(err)
	}
	cat := catalog.New(catalog.Options{DB: pool, Clock: clk, Writer: audit.NewWriter(eventCatalog, clk)})
	server := 0
	if _, err := cat.RecordReport(ctx, catalog.ReportCaller{Instance: uuid.New(), Agents: []uuid.UUID{agent}}, catalog.Report{
		Agent: agent,
		Servers: []catalog.ReportedServer{
			{Reference: "https://api.githubcopilot.com/mcp/", Transport: "http", Origin: "agent"},
			{Reference: `stdio:["npx","-y","server-fs"]`, Transport: "stdio", Origin: "agent", Name: "files"},
		},
		Tools: []catalog.ReportedTool{
			{Kind: "mcp", Origin: "agent", Server: &server, Name: "create_issue", Definition: hash},
			{Kind: "function", Origin: "agent", Name: "send_email"},
			{Kind: "builtin", Origin: "provider", Provider: "openai", Type: "web_search", Name: "web_search"},
		},
		Models: []catalog.ReportedModel{
			{Provider: "openai", Endpoint: "https://api.openai.com/v1", Name: "gpt-4o"},
			{Provider: "ollama", Endpoint: "http://gpu-01.internal:11434/", Name: "llama3.1:8b", Digest: "46e0"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	return resttest.New(t, rest.Options{Authorizer: authz.NewAuthorizer(), Catalog: cat}), hash
}

func TestTheCatalogsReadsThroughTheAPI(t *testing.T) {
	api, hash := catalogAPI(t)
	ctx := context.Background()

	// Servers a page at a time, by key.
	var keys []string
	params := &apiclient.ListCatalogServersParams{Limit: new(1)}
	for {
		res, err := api.Client.ListCatalogServersWithResponse(ctx, params, resttest.As(auditor))
		if err != nil || res.JSON200 == nil {
			t.Fatalf("%v %d %s", err, res.StatusCode(), res.Body)
		}
		for _, s := range res.JSON200.Servers {
			keys = append(keys, s.Key)
		}
		if res.JSON200.NextCursor == nil {
			break
		}
		params.Cursor = res.JSON200.NextCursor
	}
	if len(keys) != 2 || keys[0] != "files" || keys[1] != "githubcopilot" {
		t.Fatalf("server pages %v", keys)
	}

	// A server, with its ETag, and what it shows.
	list, err := api.Client.ListCatalogServersWithResponse(ctx, &apiclient.ListCatalogServersParams{Key: new("files")}, resttest.As(auditor))
	if err != nil || list.JSON200 == nil || len(list.JSON200.Servers) != 1 {
		t.Fatalf("%v %s", err, list.Body)
	}
	got, err := api.Client.GetCatalogServerWithResponse(ctx, list.JSON200.Servers[0].Id, resttest.As(auditor))
	if err != nil || got.JSON200 == nil {
		t.Fatalf("%v %s", err, got.Body)
	}
	if s := got.JSON200; s.Reference != `stdio:["npx","-y","server-fs"]` || s.Status != "discovered" || !s.PendingReview ||
		s.Blocked || len(s.Flags) != 1 || s.Flags[0] != catalog.FlagUnpinnedPackage || got.HTTPResponse.Header.Get("ETag") != `"1"` {
		t.Fatalf("server %s, ETag %s", got.Body, got.HTTPResponse.Header.Get("ETag"))
	}

	// Tools a page at a time, by key and ID, and a tool.
	var toolKeys []string
	toolParams := &apiclient.ListCatalogToolsParams{Limit: new(2)}
	for {
		res, err := api.Client.ListCatalogToolsWithResponse(ctx, toolParams, resttest.As(auditor))
		if err != nil || res.JSON200 == nil {
			t.Fatalf("%v %s", err, res.Body)
		}
		for _, tool := range res.JSON200.Tools {
			toolKeys = append(toolKeys, tool.Key)
		}
		if res.JSON200.NextCursor == nil {
			break
		}
		toolParams.Cursor = res.JSON200.NextCursor
	}
	if len(toolKeys) != 3 || toolKeys[0] != "agent/send_email" || toolKeys[1] != "githubcopilot/create_issue" ||
		toolKeys[2] != "provider.openai/web_search" {
		t.Fatalf("tool pages %v", toolKeys)
	}
	tools, err := api.Client.ListCatalogToolsWithResponse(ctx, &apiclient.ListCatalogToolsParams{Key: new("githubcopilot/create_issue")}, resttest.As(auditor))
	if err != nil || tools.JSON200 == nil || len(tools.JSON200.Tools) != 1 {
		t.Fatalf("%v %s", err, tools.Body)
	}
	tool, err := api.Client.GetCatalogToolWithResponse(ctx, tools.JSON200.Tools[0].Id, resttest.As(auditor))
	if err != nil || tool.JSON200 == nil {
		t.Fatalf("%v %s", err, tool.Body)
	}
	if tt := tool.JSON200; tt.Kind != "mcp" || tt.ServerId == nil || tt.DefinitionSha256 != nil ||
		len(tt.PendingDefinitions) != 1 || tt.PendingDefinitions[0] != hash || len(tt.Arguments) != 0 {
		t.Fatalf("tool %s", tool.Body)
	}

	// Models, and a model.
	models, err := api.Client.ListCatalogModelsWithResponse(ctx, &apiclient.ListCatalogModelsParams{Provider: new("ollama")}, resttest.As(auditor))
	if err != nil || models.JSON200 == nil || len(models.JSON200.Models) != 1 {
		t.Fatalf("%v %s", err, models.Body)
	}
	model, err := api.Client.GetCatalogModelWithResponse(ctx, models.JSON200.Models[0].Id, resttest.As(auditor))
	if err != nil || model.JSON200 == nil {
		t.Fatalf("%v %s", err, model.Body)
	}
	if m := model.JSON200; m.Key != "gpu-01/llama3.1-8b" || m.Digest != nil || len(m.PendingDigests) != 1 || m.PendingDigests[0] != "46e0" {
		t.Fatalf("model %s", model.Body)
	}

	// What the catalog does not hold is not found, and a filter it does not
	// know is refused.
	missing, err := api.Client.GetCatalogToolWithResponse(ctx, uuid.New(), resttest.As(auditor))
	if err != nil || missing.StatusCode() != http.StatusNotFound {
		t.Fatalf("an unknown tool: %v %d", err, missing.StatusCode())
	}
	flagged, err := api.Client.ListCatalogModelsWithResponse(ctx, &apiclient.ListCatalogModelsParams{Flag: &[]string{"unpinned"}}, resttest.As(auditor))
	if err != nil || flagged.StatusCode() != http.StatusBadRequest {
		t.Fatalf("an unknown flag: %v %d %s", err, flagged.StatusCode(), flagged.Body)
	}
	cursor, err := api.Client.ListCatalogToolsWithResponse(ctx, &apiclient.ListCatalogToolsParams{Cursor: new("not-a-cursor")}, resttest.As(auditor))
	if err != nil || cursor.StatusCode() != http.StatusBadRequest {
		t.Fatalf("a bad cursor: %v %d", err, cursor.StatusCode())
	}
}

// getToolDefinition answers with the stored bytes exactly as stored, so that
// their SHA-256 is the hash in the path, and as JSON only.
func TestADefinitionIsServedExactlyAsStored(t *testing.T) {
	api, hash := catalogAPI(t)
	res, err := api.Client.GetToolDefinitionWithResponse(context.Background(), hash, resttest.As(auditor))
	if err != nil || res.StatusCode() != http.StatusOK {
		t.Fatalf("%v %d %s", err, res.StatusCode(), res.Body)
	}
	sum := sha256.Sum256(res.Body)
	h := res.HTTPResponse.Header
	if string(res.Body) != storedDefinition || hex.EncodeToString(sum[:]) != hash {
		t.Fatalf("body %s, want %s", res.Body, storedDefinition)
	}
	if h.Get("Content-Type") != "application/json" || h.Get("X-Content-Type-Options") != "nosniff" ||
		h.Get("Content-Security-Policy") == "" || h.Get("ETag") != `"`+hash+`"` {
		t.Fatalf("headers %v", h)
	}

	// A hash the catalog does not store is not found, and a malformed one
	// refused.
	unknown := sha256.Sum256([]byte("unknown"))
	missing, err := api.Client.GetToolDefinitionWithResponse(context.Background(), hex.EncodeToString(unknown[:]), resttest.As(auditor))
	if err != nil || missing.StatusCode() != http.StatusNotFound {
		t.Fatalf("an unknown definition: %v %d", err, missing.StatusCode())
	}
	malformed, err := api.Client.GetToolDefinitionWithResponse(context.Background(), "ABCDEF", resttest.As(auditor))
	if err != nil || malformed.StatusCode() != http.StatusBadRequest {
		t.Fatalf("a malformed hash: %v %d", err, malformed.StatusCode())
	}
}

// The reads answer with references and reported text, so the authorizer
// refuses them to an API token without catalog.view, whatever the roles of
// its holder, and to a break-glass session (RFC-0002, Privacy; HUM-06).
func TestOnlyHoldersOfCatalogViewReadTheCatalog(t *testing.T) {
	api, hash := catalogAPI(t)
	ctx := context.Background()
	reads := map[string]func(auth.Principal) (*http.Response, error){
		"listCatalogServers": func(p auth.Principal) (*http.Response, error) {
			return api.Client.ListCatalogServers(ctx, nil, resttest.As(p))
		},
		"getCatalogServer": func(p auth.Principal) (*http.Response, error) {
			return api.Client.GetCatalogServer(ctx, uuid.New(), resttest.As(p))
		},
		"listCatalogTools": func(p auth.Principal) (*http.Response, error) {
			return api.Client.ListCatalogTools(ctx, nil, resttest.As(p))
		},
		"getCatalogTool": func(p auth.Principal) (*http.Response, error) {
			return api.Client.GetCatalogTool(ctx, uuid.New(), resttest.As(p))
		},
		"getToolDefinition": func(p auth.Principal) (*http.Response, error) {
			return api.Client.GetToolDefinition(ctx, hash, resttest.As(p))
		},
		"listCatalogModels": func(p auth.Principal) (*http.Response, error) {
			return api.Client.ListCatalogModels(ctx, nil, resttest.As(p))
		},
		"getCatalogModel": func(p auth.Principal) (*http.Response, error) {
			return api.Client.GetCatalogModel(ctx, uuid.New(), resttest.As(p))
		},
	}
	for name, read := range reads {
		for _, tt := range []struct {
			who     string
			p       auth.Principal
			allowed bool
		}{
			{"a token with catalog.view", scoped, true},
			{"a token without catalog.view", unscoped, false},
			{"a break-glass session", custodian, false},
		} {
			res, err := read(tt.p)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(res.Body)
			_ = res.Body.Close()
			if refused := res.StatusCode == http.StatusForbidden; refused == tt.allowed {
				t.Errorf("%s by %s: %d %s", name, tt.who, res.StatusCode, body)
			}
		}
	}
}
