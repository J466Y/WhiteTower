package rest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/J466Y/WhiteTower/api/events"
	"github.com/J466Y/WhiteTower/internal/api/rest/gen"
	"github.com/J466Y/WhiteTower/internal/api/rest/problem"
	"github.com/J466Y/WhiteTower/internal/audit"
	"github.com/J466Y/WhiteTower/internal/authn"
	"github.com/J466Y/WhiteTower/internal/authz"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/clock/clocktest"
	"github.com/J466Y/WhiteTower/internal/platform/db/dbtest"
	"github.com/J466Y/WhiteTower/internal/platform/logging"
	"github.com/J466Y/WhiteTower/internal/platform/ratelimit"
)

const olivia = "0192f2c4-8d1e-7c3a-9b2f-5e1d2c3b4a59"

// testAuthenticator takes the principal from a test header: an ID, or "bad"
// for a credential that is not accepted.
type testAuthenticator struct{}

func (testAuthenticator) Authenticate(r *http.Request) (*auth.Principal, error) {
	switch id := r.Header.Get("X-Test-Principal"); id {
	case "":
		return nil, nil
	case "bad":
		return nil, errors.New("the signature does not verify")
	case "breakglass":
		return &auth.Principal{
			ID:           authn.BreakglassPrincipalID.String(),
			Kind:         auth.Human,
			Name:         "Custodian",
			Roles:        []string{"custodian"},
			IsBreakglass: true,
		}, nil
	default:
		if csrf := r.Header.Get("X-Test-CSRF-Token"); csrf != "" {
			*r = *r.WithContext(authn.ContextWithSession(r.Context(), &authn.Session{CSRFToken: csrf}))
		}
		return &auth.Principal{ID: id, Kind: auth.Human, Name: "Olivia Owner", Roles: []string{"owner"}}, nil
	}
}

// fixedAuthenticator authenticates every request as its principal.
type fixedAuthenticator struct{ p auth.Principal }

func (f fixedAuthenticator) Authenticate(*http.Request) (*auth.Principal, error) {
	p := f.p
	return &p, nil
}

// allow permits the named operations only, and records what it is asked.
type allow struct {
	mu    sync.Mutex
	ops   map[string]bool
	asked []string
}

func (a *allow) Authorize(_ context.Context, _ *auth.Principal, operation string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.asked = append(a.asked, operation)
	if a.ops[operation] {
		return nil
	}
	return auth.ErrDenied
}

func options(logs io.Writer) Options {
	return Options{
		Logger:        slog.New(slog.NewJSONHandler(logs, nil)),
		Authenticator: testAuthenticator{},
		Authorizer:    auth.DenyAll{},
		Limiter:       ratelimit.New(1000, 1000),
	}
}

type result struct {
	status int
	header http.Header
	body   []byte
}

func call(h http.Handler, method, target, principal string, header http.Header, body io.Reader) result {
	r := httptest.NewRequest(method, target, body)
	for k, v := range header {
		r.Header[k] = v
	}
	if principal != "" {
		r.Header.Set("X-Test-Principal", principal)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return result{rec.Code, rec.Header(), rec.Body.Bytes()}
}

// problemOf decodes a problem answer, checking what every problem shares.
func problemOf(t *testing.T, res result, code problem.Code) problem.Problem {
	t.Helper()
	if ct := res.header.Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("Content-Type %q, body %s", ct, res.body)
	}
	var p problem.Problem
	if err := json.Unmarshal(res.body, &p); err != nil {
		t.Fatal(err)
	}
	want := problem.Codes[code]
	if p.Code != code || p.Status != want.Status || res.status != want.Status ||
		p.Title != want.Title || p.Type != problem.TypeBase+string(code) {
		t.Fatalf("got %d %+v, want the %s problem", res.status, p, code)
	}
	return p
}

func TestVersionIsPublic(t *testing.T) {
	h := Handler(options(io.Discard))
	res := call(h, http.MethodGet, "/api/v1/version", "", nil, nil)
	if res.status != http.StatusOK || !bytes.Contains(res.body, []byte(`"apiVersion":"v1"`)) {
		t.Fatalf("got %d %s", res.status, res.body)
	}
	for name, want := range map[string]string{
		"Content-Security-Policy":      "default-src 'none'; frame-ancestors 'none'",
		"Cache-Control":                "no-store",
		"Cross-Origin-Resource-Policy": "same-origin",
	} {
		if got := res.header.Get(name); got != want {
			t.Errorf("%s: %q, want %q", name, got, want)
		}
	}
}

func TestMe(t *testing.T) {
	az := &allow{ops: map[string]bool{"getMe": true}}
	opts := options(io.Discard)
	opts.Authorizer = az
	h := Handler(opts)

	t.Run("anonymous", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
		r = r.WithContext(logging.WithRequest(r.Context(), olivia))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		p := problemOf(t, result{rec.Code, rec.Header(), rec.Body.Bytes()}, problem.Unauthenticated)
		if p.Instance != "urn:uuid:"+olivia {
			t.Errorf("instance %q, want the request ID", p.Instance)
		}
	})
	t.Run("credentials not accepted", func(t *testing.T) {
		problemOf(t, call(h, http.MethodGet, "/api/v1/me", "bad", nil, nil), problem.Unauthenticated)
	})
	t.Run("authenticated and permitted", func(t *testing.T) {
		res := call(h, http.MethodGet, "/api/v1/me", olivia, nil, nil)
		var me gen.Principal
		if err := json.Unmarshal(res.body, &me); err != nil || res.status != http.StatusOK {
			t.Fatalf("got %d %s", res.status, res.body)
		}
		if me.Id.String() != olivia || me.Kind != gen.PrincipalKindHuman || me.DisplayName != "Olivia Owner" || len(me.Roles) != 1 {
			t.Fatalf("got %+v", me)
		}
		if len(me.Permissions) == 0 {
			t.Fatalf("permissions are empty: %+v", me.Permissions)
		}
		if me.CsrfToken != nil {
			t.Fatalf("unexpected csrfToken: %v", *me.CsrfToken)
		}
		if strings.Join(az.asked, ",") != "getMe" {
			t.Fatalf("the authorizer was asked about %v, want the document's operationId", az.asked)
		}
	})
	t.Run("authenticated with session includes csrf token", func(t *testing.T) {
		header := http.Header{}
		header.Set("X-Test-CSRF-Token", "test-csrf-token-xyz")
		res := call(h, http.MethodGet, "/api/v1/me", olivia, header, nil)
		var me gen.Principal
		if err := json.Unmarshal(res.body, &me); err != nil || res.status != http.StatusOK {
			t.Fatalf("got %d %s", res.status, res.body)
		}
		if me.CsrfToken == nil || *me.CsrfToken != "test-csrf-token-xyz" {
			t.Fatalf("csrfToken %v, want test-csrf-token-xyz", me.CsrfToken)
		}
	})
	t.Run("authenticated with breakglass session has isBreakglass=true", func(t *testing.T) {
		res := call(h, http.MethodGet, "/api/v1/me", "breakglass", nil, nil)
		var me gen.Principal
		if err := json.Unmarshal(res.body, &me); err != nil || res.status != http.StatusOK {
			t.Fatalf("got %d %s", res.status, res.body)
		}
		if me.IsBreakglass == nil || !*me.IsBreakglass {
			t.Fatalf("expected isBreakglass=true, got %v", me.IsBreakglass)
		}
	})
	t.Run("authenticated but not permitted", func(t *testing.T) {
		problemOf(t, call(Handler(options(io.Discard)), http.MethodGet, "/api/v1/me", olivia, nil, nil), problem.Forbidden)
	})
}

// No operation of the document can be called without authorization: an
// anonymous caller reaches only the public ones, and an authenticated one
// only what the authorizer permits (security test ST-17 rests on it).
func TestEveryOperationIsGuarded(t *testing.T) {
	h := Handler(options(io.Discard))
	ops := operations()
	if len(ops) == 0 {
		t.Fatal("no operation found in the document")
	}
	for _, op := range ops {
		path, body := target(op)
		anonymous := call(h, op.Method, path, "", nil, body())
		denied := call(h, op.Method, path, olivia, nil, body())
		switch {
		case op.Public && (anonymous.status == http.StatusUnauthorized || anonymous.status == http.StatusForbidden):
			t.Errorf("%s, public: anonymous call refused with %d", op.ID, anonymous.status)
		case !op.Public && anonymous.status != http.StatusUnauthorized:
			t.Errorf("%s: anonymous call got %d, want 401", op.ID, anonymous.status)
		case !op.Public && denied.status != http.StatusForbidden:
			t.Errorf("%s: call the authorizer denies got %d, want 403", op.ID, denied.status)
		}
	}
}

// target is where a test calls op: its path, every parameter of which is an
// ID, and an empty JSON object as the body of a method that takes one.
func target(op operation) (string, func() io.Reader) {
	path := BasePath + op.Path
	for strings.Contains(path, "{") {
		start, end := strings.Index(path, "{"), strings.Index(path, "}")
		path = path[:start] + olivia + path[end+1:]
	}
	body := func() io.Reader { return nil }
	if op.Method == http.MethodPost || op.Method == http.MethodPut || op.Method == http.MethodPatch {
		body = func() io.Reader { return strings.NewReader("{}") }
	}
	return path, body
}

// Every operation that is not public maps to a permission: the authorizer
// refuses an operation it does not know to everyone.
func TestEveryOperationHasAPermission(t *testing.T) {
	az := authz.NewAuthorizer()
	for _, op := range operations() {
		if _, ok := az.ResolveOperation(op.ID); !op.Public && !ok {
			t.Errorf("%s maps to no permission", op.ID)
		}
	}
}

// Security test ST-20: A break-glass session changes nothing: the authorizer
// refuses it every operation of the document that is not a read, so a new
// one is covered without a list to keep up to date.
func TestBreakglassCallsNoOperationThatChangesState(t *testing.T) {
	az := authz.NewAuthorizer()
	custodian := &auth.Principal{
		ID:           authn.BreakglassPrincipalID.String(),
		Kind:         auth.Human,
		Roles:        []string{string(authz.RoleOperator)},
		Scopes:       authn.BreakglassScopes,
		IsBreakglass: true,
	}
	for _, op := range operations() {
		if op.Public || op.Method == http.MethodGet {
			continue
		}
		if err := az.Authorize(context.Background(), custodian, op.ID); !errors.Is(err, auth.ErrDenied) {
			t.Errorf("%s: break-glass got %v, want refused", op.ID, err)
		}
	}
}

func TestUnmatched(t *testing.T) {
	h := Handler(options(io.Discard))
	problemOf(t, call(h, http.MethodGet, "/api/v1/no/such/thing", "", nil, nil), problem.NotFound)
	res := call(h, http.MethodPost, "/api/v1/version", "", nil, strings.NewReader("{}"))
	problemOf(t, res, problem.MethodNotAllowed)
	if allow := res.header.Get("Allow"); allow != "GET" {
		t.Fatalf("Allow %q, want GET", allow)
	}
}

func TestTheDocumentIsServed(t *testing.T) {
	h := Handler(options(io.Discard))
	res := call(h, http.MethodGet, "/api/v1/openapi.json", "", nil, nil)
	var doc struct {
		OpenAPI string         `json:"openapi"`
		Paths   map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(res.body, &doc); err != nil || res.status != http.StatusOK {
		t.Fatalf("got %d: %v", res.status, err)
	}
	if doc.OpenAPI != "3.1.0" || doc.Paths["/me"] == nil {
		t.Fatalf("got openapi %q and paths %v", doc.OpenAPI, doc.Paths)
	}
	etag := res.header.Get("ETag")
	if etag == "" || res.header.Get("Cache-Control") != "no-cache" || res.header.Get("Content-Type") != "application/json" {
		t.Fatalf("headers %v", res.header)
	}
	if again := call(h, http.MethodGet, "/api/v1/openapi.json", "", http.Header{"If-None-Match": {etag}}, nil); again.status != http.StatusNotModified {
		t.Fatalf("revalidation got %d, want 304", again.status)
	}
}

func TestRateLimits(t *testing.T) {
	limited := 0
	opts := options(io.Discard)
	opts.Limiter = ratelimit.New(1, 2)
	opts.RateLimited = func() { limited++ }
	h := Handler(opts)
	from := func(addr, principal string) result {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
		r.RemoteAddr = addr
		if principal != "" {
			r.Header.Set("X-Test-Principal", principal)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return result{rec.Code, rec.Header(), rec.Body.Bytes()}
	}

	for range 2 {
		if res := from("198.51.100.7:4000", ""); res.status != http.StatusOK {
			t.Fatalf("within the burst: %d", res.status)
		}
	}
	res := from("198.51.100.7:4001", "")
	problemOf(t, res, problem.RateLimited)
	if res.header.Get("Retry-After") != "1" || limited != 1 {
		t.Fatalf("Retry-After %q, counted %d", res.header.Get("Retry-After"), limited)
	}
	if res := from("198.51.100.8:4000", ""); res.status != http.StatusOK {
		t.Fatal("another address shares the bucket")
	}

	// One IPv6 client holds a whole /64.
	from("[2001:db8:7:7::1]:4000", "")
	from("[2001:db8:7:7::2]:4000", "")
	if res := from("[2001:db8:7:7::3]:4000", ""); res.status != http.StatusTooManyRequests {
		t.Fatalf("a third address of the same /64 got %d, want 429", res.status)
	}

	// After login, each principal has its own bucket, wherever it calls from.
	for _, p := range []string{olivia, "0192f2c4-0000-7000-8000-000000000002"} {
		for range 2 {
			if res := from("198.51.100.7:4000", p); res.status != http.StatusOK {
				t.Fatalf("principal %s within its burst: %d", p, res.status)
			}
		}
	}
}

func TestErrorAnswers(t *testing.T) {
	t.Run("body too large", func(t *testing.T) {
		rec := httptest.NewRecorder()
		requestError(rec, httptest.NewRequest(http.MethodPost, "/", nil), fmt.Errorf("can't decode JSON body: %w", &http.MaxBytesError{Limit: 1 << 20}))
		problemOf(t, result{rec.Code, rec.Header(), rec.Body.Bytes()}, problem.PayloadTooLarge)
	})
	t.Run("body not JSON", func(t *testing.T) {
		rec := httptest.NewRecorder()
		requestError(rec, httptest.NewRequest(http.MethodPost, "/", nil), errors.New("invalid character"))
		problemOf(t, result{rec.Code, rec.Header(), rec.Body.Bytes()}, problem.BadRequest)
	})
	t.Run("parameter, named but not echoed", func(t *testing.T) {
		rec := httptest.NewRecorder()
		parameterError(rec, httptest.NewRequest(http.MethodGet, "/", nil),
			&gen.InvalidParamFormatError{ParamName: "limit", Err: errors.New("parsing 'canary-9f' as int")})
		p := problemOf(t, result{rec.Code, rec.Header(), rec.Body.Bytes()}, problem.BadRequest)
		if !strings.Contains(p.Detail, `"limit"`) || strings.Contains(rec.Body.String(), "canary-9f") {
			t.Fatalf("detail %q", p.Detail)
		}
	})
	t.Run("internal error, logged but not shown", func(t *testing.T) {
		var logs bytes.Buffer
		rec := httptest.NewRecorder()
		responseError(slog.New(slog.NewJSONHandler(&logs, nil)))(rec, httptest.NewRequest(http.MethodGet, "/", nil),
			errors.New("pq: connection to 10.0.0.5 refused"))
		problemOf(t, result{rec.Code, rec.Header(), rec.Body.Bytes()}, problem.Internal)
		if strings.Contains(rec.Body.String(), "10.0.0.5") || !strings.Contains(logs.String(), "10.0.0.5") {
			t.Fatalf("answer %s, logs %s", rec.Body.String(), logs.String())
		}
	})
}

// widgets is the sample resource of plan P1-01, step 5: a list that pages
// and items that update under If-Match, behind the API's middleware.
type widgets struct {
	mu    sync.Mutex
	items []widget
}

type widget struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	version int64
}

type position struct {
	After int `json:"after"`
}

func fail(w http.ResponseWriter, r *http.Request, err error) {
	if p, ok := errors.AsType[*problem.Problem](err); ok {
		problem.Write(w, r, p)
		return
	}
	problem.Write(w, r, problem.New(problem.Internal, ""))
}

func (ws *widgets) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /widgets", func(w http.ResponseWriter, r *http.Request) {
		var limit *int
		if s := r.URL.Query().Get("limit"); s != "" {
			n, err := strconv.Atoi(s)
			if err != nil {
				fail(w, r, problem.New(problem.BadRequest, "limit must be a number"))
				return
			}
			limit = &n
		}
		size, err := PageSize(limit)
		if err != nil {
			fail(w, r, err)
			return
		}
		var pos position
		if c := r.URL.Query().Get("cursor"); c != "" {
			if err := DecodeCursor(c, &pos); err != nil {
				fail(w, r, err)
				return
			}
		}
		ws.mu.Lock()
		var page []widget
		for _, it := range ws.items {
			if it.ID > pos.After {
				page = append(page, it)
			}
		}
		ws.mu.Unlock()
		resp := struct {
			Items      []widget `json:"items"`
			NextCursor string   `json:"nextCursor,omitempty"`
		}{Items: page}
		if len(page) > size {
			resp.Items = page[:size]
			resp.NextCursor, _ = EncodeCursor(position{After: page[size-1].ID})
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("PUT /widgets/{id}", func(w http.ResponseWriter, r *http.Request) {
		version, err := IfMatch(r.Header.Get("If-Match"))
		if err != nil {
			fail(w, r, err)
			return
		}
		id, _ := strconv.Atoi(r.PathValue("id"))
		var body struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			requestError(w, r, err)
			return
		}
		ws.mu.Lock()
		defer ws.mu.Unlock()
		for i := range ws.items {
			if ws.items[i].ID != id {
				continue
			}
			if ws.items[i].version != version {
				fail(w, r, Stale())
				return
			}
			ws.items[i].Name = body.Name
			ws.items[i].version++
			w.Header().Set("ETag", ETag(ws.items[i].version))
			_ = json.NewEncoder(w).Encode(ws.items[i])
			return
		}
		fail(w, r, problem.New(problem.NotFound, "no such widget"))
	})
	mux.HandleFunc("GET /panic", func(http.ResponseWriter, *http.Request) {
		panic("boom: the secret is canary-31")
	})
	mux.HandleFunc("GET /abort", func(http.ResponseWriter, *http.Request) {
		panic(http.ErrAbortHandler)
	})
	return mux
}

func sample(t *testing.T, n int) (http.Handler, *bytes.Buffer) {
	t.Helper()
	ws := &widgets{}
	for i := 1; i <= n; i++ {
		ws.items = append(ws.items, widget{ID: i, Name: fmt.Sprint("widget ", i), version: 1})
	}
	var logs bytes.Buffer
	return chain(ws.handler(), options(&logs)), &logs
}

type widgetPage struct {
	Items      []widget `json:"items"`
	NextCursor string   `json:"nextCursor"`
}

func list(t *testing.T, h http.Handler, query string) (widgetPage, result) {
	t.Helper()
	res := call(h, http.MethodGet, "/widgets"+query, "", nil, nil)
	var page widgetPage
	if res.status == http.StatusOK {
		if err := json.Unmarshal(res.body, &page); err != nil {
			t.Fatal(err)
		}
	}
	return page, res
}

func TestSamplePagination(t *testing.T) {
	h, _ := sample(t, 260)
	first, _ := list(t, h, "")
	if len(first.Items) != DefaultPageSize || first.Items[0].ID != 1 || first.NextCursor == "" {
		t.Fatalf("first page: %d items from %d, cursor %q", len(first.Items), first.Items[0].ID, first.NextCursor)
	}
	second, _ := list(t, h, "?cursor="+first.NextCursor)
	if second.Items[0].ID != DefaultPageSize+1 {
		t.Fatalf("second page starts at %d", second.Items[0].ID)
	}
	if most, _ := list(t, h, "?limit=1000"); len(most.Items) != MaxPageSize {
		t.Fatalf("a limit of 1000 gave %d items, want %d", len(most.Items), MaxPageSize)
	}
	if last, _ := list(t, h, "?limit=200&cursor="+mustCursor(t, position{After: 100})); len(last.Items) != 160 || last.NextCursor != "" {
		t.Fatalf("last page: %d items, cursor %q", len(last.Items), last.NextCursor)
	}

	_, res := list(t, h, "?limit=0")
	problemOf(t, res, problem.BadRequest)
	tampered := base64.RawURLEncoding.EncodeToString([]byte(`{"after":1,"tenant":"other"}`))
	for _, cursor := range []string{"not-a-cursor!", tampered, strings.Repeat("A", 2000)} {
		_, res := list(t, h, "?cursor="+cursor)
		problemOf(t, res, problem.InvalidCursor)
	}
}

func mustCursor(t *testing.T, pos position) string {
	t.Helper()
	c, err := EncodeCursor(pos)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSampleOptimisticConcurrency(t *testing.T) {
	h, _ := sample(t, 3)
	update := func(ifMatch string) result {
		header := http.Header{}
		if ifMatch != "" {
			header.Set("If-Match", ifMatch)
		}
		return call(h, http.MethodPut, "/widgets/2", "", header, strings.NewReader(`{"name":"renamed"}`))
	}
	problemOf(t, update(""), problem.PreconditionRequired)
	problemOf(t, update("*"), problem.BadRequest)
	problemOf(t, update(`W/"1"`), problem.BadRequest)

	res := update(`"1"`)
	if res.status != http.StatusOK || res.header.Get("ETag") != `"2"` {
		t.Fatalf("update of the current version: %d, ETag %q", res.status, res.header.Get("ETag"))
	}
	problemOf(t, update(`"1"`), problem.PreconditionFailed) // someone else's version
	if res := update(`"2"`); res.status != http.StatusOK || res.header.Get("ETag") != `"3"` {
		t.Fatalf("update after reading again: %d, ETag %q", res.status, res.header.Get("ETag"))
	}
}

func TestSamplePanics(t *testing.T) {
	h, logs := sample(t, 0)
	res := call(h, http.MethodGet, "/panic", "", nil, nil)
	problemOf(t, res, problem.Internal)
	if bytes.Contains(res.body, []byte("canary-31")) {
		t.Fatal("the panic reached the client")
	}
	if !strings.Contains(logs.String(), "panic serving a request") || !strings.Contains(logs.String(), "canary-31") {
		t.Fatalf("the panic was not logged:\n%s", logs.String())
	}

	defer func() {
		if recover() != http.ErrAbortHandler { //nolint:errorlint // a sentinel panic value
			t.Error("http.ErrAbortHandler did not go on to net/http")
		}
	}()
	call(h, http.MethodGet, "/abort", "", nil, nil)
}

// The table of docs/reference/api-errors.md holds every code, with its
// status, and nothing else.
func TestErrorCodesAreDocumented(t *testing.T) {
	doc, err := os.ReadFile("../../../docs/reference/api-errors.md")
	if err != nil {
		t.Fatal(err)
	}
	documented := map[problem.Code]int{}
	for line := range strings.Lines(string(doc)) {
		var code string
		var status int
		if n, _ := fmt.Sscanf(line, "| `%s | %d |", &code, &status); n == 2 {
			documented[problem.Code(strings.TrimSuffix(code, "`"))] = status
		}
	}
	for code, c := range problem.Codes {
		if documented[code] != c.Status {
			t.Errorf("%s: documented with status %d, want %d", code, documented[code], c.Status)
		}
	}
	for code := range documented {
		if _, ok := problem.Codes[code]; !ok {
			t.Errorf("%s is documented but not defined", code)
		}
	}
}

func TestTokensAndServiceAccountsEndpoints(t *testing.T) {
	d := dbtest.New(t)
	database := d.Open(t)
	clk := clocktest.New(time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC))

	cat, err := audit.LoadCatalog(events.Files)
	if err != nil {
		t.Fatal(err)
	}
	writer := audit.NewWriter(cat, clk)
	sessionStore := authn.NewSessionStore(database, clk, authn.SessionOptions{})
	tokenStore := authn.NewTokenStore(database, clk, writer)
	principalStore := authn.NewPrincipalStore(database, clk, writer, sessionStore, tokenStore)

	email := "operator@example.com"
	user, err := principalStore.UpsertHuman(context.Background(), "https://idp.example.com", "sub-op", "Test Operator", &email, []string{"operators"})
	if err != nil {
		t.Fatalf("upserting test user: %v", err)
	}
	callerID := user.ID.String()

	opts := options(io.Discard)
	opts.Tokens = tokenStore
	opts.Principals = principalStore
	opts.Authorizer = &allow{ops: map[string]bool{
		"createToken":          true,
		"listTokens":           true,
		"revokeToken":          true,
		"createServiceAccount": true,
		"listServiceAccounts":  true,
	}}
	h := Handler(opts)

	var tokenID, serviceAccountID string

	t.Run("createToken", func(t *testing.T) {
		body := strings.NewReader(`{"name":"cli-key","scopes":["agent.propose"],"expiresInDays":30}`)
		res := call(h, http.MethodPost, "/api/v1/tokens", callerID, nil, body)
		if res.status != http.StatusCreated {
			t.Fatalf("createToken status %d, body %s", res.status, res.body)
		}
		var created gen.CreatedToken
		if err := json.Unmarshal(res.body, &created); err != nil {
			t.Fatalf("unmarshal created token: %v", err)
		}
		if !strings.HasPrefix(created.Token, authn.TokenPrefix) {
			t.Errorf("token %q does not have prefix %s", created.Token, authn.TokenPrefix)
		}
		if created.Name != "cli-key" {
			t.Errorf("name %q, want cli-key", created.Name)
		}
		tokenID = created.Id.String()
	})

	t.Run("listTokens", func(t *testing.T) {
		res := call(h, http.MethodGet, "/api/v1/tokens", callerID, nil, nil)
		if res.status != http.StatusOK {
			t.Fatalf("listTokens status %d, body %s", res.status, res.body)
		}
		var tokens []gen.ApiTokenMetadata
		if err := json.Unmarshal(res.body, &tokens); err != nil {
			t.Fatalf("unmarshal tokens: %v", err)
		}
		if len(tokens) == 0 {
			t.Fatal("expected at least 1 token")
		}
		if tokens[0].Id.String() != tokenID {
			t.Errorf("token ID %s, want %s", tokens[0].Id, tokenID)
		}
	})

	t.Run("createServiceAccount", func(t *testing.T) {
		body := strings.NewReader(`{"displayName":"Sync Bot","roles":["owner"]}`)
		res := call(h, http.MethodPost, "/api/v1/service-accounts", callerID, nil, body)
		if res.status != http.StatusCreated {
			t.Fatalf("createServiceAccount status %d, body %s", res.status, res.body)
		}
		var sa gen.ServiceAccount
		if err := json.Unmarshal(res.body, &sa); err != nil {
			t.Fatalf("unmarshal service account: %v", err)
		}
		if sa.DisplayName != "Sync Bot" {
			t.Errorf("displayName %q, want Sync Bot", sa.DisplayName)
		}
		if sa.ResponsiblePrincipalId.String() != callerID {
			t.Errorf("responsiblePrincipalId %s, want %s", sa.ResponsiblePrincipalId, callerID)
		}
		serviceAccountID = sa.Id.String()
	})

	// Security test ST-18: Nobody gets a role through a service account that they do not hold
	t.Run("a service account gets only roles that its creator holds", func(t *testing.T) {
		body := strings.NewReader(`{"displayName":"Escalator","roles":["operator"]}`)
		problemOf(t, call(h, http.MethodPost, "/api/v1/service-accounts", callerID, nil, body), problem.Forbidden)

		bot := opts
		bot.Authenticator = fixedAuthenticator{auth.Principal{ID: uuid.NewString(), Kind: auth.ServiceAccount, Roles: []string{"owner"}}}
		body = strings.NewReader(`{"displayName":"Grandchild","roles":["owner"]}`)
		problemOf(t, call(Handler(bot), http.MethodPost, "/api/v1/service-accounts", "", nil, body), problem.Forbidden)
	})

	// Security test ST-19: A token gives no more than whoever creates it holds, nor more than the scopes of the token it is created with
	t.Run("a token gives no more than its creator holds", func(t *testing.T) {
		scoped := opts
		scoped.Authenticator = fixedAuthenticator{auth.Principal{ID: callerID, Kind: auth.Human, Roles: []string{"owner"}, Scopes: []string{"identity.me.read"}}}
		hs := Handler(scoped)
		body := strings.NewReader(`{"name":"wider","scopes":["agent.propose"]}`)
		problemOf(t, call(hs, http.MethodPost, "/api/v1/tokens", "", nil, body), problem.Forbidden)
		body = strings.NewReader(`{"name":"narrow","scopes":["identity.me.read"]}`)
		if res := call(hs, http.MethodPost, "/api/v1/tokens", "", nil, body); res.status != http.StatusCreated {
			t.Fatalf("a scope the token holds: status %d, body %s", res.status, res.body)
		}

		adaEmail := "ada@example.com"
		ada, err := principalStore.UpsertHuman(context.Background(), "https://idp.example.com", "sub-ada", "Ada Admin", &adaEmail, nil)
		if err != nil {
			t.Fatalf("upserting the administrator: %v", err)
		}
		admin := opts
		admin.Authenticator = fixedAuthenticator{auth.Principal{ID: ada.ID.String(), Kind: auth.Human, Roles: []string{"admin"}}}
		ha := Handler(admin)
		body = strings.NewReader(`{"name":"borrowed","scopes":["agent.propose"],"principalId":"` + serviceAccountID + `"}`)
		problemOf(t, call(ha, http.MethodPost, "/api/v1/tokens", "", nil, body), problem.Forbidden)
		body = strings.NewReader(`{"name":"shared","scopes":["inventory.view"],"principalId":"` + serviceAccountID + `"}`)
		if res := call(ha, http.MethodPost, "/api/v1/tokens", "", nil, body); res.status != http.StatusCreated {
			t.Fatalf("a scope the administrator holds: status %d, body %s", res.status, res.body)
		}
	})

	t.Run("listServiceAccounts", func(t *testing.T) {
		res := call(h, http.MethodGet, "/api/v1/service-accounts", callerID, nil, nil)
		if res.status != http.StatusOK {
			t.Fatalf("listServiceAccounts status %d, body %s", res.status, res.body)
		}
		var list []gen.ServiceAccount
		if err := json.Unmarshal(res.body, &list); err != nil {
			t.Fatalf("unmarshal service accounts: %v", err)
		}
		if len(list) == 0 {
			t.Fatal("expected at least 1 service account")
		}
	})

	t.Run("revokeToken", func(t *testing.T) {
		res := call(h, http.MethodDelete, "/api/v1/tokens/"+tokenID, callerID, nil, nil)
		if res.status != http.StatusNoContent {
			t.Fatalf("revokeToken status %d, body %s", res.status, res.body)
		}

		// Listing tokens shows revokedAt is set
		res = call(h, http.MethodGet, "/api/v1/tokens", callerID, nil, nil)
		var tokens []gen.ApiTokenMetadata
		if err := json.Unmarshal(res.body, &tokens); err != nil {
			t.Fatalf("unmarshal tokens: %v", err)
		}
		found := false
		for _, tok := range tokens {
			if tok.Id.String() == tokenID {
				found = true
				if tok.RevokedAt == nil {
					t.Errorf("revoked token still has revokedAt == nil")
				}
			}
		}
		if !found {
			t.Errorf("revoked token not found in list")
		}
	})
}

type mockTokenExchanger struct {
	token *authn.CreatedToken
	err   error
}

func (m mockTokenExchanger) ExchangeIDToken(_ context.Context, _ string) (*authn.CreatedToken, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.token, nil
}

func TestExchangeTokenEndpoint(t *testing.T) {
	fakeID := uuid.MustParse("0192f2c4-8d1e-7c3a-9b2f-5e1d2c3b4a59")
	fakeToken := &authn.CreatedToken{
		APIToken: authn.APIToken{
			ID:          fakeID,
			PrincipalID: fakeID,
			Name:        "CLI session (wtctl)",
			TokenPrefix: "wt_pat_abcd",
			Scopes:      []string{"agent:halt", "inventory:view"},
			CreatedAt:   time.Now().UTC(),
			ExpiresAt:   time.Now().UTC().Add(12 * time.Hour),
		},
		Token: "wt_pat_abcdef1234567890",
	}

	t.Run("successful exchange", func(t *testing.T) {
		opts := options(io.Discard)
		opts.Exchanger = mockTokenExchanger{token: fakeToken}
		h := Handler(opts)

		body := strings.NewReader(`{"idToken":"valid-id-token"}`)
		res := call(h, http.MethodPost, "/api/v1/tokens/exchange", "", nil, body)
		if res.status != http.StatusOK {
			t.Fatalf("got status %d, body %s", res.status, res.body)
		}
		var resp gen.CreatedToken
		if err := json.Unmarshal(res.body, &resp); err != nil {
			t.Fatalf("unmarshaling response: %v", err)
		}
		if resp.Token != fakeToken.Token {
			t.Errorf("got token %q, want %q", resp.Token, fakeToken.Token)
		}
		if resp.TokenPrefix != fakeToken.TokenPrefix {
			t.Errorf("got prefix %q, want %q", resp.TokenPrefix, fakeToken.TokenPrefix)
		}
		if len(resp.Scopes) != len(fakeToken.Scopes) {
			t.Errorf("got scopes %v, want %v", resp.Scopes, fakeToken.Scopes)
		}
	})

	t.Run("missing body or idToken", func(t *testing.T) {
		opts := options(io.Discard)
		opts.Exchanger = mockTokenExchanger{token: fakeToken}
		h := Handler(opts)

		res := call(h, http.MethodPost, "/api/v1/tokens/exchange", "", nil, strings.NewReader(`{"idToken":""}`))
		problemOf(t, res, problem.BadRequest)
	})

	t.Run("deactivated principal is refused with forbidden", func(t *testing.T) {
		opts := options(io.Discard)
		opts.Exchanger = mockTokenExchanger{err: authn.ErrPrincipalInactive}
		h := Handler(opts)

		body := strings.NewReader(`{"idToken":"inactive-user-token"}`)
		res := call(h, http.MethodPost, "/api/v1/tokens/exchange", "", nil, body)
		problemOf(t, res, problem.Forbidden)
	})

	t.Run("invalid ID token is refused with unauthenticated", func(t *testing.T) {
		opts := options(io.Discard)
		opts.Exchanger = mockTokenExchanger{err: authn.ErrInvalidToken}
		h := Handler(opts)

		body := strings.NewReader(`{"idToken":"invalid-token"}`)
		res := call(h, http.MethodPost, "/api/v1/tokens/exchange", "", nil, body)
		problemOf(t, res, problem.Unauthenticated)
	})

	t.Run("unconfigured exchanger returns internal problem", func(t *testing.T) {
		opts := options(io.Discard)
		opts.Exchanger = nil
		h := Handler(opts)

		body := strings.NewReader(`{"idToken":"some-token"}`)
		res := call(h, http.MethodPost, "/api/v1/tokens/exchange", "", nil, body)
		problemOf(t, res, problem.Internal)
	})
}
