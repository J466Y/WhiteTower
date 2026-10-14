package rest

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/ratelimit"
)

type mockCSRFValidator struct {
	validToken string
}

func (m *mockCSRFValidator) ValidateRequestCSRF(r *http.Request) bool {
	token := r.Header.Get("X-CSRF-Token")
	if token == "" {
		token = r.Header.Get("X-WT-CSRF-Token")
	}
	return token == m.validToken
}

// Security test ST-13: State-changing requests without a valid CSRF token are refused
func TestCSRFProtection(t *testing.T) {
	const goodToken = "valid-csrf-token-abc-123"
	validator := &mockCSRFValidator{validToken: goodToken}

	var handlerInvoked bool
	targetHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerInvoked = true
		w.WriteHeader(http.StatusOK)
	})

	protectedHandler := csrf(targetHandler, validator)

	t.Run("GET requests bypass CSRF validation", func(t *testing.T) {
		handlerInvoked = false
		r := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
		rec := httptest.NewRecorder()

		protectedHandler.ServeHTTP(rec, r)
		if !handlerInvoked || rec.Code != http.StatusOK {
			t.Errorf("GET requests should bypass CSRF, got code %d, invoked=%v", rec.Code, handlerInvoked)
		}
	})

	t.Run("state-changing POST without CSRF token is refused", func(t *testing.T) {
		handlerInvoked = false
		r := httptest.NewRequest(http.MethodPost, "/api/v1/something", nil)
		rec := httptest.NewRecorder()

		protectedHandler.ServeHTTP(rec, r)
		if handlerInvoked {
			t.Errorf("handler must not be invoked on missing CSRF token")
		}
		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden, got %d", rec.Code)
		}
	})

	t.Run("state-changing POST with invalid CSRF token is refused", func(t *testing.T) {
		handlerInvoked = false
		r := httptest.NewRequest(http.MethodPost, "/api/v1/something", nil)
		r.Header.Set("X-CSRF-Token", "wrong-token")
		rec := httptest.NewRecorder()

		protectedHandler.ServeHTTP(rec, r)
		if handlerInvoked {
			t.Errorf("handler must not be invoked on invalid CSRF token")
		}
		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden, got %d", rec.Code)
		}
	})

	t.Run("state-changing POST with valid CSRF token succeeds", func(t *testing.T) {
		handlerInvoked = false
		r := httptest.NewRequest(http.MethodPost, "/api/v1/something", nil)
		r.Header.Set("X-CSRF-Token", goodToken)
		rec := httptest.NewRecorder()

		protectedHandler.ServeHTTP(rec, r)
		if !handlerInvoked || rec.Code != http.StatusOK {
			t.Errorf("handler should be invoked with valid CSRF token, got code %d, invoked=%v", rec.Code, handlerInvoked)
		}
	})

	t.Run("alternative X-WT-CSRF-Token header also accepted", func(t *testing.T) {
		handlerInvoked = false
		r := httptest.NewRequest(http.MethodPut, "/api/v1/something", nil)
		r.Header.Set("X-WT-CSRF-Token", goodToken)
		rec := httptest.NewRecorder()

		protectedHandler.ServeHTTP(rec, r)
		if !handlerInvoked || rec.Code != http.StatusOK {
			t.Errorf("handler should accept X-WT-CSRF-Token, got code %d, invoked=%v", rec.Code, handlerInvoked)
		}
	})

	t.Run("nil validator passes through all requests", func(t *testing.T) {
		handlerInvoked = false
		passHandler := csrf(targetHandler, nil)
		r := httptest.NewRequest(http.MethodPost, "/api/v1/something", nil)
		rec := httptest.NewRecorder()

		passHandler.ServeHTTP(rec, r)
		if !handlerInvoked || rec.Code != http.StatusOK {
			t.Errorf("nil validator should pass through, got code %d, invoked=%v", rec.Code, handlerInvoked)
		}
	})
}

func TestCSRFMiddlewareIntegratesInChain(t *testing.T) {
	opts := Options{
		Logger:        slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Authenticator: auth.Unauthenticated{},
		Authorizer:    &allow{ops: map[string]bool{"getVersion": true}},
		CSRF:          &mockCSRFValidator{validToken: "good-token"},
		Limiter:       ratelimit.New(1000, 1000),
	}
	h := Handler(opts)

	// GET /version should succeed without CSRF
	req := httptest.NewRequest(http.MethodGet, BasePath+"/version", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 OK for GET /version, got %d", rec.Code)
	}
}
