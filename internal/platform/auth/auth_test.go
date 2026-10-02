package auth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/J466Y/WhiteTower/internal/platform/auth"
)

func TestPrincipalTravelsInTheContext(t *testing.T) {
	if auth.PrincipalFrom(context.Background()) != nil {
		t.Fatal("a principal without authentication")
	}
	p := &auth.Principal{ID: "0192f2c4-8d1e-7c3a-9b2f-5e1d2c3b4a59", Kind: auth.Human}
	if got := auth.PrincipalFrom(auth.WithPrincipal(context.Background(), p)); got != p {
		t.Fatalf("got %v", got)
	}
}

// Until plan P1-03, nobody is authenticated and nothing is permitted.
func TestTheStandIns(t *testing.T) {
	p, err := auth.Unauthenticated{}.Authenticate(httptest.NewRequest(http.MethodGet, "/api/v1/me", nil))
	if p != nil || err != nil {
		t.Fatalf("Unauthenticated returned %v, %v", p, err)
	}
	if err := (auth.DenyAll{}).Authorize(context.Background(), &auth.Principal{}, "getMe"); !errors.Is(err, auth.ErrDenied) {
		t.Fatalf("DenyAll returned %v", err)
	}
}
