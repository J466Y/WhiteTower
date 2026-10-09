package resttest_test

import (
	"context"
	"net/http"
	"slices"
	"sync"
	"testing"

	"github.com/J466Y/WhiteTower/internal/api/rest"
	"github.com/J466Y/WhiteTower/internal/api/rest/resttest"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/golden"
)

var olivia = auth.Principal{
	ID: "0192f2c4-8d1e-7c3a-9b2f-5e1d2c3b4a59", Kind: auth.Human, Name: "Olivia Owner", Roles: []string{"owner"},
}

// A test of the public API, as a domain package writes one: the API served
// with what it needs, called through the generated client as a principal,
// and the answer checked against a golden file.
func TestCallingTheAPIAsAPrincipal(t *testing.T) {
	api := resttest.New(t, rest.Options{})
	resp, err := api.Client.GetMeWithResponse(context.Background(), resttest.As(olivia))
	if err != nil || resp.StatusCode() != http.StatusOK {
		t.Fatalf("%v %s", err, resp.Body)
	}
	golden.AssertJSON(t, "testdata/me.json", resp.JSON200)
}

func TestAnonymousCallsAreUnauthenticated(t *testing.T) {
	api := resttest.New(t, rest.Options{})
	resp, err := api.Client.GetMeWithResponse(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if p := resp.ApplicationproblemJSONDefault; resp.StatusCode() != http.StatusUnauthorized || p == nil ||
		p.Code != "unauthenticated" {
		t.Fatalf("%d %s", resp.StatusCode(), resp.Body)
	}
}

// recording permits everything, and records what it is asked.
type recording struct {
	mu    sync.Mutex
	asked []string
}

func (r *recording) Authorize(_ context.Context, p *auth.Principal, operation string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.asked = append(r.asked, p.ID+" "+operation)
	return nil
}

// What a test sets in rest.Options replaces resttest's defaults.
func TestOptionsReplaceTheDefaults(t *testing.T) {
	authorizer := &recording{}
	api := resttest.New(t, rest.Options{Authorizer: authorizer})
	if _, err := api.Client.GetMeWithResponse(context.Background(), resttest.As(olivia)); err != nil {
		t.Fatal(err)
	}
	authorizer.mu.Lock()
	defer authorizer.mu.Unlock()
	if want := []string{olivia.ID + " getMe"}; !slices.Equal(authorizer.asked, want) {
		t.Fatalf("asked %v, want %v", authorizer.asked, want)
	}
}
