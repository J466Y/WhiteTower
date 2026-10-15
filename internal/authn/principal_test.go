package authn_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/J466Y/WhiteTower/internal/authn"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/clock/clocktest"
)

func TestPrincipalLifecycleAndAuditing(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(testEpoch)
	sessionStore, principalStore, _ := setupAuthn(t, clk)

	const (
		issuer      = "https://idp.example.com"
		subject     = "sub-bob-99"
		initialName = "Bob Builder"
	)
	email := "bob@example.com"
	groups := []string{"developers", "engineers"}

	// 1. Initial upsert
	p1, err := principalStore.UpsertHuman(ctx, issuer, subject, initialName, &email, groups)
	if err != nil {
		t.Fatalf("upserting principal: %v", err)
	}
	if p1.DisplayName != initialName {
		t.Errorf("expected %s, got %s", initialName, p1.DisplayName)
	}
	if p1.Status != "active" {
		t.Errorf("expected active status, got %s", p1.Status)
	}

	// 2. Subsequent upsert (e.g. login with changed name or groups)
	updatedName := "Bob The Builder"
	updatedGroups := []string{"developers", "architects"}
	clk.Advance(time.Hour)
	p2, err := principalStore.UpsertHuman(ctx, issuer, subject, updatedName, &email, updatedGroups)
	if err != nil {
		t.Fatalf("updating principal: %v", err)
	}
	if p2.ID != p1.ID {
		t.Errorf("principal ID must remain constant on upsert")
	}
	if p2.DisplayName != updatedName {
		t.Errorf("expected updated name %s, got %s", updatedName, p2.DisplayName)
	}

	// 3. Retrieval by ID and identity
	byID, err := principalStore.GetByID(ctx, p1.ID)
	if err != nil {
		t.Fatalf("getting principal by ID: %v", err)
	}
	if byID.DisplayName != updatedName {
		t.Errorf("mismatched display name: %s", byID.DisplayName)
	}

	byIdent, err := principalStore.GetByIdentity(ctx, issuer, subject)
	if err != nil {
		t.Fatalf("getting principal by identity: %v", err)
	}
	if byIdent.ID != p1.ID {
		t.Errorf("mismatched ID on identity lookup")
	}

	if _, err := principalStore.GetByID(ctx, uuid.New()); !errors.Is(err, authn.ErrPrincipalNotFound) {
		t.Errorf("expected ErrPrincipalNotFound for random ID, got %v", err)
	}
	if _, err := principalStore.GetByIdentity(ctx, "unknown-issuer", "unknown-sub"); !errors.Is(err, authn.ErrPrincipalNotFound) {
		t.Errorf("expected ErrPrincipalNotFound for unknown identity, got %v", err)
	}

	// 4. Create an active session and deactivate
	session, err := sessionStore.Create(ctx, p1.ID, "oidc", []string{"user"})
	if err != nil {
		t.Fatalf("creating session: %v", err)
	}

	adminActor := auth.Principal{ID: uuid.Must(uuid.NewV7()).String(), Kind: auth.Human}
	deactReason := "Account suspended pending investigation"
	if err := principalStore.Deactivate(ctx, p1.ID, adminActor, deactReason); err != nil {
		t.Fatalf("deactivating principal: %v", err)
	}

	// Check updated status
	deactivated, err := principalStore.GetByID(ctx, p1.ID)
	if err != nil {
		t.Fatalf("fetching deactivated principal: %v", err)
	}
	if deactivated.Status != "inactive" {
		t.Errorf("expected inactive status, got %s", deactivated.Status)
	}
	if deactivated.StatusReason == nil || *deactivated.StatusReason != deactReason {
		t.Errorf("status reason not recorded")
	}

	// Session must be invalid
	_, err = sessionStore.Get(ctx, session.Token)
	if err == nil {
		t.Errorf("session should be invalid for deactivated principal")
	}

	// 5. Reactivate
	reactReason := "Investigation cleared"
	if err := principalStore.Reactivate(ctx, p1.ID, adminActor, reactReason); err != nil {
		t.Fatalf("reactivating principal: %v", err)
	}

	reactivated, err := principalStore.GetByID(ctx, p1.ID)
	if err != nil {
		t.Fatalf("fetching reactivated principal: %v", err)
	}
	if reactivated.Status != "active" {
		t.Errorf("expected active status after reactivation, got %s", reactivated.Status)
	}
}
