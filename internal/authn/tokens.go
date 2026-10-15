package authn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/J466Y/WhiteTower/internal/audit"
	"github.com/J466Y/WhiteTower/internal/authn/authndb"
	"github.com/J466Y/WhiteTower/internal/authz"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/clock"
	"github.com/J466Y/WhiteTower/internal/platform/db"
)

// TokenPrefix is the standard recognizable prefix for all White Tower personal access tokens.
const TokenPrefix = "wt_pat_"

// MaxTokenLifetimeDays is the maximum allowable lifetime for an API token (90 days).
const MaxTokenLifetimeDays = 90

// DefaultTokenLifetimeDays is the default token lifetime if unspecified (30 days).
const DefaultTokenLifetimeDays = 30

var (
	// ErrInvalidToken is returned when a token is malformed or its hash is not found.
	ErrInvalidToken = errors.New("invalid API token")
	// ErrTokenExpired is returned when a token has passed its expiry timestamp.
	ErrTokenExpired = errors.New("API token has expired")
	// ErrTokenRevoked is returned when a token has been explicitly revoked.
	ErrTokenRevoked = errors.New("API token has been revoked")
	// ErrTokenNotFound is returned when looking up a token by ID fails.
	ErrTokenNotFound = errors.New("API token not found")
)

// APIToken represents metadata of a personal access or service account token.
type APIToken struct {
	ID          uuid.UUID
	PrincipalID uuid.UUID
	Name        string
	TokenPrefix string
	TokenHash   []byte
	Scopes      []string
	CreatedBy   uuid.UUID
	CreatedAt   time.Time
	ExpiresAt   time.Time
	LastUsedAt  *time.Time
	RevokedAt   *time.Time
}

// CreatedToken contains the token metadata along with the raw plaintext secret.
// The raw token is only returned once upon generation and never stored.
type CreatedToken struct {
	APIToken
	Token string
}

// TokenStore manages the lifecycle, hashing, and authentication of API tokens.
type TokenStore struct {
	database *db.DB
	clk      clock.Clock
	writer   *audit.Writer
}

// NewTokenStore returns an initialized TokenStore.
func NewTokenStore(database *db.DB, clk clock.Clock, writer *audit.Writer) *TokenStore {
	return &TokenStore{
		database: database,
		clk:      clk,
		writer:   writer,
	}
}

// GenerateToken produces a high-entropy random API token, its display prefix, and its SHA-256 hash.
func GenerateToken() (rawToken string, prefix string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", nil, fmt.Errorf("generating random token entropy: %w", err)
	}
	rawToken = TokenPrefix + base64.RawURLEncoding.EncodeToString(b)
	prefix = rawToken[:15]
	sum := sha256.Sum256([]byte(rawToken))
	return rawToken, prefix, sum[:], nil
}

// Create generates and persists a new API token for principalID, recording an audit event.
func (ts *TokenStore) Create(
	ctx context.Context,
	principalID uuid.UUID,
	name string,
	scopes []string,
	expiresInDays int,
	actor auth.Principal,
) (*CreatedToken, error) {
	if expiresInDays == 0 {
		expiresInDays = DefaultTokenLifetimeDays
	}
	if expiresInDays < 1 || expiresInDays > MaxTokenLifetimeDays {
		return nil, fmt.Errorf("token expiry must be between 1 and %d days", MaxTokenLifetimeDays)
	}
	return ts.CreateWithLifetime(ctx, principalID, name, scopes, time.Duration(expiresInDays)*24*time.Hour, actor)
}

// CreateWithLifetime generates and persists a new API token with an explicit lifetime duration.
func (ts *TokenStore) CreateWithLifetime(
	ctx context.Context,
	principalID uuid.UUID,
	name string,
	scopes []string,
	lifetime time.Duration,
	actor auth.Principal,
) (*CreatedToken, error) {
	name = strings.TrimSpace(name)
	if len(name) < 1 || len(name) > 100 {
		return nil, errors.New("token name must be between 1 and 100 characters")
	}

	if len(scopes) == 0 {
		return nil, errors.New("at least one scope is required")
	}
	for _, s := range scopes {
		if !authz.IsValidPermission(authz.Permission(s)) {
			return nil, fmt.Errorf("invalid scope %q", s)
		}
	}

	if lifetime <= 0 || lifetime > time.Duration(MaxTokenLifetimeDays)*24*time.Hour {
		return nil, fmt.Errorf("token lifetime must be between 1s and %d days", MaxTokenLifetimeDays)
	}

	rawToken, prefix, hash, err := GenerateToken()
	if err != nil {
		return nil, err
	}

	tokenID, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("generating token UUID: %w", err)
	}

	now := ts.clk.Now().UTC()
	expiresAt := now.Add(lifetime)

	creatorID := principalID
	if actor.ID != "" {
		if parsed, err := uuid.Parse(actor.ID); err == nil {
			creatorID = parsed
		}
	}

	var created *CreatedToken
	err = ts.database.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := authndb.New(tx)
		// Ensure principal exists and is active
		p, err := q.GetPrincipalByID(ctx, principalID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrPrincipalNotFound
			}
			return fmt.Errorf("verifying principal: %w", err)
		}
		if p.Status != "active" {
			return ErrPrincipalInactive
		}

		if err := q.CreateAPIToken(ctx, authndb.CreateAPITokenParams{
			ID:          tokenID,
			PrincipalID: principalID,
			Name:        name,
			TokenPrefix: prefix,
			TokenHash:   hash,
			Scopes:      scopes,
			CreatedBy:   creatorID,
			CreatedAt:   now,
			ExpiresAt:   expiresAt,
		}); err != nil {
			return fmt.Errorf("inserting api token: %w", err)
		}

		actorPayload := map[string]any{
			"type": "human",
			"id":   actor.ID,
		}
		if actor.Kind == auth.ServiceAccount {
			actorPayload["type"] = "service_account"
		} else if actor.ID == "" {
			actorPayload["type"] = "system"
			delete(actorPayload, "id")
		}

		if err := ts.writer.Record(ctx, tx, audit.Event{
			Type:    "whitetower.token.created.v1",
			Subject: principalID.String(),
			Data: map[string]any{
				"token_id":     tokenID.String(),
				"principal_id": principalID.String(),
				"token_prefix": prefix,
				"scopes":       scopes,
				"actor":        actorPayload,
			},
		}); err != nil {
			return fmt.Errorf("recording token creation audit event: %w", err)
		}

		created = &CreatedToken{
			APIToken: APIToken{
				ID:          tokenID,
				PrincipalID: principalID,
				Name:        name,
				TokenPrefix: prefix,
				TokenHash:   hash,
				Scopes:      scopes,
				CreatedBy:   creatorID,
				CreatedAt:   now,
				ExpiresAt:   expiresAt,
			},
			Token: rawToken,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return created, nil
}

// GetByToken authenticates rawToken, checks revocation, expiration, and principal status.
func (ts *TokenStore) GetByToken(ctx context.Context, rawToken string) (*APIToken, *Principal, error) {
	if !strings.HasPrefix(rawToken, TokenPrefix) {
		return nil, nil, ErrInvalidToken
	}

	sum := sha256.Sum256([]byte(rawToken))
	q := authndb.New(ts.database)

	row, err := q.GetAPITokenByHash(ctx, sum[:])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, ErrInvalidToken
		}
		return nil, nil, fmt.Errorf("querying token: %w", err)
	}

	if row.RevokedAt != nil {
		return nil, nil, ErrTokenRevoked
	}

	now := ts.clk.Now().UTC()
	if now.After(row.ExpiresAt) {
		return nil, nil, ErrTokenExpired
	}

	pRow, err := q.GetPrincipalByID(ctx, row.PrincipalID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, ErrPrincipalNotFound
		}
		return nil, nil, fmt.Errorf("querying token principal: %w", err)
	}
	if pRow.Status != "active" {
		return nil, nil, ErrPrincipalInactive
	}

	// Update last used timestamp
	_ = q.TouchAPITokenLastUsed(ctx, authndb.TouchAPITokenLastUsedParams{
		ID:         row.ID,
		LastUsedAt: &now,
	})

	token := &APIToken{
		ID:          row.ID,
		PrincipalID: row.PrincipalID,
		Name:        row.Name,
		TokenPrefix: row.TokenPrefix,
		TokenHash:   row.TokenHash,
		Scopes:      row.Scopes,
		CreatedBy:   row.CreatedBy,
		CreatedAt:   row.CreatedAt,
		ExpiresAt:   row.ExpiresAt,
		LastUsedAt:  &now,
		RevokedAt:   row.RevokedAt,
	}

	return token, fromDBModel(pRow), nil
}

// Revoke revokes a single token by its ID, recording an audited event.
func (ts *TokenStore) Revoke(ctx context.Context, tokenID uuid.UUID, actor auth.Principal, reason string) error {
	if reason == "" {
		reason = "manual revocation"
	}

	return ts.database.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := authndb.New(tx)
		token, err := q.GetAPITokenByID(ctx, tokenID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrTokenNotFound
			}
			return fmt.Errorf("reading token: %w", err)
		}
		if token.RevokedAt != nil {
			return nil
		}

		now := ts.clk.Now().UTC()
		rows, err := q.RevokeAPIToken(ctx, authndb.RevokeAPITokenParams{
			ID:        tokenID,
			RevokedAt: &now,
		})
		if err != nil {
			return fmt.Errorf("revoking token: %w", err)
		}
		if rows == 0 {
			return nil
		}

		actorPayload := map[string]any{
			"type": "human",
			"id":   actor.ID,
		}
		if actor.Kind == auth.ServiceAccount {
			actorPayload["type"] = "service_account"
		} else if actor.ID == "" {
			actorPayload["type"] = "system"
			delete(actorPayload, "id")
		}

		if err := ts.writer.Record(ctx, tx, audit.Event{
			Type:    "whitetower.token.revoked.v1",
			Subject: token.PrincipalID.String(),
			Data: map[string]any{
				"token_id":     tokenID.String(),
				"principal_id": token.PrincipalID.String(),
				"actor":        actorPayload,
				"reason":       reason,
			},
		}); err != nil {
			return fmt.Errorf("recording token revocation audit event: %w", err)
		}

		return nil
	})
}

// RevokeAllForPrincipalTx revokes all tokens of principalID inside an existing transaction.
func (ts *TokenStore) RevokeAllForPrincipalTx(ctx context.Context, tx *db.Tx, principalID uuid.UUID) error {
	q := authndb.New(tx)
	now := ts.clk.Now().UTC()
	_, err := q.RevokeAPITokensForPrincipal(ctx, authndb.RevokeAPITokensForPrincipalParams{
		PrincipalID: principalID,
		RevokedAt:   &now,
	})
	return err
}

// ListByPrincipal returns all API tokens belonging to principalID.
func (ts *TokenStore) ListByPrincipal(ctx context.Context, principalID uuid.UUID) ([]*APIToken, error) {
	q := authndb.New(ts.database)
	rows, err := q.ListAPITokensByPrincipal(ctx, principalID)
	if err != nil {
		return nil, fmt.Errorf("querying principal tokens: %w", err)
	}

	result := make([]*APIToken, len(rows))
	for i, r := range rows {
		result[i] = &APIToken{
			ID:          r.ID,
			PrincipalID: r.PrincipalID,
			Name:        r.Name,
			TokenPrefix: r.TokenPrefix,
			TokenHash:   r.TokenHash,
			Scopes:      r.Scopes,
			CreatedBy:   r.CreatedBy,
			CreatedAt:   r.CreatedAt,
			ExpiresAt:   r.ExpiresAt,
			LastUsedAt:  r.LastUsedAt,
			RevokedAt:   r.RevokedAt,
		}
	}
	return result, nil
}
