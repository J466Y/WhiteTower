package authn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/J466Y/WhiteTower/internal/audit"
	"github.com/J466Y/WhiteTower/internal/authz"
	"github.com/J466Y/WhiteTower/internal/platform/clock"
	"github.com/J466Y/WhiteTower/internal/platform/db"
	"github.com/J466Y/WhiteTower/internal/platform/metrics"
	"github.com/J466Y/WhiteTower/internal/platform/ratelimit"
)

// BreakglassPrincipalID is the reserved identifier for the emergency break-glass custodian.
var BreakglassPrincipalID = uuid.MustParse("00000000-0000-0000-0000-000000000001")

// BreakglassCredentialPrefix is the standard prefix for emergency break-glass credentials.
const BreakglassCredentialPrefix = "wt_bg_"

// BreakglassLifetime is the maximum duration of a break-glass session (1 hour, ST-20).
const BreakglassLifetime = 1 * time.Hour

// BreakglassScopes defines the strict subset of permissions allowed during emergency break-glass (ST-20).
// A break-glass session can halt agents and the fleet, end every session and
// API token (HUM-10), and read, and nothing else.
var BreakglassScopes = []string{
	string(authz.PermissionHaltAgentIssue),
	string(authz.PermissionHaltFleetIssue),
	string(authz.PermissionIdentityEmergencyRevoke),
	string(authz.PermissionInventoryView),
	string(authz.PermissionAuditEventsRead),
	string(authz.PermissionAuditVerify),
	string(authz.PermissionAuditExport),
	string(authz.PermissionIdentityMeRead),
}

// GenerateBreakglassCredential generates 256 bits of CSPRNG entropy encoded with the wt_bg_ prefix,
// and computes a salted SHA-256 hash in the format $wt$1$<hex_salt>$<hex_hash>.
func GenerateBreakglassCredential() (rawCredential string, hashString string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("generating credential entropy: %w", err)
	}
	rawCredential = BreakglassCredentialPrefix + base64.RawURLEncoding.EncodeToString(b)

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", "", fmt.Errorf("generating salt: %w", err)
	}
	saltHex := hex.EncodeToString(salt)

	hasher := sha256.New()
	hasher.Write(salt)
	hasher.Write([]byte(rawCredential))
	hashHex := hex.EncodeToString(hasher.Sum(nil))

	hashString = fmt.Sprintf("$wt$1$%s$%s", saltHex, hashHex)
	return rawCredential, hashString, nil
}

// VerifyCredential validates a candidate break-glass credential against the stored salted hash string.
func VerifyCredential(hashString string, candidate string) bool {
	parts := strings.Split(strings.TrimSpace(hashString), "$")
	// Format: "" , "wt" , "1" , <saltHex> , <hashHex>
	if len(parts) != 5 || parts[1] != "wt" || parts[2] != "1" {
		return false
	}
	saltHex := parts[3]
	expectedHashHex := parts[4]

	salt, err := hex.DecodeString(saltHex)
	if err != nil || len(salt) == 0 {
		return false
	}

	hasher := sha256.New()
	hasher.Write(salt)
	hasher.Write([]byte(candidate))
	actualHashHex := hex.EncodeToString(hasher.Sum(nil))

	return subtle.ConstantTimeCompare([]byte(actualHashHex), []byte(expectedHashHex)) == 1
}

// BreakglassOptions configures the break-glass service.
type BreakglassOptions struct {
	Enabled            bool
	CredentialHashFile string
	Clock              clock.Clock
	Logger             *slog.Logger
	Limiter            *ratelimit.Limiter
	// SignIns counts break-glass sign-ins, by result. None: they are
	// logged, and not counted.
	SignIns *metrics.SignIns
}

// BreakglassService manages emergency break-glass authentication and session issuance (plan P1-03, step 9; ST-20).
type BreakglassService struct {
	opts     BreakglassOptions
	database *db.DB
	sessions *SessionStore
	writer   *audit.Writer
	logger   *slog.Logger
	signIns  signIns
}

// NewBreakglassService creates an initialized BreakglassService.
func NewBreakglassService(
	opts BreakglassOptions,
	database *db.DB,
	sessions *SessionStore,
	writer *audit.Writer,
) *BreakglassService {
	if opts.Clock == nil {
		opts.Clock = clock.System
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Limiter == nil {
		// Default to 5 requests per minute for break-glass attempts (ST-20, ST-22).
		opts.Limiter = ratelimit.New(5.0/60.0, 5)
	}
	return &BreakglassService{
		opts:     opts,
		database: database,
		sessions: sessions,
		writer:   writer,
		logger:   opts.Logger,
		signIns:  signIns{logger: opts.Logger, metrics: opts.SignIns},
	}
}

// ServeHTTP handles requests to /auth/breakglass (ST-20).
func (s *BreakglassService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.opts.Enabled {
		http.Error(w, "break-glass emergency access is disabled", http.StatusForbidden)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Rate limiting (ST-20, ST-22). Each refusal from here on logs one line,
	// never with the credential, and every end of the sign-in is counted by
	// its result.
	ctx := r.Context()
	ip := breakglassClientIP(r)
	if ok, wait := s.opts.Limiter.Allow(ip, s.opts.Clock.Now()); !ok {
		s.signIns.refused(ctx, "breakglass", refusedRateLimited, nil)
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds()+1)))
		http.Error(w, "too many break-glass attempts; retry later", http.StatusTooManyRequests)
		return
	}

	var candidate string
	contentType := r.Header.Get("Content-Type")
	if strings.HasPrefix(contentType, "application/json") {
		var body struct {
			Credential string `json:"credential"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			s.signIns.refused(ctx, "breakglass", refusedInvalidRequest, nil, "error", "the body is not JSON with a credential")
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		candidate = body.Credential
	} else {
		candidate = r.FormValue("credential")
	}

	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		s.signIns.refused(ctx, "breakglass", refusedInvalidRequest, nil, "error", "no credential")
		http.Error(w, "credential is required", http.StatusBadRequest)
		return
	}

	if s.opts.CredentialHashFile == "" {
		s.logger.Error("break-glass enabled but credential_hash_file is empty")
		s.signIns.ended("breakglass", resultError)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	hashData, err := os.ReadFile(s.opts.CredentialHashFile)
	if err != nil {
		s.logger.Error("reading break-glass credential hash file", "error", err)
		s.signIns.ended("breakglass", resultError)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if !VerifyCredential(string(hashData), candidate) {
		s.signIns.refused(ctx, "breakglass", refusedInvalidCredential, nil)
		http.Error(w, "invalid break-glass credential", http.StatusUnauthorized)
		return
	}

	now := s.opts.Clock.Now().UTC()
	var session *Session

	err = s.database.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		// Provision the break-glass principal record if it does not exist:
		// its first use records the principal's creation.
		_, err := signInHuman(ctx, tx, s.writer, now, BreakglassPrincipalID, "breakglass", Identity{
			Issuer:      "whitetower:breakglass",
			Subject:     "custodian",
			DisplayName: "Break-Glass Custodian",
		})
		if err != nil {
			return fmt.Errorf("upserting break-glass principal: %w", err)
		}

		// Issue a 1-hour session with RoleOperator permissions restricted by
		// BreakglassScopes. Security test ST-14: the session that the browser
		// held is revoked in the same transaction, and recorded; the event
		// below records the sign-in.
		session, err = s.sessions.ReplaceTx(ctx, tx, heldSessions(r), BreakglassPrincipalID, "breakglass", []string{string(authz.RoleOperator)}, BreakglassLifetime)
		if err != nil {
			return fmt.Errorf("creating break-glass session: %w", err)
		}

		// Security test ST-20: Each use raises the critical event.
		if err := s.writer.Record(ctx, tx, audit.Event{
			Type:    "whitetower.breakglass.used.v1",
			Subject: BreakglassPrincipalID.String(),
			Data: map[string]any{
				"actor": map[string]any{
					"type": "breakglass",
					"id":   BreakglassPrincipalID.String(),
				},
				"expires_at": session.AbsoluteExpiresAt.UTC().Format("2006-01-02T15:04:05.000Z"),
				"actor_ip":   ip,
			},
		}); err != nil {
			return fmt.Errorf("recording break-glass audit event: %w", err)
		}
		return nil
	})
	if err != nil {
		s.logger.Error("establishing break-glass session", "error", err)
		s.signIns.ended("breakglass", resultError)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	s.signIns.ended("breakglass", resultSuccess)

	// Security test ST-20: Each use logs an alert.
	s.logger.ErrorContext(ctx, "SECURITY ALERT: break-glass emergency credential used",
		"principal_id", BreakglassPrincipalID.String(),
		"ip", ip,
		"expires_at", session.AbsoluteExpiresAt,
	)

	http.SetCookie(w, s.sessions.CookieForSession(session))

	if strings.Contains(r.Header.Get("Accept"), "application/json") || strings.HasPrefix(contentType, "application/json") {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":     "authenticated",
			"expires_at": session.AbsoluteExpiresAt,
		})
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func breakglassClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		if addr, err := netip.ParseAddr(host); err == nil {
			return ratelimit.AddressKey(addr)
		}
		return host
	}
	return r.RemoteAddr
}
