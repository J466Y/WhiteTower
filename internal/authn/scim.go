package authn

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/logging"
)

// SCIM 2.0 Schemas (RFC 7643, RFC 7644).
const (
	SCIMContentType = "application/scim+json; charset=utf-8"
	SchemaUser      = "urn:ietf:params:scim:schemas:core:2.0:User"
	SchemaError     = "urn:ietf:params:scim:api:messages:2.0:Error"
	SchemaList      = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SchemaPatch     = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
)

// SCIMPrincipalID is the reserved system identifier for SCIM provisioning and deprovisioning actions.
var SCIMPrincipalID = uuid.MustParse("00000000-0000-0000-0000-000000000002")

// SCIMPrincipal represents the service account actor attributed in audit records for SCIM operations.
var SCIMPrincipal = auth.Principal{
	ID:    SCIMPrincipalID.String(),
	Kind:  auth.ServiceAccount,
	Name:  "SCIM Provisioner",
	Roles: []string{"admin"},
}

// SCIMOptions configures the SCIM 2.0 service.
type SCIMOptions struct {
	Enabled   bool
	TokenFile string
	Logger    *slog.Logger
}

// SCIMService handles SCIM 2.0 endpoints under /scim/v2/Users (plan P1-03, step 8; HUM-05; ST-21; threat model T-18).
type SCIMService struct {
	enabled    bool
	token      string
	logger     *slog.Logger
	principals *PrincipalStore
}

// NewSCIMService initializes a new SCIMService.
func NewSCIMService(opts SCIMOptions, principals *PrincipalStore) (*SCIMService, error) {
	svc := &SCIMService{
		enabled:    opts.Enabled,
		logger:     opts.Logger,
		principals: principals,
	}
	if svc.logger == nil {
		svc.logger = slog.New(slog.DiscardHandler)
	}

	if opts.Enabled {
		if opts.TokenFile == "" {
			return nil, errors.New("scim token file path must be specified when scim is enabled")
		}
		data, err := os.ReadFile(opts.TokenFile)
		if err != nil {
			return nil, fmt.Errorf("reading scim token file %s: %w", opts.TokenFile, err)
		}
		svc.token = strings.TrimSpace(string(data))
		if svc.token == "" {
			return nil, fmt.Errorf("scim token file %s is empty", opts.TokenFile)
		}
	}

	return svc, nil
}

// ServeHTTP handles SCIM 2.0 requests under /scim/v2/Users.
func (s *SCIMService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.enabled {
		s.writeError(w, http.StatusNotFound, "", "SCIM endpoint is disabled")
		return
	}

	// Verify bearer token (ST-21; threat model T-18).
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		s.writeError(w, http.StatusUnauthorized, "", "Unauthorized: missing bearer token")
		return
	}
	candidateToken := strings.TrimPrefix(authHeader, "Bearer ")
	if subtle.ConstantTimeCompare([]byte(candidateToken), []byte(s.token)) != 1 {
		safeRemoteAddr := strings.ReplaceAll(r.RemoteAddr, "\n", "")
		safeRemoteAddr = strings.ReplaceAll(safeRemoteAddr, "\r", "")
		s.logger.Warn("SCIM authentication failed: invalid bearer token", "remote_addr", logging.Sanitize(safeRemoteAddr))
		s.writeError(w, http.StatusUnauthorized, "", "Unauthorized: invalid bearer token")
		return
	}

	subpath := strings.TrimPrefix(r.URL.Path, "/scim/v2/Users")
	subpath = strings.TrimPrefix(subpath, "/")

	if subpath == "" {
		switch r.Method {
		case http.MethodGet:
			s.handleListUsers(w, r)
		case http.MethodPost:
			s.handleCreateUser(w, r)
		default:
			s.writeError(w, http.StatusMethodNotAllowed, "", fmt.Sprintf("Method %s not allowed on /scim/v2/Users", r.Method))
		}
		return
	}

	// Subpath is the user ID.
	switch r.Method {
	case http.MethodGet:
		s.handleGetUser(w, r, subpath)
	case http.MethodPatch:
		s.handlePatchUser(w, r, subpath)
	case http.MethodDelete:
		s.handleDeleteUser(w, r, subpath)
	default:
		s.writeError(w, http.StatusMethodNotAllowed, "", fmt.Sprintf("Method %s not allowed on /scim/v2/Users/{id}", r.Method))
	}
}

type scimErrorResponse struct {
	Schemas  []string `json:"schemas"`
	Status   string   `json:"status"`
	ScimType string   `json:"scimType,omitempty"`
	Detail   string   `json:"detail,omitempty"`
}

func (s *SCIMService) writeError(w http.ResponseWriter, status int, scimType, detail string) {
	w.Header().Set("Content-Type", SCIMContentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(scimErrorResponse{
		Schemas:  []string{SchemaError},
		Status:   strconv.Itoa(status),
		ScimType: scimType,
		Detail:   detail,
	})
}

type scimName struct {
	Formatted  string `json:"formatted,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
}

type scimEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

type scimMeta struct {
	ResourceType string     `json:"resourceType"`
	Created      *time.Time `json:"created,omitempty"`
	LastModified *time.Time `json:"lastModified,omitempty"`
	Location     string     `json:"location,omitempty"`
}

type scimUserResource struct {
	Schemas     []string    `json:"schemas"`
	ID          string      `json:"id"`
	UserName    string      `json:"userName"`
	DisplayName string      `json:"displayName"`
	Name        *scimName   `json:"name,omitempty"`
	Emails      []scimEmail `json:"emails,omitempty"`
	Active      bool        `json:"active"`
	Meta        scimMeta    `json:"meta"`
}

type scimListResponse struct {
	Schemas      []string           `json:"schemas"`
	TotalResults int64              `json:"totalResults"`
	StartIndex   int64              `json:"startIndex"`
	ItemsPerPage int64              `json:"itemsPerPage"`
	Resources    []scimUserResource `json:"Resources"`
}

func principalToSCIM(p *Principal) scimUserResource {
	userName := ""
	if p.Subject != nil {
		userName = *p.Subject
	}
	if userName == "" && p.Email != nil {
		userName = *p.Email
	}
	var emails []scimEmail
	if p.Email != nil && *p.Email != "" {
		emails = append(emails, scimEmail{
			Value:   *p.Email,
			Type:    "work",
			Primary: true,
		})
	}
	loc := "/scim/v2/Users/" + p.ID.String()
	return scimUserResource{
		Schemas:     []string{SchemaUser},
		ID:          p.ID.String(),
		UserName:    userName,
		DisplayName: p.DisplayName,
		Name: &scimName{
			Formatted: p.DisplayName,
		},
		Emails: emails,
		Active: p.Status == "active",
		Meta: scimMeta{
			ResourceType: "User",
			Created:      &p.CreatedAt,
			LastModified: &p.UpdatedAt,
			Location:     loc,
		},
	}
}

var filterRegex = regexp.MustCompile(`(?i)(?:userName|emails\.value)\s+eq\s+["']?([^"']+)["']?`)

func (s *SCIMService) handleListUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	filter := strings.TrimSpace(r.URL.Query().Get("filter"))

	if filter != "" {
		matches := filterRegex.FindStringSubmatch(filter)
		if len(matches) > 1 {
			val := matches[1]
			p, err := s.principals.GetBySubjectOrEmail(ctx, val)
			if err != nil {
				if errors.Is(err, ErrPrincipalNotFound) {
					s.writeListResponse(w, 0, 1, 0, []scimUserResource{})
					return
				}
				safeFilter := strings.ReplaceAll(filter, "\n", "")
				safeFilter = strings.ReplaceAll(safeFilter, "\r", "")
				s.logger.Error("querying principal by filter", "error", err, "filter", logging.Sanitize(safeFilter))
				s.writeError(w, http.StatusInternalServerError, "", "Internal server error")
				return
			}
			s.writeListResponse(w, 1, 1, 1, []scimUserResource{principalToSCIM(p)})
			return
		}
	}

	startIndex := int64(1)
	if sIdxStr := r.URL.Query().Get("startIndex"); sIdxStr != "" {
		if parsed, err := strconv.ParseInt(sIdxStr, 10, 64); err == nil && parsed > 0 {
			startIndex = parsed
		}
	}

	count := int64(100)
	if countStr := r.URL.Query().Get("count"); countStr != "" {
		if parsed, err := strconv.ParseInt(countStr, 10, 64); err == nil && parsed >= 0 {
			count = parsed
		}
	}

	var offset int32
	if startIndex > 1 && startIndex <= math.MaxInt32 {
		//nolint:gosec // G115: bounded between 1 and math.MaxInt32
		offset = int32(startIndex - 1)
	}
	var limit int32 = 100
	if count >= 0 && count <= 1000 {
		//nolint:gosec // G115: bounded between 0 and 1000
		limit = int32(count)
	} else if count > 1000 {
		limit = 1000
	}
	humans, total, err := s.principals.ListHumans(ctx, limit, offset)
	if err != nil {
		s.logger.Error("listing human principals", "error", err)
		s.writeError(w, http.StatusInternalServerError, "", "Internal server error")
		return
	}

	resources := make([]scimUserResource, len(humans))
	for i, h := range humans {
		resources[i] = principalToSCIM(h)
	}

	s.writeListResponse(w, total, startIndex, int64(len(resources)), resources)
}

func (s *SCIMService) writeListResponse(w http.ResponseWriter, total, startIndex, itemsPerPage int64, resources []scimUserResource) {
	w.Header().Set("Content-Type", SCIMContentType)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(scimListResponse{
		Schemas:      []string{SchemaList},
		TotalResults: total,
		StartIndex:   startIndex,
		ItemsPerPage: itemsPerPage,
		Resources:    resources,
	})
}

type scimCreateUserRequest struct {
	Schemas     []string `json:"schemas"`
	UserName    string   `json:"userName"`
	DisplayName string   `json:"displayName"`
	Name        *struct {
		Formatted  string `json:"formatted"`
		FamilyName string `json:"familyName"`
		GivenName  string `json:"givenName"`
	} `json:"name"`
	Emails []struct {
		Value   string `json:"value"`
		Type    string `json:"type"`
		Primary bool   `json:"primary"`
	} `json:"emails"`
	Active *bool `json:"active"`
}

func (s *SCIMService) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req scimCreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalidSyntax", "Malformed SCIM user JSON payload")
		return
	}

	if strings.TrimSpace(req.UserName) == "" {
		s.writeError(w, http.StatusBadRequest, "invalidValue", "userName is required")
		return
	}

	// Check for collision
	if existing, err := s.principals.GetBySubjectOrEmail(ctx, req.UserName); err == nil && existing != nil {
		safeUserName := strings.ReplaceAll(req.UserName, "\n", "")
		safeUserName = strings.ReplaceAll(safeUserName, "\r", "")
		s.writeError(w, http.StatusConflict, "uniqueness", fmt.Sprintf("User with userName %q already exists", logging.Sanitize(safeUserName)))
		return
	}

	displayName := req.DisplayName
	if displayName == "" && req.Name != nil && req.Name.Formatted != "" {
		displayName = req.Name.Formatted
	}
	if displayName == "" {
		displayName = req.UserName
	}

	var email *string
	for _, e := range req.Emails {
		if e.Primary && e.Value != "" {
			email = &e.Value
			break
		}
	}
	if email == nil && len(req.Emails) > 0 && req.Emails[0].Value != "" {
		email = &req.Emails[0].Value
	}
	if email == nil && strings.Contains(req.UserName, "@") {
		email = &req.UserName
	}

	created, err := s.principals.UpsertHuman(ctx, "scim", req.UserName, displayName, email, []string{})
	if err != nil {
		safeUserName := strings.ReplaceAll(req.UserName, "\n", "")
		safeUserName = strings.ReplaceAll(safeUserName, "\r", "")
		s.logger.Error("creating human principal via SCIM", "error", err, "userName", logging.Sanitize(safeUserName))
		s.writeError(w, http.StatusInternalServerError, "", "Internal server error")
		return
	}

	if req.Active != nil && !*req.Active {
		if err := s.principals.Deactivate(ctx, created.ID, SCIMPrincipal, "SCIM initial provisioning as inactive"); err != nil {
			s.logger.Error("deactivating principal after initial creation", "error", err, "id", created.ID)
		}
		// Refetch
		if updated, err := s.principals.GetByID(ctx, created.ID); err == nil {
			created = updated
		}
	}

	w.Header().Set("Content-Type", SCIMContentType)
	w.Header().Set("Location", "/scim/v2/Users/"+created.ID.String())
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(principalToSCIM(created))
}

func (s *SCIMService) handleGetUser(w http.ResponseWriter, r *http.Request, idStr string) {
	ctx := r.Context()
	id, err := uuid.Parse(idStr)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "", "User not found")
		return
	}

	p, err := s.principals.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, ErrPrincipalNotFound) {
			s.writeError(w, http.StatusNotFound, "", "User not found")
			return
		}
		s.logger.Error("getting user by ID via SCIM", "error", err, "id", id.String())
		s.writeError(w, http.StatusInternalServerError, "", "Internal server error")
		return
	}

	w.Header().Set("Content-Type", SCIMContentType)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(principalToSCIM(p))
}

type scimPatchOp struct {
	Schemas    []string `json:"schemas"`
	Operations []struct {
		Op    string `json:"op"`
		Path  string `json:"path"`
		Value any    `json:"value"`
	} `json:"Operations"`
}

func (s *SCIMService) handlePatchUser(w http.ResponseWriter, r *http.Request, idStr string) {
	ctx := r.Context()
	id, err := uuid.Parse(idStr)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "", "User not found")
		return
	}

	p, err := s.principals.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, ErrPrincipalNotFound) {
			s.writeError(w, http.StatusNotFound, "", "User not found")
			return
		}
		s.logger.Error("getting user before patch via SCIM", "error", err, "id", id.String())
		s.writeError(w, http.StatusInternalServerError, "", "Internal server error")
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalidSyntax", "Failed to read request body")
		return
	}

	var patchReq scimPatchOp
	if err := json.Unmarshal(bodyBytes, &patchReq); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalidSyntax", "Malformed SCIM patch JSON payload")
		return
	}

	// Process patch operations, specifically inspecting active status modifications.
	for _, op := range patchReq.Operations {
		opName := strings.ToLower(op.Op)
		if opName != "replace" && opName != "add" {
			continue
		}

		var targetActive *bool
		if strings.EqualFold(op.Path, "active") {
			switch val := op.Value.(type) {
			case bool:
				targetActive = &val
			case string:
				if b, err := strconv.ParseBool(val); err == nil {
					targetActive = &b
				}
			}
		} else if op.Path == "" {
			// e.g. "value": { "active": false }
			if m, ok := op.Value.(map[string]any); ok {
				if activeVal, hasActive := m["active"]; hasActive {
					switch val := activeVal.(type) {
					case bool:
						targetActive = &val
					case string:
						if b, err := strconv.ParseBool(val); err == nil {
							targetActive = &b
						}
					}
				}
			}
		}

		if targetActive != nil {
			if !*targetActive {
				// Deprovisioning: deactivate principal, revoking sessions and tokens (HUM-05, ST-21).
				if err := s.principals.Deactivate(ctx, p.ID, SCIMPrincipal, "SCIM deprovisioning (patch active=false)"); err != nil {
					s.logger.Error("deactivating principal via SCIM patch", "error", err, "id", p.ID)
					s.writeError(w, http.StatusInternalServerError, "", "Failed to deactivate principal")
					return
				}
			} else {
				// Re-provisioning: reactivate principal.
				if err := s.principals.Reactivate(ctx, p.ID, SCIMPrincipal, "SCIM provisioning (patch active=true)"); err != nil {
					s.logger.Error("reactivating principal via SCIM patch", "error", err, "id", p.ID)
					s.writeError(w, http.StatusInternalServerError, "", "Failed to reactivate principal")
					return
				}
			}
		}
	}

	// Refetch and return updated user resource.
	updated, err := s.principals.GetByID(ctx, id)
	if err != nil {
		s.logger.Error("fetching user after patch", "error", err, "id", id.String())
		s.writeError(w, http.StatusInternalServerError, "", "Internal server error")
		return
	}

	w.Header().Set("Content-Type", SCIMContentType)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(principalToSCIM(updated))
}

func (s *SCIMService) handleDeleteUser(w http.ResponseWriter, r *http.Request, idStr string) {
	ctx := r.Context()
	id, err := uuid.Parse(idStr)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "", "User not found")
		return
	}

	p, err := s.principals.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, ErrPrincipalNotFound) {
			s.writeError(w, http.StatusNotFound, "", "User not found")
			return
		}
		s.logger.Error("getting user before delete via SCIM", "error", err, "id", id.String())
		s.writeError(w, http.StatusInternalServerError, "", "Internal server error")
		return
	}

	// Step 8: "delete as deactivation" (HUM-05, ST-21).
	if err := s.principals.Deactivate(ctx, p.ID, SCIMPrincipal, "SCIM deprovisioning (delete)"); err != nil {
		s.logger.Error("deactivating principal via SCIM delete", "error", err, "id", p.ID)
		s.writeError(w, http.StatusInternalServerError, "", "Failed to deactivate principal")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
