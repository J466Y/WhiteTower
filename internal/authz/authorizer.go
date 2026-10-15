package authz

import (
	"context"
	"fmt"
	"sync"

	"github.com/J466Y/WhiteTower/internal/platform/auth"
)

type relationshipKey struct{}

// ContextWithRelationship returns a new context carrying the given relationship.
func ContextWithRelationship(ctx context.Context, rel Relationship) context.Context {
	return context.WithValue(ctx, relationshipKey{}, rel)
}

// RelationshipFromContext returns the Relationship attached to ctx, if any.
func RelationshipFromContext(ctx context.Context) (Relationship, bool) {
	rel, ok := ctx.Value(relationshipKey{}).(Relationship)
	return rel, ok
}

// Authorizer evaluates API operations and domain permissions against the
// role-to-permission matrix and separation of duties rules.
type Authorizer struct {
	mu         sync.RWMutex
	operations map[string]Permission
}

var _ auth.Authorizer = (*Authorizer)(nil)

// NewAuthorizer returns an initialized Authorizer with standard operation mappings.
func NewAuthorizer() *Authorizer {
	az := &Authorizer{
		operations: make(map[string]Permission),
	}
	az.registerDefaults()
	return az
}

// registerDefaults sets up standard OpenAPI operation mappings to permissions.
func (az *Authorizer) registerDefaults() {
	az.operations["getMe"] = PermissionIdentityMeRead
	az.operations["getAuditEvents"] = PermissionAuditEventsRead
	az.operations["getAuditCheckpoints"] = PermissionAuditVerify
	az.operations["exportAudit"] = PermissionAuditExport
	az.operations["listAgents"] = PermissionInventoryView
	az.operations["getAgent"] = PermissionInventoryView
	az.operations["proposeAgent"] = PermissionAgentPropose
	az.operations["editAgent"] = PermissionAgentMetadataEdit
	az.operations["activateAgent"] = PermissionAgentActivate
	az.operations["suspendAgent"] = PermissionAgentSuspend
	az.operations["reinstateAgent"] = PermissionAgentReinstate
	az.operations["retireAgent"] = PermissionAgentRetire
	az.operations["manageCredentials"] = PermissionAgentCredentialsManage
	az.operations["haltAgent"] = PermissionHaltAgentIssue
	az.operations["haltFleet"] = PermissionHaltFleetIssue
	az.operations["requestHaltRelease"] = PermissionHaltReleaseRequest
	az.operations["approveHaltRelease"] = PermissionHaltReleaseApprove
	az.operations["validateUsecase"] = PermissionUsecaseValidate
	az.operations["authorGlobalPolicy"] = PermissionPolicyGlobalAuthor
	az.operations["approveGlobalPolicy"] = PermissionPolicyGlobalApprove
	az.operations["authorAgentPolicy"] = PermissionPolicyAgentAuthor
	az.operations["approveAgentPolicy"] = PermissionPolicyAgentApprove
	az.operations["manageModules"] = PermissionModuleManage
	az.operations["manageSettings"] = PermissionSettingsManage
	az.operations["listTokens"] = PermissionIdentityMeRead
	az.operations["createToken"] = PermissionIdentityMeRead
	az.operations["revokeToken"] = PermissionIdentityMeRead
	az.operations["listServiceAccounts"] = PermissionIdentityMeRead
	az.operations["createServiceAccount"] = PermissionIdentityMeRead
}

// RegisterOperation maps an OpenAPI operation ID to a Permission.
func (az *Authorizer) RegisterOperation(operationID string, perm Permission) {
	az.mu.Lock()
	defer az.mu.Unlock()
	az.operations[operationID] = perm
}

// ResolveOperation returns the permission mapped to operation, or the operation
// itself if it matches a known Permission.
func (az *Authorizer) ResolveOperation(operation string) (Permission, bool) {
	az.mu.RLock()
	defer az.mu.RUnlock()

	if p, ok := az.operations[operation]; ok {
		return p, true
	}
	perm := Permission(operation)
	if IsValidPermission(perm) {
		return perm, true
	}
	return "", false
}

// Authorize checks whether the authenticated principal has permission to invoke
// operation. Denies by default if unauthenticated, unknown operation, or not permitted.
func (az *Authorizer) Authorize(ctx context.Context, p *auth.Principal, operation string) error {
	if p == nil {
		return auth.ErrDenied
	}

	perm, ok := az.ResolveOperation(operation)
	if !ok {
		return fmt.Errorf("%w: unknown operation %q", auth.ErrDenied, operation)
	}

	// Enforce API token scopes: a scoped token can do only what its scopes allow (ST-19).
	if p.Scopes != nil {
		hasScope := false
		for _, s := range p.Scopes {
			if s == string(perm) || s == "*" {
				hasScope = true
				break
			}
		}
		if !hasScope {
			return auth.ErrDenied
		}
	}

	rel, hasRel := RelationshipFromContext(ctx)
	if hasRel {
		if !Allows(p.Roles, perm, rel) {
			return auth.ErrDenied
		}
		return nil
	}

	// Without resource context, verify if any role holds a grant for the permission.
	_, hasGrant := EffectiveGrant(p.Roles, perm)
	if !hasGrant {
		return auth.ErrDenied
	}
	return nil
}

// AuthorizeResource checks if the principal is authorized for permission under
// the specified resource relationship.
func (az *Authorizer) AuthorizeResource(p *auth.Principal, perm Permission, rel Relationship) error {
	if p == nil {
		return auth.ErrDenied
	}
	if !Allows(p.Roles, perm, rel) {
		return auth.ErrDenied
	}
	return nil
}
