package authz

import (
	"context"
	"fmt"
	"slices"
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
	// viewsCatalog holds the operations that also need PermissionCatalogView,
	// whose answers carry references and reported text.
	viewsCatalog map[string]bool
}

var _ auth.Authorizer = (*Authorizer)(nil)

// NewAuthorizer returns an initialized Authorizer with standard operation mappings.
func NewAuthorizer() *Authorizer {
	az := &Authorizer{
		operations:   make(map[string]Permission),
		viewsCatalog: make(map[string]bool),
	}
	az.registerDefaults()
	return az
}

// registerDefaults sets up standard OpenAPI operation mappings to permissions.
func (az *Authorizer) registerDefaults() {
	az.operations["getMe"] = PermissionIdentityMeRead
	az.operations["getAuditEvents"] = PermissionAuditEventsRead
	az.operations["getAuditEvent"] = PermissionAuditEventsRead
	az.operations["getAuditCheckpoints"] = PermissionAuditVerify
	az.operations["getAuditKeys"] = PermissionAuditVerify
	az.operations["exportAudit"] = PermissionAuditExport
	az.operations["manageCredentials"] = PermissionAgentCredentialsManage
	az.operations["haltAgent"] = PermissionHaltAgentIssue
	az.operations["haltFleet"] = PermissionHaltFleetIssue
	az.operations["requestHaltRelease"] = PermissionHaltReleaseRequest
	az.operations["approveHaltRelease"] = PermissionHaltReleaseApprove
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
	az.operations["revokeAllSessionsAndTokens"] = PermissionIdentityEmergencyRevoke

	// The inventory (plan P1-04). Its handlers check the scope of each grant
	// against the agent: ownership, an active agent, a sign-off.
	az.operations["listAgents"] = PermissionInventoryView
	az.operations["proposeAgent"] = PermissionAgentPropose
	az.operations["exportAgents"] = PermissionInventoryView
	az.operations["getAgent"] = PermissionInventoryView
	az.operations["editAgent"] = PermissionAgentMetadataEdit
	az.operations["getAgentActions"] = PermissionInventoryView
	az.operations["listAgentTransitions"] = PermissionInventoryView
	// Each lifecycle action needs its own permission besides this one. The
	// inventory checks it with Authorize, the action's permission as the
	// operation and the agent's relationship in the context: unlike
	// AuthorizeResource, that call also enforces a token's scopes.
	az.operations["transitionAgent"] = PermissionInventoryView
	az.operations["listAgentInstances"] = PermissionInventoryView
	az.operations["listAgentOwners"] = PermissionInventoryView
	az.operations["reassignAgentOwner"] = PermissionAgentOwnershipReassign
	az.operations["addAgentDelegate"] = PermissionAgentMetadataEdit
	az.operations["removeAgentDelegate"] = PermissionAgentMetadataEdit
	az.operations["requestOwnershipTransfer"] = PermissionAgentMetadataEdit
	az.operations["cancelOwnershipTransfer"] = PermissionAgentMetadataEdit
	// Accepting an agent makes one its owner, which needs the owner role, as
	// proposing one does; declining needs none.
	az.operations["acceptOwnershipTransfer"] = PermissionAgentPropose
	az.operations["declineOwnershipTransfer"] = PermissionIdentityMeRead
	az.operations["listUseCases"] = PermissionInventoryView
	az.operations["createUseCase"] = PermissionAgentPropose
	az.operations["getUseCase"] = PermissionInventoryView
	az.operations["editUseCase"] = PermissionAgentPropose
	az.operations["listUseCaseDecisions"] = PermissionInventoryView
	az.operations["listDataCategories"] = PermissionInventoryView
	az.operations["listAgentReviews"] = PermissionInventoryView
	az.operations["listReviews"] = PermissionInventoryView
	az.operations["getReview"] = PermissionInventoryView
	az.operations["completeReview"] = PermissionAgentReview
	az.operations["signOffReview"] = PermissionAgentReview
	az.operations["listInboxItems"] = PermissionIdentityMeRead

	// The catalog of MCP servers, tools and models, and agents' tooling (plan
	// P1-16). The handlers of the agents' tooling check the scope of each
	// grant against the agent, as the inventory's do: an owner requests,
	// disables and declares only for the agents they own. Their answers
	// carry references and reported text, so each also needs
	// PermissionCatalogView, which Authorize checks here rather than in each
	// handler.
	az.catalogOperation("listCatalogServers", PermissionCatalogView)
	az.catalogOperation("getCatalogServer", PermissionCatalogView)
	az.catalogOperation("approveCatalogServer", PermissionCatalogEntryApprove)
	az.catalogOperation("declineCatalogServer", PermissionCatalogEntryApprove)
	az.catalogOperation("listCatalogTools", PermissionCatalogView)
	az.catalogOperation("getCatalogTool", PermissionCatalogView)
	az.catalogOperation("approveCatalogTool", PermissionCatalogEntryApprove)
	az.catalogOperation("declineCatalogTool", PermissionCatalogEntryApprove)
	az.catalogOperation("getToolDefinition", PermissionCatalogView)
	az.catalogOperation("listCatalogModels", PermissionCatalogView)
	az.catalogOperation("getCatalogModel", PermissionCatalogView)
	az.catalogOperation("approveCatalogModel", PermissionCatalogEntryApprove)
	az.catalogOperation("declineCatalogModel", PermissionCatalogEntryApprove)
	az.catalogOperation("declinePendingFromAgent", PermissionCatalogEntryApprove)
	az.catalogOperation("listCatalogBlocks", PermissionCatalogView)
	az.catalogOperation("issueCatalogBlock", PermissionCatalogBlockIssue)
	az.catalogOperation("getCatalogBlock", PermissionCatalogView)
	az.catalogOperation("requestCatalogUnblock", PermissionCatalogUnblockRequest)
	az.catalogOperation("approveCatalogUnblock", PermissionCatalogUnblockApprove)
	// A decline only denies, so whoever may approve may decline any
	// request, their own included.
	az.catalogOperation("declineCatalogUnblock", PermissionCatalogUnblockApprove)
	az.catalogOperation("compileUsageRules", PermissionCatalogView)
	az.catalogOperation("listAgentTooling", PermissionCatalogView)
	az.catalogOperation("listAgentToolingRequests", PermissionCatalogView)
	az.catalogOperation("requestAgentTooling", PermissionToolingEnableRequest)
	az.catalogOperation("approveAgentToolingRequest", PermissionToolingEnableApprove)
	az.catalogOperation("declineAgentToolingRequest", PermissionToolingEnableApprove)
	az.catalogOperation("disableAgentTooling", PermissionToolingDisable)
	az.catalogOperation("getAgentDeclaredTooling", PermissionCatalogView)
	az.catalogOperation("declareAgentTooling", PermissionToolingDeclare)
}

// catalogOperation maps an operation of the catalog to its permission, and
// marks it as one that also needs PermissionCatalogView.
func (az *Authorizer) catalogOperation(operationID string, perm Permission) {
	az.operations[operationID] = perm
	az.viewsCatalog[operationID] = true
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

	// An emergency revocation (HUM-10, ST-89) is the break-glass custodian's,
	// by the session, and the platform administrator's, by role, below.
	if perm == PermissionIdentityEmergencyRevoke && p.IsBreakglass {
		return nil
	}
	// A permission that is no token scope is never an API token's, whatever
	// its scopes hold, even an administrator's: a token that someone obtained
	// through a compromised identity provider must not end the sessions of
	// the people who answer the incident.
	if p.Scopes != nil && !p.IsBreakglass && !IsTokenScope(perm) {
		return auth.ErrDenied
	}

	// Enforce break-glass restrictions (ST-20): besides an emergency
	// revocation, above, can halt agents and the fleet and read, and nothing else.
	if p.IsBreakglass {
		switch perm {
		case PermissionHaltAgentIssue, PermissionHaltFleetIssue, PermissionInventoryView, PermissionAuditEventsRead, PermissionAuditVerify, PermissionAuditExport, PermissionIdentityMeRead:
			// These change state, although the permission they map to only reads.
			switch operation {
			case "createToken", "revokeToken", "createServiceAccount", "transitionAgent", "declineOwnershipTransfer":
				return auth.ErrDenied
			}
		default:
			return auth.ErrDenied
		}
	}

	// Enforce API token scopes: a scoped token can do only what its scopes allow (ST-19).
	if p.Scopes != nil && !hasScope(p.Scopes, perm) {
		return auth.ErrDenied
	}

	// An operation of the catalog answers with references and reported text,
	// which only PermissionCatalogView shows (RFC-0002, Privacy): it needs
	// that permission too, from a role and, for a token, in its scopes.
	if az.needsCatalogView(operation) {
		if _, ok := EffectiveGrant(p.Roles, PermissionCatalogView); !ok || (p.Scopes != nil && !hasScope(p.Scopes, PermissionCatalogView)) {
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

// needsCatalogView reports whether operation is one of the catalog, which
// also needs PermissionCatalogView.
func (az *Authorizer) needsCatalogView(operation string) bool {
	az.mu.RLock()
	defer az.mu.RUnlock()
	return az.viewsCatalog[operation]
}

// hasScope reports whether a token's scopes hold perm, or every permission.
func hasScope(scopes []string, perm Permission) bool {
	return slices.Contains(scopes, string(perm)) || slices.Contains(scopes, "*")
}

// AuthorizeResource checks if the principal is authorized for permission under
// the specified resource relationship.
func (az *Authorizer) AuthorizeResource(p *auth.Principal, perm Permission, rel Relationship) error {
	if p == nil {
		return auth.ErrDenied
	}
	if p.IsBreakglass {
		switch perm {
		case PermissionHaltAgentIssue, PermissionHaltFleetIssue, PermissionInventoryView, PermissionAuditEventsRead, PermissionAuditVerify, PermissionAuditExport, PermissionIdentityMeRead:
		default:
			return auth.ErrDenied
		}
	}
	if !Allows(p.Roles, perm, rel) {
		return auth.ErrDenied
	}
	return nil
}
