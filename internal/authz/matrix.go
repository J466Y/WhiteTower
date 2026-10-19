package authz

import "slices"

// Scope defines the boundary of a permission grant.
type Scope string

const (
	// ScopeAll grants unconditional access across all resources.
	ScopeAll Scope = "all"

	// ScopeOwn grants access only to resources the principal owns or delegates for.
	ScopeOwn Scope = "own"

	// ScopeActiveOnly grants access only to resources in active lifecycle state.
	ScopeActiveOnly Scope = "active_only"

	// ScopeSignOff grants approval/sign-off authority on high and critical risk reviews.
	ScopeSignOff Scope = "sign_off"
)

// Grant specifies a permission and its applicable scope.
type Grant struct {
	Scope Scope
}

// Relationship describes the relationship between the requesting principal
// and the resource being acted upon.
type Relationship struct {
	// IsOwner is true if the principal is the registered owner or an authorized delegate of the agent.
	IsOwner bool

	// IsActive is true if the target agent is in active status.
	IsActive bool

	// IsHighOrCriticalRisk is true if the agent is classified as high or critical risk.
	IsHighOrCriticalRisk bool
}

// Allows returns true if the grant's scope permits the action given the relationship.
func (g Grant) Allows(rel Relationship) bool {
	switch g.Scope {
	case ScopeAll:
		return true
	case ScopeOwn:
		return rel.IsOwner
	case ScopeActiveOnly:
		return rel.IsActive
	case ScopeSignOff:
		return rel.IsHighOrCriticalRisk
	default:
		return false
	}
}

// Matrix is the definitive role-to-permission mapping derived from requirements section 5.2.1.
// Every entry is explicit; undefined combinations are denied by default.
var Matrix = map[Role]map[Permission]Grant{
	RoleSteering: {
		PermissionInventoryView:       {Scope: ScopeAll},
		PermissionPolicyGlobalAuthor:  {Scope: ScopeAll},
		PermissionPolicyGlobalApprove: {Scope: ScopeAll},
		PermissionHaltAgentIssue:      {Scope: ScopeAll},
		PermissionHaltFleetIssue:      {Scope: ScopeAll},
		PermissionHaltReleaseRequest:  {Scope: ScopeAll},
		PermissionHaltReleaseApprove:  {Scope: ScopeAll},
		PermissionAuditEventsRead:     {Scope: ScopeAll},
		PermissionAuditVerify:         {Scope: ScopeAll},
		PermissionAuditExport:         {Scope: ScopeAll},
		PermissionIdentityMeRead:      {Scope: ScopeAll},
	},

	RoleAdvisory: {
		PermissionInventoryView:          {Scope: ScopeAll},
		PermissionAgentOwnershipReassign: {Scope: ScopeAll},
		PermissionUsecaseValidate:        {Scope: ScopeAll},
		PermissionPolicyGlobalAuthor:     {Scope: ScopeAll},
		PermissionPolicyAgentAuthor:      {Scope: ScopeAll},
		PermissionPolicyAgentApprove:     {Scope: ScopeAll},
		PermissionAgentReview:            {Scope: ScopeSignOff},
		PermissionAgentSuspend:           {Scope: ScopeAll},
		PermissionAgentReinstate:         {Scope: ScopeAll},
		PermissionAgentRetire:            {Scope: ScopeAll},
		PermissionHaltAgentIssue:         {Scope: ScopeAll},
		PermissionHaltReleaseRequest:     {Scope: ScopeAll},
		PermissionHaltReleaseApprove:     {Scope: ScopeAll},
		PermissionAuditEventsRead:        {Scope: ScopeAll},
		PermissionAuditVerify:            {Scope: ScopeAll},
		PermissionAuditExport:            {Scope: ScopeAll},
		PermissionIdentityMeRead:         {Scope: ScopeAll},
	},

	RoleOwner: {
		PermissionInventoryView:          {Scope: ScopeAll},
		PermissionAgentPropose:           {Scope: ScopeAll},
		PermissionAgentMetadataEdit:      {Scope: ScopeOwn},
		PermissionPolicyAgentAuthor:      {Scope: ScopeOwn},
		PermissionAgentActivate:          {Scope: ScopeOwn},
		PermissionAgentReview:            {Scope: ScopeOwn},
		PermissionAgentSuspend:           {Scope: ScopeOwn},
		PermissionAgentRetire:            {Scope: ScopeOwn},
		PermissionAgentCredentialsManage: {Scope: ScopeOwn},
		PermissionHaltAgentIssue:         {Scope: ScopeOwn},
		PermissionHaltReleaseRequest:     {Scope: ScopeOwn},
		PermissionAuditEventsRead:        {Scope: ScopeOwn},
		PermissionIdentityMeRead:         {Scope: ScopeAll},
	},

	RoleUser: {
		PermissionInventoryView:  {Scope: ScopeActiveOnly},
		PermissionIdentityMeRead: {Scope: ScopeAll},
	},

	RoleOperator: {
		PermissionInventoryView:          {Scope: ScopeAll},
		PermissionAgentMetadataEdit:      {Scope: ScopeAll},
		PermissionAgentOwnershipReassign: {Scope: ScopeAll},
		PermissionAgentActivate:          {Scope: ScopeAll},
		PermissionAgentSuspend:           {Scope: ScopeAll},
		PermissionAgentReinstate:         {Scope: ScopeAll},
		PermissionAgentRetire:            {Scope: ScopeAll},
		PermissionAgentCredentialsManage: {Scope: ScopeAll},
		PermissionHaltAgentIssue:         {Scope: ScopeAll},
		PermissionHaltFleetIssue:         {Scope: ScopeAll},
		PermissionHaltReleaseRequest:     {Scope: ScopeAll},
		PermissionHaltReleaseApprove:     {Scope: ScopeAll},
		PermissionModuleManage:           {Scope: ScopeAll},
		PermissionAuditEventsRead:        {Scope: ScopeAll},
		PermissionAuditVerify:            {Scope: ScopeAll},
		PermissionAuditExport:            {Scope: ScopeAll},
		PermissionIdentityMeRead:         {Scope: ScopeAll},
	},

	RoleAuditor: {
		PermissionInventoryView:   {Scope: ScopeAll},
		PermissionAuditEventsRead: {Scope: ScopeAll},
		PermissionAuditVerify:     {Scope: ScopeAll},
		PermissionAuditExport:     {Scope: ScopeAll},
		PermissionIdentityMeRead:  {Scope: ScopeAll},
	},

	RoleAdmin: {
		PermissionInventoryView:  {Scope: ScopeAll},
		PermissionSettingsManage: {Scope: ScopeAll},
		PermissionIdentityMeRead: {Scope: ScopeAll},
	},
}

// RoleGrant returns the grant for a given role and permission, if defined.
func RoleGrant(role Role, perm Permission) (Grant, bool) {
	roleMap, ok := Matrix[role]
	if !ok {
		return Grant{}, false
	}
	grant, ok := roleMap[perm]
	return grant, ok
}

// HasPermission returns true if the given role has any grant for the permission.
func HasPermission(role Role, perm Permission) bool {
	_, ok := RoleGrant(role, perm)
	return ok
}

// EffectiveGrant returns the broadest grant across all supplied roles for the permission.
// ScopeAll takes highest precedence.
func EffectiveGrant(roles []string, perm Permission) (Grant, bool) {
	var best Grant
	found := false
	for _, rStr := range roles {
		grant, ok := RoleGrant(Role(rStr), perm)
		if !ok {
			continue
		}
		if !found || grant.Scope == ScopeAll {
			best = grant
			found = true
			if grant.Scope == ScopeAll {
				break
			}
		}
	}
	return best, found
}

// Allows checks if the principal with the given roles is permitted to perform
// an action requiring perm under the given relationship context.
func Allows(roles []string, perm Permission, rel Relationship) bool {
	for _, rStr := range roles {
		grant, ok := RoleGrant(Role(rStr), perm)
		if !ok {
			continue
		}
		if grant.Allows(rel) {
			return true
		}
	}
	return false
}

// PermissionsList returns a sorted list of unique permission IDs granted to any of the roles.
func PermissionsList(roles []string) []string {
	seen := map[Permission]bool{}
	for _, rStr := range roles {
		for perm := range Matrix[Role(rStr)] {
			seen[perm] = true
		}
	}
	list := make([]string, 0, len(seen))
	for perm := range seen {
		list = append(list, string(perm))
	}
	slices.Sort(list)
	return list
}
