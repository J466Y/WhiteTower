package authz

import "slices"

// Permission is a stable identifier for an action guarded by authorization.
type Permission string

// The permissions of White Tower, derived from requirements section 5.2.1.
const (
	// PermissionInventoryView allows viewing the agent inventory.
	PermissionInventoryView Permission = "inventory.view"

	// PermissionAgentPropose allows proposing a new agent into the inventory.
	PermissionAgentPropose Permission = "agent.propose"

	// PermissionAgentMetadataEdit allows editing metadata of an existing agent.
	PermissionAgentMetadataEdit Permission = "agent.metadata.edit"

	// PermissionAgentOwnershipReassign allows making another principal an
	// agent's primary owner at once, without their acceptance.
	PermissionAgentOwnershipReassign Permission = "agent.ownership.reassign"

	// PermissionUsecaseValidate allows validating or rejecting an agent use case.
	PermissionUsecaseValidate Permission = "usecase.validate"

	// PermissionPolicyGlobalAuthor allows authoring a global policy document.
	PermissionPolicyGlobalAuthor Permission = "policy.global.author"

	// PermissionPolicyGlobalApprove allows approving a global policy version.
	PermissionPolicyGlobalApprove Permission = "policy.global.approve"

	// PermissionPolicyAgentAuthor allows authoring an agent-specific policy document.
	PermissionPolicyAgentAuthor Permission = "policy.agent.author"

	// PermissionPolicyAgentApprove allows approving an agent-specific policy version.
	PermissionPolicyAgentApprove Permission = "policy.agent.approve"

	// PermissionAgentActivate allows activating an agent to production state.
	PermissionAgentActivate Permission = "agent.activate"

	// PermissionAgentReview allows completing or signing off on a periodic review.
	PermissionAgentReview Permission = "agent.review"

	// PermissionAgentSuspend allows suspending an active agent.
	PermissionAgentSuspend Permission = "agent.suspend"

	// PermissionAgentReinstate allows reinstating a suspended agent.
	PermissionAgentReinstate Permission = "agent.reinstate"

	// PermissionAgentRetire allows retiring an agent permanently.
	PermissionAgentRetire Permission = "agent.retire"

	// PermissionAgentCredentialsManage allows generating or rotating agent credentials.
	//nolint:gosec // G101 false positive on permission identifier name containing "credentials"
	PermissionAgentCredentialsManage Permission = "agent.credentials.manage"

	// PermissionHaltAgentIssue allows executing an emergency halt against an individual agent.
	PermissionHaltAgentIssue Permission = "halt.agent.issue"

	// PermissionHaltFleetIssue allows executing an emergency halt against the entire fleet.
	PermissionHaltFleetIssue Permission = "halt.fleet.issue"

	// PermissionHaltReleaseRequest allows requesting the release of an agent or fleet halt.
	PermissionHaltReleaseRequest Permission = "halt.release.request"

	// PermissionHaltReleaseApprove allows approving the release of an agent or fleet halt.
	PermissionHaltReleaseApprove Permission = "halt.release.approve"

	// PermissionModuleManage allows registering, updating, and managing enforcement modules.
	PermissionModuleManage Permission = "module.manage"

	// PermissionAuditEventsRead allows querying and viewing entries from the audit log.
	PermissionAuditEventsRead Permission = "audit.events.read"

	// PermissionAuditVerify allows verifying cryptographic Merkle proofs and checkpoints.
	PermissionAuditVerify Permission = "audit.verify"

	// PermissionAuditExport allows exporting audit evidence to external sinks and files.
	PermissionAuditExport Permission = "audit.export"

	// PermissionSettingsManage allows configuring system settings and role mappings.
	PermissionSettingsManage Permission = "settings.manage"

	// PermissionIdentityMeRead allows reading the caller's own identity, roles, and permissions.
	PermissionIdentityMeRead Permission = "identity.me.read"
)

// allPermissions lists all permissions in deterministic order.
var allPermissions = []Permission{
	PermissionInventoryView,
	PermissionAgentPropose,
	PermissionAgentMetadataEdit,
	PermissionAgentOwnershipReassign,
	PermissionUsecaseValidate,
	PermissionPolicyGlobalAuthor,
	PermissionPolicyGlobalApprove,
	PermissionPolicyAgentAuthor,
	PermissionPolicyAgentApprove,
	PermissionAgentActivate,
	PermissionAgentReview,
	PermissionAgentSuspend,
	PermissionAgentReinstate,
	PermissionAgentRetire,
	PermissionAgentCredentialsManage,
	PermissionHaltAgentIssue,
	PermissionHaltFleetIssue,
	PermissionHaltReleaseRequest,
	PermissionHaltReleaseApprove,
	PermissionModuleManage,
	PermissionAuditEventsRead,
	PermissionAuditVerify,
	PermissionAuditExport,
	PermissionSettingsManage,
	PermissionIdentityMeRead,
}

// AllPermissions returns a copy of all defined permissions.
func AllPermissions() []Permission {
	return slices.Clone(allPermissions)
}

// IsValidPermission returns true if p is a defined permission.
func IsValidPermission(p Permission) bool {
	return slices.Contains(allPermissions, p)
}
