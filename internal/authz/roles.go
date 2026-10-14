// Package authz implements the authorization engine of White Tower: roles,
// the role-to-permission matrix derived from requirements section 5.2.1,
// separation of duties checks, and operation authorization.
package authz

import (
	"fmt"
	"slices"
)

// Role is a governance role bound to a principal.
type Role string

// The seven roles of the White Tower governance model (requirements 5.2.1).
const (
	// RoleSteering is a Steering Committee member with strategic governance oversight:
	// approves global policies, issues agent and fleet halts, and approves halt releases.
	RoleSteering Role = "steering"

	// RoleAdvisory is an AI Advisory Committee member with risk and technical oversight:
	// validates use cases, reviews policies, signs off on periodic reviews, and oversees lifecycle.
	RoleAdvisory Role = "advisory"

	// RoleOwner is an Agent Owner or delegate responsible for specific agents:
	// proposes agents, authors agent-specific policies, manages credentials, and monitors own agents.
	RoleOwner Role = "owner"

	// RoleUser is a standard organizational user:
	// limited to viewing active agents in the inventory.
	RoleUser Role = "user"

	// RoleOperator is a Platform Operator managing operational infrastructure:
	// manages modules, executes operational lifecycle transitions, issues halts, and exports evidence.
	RoleOperator Role = "operator"

	// RoleAuditor is an internal or external compliance auditor:
	// inspects inventory, reads the audit log, and verifies and exports audit evidence.
	RoleAuditor Role = "auditor"

	// RoleAdmin is a Platform Administrator managing platform settings and role mappings.
	RoleAdmin Role = "admin"
)

// allRoles lists all valid roles in deterministic order.
var allRoles = []Role{
	RoleSteering,
	RoleAdvisory,
	RoleOwner,
	RoleUser,
	RoleOperator,
	RoleAuditor,
	RoleAdmin,
}

// AllRoles returns a copy of all defined roles.
func AllRoles() []Role {
	return slices.Clone(allRoles)
}

// IsValidRole returns true if r matches one of the defined roles.
func IsValidRole(r Role) bool {
	return slices.Contains(allRoles, r)
}

// ParseRole validates and converts a string into a Role.
func ParseRole(s string) (Role, error) {
	r := Role(s)
	if !IsValidRole(r) {
		return "", fmt.Errorf("unknown role %q", s)
	}
	return r, nil
}
