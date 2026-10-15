package authn

import (
	"slices"
	"strings"

	"github.com/J466Y/WhiteTower/internal/authz"
)

// ResolveEffectiveRoles computes the effective roles of a principal from their IdP groups
// and any locally assigned role bindings (requirements HUM-02, plan P1-03 step 4).
func ResolveEffectiveRoles(idpGroups []string, roleMapping map[string]string, localBindings []string) []string {
	seen := make(map[string]bool)

	// 1. Map IdP groups to roles.
	for _, group := range idpGroups {
		groupName := strings.TrimPrefix(group, "/")
		if roleName, ok := roleMapping[groupName]; ok {
			if authz.IsValidRole(authz.Role(roleName)) {
				seen[roleName] = true
			}
		} else if roleName, ok := roleMapping[group]; ok {
			if authz.IsValidRole(authz.Role(roleName)) {
				seen[roleName] = true
			}
		}
	}

	// 2. Add local database bindings.
	for _, r := range localBindings {
		if authz.IsValidRole(authz.Role(r)) {
			seen[r] = true
		}
	}

	result := make([]string, 0, len(seen))
	for r := range seen {
		result = append(result, r)
	}
	slices.Sort(result)
	return result
}
