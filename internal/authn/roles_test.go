package authn_test

import (
	"reflect"
	"testing"

	"github.com/J466Y/WhiteTower/internal/authn"
)

func TestResolveEffectiveRoles(t *testing.T) {
	mapping := map[string]string{
		"wt-steering":  "steering",
		"wt-advisory":  "advisory",
		"wt-owners":    "owner",
		"wt-users":     "user",
		"wt-operators": "operator",
		"wt-auditors":  "auditor",
		"wt-admins":    "admin",
	}

	tests := []struct {
		name          string
		idpGroups     []string
		localBindings []string
		wantRoles     []string
	}{
		{
			name:          "single idp group without slash",
			idpGroups:     []string{"wt-owners"},
			localBindings: nil,
			wantRoles:     []string{"owner"},
		},
		{
			name:          "idp group with leading slash",
			idpGroups:     []string{"/wt-steering"},
			localBindings: nil,
			wantRoles:     []string{"steering"},
		},
		{
			name:          "multiple idp groups and local bindings merged and sorted",
			idpGroups:     []string{"/wt-owners", "wt-users"},
			localBindings: []string{"operator"},
			wantRoles:     []string{"operator", "owner", "user"},
		},
		{
			name:          "duplicate roles deduplicated",
			idpGroups:     []string{"/wt-operators", "wt-operators"},
			localBindings: []string{"operator"},
			wantRoles:     []string{"operator"},
		},
		{
			name:          "unmapped and invalid roles ignored",
			idpGroups:     []string{"engineering", "random-team", "/wt-auditors"},
			localBindings: []string{"fake-role"},
			wantRoles:     []string{"auditor"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := authn.ResolveEffectiveRoles(tc.idpGroups, mapping, tc.localBindings)
			if !reflect.DeepEqual(got, tc.wantRoles) {
				t.Errorf("got %v, want %v", got, tc.wantRoles)
			}
		})
	}
}
