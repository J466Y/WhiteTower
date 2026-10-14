package authz

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/J466Y/WhiteTower/internal/platform/auth"
)

// Security test ST-17: Every role and permission pair of the matrix, including the negatives; no handler bypasses the authorization engine
func TestPermissionMatrixEveryRoleAndPermissionPair(t *testing.T) {
	// expected maps each role to its exact expected permission grants.
	expected := map[Role]map[Permission]Scope{
		RoleSteering: {
			PermissionInventoryView:       ScopeAll,
			PermissionPolicyGlobalAuthor:  ScopeAll,
			PermissionPolicyGlobalApprove: ScopeAll,
			PermissionHaltAgentIssue:      ScopeAll,
			PermissionHaltFleetIssue:      ScopeAll,
			PermissionHaltReleaseRequest:  ScopeAll,
			PermissionHaltReleaseApprove:  ScopeAll,
			PermissionAuditEventsRead:     ScopeAll,
			PermissionAuditVerify:         ScopeAll,
			PermissionAuditExport:         ScopeAll,
			PermissionIdentityMeRead:      ScopeAll,
		},
		RoleAdvisory: {
			PermissionInventoryView:      ScopeAll,
			PermissionUsecaseValidate:    ScopeAll,
			PermissionPolicyGlobalAuthor: ScopeAll,
			PermissionPolicyAgentAuthor:  ScopeAll,
			PermissionPolicyAgentApprove: ScopeAll,
			PermissionAgentReview:        ScopeSignOff,
			PermissionAgentSuspend:       ScopeAll,
			PermissionAgentReinstate:     ScopeAll,
			PermissionAgentRetire:        ScopeAll,
			PermissionHaltAgentIssue:     ScopeAll,
			PermissionHaltReleaseRequest: ScopeAll,
			PermissionHaltReleaseApprove: ScopeAll,
			PermissionAuditEventsRead:    ScopeAll,
			PermissionAuditVerify:        ScopeAll,
			PermissionAuditExport:        ScopeAll,
			PermissionIdentityMeRead:     ScopeAll,
		},
		RoleOwner: {
			PermissionInventoryView:          ScopeAll,
			PermissionAgentPropose:           ScopeAll,
			PermissionAgentMetadataEdit:      ScopeOwn,
			PermissionPolicyAgentAuthor:      ScopeOwn,
			PermissionAgentActivate:          ScopeOwn,
			PermissionAgentReview:            ScopeOwn,
			PermissionAgentSuspend:           ScopeOwn,
			PermissionAgentRetire:            ScopeOwn,
			PermissionAgentCredentialsManage: ScopeOwn,
			PermissionHaltAgentIssue:         ScopeOwn,
			PermissionHaltReleaseRequest:     ScopeOwn,
			PermissionAuditEventsRead:        ScopeOwn,
			PermissionIdentityMeRead:         ScopeAll,
		},
		RoleUser: {
			PermissionInventoryView:  ScopeActiveOnly,
			PermissionIdentityMeRead: ScopeAll,
		},
		RoleOperator: {
			PermissionInventoryView:          ScopeAll,
			PermissionAgentMetadataEdit:      ScopeAll,
			PermissionAgentActivate:          ScopeAll,
			PermissionAgentSuspend:           ScopeAll,
			PermissionAgentReinstate:         ScopeAll,
			PermissionAgentRetire:            ScopeAll,
			PermissionAgentCredentialsManage: ScopeAll,
			PermissionHaltAgentIssue:         ScopeAll,
			PermissionHaltFleetIssue:         ScopeAll,
			PermissionHaltReleaseRequest:     ScopeAll,
			PermissionHaltReleaseApprove:     ScopeAll,
			PermissionModuleManage:           ScopeAll,
			PermissionAuditEventsRead:        ScopeAll,
			PermissionAuditVerify:            ScopeAll,
			PermissionAuditExport:            ScopeAll,
			PermissionIdentityMeRead:         ScopeAll,
		},
		RoleAuditor: {
			PermissionInventoryView:   ScopeAll,
			PermissionAuditEventsRead: ScopeAll,
			PermissionAuditVerify:     ScopeAll,
			PermissionAuditExport:     ScopeAll,
			PermissionIdentityMeRead:  ScopeAll,
		},
		RoleAdmin: {
			PermissionInventoryView:  ScopeAll,
			PermissionSettingsManage: ScopeAll,
			PermissionIdentityMeRead: ScopeAll,
		},
	}

	roles := AllRoles()
	permissions := AllPermissions()

	if len(roles) != 7 {
		t.Fatalf("expected 7 roles, got %d", len(roles))
	}
	if len(permissions) != 24 {
		t.Fatalf("expected 24 permissions, got %d", len(permissions))
	}

	totalChecked := 0
	for _, role := range roles {
		expMap := expected[role]
		for _, perm := range permissions {
			totalChecked++
			grant, hasGrant := RoleGrant(role, perm)
			wantScope, wantGrant := expMap[perm]

			if hasGrant != wantGrant {
				t.Errorf("role %s, perm %s: got grant=%v, want grant=%v", role, perm, hasGrant, wantGrant)
				continue
			}

			if hasGrant && grant.Scope != wantScope {
				t.Errorf("role %s, perm %s: got scope %q, want scope %q", role, perm, grant.Scope, wantScope)
			}
		}
	}

	if totalChecked != 7*24 {
		t.Fatalf("expected 168 checks, got %d", totalChecked)
	}
}

// Security test ST-18: Separation of duties: self-approval, self-validation, a one-person release and granting oneself a role are refused
func TestSeparationOfDuties(t *testing.T) {
	t.Run("self-approval and self-validation refused", func(t *testing.T) {
		const author = "0192f2c4-0001-7000-8000-000000000001"
		const other = "0192f2c4-0002-7000-8000-000000000002"

		if err := CheckApproval(author, author); !errors.Is(err, ErrSelfApproval) {
			t.Errorf("expected ErrSelfApproval for self-approval, got %v", err)
		}
		if err := CheckApproval(author, other); err != nil {
			t.Errorf("unexpected error for two-person approval: %v", err)
		}
		if err := CheckApproval("", other); !errors.Is(err, ErrMissingPrincipal) {
			t.Errorf("expected ErrMissingPrincipal, got %v", err)
		}
	})

	t.Run("one-person halt release refused", func(t *testing.T) {
		const requester = "0192f2c4-0001-7000-8000-000000000001"
		const approver = "0192f2c4-0002-7000-8000-000000000002"

		if err := CheckHaltRelease(requester, requester); !errors.Is(err, ErrSinglePersonRelease) {
			t.Errorf("expected ErrSinglePersonRelease, got %v", err)
		}
		if err := CheckHaltRelease(requester, approver); err != nil {
			t.Errorf("unexpected error for two-person release: %v", err)
		}
		if err := CheckHaltRelease(requester, ""); !errors.Is(err, ErrMissingPrincipal) {
			t.Errorf("expected ErrMissingPrincipal, got %v", err)
		}
	})

	t.Run("self role grant refused", func(t *testing.T) {
		const admin = "0192f2c4-0001-7000-8000-000000000001"
		const target = "0192f2c4-0002-7000-8000-000000000002"

		if err := CheckRoleGrant(admin, admin); !errors.Is(err, ErrSelfRoleGrant) {
			t.Errorf("expected ErrSelfRoleGrant, got %v", err)
		}
		if err := CheckRoleGrant(admin, target); err != nil {
			t.Errorf("unexpected error for distinct target grant: %v", err)
		}
		if err := CheckRoleGrant("", target); !errors.Is(err, ErrMissingPrincipal) {
			t.Errorf("expected ErrMissingPrincipal, got %v", err)
		}
	})
}

func TestRelationshipAllows(t *testing.T) {
	cases := []struct {
		name   string
		grant  Grant
		rel    Relationship
		expect bool
	}{
		{"ScopeAll allows anything", Grant{Scope: ScopeAll}, Relationship{}, true},
		{"ScopeOwn allows owner", Grant{Scope: ScopeOwn}, Relationship{IsOwner: true}, true},
		{"ScopeOwn rejects non-owner", Grant{Scope: ScopeOwn}, Relationship{IsOwner: false}, false},
		{"ScopeActiveOnly allows active", Grant{Scope: ScopeActiveOnly}, Relationship{IsActive: true}, true},
		{"ScopeActiveOnly rejects inactive", Grant{Scope: ScopeActiveOnly}, Relationship{IsActive: false}, false},
		{"ScopeSignOff allows high risk", Grant{Scope: ScopeSignOff}, Relationship{IsHighOrCriticalRisk: true}, true},
		{"ScopeSignOff rejects low risk", Grant{Scope: ScopeSignOff}, Relationship{IsHighOrCriticalRisk: false}, false},
		{"unknown scope rejects", Grant{Scope: Scope("unknown")}, Relationship{IsOwner: true}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.grant.Allows(tc.rel); got != tc.expect {
				t.Errorf("got %v, want %v", got, tc.expect)
			}
		})
	}
}

func TestAuthorizer(t *testing.T) {
	az := NewAuthorizer()
	ctx := context.Background()

	t.Run("unauthenticated denied", func(t *testing.T) {
		if err := az.Authorize(ctx, nil, "getMe"); !errors.Is(err, auth.ErrDenied) {
			t.Errorf("expected auth.ErrDenied, got %v", err)
		}
	})

	t.Run("unknown operation denied", func(t *testing.T) {
		p := &auth.Principal{ID: "p1", Roles: []string{"admin"}}
		if err := az.Authorize(ctx, p, "nonexistentOperation"); !errors.Is(err, auth.ErrDenied) {
			t.Errorf("expected auth.ErrDenied for unknown op, got %v", err)
		}
	})

	t.Run("getMe allowed for all valid roles", func(t *testing.T) {
		for _, r := range AllRoles() {
			p := &auth.Principal{ID: "p1", Roles: []string{string(r)}}
			if err := az.Authorize(ctx, p, "getMe"); err != nil {
				t.Errorf("role %s should be authorized for getMe, got %v", r, err)
			}
		}
	})

	t.Run("halt fleet allowed for steering and operator only", func(t *testing.T) {
		steering := &auth.Principal{ID: "p1", Roles: []string{string(RoleSteering)}}
		operator := &auth.Principal{ID: "p2", Roles: []string{string(RoleOperator)}}
		user := &auth.Principal{ID: "p3", Roles: []string{string(RoleUser)}}
		owner := &auth.Principal{ID: "p4", Roles: []string{string(RoleOwner)}}

		if err := az.Authorize(ctx, steering, "haltFleet"); err != nil {
			t.Errorf("steering should halt fleet, got %v", err)
		}
		if err := az.Authorize(ctx, operator, "haltFleet"); err != nil {
			t.Errorf("operator should halt fleet, got %v", err)
		}
		if err := az.Authorize(ctx, user, "haltFleet"); !errors.Is(err, auth.ErrDenied) {
			t.Errorf("user must be denied halt fleet, got %v", err)
		}
		if err := az.Authorize(ctx, owner, "haltFleet"); !errors.Is(err, auth.ErrDenied) {
			t.Errorf("owner must be denied fleet halt, got %v", err)
		}
	})

	t.Run("context relationship check", func(t *testing.T) {
		owner := &auth.Principal{ID: "p1", Roles: []string{string(RoleOwner)}}

		ownCtx := ContextWithRelationship(ctx, Relationship{IsOwner: true})
		notOwnCtx := ContextWithRelationship(ctx, Relationship{IsOwner: false})

		if err := az.Authorize(ownCtx, owner, "editAgent"); err != nil {
			t.Errorf("owner should edit own agent, got %v", err)
		}
		if err := az.Authorize(notOwnCtx, owner, "editAgent"); !errors.Is(err, auth.ErrDenied) {
			t.Errorf("owner must NOT edit other's agent, got %v", err)
		}
	})
}

func TestPermissionsList(t *testing.T) {
	perms := PermissionsList([]string{string(RoleAdmin)})
	if !slices.Contains(perms, string(PermissionSettingsManage)) {
		t.Errorf("admin should have settings.manage in permissions list")
	}
	if !slices.Contains(perms, string(PermissionInventoryView)) {
		t.Errorf("admin should have inventory.view in permissions list")
	}
	if slices.Contains(perms, string(PermissionHaltFleetIssue)) {
		t.Errorf("admin should NOT have halt.fleet.issue")
	}
	if !slices.IsSorted(perms) {
		t.Errorf("permissions list must be sorted")
	}
}

func TestParseRole(t *testing.T) {
	r, err := ParseRole("operator")
	if err != nil || r != RoleOperator {
		t.Errorf("expected RoleOperator, got %v, err=%v", r, err)
	}

	_, err = ParseRole("invalid_role")
	if err == nil {
		t.Errorf("expected error for invalid role")
	}
}
