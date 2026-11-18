package rest

import (
	"context"
	"errors"
	"slices"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/J466Y/WhiteTower/api/openapi"
	"github.com/J466Y/WhiteTower/internal/authz"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
)

// Every operation of the tag catalog answers with references or reported
// text, so the authorizer refuses it to a token without catalog.view,
// whatever its other scopes. A new operation of the tag is covered without a
// list to keep up to date.
func TestEveryOperationOfTheCatalogNeedsCatalogView(t *testing.T) {
	var doc struct {
		Paths map[string]map[string]yaml.Node `yaml:"paths"`
	}
	if err := yaml.Unmarshal(openapi.Document, &doc); err != nil {
		t.Fatal(err)
	}
	var roles, others []string
	for _, r := range authz.AllRoles() {
		roles = append(roles, string(r))
	}
	for _, p := range authz.AllPermissions() {
		if p != authz.PermissionCatalogView {
			others = append(others, string(p))
		}
	}
	az := authz.NewAuthorizer()
	ctx := authz.ContextWithRelationship(context.Background(), authz.Relationship{IsOwner: true})
	found := 0
	for _, item := range doc.Paths {
		for method, node := range item {
			var op struct {
				OperationID string   `yaml:"operationId"`
				Tags        []string `yaml:"tags"`
			}
			if !httpMethods[method] || node.Decode(&op) != nil || !slices.Contains(op.Tags, "catalog") {
				continue
			}
			found++
			without := &auth.Principal{ID: olivia, Roles: roles, Scopes: others}
			if err := az.Authorize(ctx, without, op.OperationID); !errors.Is(err, auth.ErrDenied) {
				t.Errorf("%s with every scope but catalog.view: got %v, want refused", op.OperationID, err)
			}
			with := &auth.Principal{ID: olivia, Roles: roles, Scopes: append(slices.Clone(others), string(authz.PermissionCatalogView))}
			if err := az.Authorize(ctx, with, op.OperationID); err != nil {
				t.Errorf("%s with every scope: got %v, want allowed", op.OperationID, err)
			}
		}
	}
	if found == 0 {
		t.Fatal("no operation of the tag catalog in the document")
	}
}
