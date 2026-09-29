// Package moduleapi implements the module API described in api/proto.
package moduleapi

import (
	"context"
	"net/http"

	"connectrpc.com/connect"

	"github.com/J466Y/WhiteTower/internal/version"
	modulev1alpha1 "github.com/J466Y/WhiteTower/pkg/moduleapi/whitetower/module/v1alpha1"
	"github.com/J466Y/WhiteTower/pkg/moduleapi/whitetower/module/v1alpha1/modulev1alpha1connect"
)

// ContractVersions lists the module contract versions this server supports.
var ContractVersions = []string{"v1alpha1"}

// MetaService is a placeholder that exercises the code generation pipeline.
// RFC-0001 (plan P0-03) defines the real module contracts.
type MetaService struct{}

var _ modulev1alpha1connect.MetaServiceHandler = MetaService{}

// GetServerInfo returns the version of the server and the contract versions it
// supports.
func (MetaService) GetServerInfo(
	context.Context, *connect.Request[modulev1alpha1.GetServerInfoRequest],
) (*connect.Response[modulev1alpha1.GetServerInfoResponse], error) {
	return connect.NewResponse(&modulev1alpha1.GetServerInfoResponse{
		Version:          version.Get().Version,
		ContractVersions: ContractVersions,
	}), nil
}

// Handler returns the path prefix and the handler of the module API services.
func Handler() (string, http.Handler) {
	return modulev1alpha1connect.NewMetaServiceHandler(MetaService{})
}
