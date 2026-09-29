// Package rest implements the public REST API described in api/openapi.
package rest

import (
	"context"
	"net/http"

	"github.com/J466Y/WhiteTower/internal/api/rest/gen"
	"github.com/J466Y/WhiteTower/internal/version"
)

// BasePath is where the public API is mounted.
const BasePath = "/api/v1"

// Server implements the operations of the public API.
type Server struct{}

var _ gen.StrictServerInterface = Server{}

// GetVersion returns the version of the running server.
func (Server) GetVersion(context.Context, gen.GetVersionRequestObject) (gen.GetVersionResponseObject, error) {
	v := version.Get()
	return gen.GetVersion200JSONResponse{
		Version:    v.Version,
		Commit:     v.Commit,
		ApiVersion: gen.V1,
	}, nil
}

// Handler returns the HTTP handler of the public API, which expects requests
// under BasePath.
func Handler() http.Handler {
	return gen.HandlerWithOptions(gen.NewStrictHandler(Server{}, nil), gen.StdHTTPServerOptions{
		BaseURL: BasePath,
	})
}
