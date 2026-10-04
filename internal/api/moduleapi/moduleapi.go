// Package moduleapi implements the module API of the module contracts
// (api/proto; contracts, section 4): the services that enforcement points and
// other modules call on the machine listener.
package moduleapi

import (
	"context"
	"log/slog"
	"net/http"

	"connectrpc.com/connect"

	"github.com/J466Y/WhiteTower/internal/platform/metrics"
	"github.com/J466Y/WhiteTower/internal/version"
	modulev1alpha1 "github.com/J466Y/WhiteTower/pkg/moduleapi/whitetower/module/v1alpha1"
	"github.com/J466Y/WhiteTower/pkg/moduleapi/whitetower/module/v1alpha1/modulev1alpha1connect"
)

// Message size limits (contracts, section 4.8), once decompressed. A request
// over the limit is refused with RESOURCE_EXHAUSTED before it is decoded.
const (
	// MaxMessageBytes bounds a request or a response.
	MaxMessageBytes = 4 << 20
	// MaxWatchMessageBytes bounds a message of a watch stream: the core
	// splits larger snapshots into parts.
	MaxWatchMessageBytes = 1 << 20
)

// Options are what the module API needs from the rest of the server.
type Options struct {
	// Logger receives what callers only see as an internal error.
	Logger *slog.Logger
	// Authenticator verifies the access token of every call.
	Authenticator Authenticator
	// Metrics counts the calls.
	Metrics *metrics.RPC
}

// Handler returns the module API: every service of the contracts, behind the
// same middleware. Until the plans that implement them, the services answer
// UNIMPLEMENTED: the registry, the watch stream and the acknowledgements
// (P1-07, with the halts of P1-08), the policy bundles (P1-06) and the events
// (P1-07, with the audit log of P1-02).
func Handler(opts Options) http.Handler {
	return mount(opts, services{
		meta:       MetaService{},
		registry:   registryService{},
		governance: governanceService{},
		policy:     policyService{},
		events:     eventService{},
	})
}

// services are the implementations that Handler mounts.
type services struct {
	meta       modulev1alpha1connect.MetaServiceHandler
	registry   modulev1alpha1connect.RegistryServiceHandler
	governance modulev1alpha1connect.GovernanceServiceHandler
	policy     modulev1alpha1connect.PolicyServiceHandler
	events     modulev1alpha1connect.EventServiceHandler
}

func mount(opts Options, s services) http.Handler {
	options := handlerOptions(opts)
	mux := http.NewServeMux()
	mux.Handle(modulev1alpha1connect.NewMetaServiceHandler(s.meta, options...))
	mux.Handle(modulev1alpha1connect.NewRegistryServiceHandler(s.registry, options...))
	mux.Handle(modulev1alpha1connect.NewGovernanceServiceHandler(s.governance, options...))
	mux.Handle(modulev1alpha1connect.NewPolicyServiceHandler(s.policy, options...))
	mux.Handle(modulev1alpha1connect.NewEventServiceHandler(s.events, options...))
	return mux
}

// handlerOptions are the options of every service: the middleware, panic
// recovery and the size limit of requests; the interceptor limits responses.
// Panics are recovered inside the interceptor, which counts them as internal
// errors.
func handlerOptions(opts Options) []connect.HandlerOption {
	c := &calls{auth: opts.Authenticator, metrics: opts.Metrics, logger: opts.Logger}
	return []connect.HandlerOption{
		connect.WithRequestGate(c.gate),
		connect.WithInterceptors(c),
		connect.WithRecover(c.recovered),
		connect.WithReadMaxBytes(MaxMessageBytes),
	}
}

// MetaService tells callers about the core.
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

// The services that later plans implement.
type (
	registryService struct {
		modulev1alpha1connect.UnimplementedRegistryServiceHandler
	}
	governanceService struct {
		modulev1alpha1connect.UnimplementedGovernanceServiceHandler
	}
	policyService struct {
		modulev1alpha1connect.UnimplementedPolicyServiceHandler
	}
	eventService struct {
		modulev1alpha1connect.UnimplementedEventServiceHandler
	}
)
