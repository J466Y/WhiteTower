package moduleapi

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/J466Y/WhiteTower/internal/platform/logging"
	"github.com/J466Y/WhiteTower/internal/platform/metrics"
	"github.com/J466Y/WhiteTower/internal/version"
	modulev1alpha1 "github.com/J466Y/WhiteTower/pkg/moduleapi/whitetower/module/v1alpha1"
	"github.com/J466Y/WhiteTower/pkg/moduleapi/whitetower/module/v1alpha1/modulev1alpha1connect"
)

const testIdentity = "spiffe://example.org/module/0192f2c4-8d1e-7c3a-9b2f-5e1d2c3b4a59"

// testTokens accepts the token "good", for a test module, and nothing else.
type testTokens struct{}

func (testTokens) Authenticate(_ context.Context, header http.Header) (*Caller, error) {
	if header.Get("Authorization") != "Bearer good" {
		return nil, errors.New("not the test token")
	}
	return &Caller{Identity: testIdentity}, nil
}

// authorized is a request that carries the test token.
func authorized[T any](msg *T) *connect.Request[T] {
	req := connect.NewRequest(msg)
	req.Header().Set("Authorization", "Bearer good")
	return req
}

// protocols are the protocols and encodings of the module API (contracts,
// section 4.1), with clients that compress their requests or not. Connect
// clients make GET requests, when asked to, for procedures without side
// effects.
var protocols = []struct {
	name string
	opts []connect.ClientOption
	json bool
}{
	{"gRPC", []connect.ClientOption{connect.WithGRPC()}, false},
	{"gRPC with gzip", []connect.ClientOption{connect.WithGRPC(), connect.WithSendGzip()}, false},
	{"gRPC-Web", []connect.ClientOption{connect.WithGRPCWeb()}, false},
	{"Connect", nil, false},
	{"Connect with JSON", []connect.ClientOption{connect.WithProtoJSON()}, true},
	{"Connect with JSON and gzip", []connect.ClientOption{connect.WithProtoJSON(), connect.WithSendGzip()}, true},
	{"Connect GET with JSON", []connect.ClientOption{connect.WithHTTPGet(), connect.WithProtoJSON()}, true},
}

// syncBuffer collects the logs that handlers write while the test reads them.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// records returns the JSON log records whose message is msg.
func (b *syncBuffer) records(t *testing.T, msg string) []map[string]any {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []map[string]any
	for line := range strings.Lines(b.buf.String()) {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("not a JSON line: %q", line)
		}
		if m["msg"] == msg {
			out = append(out, m)
		}
	}
	return out
}

// testAPI is a module API served over HTTPS and HTTP/2, as the machine
// listener serves it, with a span for each request, as the observer starts
// one. The test reads its logs, spans and metrics.
type testAPI struct {
	url      string
	client   *http.Client
	logs     *syncBuffer
	spans    *tracetest.SpanRecorder
	registry *prometheus.Registry
}

// serve serves the module API with the default services, but for those set
// in replace.
func serve(t *testing.T, auth Authenticator, replace services) *testAPI {
	t.Helper()
	a := &testAPI{logs: &syncBuffer{}, spans: tracetest.NewSpanRecorder(), registry: prometheus.NewRegistry()}
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(a.spans))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	h := mount(Options{Logger: logging.New(a.logs, "info"), Authenticator: auth, Metrics: metrics.NewRPC(a.registry)}, services{
		meta:       cmp.Or[modulev1alpha1connect.MetaServiceHandler](replace.meta, MetaService{}),
		registry:   cmp.Or[modulev1alpha1connect.RegistryServiceHandler](replace.registry, registryService{}),
		governance: cmp.Or[modulev1alpha1connect.GovernanceServiceHandler](replace.governance, governanceService{}),
		policy:     cmp.Or[modulev1alpha1connect.PolicyServiceHandler](replace.policy, policyService{}),
		events:     cmp.Or[modulev1alpha1connect.EventServiceHandler](replace.events, eventService{}),
	})
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, span := tp.Tracer("test").Start(r.Context(), "request")
		defer span.End()
		h.ServeHTTP(w, r.WithContext(ctx))
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	a.url, a.client = srv.URL, srv.Client()
	return a
}

// eventually waits for cond, which handlers that end after their response
// make true.
func eventually(t *testing.T, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
	}
}

// message returns what a call's error tells its caller.
func message(err error) string {
	var ce *connect.Error
	if errors.As(err, &ce) {
		return ce.Message()
	}
	return ""
}

// The criterion of plan P1-01, step 6: a generated client calls the module
// API over gRPC and over the Connect protocol with JSON.
func TestGetServerInfo(t *testing.T) {
	a := serve(t, testTokens{}, services{})
	for _, p := range protocols {
		t.Run(p.name, func(t *testing.T) {
			client := modulev1alpha1connect.NewMetaServiceClient(a.client, a.url, p.opts...)
			resp, err := client.GetServerInfo(context.Background(), authorized(&modulev1alpha1.GetServerInfoRequest{}))
			if err != nil {
				t.Fatal(err)
			}
			if resp.Msg.GetVersion() != version.Get().Version || !slices.Equal(resp.Msg.GetContractVersions(), ContractVersions) {
				t.Fatalf("got %v", resp.Msg)
			}
		})
	}
}

// Contracts, section 4.2: every call carries a token.
func TestEveryCallNeedsAToken(t *testing.T) {
	a := serve(t, testTokens{}, services{})
	for _, p := range protocols {
		for _, header := range []string{"", "Bearer bad", "good"} {
			t.Run(p.name+"/"+cmp.Or(header, "none"), func(t *testing.T) {
				req := connect.NewRequest(&modulev1alpha1.GetServerInfoRequest{})
				if header != "" {
					req.Header().Set("Authorization", header)
				}
				_, err := modulev1alpha1connect.NewMetaServiceClient(a.client, a.url, p.opts...).GetServerInfo(context.Background(), req)
				if connect.CodeOf(err) != connect.CodeUnauthenticated || message(err) != errUnauthenticated.Error() {
					t.Fatalf("got %v, want UNAUTHENTICATED", err)
				}
			})
		}
	}
}

// Until plan P1-05 issues tokens, the server accepts none.
func TestNoTokensAcceptsNone(t *testing.T) {
	a := serve(t, NoTokens{}, services{})
	_, err := modulev1alpha1connect.NewMetaServiceClient(a.client, a.url).GetServerInfo(context.Background(),
		authorized(&modulev1alpha1.GetServerInfoRequest{}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("got %v, want UNAUTHENTICATED", err)
	}
}

// The token is checked before the message is read, so that a caller without
// one costs no decoding, whatever it sends.
func TestTheTokenIsCheckedBeforeTheMessage(t *testing.T) {
	a := serve(t, testTokens{}, services{})
	huge := &modulev1alpha1.RegisterInstanceRequest{Module: strings.Repeat("x", MaxMessageBytes)}
	for _, p := range protocols {
		t.Run(p.name, func(t *testing.T) {
			_, err := modulev1alpha1connect.NewRegistryServiceClient(a.client, a.url, p.opts...).RegisterInstance(
				context.Background(), connect.NewRequest(huge))
			if connect.CodeOf(err) != connect.CodeUnauthenticated {
				t.Fatalf("got %v, want UNAUTHENTICATED", err)
			}
		})
	}
}

// Contracts, section 4.8: a request over 4 MiB is refused with
// RESOURCE_EXHAUSTED before its handler runs. A compressed request counts
// once decompressed, so that a few kilobytes cannot unpack into gigabytes
// (threat model, T-11).
func TestMessagesOverTheLimitAreRefused(t *testing.T) {
	a := serve(t, testTokens{}, services{})
	huge := &modulev1alpha1.RegisterInstanceRequest{Module: strings.Repeat("x", MaxMessageBytes)}
	for _, p := range protocols {
		t.Run(p.name, func(t *testing.T) {
			_, err := modulev1alpha1connect.NewRegistryServiceClient(a.client, a.url, p.opts...).RegisterInstance(
				context.Background(), authorized(huge))
			if connect.CodeOf(err) != connect.CodeResourceExhausted {
				t.Fatalf("got %v, want RESOURCE_EXHAUSTED", err)
			}
		})
	}
}

// bigInfo answers with a response under the limit in binary protobuf, about
// 4.2 MB, but over it in JSON, about 5.6 MB.
type bigInfo struct{}

func (bigInfo) GetServerInfo(context.Context, *connect.Request[modulev1alpha1.GetServerInfoRequest],
) (*connect.Response[modulev1alpha1.GetServerInfoResponse], error) {
	return connect.NewResponse(&modulev1alpha1.GetServerInfoResponse{
		ContractVersions: slices.Repeat([]string{"a"}, 1_390_000),
	}), nil
}

// Contracts, section 4.8: the core sends no response over 4 MiB, measured in
// the encoding of the call; trying to is a bug of the core's.
func TestResponsesOverTheLimitAreNotSent(t *testing.T) {
	a := serve(t, testTokens{}, services{meta: bigInfo{}})
	failures := 0
	for _, p := range protocols {
		t.Run(p.name, func(t *testing.T) {
			_, err := modulev1alpha1connect.NewMetaServiceClient(a.client, a.url, p.opts...).GetServerInfo(
				context.Background(), authorized(&modulev1alpha1.GetServerInfoRequest{}))
			switch {
			case !p.json && err != nil:
				t.Fatalf("got %v, want the response", err)
			case p.json && (connect.CodeOf(err) != connect.CodeInternal || message(err) != "internal error"):
				t.Fatalf("got %v, want INTERNAL", err)
			case p.json:
				failures++
			}
		})
	}
	if failed := a.logs.records(t, "module API call failed"); len(failed) != failures ||
		!strings.Contains(failed[0]["error"].(string), "exceeds the 4194304-byte limit") {
		t.Fatalf("log records %v", failed)
	}
}

// sizedWatch sends one change, which removes the given agents.
type sizedWatch struct {
	governanceService
	removed []string
}

func (w sizedWatch) Watch(_ context.Context, _ *connect.Request[modulev1alpha1.WatchRequest],
	stream *connect.ServerStream[modulev1alpha1.WatchResponse],
) error {
	return stream.Send(&modulev1alpha1.WatchResponse{Message: &modulev1alpha1.WatchResponse_Change{
		Change: &modulev1alpha1.StateChange{RemovedAgentIds: w.removed},
	}})
}

// Contracts, section 4.8: the core sends no watch message over 1 MiB, in the
// encoding of the stream, even when it compresses the message (clients
// accept gzip by default). A client would refuse it, reconnect and get it
// again: its agents would stay closed.
func TestWatchMessagesOverTheLimitAreNotSent(t *testing.T) {
	// About 1.0 MB in binary protobuf, and 1.4 MB in JSON.
	many := slices.Repeat([]string{"a"}, 340_000)
	// Compressed, a few kilobytes.
	long := []string{strings.Repeat("x", MaxWatchMessageBytes)}
	for _, tt := range []struct {
		name    string
		removed []string
		opts    []connect.ClientOption
		sent    bool
	}{
		{"under the limit", many, nil, true},
		{"over the limit in JSON", many, []connect.ClientOption{connect.WithProtoJSON()}, false},
		{"over the limit, compressed under it", long, nil, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := serve(t, testTokens{}, services{governance: sizedWatch{removed: tt.removed}})
			stream, err := modulev1alpha1connect.NewGovernanceServiceClient(a.client, a.url, tt.opts...).Watch(
				context.Background(), authorized(&modulev1alpha1.WatchRequest{}))
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			if sent := stream.Receive(); sent != tt.sent {
				t.Fatalf("sent: %v, want %v (%v)", sent, tt.sent, stream.Err())
			}
			if tt.sent {
				return
			}
			if connect.CodeOf(stream.Err()) != connect.CodeInternal || message(stream.Err()) != "internal error" {
				t.Fatalf("stream ended with %v, want INTERNAL", stream.Err())
			}
			if failed := a.logs.records(t, "module API call failed"); len(failed) != 1 ||
				!strings.Contains(failed[0]["error"].(string), "exceeds the 1048576-byte limit") {
				t.Fatalf("log records %v", failed)
			}
		})
	}
}

// procedures returns every procedure of the module contracts.
func procedures() []string {
	var out []string
	protoregistry.GlobalFiles.RangeFilesByPackage("whitetower.module.v1alpha1", func(f protoreflect.FileDescriptor) bool {
		for i := range f.Services().Len() {
			s := f.Services().Get(i)
			for j := range s.Methods().Len() {
				out = append(out, "/"+string(s.FullName())+"/"+string(s.Methods().Get(j).Name()))
			}
		}
		return true
	})
	slices.Sort(out)
	return out
}

// Until the plans that implement them, the services answer UNIMPLEMENTED.
func TestStubsAreUnimplemented(t *testing.T) {
	a := serve(t, testTokens{}, services{})
	ctx := context.Background()
	registry := modulev1alpha1connect.NewRegistryServiceClient(a.client, a.url)
	governance := modulev1alpha1connect.NewGovernanceServiceClient(a.client, a.url)
	policy := modulev1alpha1connect.NewPolicyServiceClient(a.client, a.url)
	events := modulev1alpha1connect.NewEventServiceClient(a.client, a.url)
	calls := map[string]func() error{
		modulev1alpha1connect.RegistryServiceRegisterInstanceProcedure: func() error {
			_, err := registry.RegisterInstance(ctx, authorized(&modulev1alpha1.RegisterInstanceRequest{}))
			return err
		},
		modulev1alpha1connect.RegistryServiceHeartbeatProcedure: func() error {
			_, err := registry.Heartbeat(ctx, authorized(&modulev1alpha1.HeartbeatRequest{}))
			return err
		},
		modulev1alpha1connect.RegistryServiceDeregisterInstanceProcedure: func() error {
			_, err := registry.DeregisterInstance(ctx, authorized(&modulev1alpha1.DeregisterInstanceRequest{}))
			return err
		},
		modulev1alpha1connect.GovernanceServiceWatchProcedure: func() error {
			stream, err := governance.Watch(ctx, authorized(&modulev1alpha1.WatchRequest{}))
			if err != nil {
				return err
			}
			defer stream.Close()
			for stream.Receive() {
			}
			return stream.Err()
		},
		modulev1alpha1connect.GovernanceServiceAcknowledgeProcedure: func() error {
			_, err := governance.Acknowledge(ctx, authorized(&modulev1alpha1.AcknowledgeRequest{}))
			return err
		},
		modulev1alpha1connect.PolicyServiceGetBundleProcedure: func() error {
			_, err := policy.GetBundle(ctx, authorized(&modulev1alpha1.GetBundleRequest{}))
			return err
		},
		modulev1alpha1connect.PolicyServiceGetBundleKeysProcedure: func() error {
			_, err := policy.GetBundleKeys(ctx, authorized(&modulev1alpha1.GetBundleKeysRequest{}))
			return err
		},
		modulev1alpha1connect.EventServicePublishProcedure: func() error {
			_, err := events.Publish(ctx, authorized(&modulev1alpha1.PublishRequest{}))
			return err
		},
	}
	stubs := slices.DeleteFunc(procedures(), func(p string) bool {
		return p == modulev1alpha1connect.MetaServiceGetServerInfoProcedure
	})
	if got := slices.Sorted(maps.Keys(calls)); !slices.Equal(got, stubs) {
		t.Fatalf("the test calls %v; the contracts have %v", got, stubs)
	}
	for procedure, call := range calls {
		// The stub's own message, not a 404: the service is mounted.
		if err := call(); connect.CodeOf(err) != connect.CodeUnimplemented || !strings.HasSuffix(message(err), "is not implemented") {
			t.Errorf("%s: %v, want UNIMPLEMENTED from the stub", procedure, err)
		}
	}
}

func TestCallsAreCounted(t *testing.T) {
	a := serve(t, testTokens{}, services{})
	ctx := context.Background()
	meta := modulev1alpha1connect.NewMetaServiceClient(a.client, a.url)
	if _, err := meta.GetServerInfo(ctx, authorized(&modulev1alpha1.GetServerInfoRequest{})); err != nil {
		t.Fatal(err)
	}
	_, _ = meta.GetServerInfo(ctx, connect.NewRequest(&modulev1alpha1.GetServerInfoRequest{}))
	_, _ = modulev1alpha1connect.NewRegistryServiceClient(a.client, a.url).Heartbeat(ctx, authorized(&modulev1alpha1.HeartbeatRequest{}))

	want := `
# HELP whitetower_rpc_server_handled_total Module API calls that ended, by procedure and code.
# TYPE whitetower_rpc_server_handled_total counter
whitetower_rpc_server_handled_total{code="ok",procedure="/whitetower.module.v1alpha1.MetaService/GetServerInfo"} 1
whitetower_rpc_server_handled_total{code="unauthenticated",procedure="/whitetower.module.v1alpha1.MetaService/GetServerInfo"} 1
whitetower_rpc_server_handled_total{code="unimplemented",procedure="/whitetower.module.v1alpha1.RegistryService/Heartbeat"} 1
`
	if err := testutil.GatherAndCompare(a.registry, strings.NewReader(want), "whitetower_rpc_server_handled_total"); err != nil {
		t.Error(err)
	}
	// The calls that reached their handler are timed.
	families, err := a.registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	timed := map[string]uint64{}
	for _, f := range families {
		if f.GetName() == "whitetower_rpc_server_duration_seconds" {
			for _, m := range f.GetMetric() {
				timed[m.GetLabel()[0].GetValue()] = m.GetHistogram().GetSampleCount()
			}
		}
	}
	if want := map[string]uint64{
		modulev1alpha1connect.MetaServiceGetServerInfoProcedure: 1,
		modulev1alpha1connect.RegistryServiceHeartbeatProcedure: 1,
	}; !maps.Equal(timed, want) {
		t.Errorf("timed calls %v, want %v", timed, want)
	}
}

// heldWatch sends a message on each watch stream, which the client's call
// waits for, then holds the stream open until its caller goes away.
type heldWatch struct{ governanceService }

func (heldWatch) Watch(ctx context.Context, _ *connect.Request[modulev1alpha1.WatchRequest],
	stream *connect.ServerStream[modulev1alpha1.WatchResponse],
) error {
	if err := stream.Send(&modulev1alpha1.WatchResponse{Version: 1}); err != nil {
		return err
	}
	<-ctx.Done()
	return ctx.Err()
}

// Open streams are counted while they last. A caller that goes away is no
// failure of the server's.
func TestOpenStreamsAreCounted(t *testing.T) {
	a := serve(t, testTokens{}, services{governance: heldWatch{}})
	open := func() float64 { return gauge(t, a.registry, "whitetower_rpc_server_open_streams") }

	ctx, cancel := context.WithCancel(context.Background())
	stream, err := modulev1alpha1connect.NewGovernanceServiceClient(a.client, a.url).Watch(ctx,
		authorized(&modulev1alpha1.WatchRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if !stream.Receive() {
		t.Fatalf("no first message: %v", stream.Err())
	}
	if v := open(); v != 1 {
		t.Fatalf("%v open streams, want 1", v)
	}
	cancel()
	_ = stream.Close()
	eventually(t, func() bool { return open() == 0 })
	if err := testutil.GatherAndCompare(a.registry, strings.NewReader(`
# HELP whitetower_rpc_server_handled_total Module API calls that ended, by procedure and code.
# TYPE whitetower_rpc_server_handled_total counter
whitetower_rpc_server_handled_total{code="canceled",procedure="/whitetower.module.v1alpha1.GovernanceService/Watch"} 1
`), "whitetower_rpc_server_handled_total"); err != nil {
		t.Error(err)
	}
	if failed := a.logs.records(t, "module API call failed"); len(failed) != 0 {
		t.Errorf("a canceled stream was logged as a failure: %v", failed)
	}
}

// gauge returns the value of the one series of the named gauge, or 0
// before it has any.
func gauge(t *testing.T, reg *prometheus.Registry, name string) float64 {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() == name {
			if len(f.GetMetric()) != 1 {
				t.Fatalf("%s has %d series", name, len(f.GetMetric()))
			}
			return f.GetMetric()[0].GetGauge().GetValue()
		}
	}
	return 0
}

// failing is a MetaService whose calls fail with err, or panic without one.
type failing struct{ err error }

func (f failing) GetServerInfo(context.Context, *connect.Request[modulev1alpha1.GetServerInfoRequest],
) (*connect.Response[modulev1alpha1.GetServerInfoResponse], error) {
	if f.err == nil {
		panic("the secret is 42")
	}
	return nil, f.err
}

// Threat model, T-10: the cause of an internal error, or a panic, stays in
// the server's log. Other errors reach the caller as they are.
func TestInternalErrorsStayInTheLog(t *testing.T) {
	const panicked, failed = "panic serving a module API call", "module API call failed"
	for _, tt := range []struct {
		name    string
		err     error // nil for a panic
		code    connect.Code
		message string // what the caller reads
		logged  string // the log record that holds the cause, if any
		cause   string
	}{
		{"panic", nil, connect.CodeInternal, "internal error", panicked, "the secret is 42"},
		{
			"plain error", errors.New(`password authentication failed for user "whitetower_app"`),
			connect.CodeUnknown, "internal error", failed, "whitetower_app",
		},
		{
			"internal", connect.NewError(connect.CodeInternal, errors.New("disk full")),
			connect.CodeInternal, "internal error", failed, "disk full",
		},
		{
			"data loss", connect.NewError(connect.CodeDataLoss, errors.New("checksum mismatch")),
			connect.CodeDataLoss, "internal error", failed, "checksum mismatch",
		},
		{
			"not found", connect.NewError(connect.CodeNotFound, errors.New("no bundle 7")),
			connect.CodeNotFound, "no bundle 7", "", "",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := serve(t, testTokens{}, services{meta: failing{tt.err}})
			_, err := modulev1alpha1connect.NewMetaServiceClient(a.client, a.url).GetServerInfo(context.Background(),
				authorized(&modulev1alpha1.GetServerInfoRequest{}))
			if connect.CodeOf(err) != tt.code || message(err) != tt.message {
				t.Fatalf("got %v, want %v with %q", err, tt.code, tt.message)
			}
			for _, msg := range []string{panicked, failed} {
				records := a.logs.records(t, msg)
				switch {
				case msg != tt.logged:
					if len(records) != 0 {
						t.Errorf("unexpected %q records: %v", msg, records)
					}
				case len(records) != 1 || records[0]["procedure"] != modulev1alpha1connect.MetaServiceGetServerInfoProcedure ||
					!strings.Contains(fmt.Sprint(records[0]), tt.cause):
					t.Errorf("%q records %v, want one with %q", msg, records, tt.cause)
				case msg == panicked && records[0]["stack"] == "":
					t.Errorf("the panic record lacks its stack: %v", records[0])
				}
			}
		})
	}
}

// panickingTokens is an authenticator with a bug.
type panickingTokens struct{}

func (panickingTokens) Authenticate(context.Context, http.Header) (*Caller, error) {
	panic("the verifier has a bug")
}

// connect.WithRecover does not cover the gate, which recovers by itself.
func TestAPanicInTheAuthenticatorIsAnInternalError(t *testing.T) {
	a := serve(t, panickingTokens{}, services{})
	_, err := modulev1alpha1connect.NewMetaServiceClient(a.client, a.url).GetServerInfo(context.Background(),
		authorized(&modulev1alpha1.GetServerInfoRequest{}))
	if connect.CodeOf(err) != connect.CodeInternal || message(err) != "internal error" {
		t.Fatalf("got %v, want INTERNAL", err)
	}
	if records := a.logs.records(t, "panic serving a module API call"); len(records) != 1 {
		t.Fatalf("panic records: %v", records)
	}
	if err := testutil.GatherAndCompare(a.registry, strings.NewReader(`
# HELP whitetower_rpc_server_handled_total Module API calls that ended, by procedure and code.
# TYPE whitetower_rpc_server_handled_total counter
whitetower_rpc_server_handled_total{code="internal",procedure="/whitetower.module.v1alpha1.MetaService/GetServerInfo"} 1
`), "whitetower_rpc_server_handled_total"); err != nil {
		t.Error(err)
	}
}

// introspecting is a MetaService that reports what its calls' contexts
// carry.
type introspecting struct{ got chan [2]string }

func (i introspecting) GetServerInfo(ctx context.Context, _ *connect.Request[modulev1alpha1.GetServerInfoRequest],
) (*connect.Response[modulev1alpha1.GetServerInfoResponse], error) {
	i.got <- [2]string{ContractVersion(ctx), CallerFrom(ctx).Identity}
	return connect.NewResponse(&modulev1alpha1.GetServerInfoResponse{}), nil
}

func TestHandlersKnowTheCallerAndTheContractVersion(t *testing.T) {
	got := make(chan [2]string, 1)
	a := serve(t, testTokens{}, services{meta: introspecting{got}})
	if _, err := modulev1alpha1connect.NewMetaServiceClient(a.client, a.url).GetServerInfo(context.Background(),
		authorized(&modulev1alpha1.GetServerInfoRequest{})); err != nil {
		t.Fatal(err)
	}
	if v := <-got; v != [2]string{"v1alpha1", testIdentity} {
		t.Fatalf("the handler saw version %q and caller %q", v[0], v[1])
	}
}

func TestSpansDescribeTheCall(t *testing.T) {
	for _, tt := range []struct {
		name   string
		token  bool
		meta   modulev1alpha1connect.MetaServiceHandler
		code   string
		failed bool
	}{
		{name: "ok", token: true, code: "ok"},
		{name: "unauthenticated", code: "unauthenticated"},
		{name: "internal", token: true, meta: failing{}, code: "internal", failed: true},
		{name: "not found", token: true, meta: failing{connect.NewError(connect.CodeNotFound, errors.New("no"))}, code: "not_found"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := serve(t, testTokens{}, services{meta: tt.meta})
			req := connect.NewRequest(&modulev1alpha1.GetServerInfoRequest{})
			if tt.token {
				req = authorized(&modulev1alpha1.GetServerInfoRequest{})
			}
			_, _ = modulev1alpha1connect.NewMetaServiceClient(a.client, a.url).GetServerInfo(context.Background(), req)
			eventually(t, func() bool { return len(a.spans.Ended()) == 1 })
			span := a.spans.Ended()[0]
			attrs := map[string]string{}
			for _, kv := range span.Attributes() {
				attrs[string(kv.Key)] = kv.Value.String()
			}
			want := map[string]string{
				"rpc.system.name":             "connectrpc",
				"rpc.method":                  "whitetower.module.v1alpha1.MetaService/GetServerInfo",
				"rpc.response.status_code":    tt.code,
				"whitetower.contract_version": "v1alpha1",
			}
			if !maps.Equal(attrs, want) {
				t.Errorf("attributes %v, want %v", attrs, want)
			}
			if failed := span.Status().Code == codes.Error; failed != tt.failed {
				t.Errorf("span status %v, want an error: %v", span.Status(), tt.failed)
			}
		})
	}
}
