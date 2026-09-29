package kit_test

import (
	"context"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	modulev1alpha1 "github.com/J466Y/WhiteTower/pkg/moduleapi/whitetower/module/v1alpha1"
	"github.com/J466Y/WhiteTower/test/conformance/kit"
	"github.com/J466Y/WhiteTower/test/conformance/profile"
	"github.com/J466Y/WhiteTower/test/conformance/stubep"
)

const agentID = "0192f1c2-7a3b-7c4d-8e5f-000000000001"

// TestStartClosedAgainstStub runs scenario S-01 end to end: the kit's fake
// core and the stub enforcement point talk over the real module API, on HTTP/2
// with TLS, and the kit drives the stub through the driver protocol.
func TestStartClosedAgainstStub(t *testing.T) {
	vectors := os.DirFS("../vectors/bundles")
	keys, err := kit.LoadKeys(vectors)
	if err != nil {
		t.Fatal(err)
	}
	b, ref, err := kit.LoadBundle(vectors, "valid")
	if err != nil {
		t.Fatal(err)
	}

	core := kit.NewCore(keys)
	server := httptest.NewUnstartedServer(core.Handler())
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	ep := stubep.New(stubep.Config{
		AgentID: agentID, Environment: "production", Trusted: keys,
		CoreURL: server.URL, HTTPClient: server.Client(),
	})
	driverServer := httptest.NewServer(ep.DriverHandler())
	defer driverServer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ep.Run(ctx)
	}()
	defer wg.Wait()
	defer cancel()

	err = kit.StartClosed(ctx, core, &kit.Driver{URL: driverServer.URL, Client: driverServer.Client()}, kit.Fixture{
		Agent: &modulev1alpha1.AgentState{
			AgentId:        agentID,
			Slug:           "invoice-triage",
			LifecycleState: modulev1alpha1.LifecycleState_LIFECYCLE_STATE_ACTIVE,
			LeaseTtl:       durationpb.New(30 * time.Second),
			HaltMode:       modulev1alpha1.HaltMode_HALT_MODE_INTERRUPT,
			Attributes: &modulev1alpha1.AgentAttributes{
				Kind: "in_house", RiskTier: "high", DataCategories: []string{"customer data"},
				Labels: map[string]string{"team": "finance"}, OwnerId: "0192f1c2-7a3b-7c4d-8e5f-0000000000a1",
			},
		},
		Bundle: b,
		Ref:    ref,
		Permitted: kit.DecideRequest{
			Action:   profile.Action{Name: "tool.invoke"},
			Resource: profile.Resource{Type: "tool", ID: "read_invoice", Properties: map[string]any{"kind": "function"}},
			Context:  profile.Context{Time: "2026-09-29T10:00:00.000Z"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(core.Instances()); n == 0 {
		t.Error("the stub never registered")
	}
}
