package audit_test

import (
	"context"
	"testing"
	"time"

	"github.com/J466Y/WhiteTower/api/events"
	"github.com/J466Y/WhiteTower/internal/audit"
	"github.com/J466Y/WhiteTower/internal/platform/clock/clocktest"
)

// Security test ST-11: Fuzzing of the CloudEvents parser and the ingestion path
func FuzzIngestionParser(f *testing.F) {
	cat, err := audit.LoadCatalog(events.Files)
	if err != nil {
		f.Fatal(err)
	}

	clk := clocktest.New(epoch)
	ing := audit.NewIngester(audit.IngesterOptions{
		Catalog:       cat,
		Clock:         clk,
		RateLimit:     100_000,
		RateBurst:     100_000,
		MaxSealingLag: 10 * time.Minute,
	})

	// An enforcement point inside the agent, and an instance of a module
	// whose scope is the agent, each with its own sources.
	types := []string{
		"whitetower.decision.made.v1",
		"whitetower.action.executed.v1",
		"whitetower.instance.started.v1",
	}
	ep, module := enforcementPoint(), quarantineModule()
	ep.AllowedTypes, module.AllowedTypes = types, types
	callers := []audit.IngestCaller{ep, module}

	// Seeds
	f.Add(decisionEvent(epSource(agent, stream), "ev-fuzz-01", 1, agent, "allow", "policy.permit"))
	f.Add(instanceStartedEvent(moduleSource("k8s-quarantine", stream), "ev-fuzz-02", 1, agent))
	f.Add([]byte(`{"specversion": "1.0", "id": "ev-01", "source": "/agents/`))
	f.Add([]byte(`{"specversion": 1, "id": null, "data": 12345}`))
	f.Add([]byte(`{"specversion": "1.0", "id": "", "source": "core", "type": "whitetower.decision.made.v1", "time": "invalid", "wtseq": "not-a-number"}`))
	f.Add([]byte(``))
	f.Add([]byte(`   `))
	f.Add([]byte(`{}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{"specversion":"1.0","id":"\u0000","source":"/agents/\u0000/ep/1"}`))

	ctx := context.Background()

	f.Fuzz(func(t *testing.T, data []byte) {
		// The fake clock moves on, so that the rate limit never stops an
		// input before the parser: on a clock that stands still, a worker's
		// burst runs out after 100,000 inputs.
		clk.Advance(time.Second)
		// The parser and validation must never panic, crash or hang on untrusted input.
		for _, caller := range callers {
			_, _ = ing.Ingest(ctx, caller, [][]byte{data})
		}
	})
}
