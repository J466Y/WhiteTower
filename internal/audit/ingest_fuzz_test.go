package audit_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

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

	agentUUID := uuid.MustParse(agent)
	caller := audit.IngestCaller{
		InstanceID:    "inst-01",
		AllowedAgents: []uuid.UUID{agentUUID},
		AllowedTypes: []string{
			"whitetower.decision.made.v1",
			"whitetower.action.executed.v1",
			"whitetower.instance.started.v1",
		},
	}

	// Seeds
	f.Add(decisionEvent(fmt.Sprintf("/agents/%s/ep/ep-01", agent), "ev-fuzz-01", 1, agent, "allow", "policy.permit"))
	f.Add(instanceStartedEvent("/modules/mod-01/inst-01", "ev-fuzz-02", 1, "inst-01"))
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
		// The parser and validation must never panic, crash or hang on untrusted input.
		_, _ = ing.Ingest(ctx, caller, [][]byte{data})
	})
}
