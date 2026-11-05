package contracts

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// reasonRules says, for each reason of section 6.6, whether a decision event
// records a decision with it, which a denial with gate.evidence_full never is
// (EP-8); whether the event requires the environment that the registration
// returned, which exists whenever policies were evaluated (I-7); and whether a
// decision carries the version of the bundle that decided: always, never or
// either (section 6.6).
var reasonRules = []struct {
	reason        string
	recorded      bool
	environment   bool
	bundleVersion string
}{
	{"policy.permit", true, true, "always"},
	{"policy.forbid", true, true, "always"},
	{"policy.no_permit", true, true, "always"},
	{"error.evaluation", true, true, "always"},
	{"error.timeout", true, true, "either"},
	{"error.unknown_agent", true, false, "either"},
	{"error.invalid_request", true, false, "either"},
	{"gate.no_state", true, false, "never"},
	{"gate.lease_expired", true, false, "never"},
	{"gate.halted", true, false, "never"},
	{"gate.fleet_halted", true, false, "never"},
	{"gate.lifecycle", true, false, "never"},
	{"gate.no_bundle", true, false, "never"},
	{"gate.evidence_full", false, false, "never"},
}

// bundleVersionAllowed reports whether a decision whose reason has the rule
// given may carry a bundle version, when present is true, or leave it out.
func bundleVersionAllowed(rule string, present bool) bool {
	switch rule {
	case "always":
		return present
	case "never":
		return !present
	default:
		return true
	}
}

// validate checks a document, given as Go values, against a schema, through
// its JSON form.
func validate(t *testing.T, sch *jsonschema.Schema, doc any) error {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return sch.Validate(inst)
}

// exampleEvent returns the example of an event type, for a test to change.
func exampleEvent(t *testing.T, eventType string) map[string]any {
	t.Helper()
	var event map[string]any
	loadJSON(t, api+"/events/examples/"+eventType+".json", &event)
	return event
}

// TestTheDecisionEventTiesItsEnvironmentAndBundleVersionToItsReason gives the
// example of decision.made each reason, with and without an environment and a
// bundle version (I-7, section 6.6). It refuses gate.evidence_full whatever
// the other members, since that denial is never recorded (EP-8).
func TestTheDecisionEventTiesItsEnvironmentAndBundleVersionToItsReason(t *testing.T) {
	sch := compile(t, api+"/events/schemas/whitetower.decision.made.v1.json")
	for _, rule := range reasonRules {
		for _, environment := range []bool{true, false} {
			for _, bundleVersion := range []bool{true, false} {
				name := rule.reason
				if !environment {
					name += " without an environment"
				}
				if !bundleVersion {
					name += " without a bundle version"
				}
				t.Run(name, func(t *testing.T) {
					data := exampleEvent(t, "whitetower.decision.made.v1")["data"].(map[string]any)
					data["reason"] = rule.reason
					data["decision"] = "deny"
					if rule.reason == "policy.permit" {
						data["decision"] = "allow"
					}
					if !environment {
						delete(data, "environment")
					}
					if !bundleVersion {
						delete(data, "bundle_version")
					}
					valid := rule.recorded && (environment || !rule.environment) && bundleVersionAllowed(rule.bundleVersion, bundleVersion)
					err := validate(t, sch, data)
					switch {
					case valid && err != nil:
						t.Errorf("refused: %v", err)
					case !valid && err == nil:
						t.Error("accepted")
					}
				})
			}
		}
	}
}

// TestTheEventSchemasFollowSections5And8 changes one thing in an example and
// checks it against the envelope's schema and its type's: the rules of
// sections 5.3, 5.5, 5.8, 8.2 and 8.3 that the schemas state, each refusal
// next to what the rule accepts.
func TestTheEventSchemasFollowSections5And8(t *testing.T) {
	envelope := compile(t, api+"/events/cloudevent.schema.json")
	hash := strings.Repeat("0123456789abcdef", 4)
	traceparent := func(value string) func(map[string]any) {
		return func(e map[string]any) { e["traceparent"] = value }
	}
	source := func(value string) func(map[string]any) {
		return func(e map[string]any) { e["source"] = value }
	}
	resource := func(value map[string]any) func(map[string]any) {
		return func(e map[string]any) { e["data"].(map[string]any)["resource"] = value }
	}
	arguments := func(value map[string]any) func(map[string]any) {
		return func(e map[string]any) { e["data"].(map[string]any)["arguments"] = value }
	}
	mechanism := func(value string) func(map[string]any) {
		return func(e map[string]any) { e["data"].(map[string]any)["mechanism"] = value }
	}
	without := func(member string) func(map[string]any) {
		return func(e map[string]any) { delete(e["data"].(map[string]any), member) }
	}
	const (
		decision    = "whitetower.decision.made.v1"
		halted      = "whitetower.instance.halted.v1"
		expired     = "whitetower.lease.expired.v1"
		quarantined = "whitetower.quarantine.applied.v1"
		lifted      = "whitetower.quarantine.lifted.v1"
		agentStream = "/agents/0192f1c2-7a3b-7c4d-8e5f-000000000001/ep/"
		quarantine  = "/modules/k8s-quarantine/"
	)
	cases := []struct {
		name    string
		example string
		edit    func(map[string]any)
		valid   bool
	}{
		// Section 8.2: the envelope.
		{"without datacontenttype", decision, func(e map[string]any) { delete(e, "datacontenttype") }, true},
		{"a datacontenttype other than JSON", decision, func(e map[string]any) { e["datacontenttype"] = "text/plain" }, false},
		{"a traceparent of version 00", decision, traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"), true},
		{"a traceparent of version 00 with a field after its flags", decision, traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-00"), false},
		{"a traceparent of version 01", decision, traceparent("01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"), true},
		{"a traceparent of version fe with fields after its flags", decision, traceparent("fe-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-what-comes-next"), true},
		// W3C Trace Context reads nothing of these fields, so the pattern takes
		// any character there, a line break included, which the . of Go's
		// regular expressions and of ECMA-262 would each refuse in part.
		{"a traceparent of a higher version with a line break after its flags", decision, traceparent("cc-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-a\nb"), true},
		{"a traceparent of version ff", decision, traceparent("ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"), false},
		{"a traceparent of a higher version whose flags are followed by no dash", decision, traceparent("cc-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01x"), false},
		{"a traceparent of a higher version with a short trace ID", decision, traceparent("cc-4bf92f3577b34da6a3ce929d0e0e473-00f067aa0ba902b7-01"), false},
		{"a traceparent with an uppercase version", decision, traceparent("0A-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"), false},
		// A source names its evidence buffer by 16 to 64 lowercase hexadecimal
		// characters, never by a host, pod, cluster or instance name.
		{"an agent's stream ID of 16 characters", decision, source(agentStream + hash[:16]), true},
		{"an agent's stream ID of 64 characters", decision, source(agentStream + hash), true},
		{"an agent's stream ID of 15 characters", decision, source(agentStream + hash[:15]), false},
		{"an agent's stream ID of 65 characters", decision, source(agentStream + hash + "0"), false},
		{"an agent's stream ID in uppercase", decision, source(agentStream + strings.ToUpper(hash[:16])), false},
		{"an agent's stream named after its host", decision, source(agentStream + "ep-host-01"), false},
		{"a module's stream ID of 16 characters", quarantined, source(quarantine + hash[:16]), true},
		{"a module's stream ID of 64 characters", quarantined, source(quarantine + hash), true},
		{"a module's stream ID of 15 characters", quarantined, source(quarantine + hash[:15]), false},
		{"a module's stream ID of 65 characters", quarantined, source(quarantine + hash + "0"), false},
		{"a module's stream named after its cluster", quarantined, source(quarantine + "prod-eu-1"), false},

		// Section 8.3: what a decision event records.
		{"a resource ID recorded as its SHA-256", decision, resource(map[string]any{"type": "tool", "id_sha256": hash}), true},
		{"a resource with both its ID and a SHA-256", decision, resource(map[string]any{"type": "tool", "id": "send_email", "id_sha256": hash}), false},
		{"a resource with neither its ID nor a SHA-256", decision, resource(map[string]any{"type": "tool"}), false},
		{"an empty resource ID, which is recorded as its SHA-256", decision, resource(map[string]any{"type": "tool", "id": ""}), false},
		{"a resource ID of 513 characters", decision, resource(map[string]any{"type": "tool", "id": strings.Repeat("a", 513)}), false},
		{"a resource's SHA-256 in uppercase", decision, resource(map[string]any{"type": "tool", "id_sha256": strings.ToUpper(hash)}), false},
		{"argument names, one recorded as its SHA-256", decision, arguments(map[string]any{"names": []any{"to"}, "names_sha256": []any{hash}}), true},
		{"an argument name of 129 characters", decision, arguments(map[string]any{"names": []any{strings.Repeat("n", 129)}}), false},
		{"an argument name's SHA-256 that is not one", decision, arguments(map[string]any{"names_sha256": []any{"to"}}), false},
		{"the hashed mode with its key's ID", decision, arguments(map[string]any{"hmac_sha256": hash, "key_id": "hmac-2026-10"}), true},
		{"the hashed mode without its key's ID", decision, arguments(map[string]any{"hmac_sha256": hash}), false},
		{"a key's ID without the HMAC", decision, arguments(map[string]any{"key_id": "hmac-2026-10"}), false},

		// Section 5.5: a halt's scope that the instance does not know.
		{"a halt without its scope", halted, func(e map[string]any) { delete(e["data"].(map[string]any), "scope") }, true},

		// Section 5.3: why the lease ran out, and what the halt mode did.
		{"a lease expiry with its cause, halt mode and layers", expired, func(map[string]any) {}, true},
		{"a lease expiry without them", expired, func(e map[string]any) {
			data := e["data"].(map[string]any)
			delete(data, "cause")
			delete(data, "halt_mode")
			delete(data, "layers")
		}, true},
		{"stale renewals", expired, func(e map[string]any) { e["data"].(map[string]any)["cause"] = "stale_renewals" }, true},
		{"an unknown cause", expired, func(e map[string]any) { e["data"].(map[string]any)["cause"] = "core_unreachable" }, false},
		{"an unknown halt mode", expired, func(e map[string]any) { e["data"].(map[string]any)["halt_mode"] = "pause" }, false},
		{"no layers", expired, func(e map[string]any) { e["data"].(map[string]any)["layers"] = []any{} }, false},
		// A lease under 10 seconds is applied as it is, and can run out.
		{"a lease of 5 seconds", expired, func(e map[string]any) { e["data"].(map[string]any)["lease_ttl_ms"] = 5000 }, true},
		{"a lease of 0 milliseconds", expired, func(e map[string]any) { e["data"].(map[string]any)["lease_ttl_ms"] = 0 }, false},

		// Section 5.8: the quarantine events name their cluster and their
		// mechanism, an open value in the form of a slug.
		{"a quarantine by another known mechanism", quarantined, mechanism("admin-network-policy"), true},
		{"a quarantine by a mechanism that the schema does not list", quarantined, mechanism("ovn-kubernetes"), true},
		{"a quarantine by a mechanism of 63 characters", quarantined, mechanism(strings.Repeat("a", 63)), true},
		{"a quarantine by a mechanism of 64 characters", quarantined, mechanism(strings.Repeat("a", 64)), false},
		{"a quarantine by a mechanism in uppercase", quarantined, mechanism("Cilium"), false},
		{"a quarantine by a mechanism that ends with a dash", quarantined, mechanism("cilium-"), false},
		{"a quarantine by an empty mechanism", quarantined, mechanism(""), false},
		{"a quarantine without its mechanism", quarantined, without("mechanism"), false},
		{"a quarantine without its cluster", quarantined, without("cluster"), false},
		{"a quarantine that still names its CNI", quarantined, func(e map[string]any) { e["data"].(map[string]any)["cni"] = "cilium" }, false},
		{"a lift by a mechanism that the schema does not list", lifted, mechanism("ovn-kubernetes"), true},
		{"a lift by a mechanism in uppercase", lifted, mechanism("Cilium"), false},
		{"a lift without its mechanism", lifted, without("mechanism"), false},
		{"a lift without its cluster", lifted, without("cluster"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			event := exampleEvent(t, tc.example)
			tc.edit(event)
			err := validate(t, envelope, event)
			if err == nil {
				err = validate(t, compile(t, api+"/events/schemas/"+tc.example+".json"), event["data"])
			}
			switch {
			case tc.valid && err != nil:
				t.Errorf("refused: %v", err)
			case !tc.valid && err == nil:
				t.Error("accepted")
			}
		})
	}
}
