package contracts

import "testing"

// TestTheDecisionResponseSchemaTiesBundleVersionToTheReason gives a response
// each reason, with and without a bundle version (section 6.6).
func TestTheDecisionResponseSchemaTiesBundleVersionToTheReason(t *testing.T) {
	sch := compile(t, api+"/policy/decision-response.schema.json")
	for _, rule := range reasonRules {
		for _, bundleVersion := range []bool{true, false} {
			name := rule.reason
			if !bundleVersion {
				name += " without a bundle version"
			}
			t.Run(name, func(t *testing.T) {
				context := map[string]any{"reason": rule.reason, "policies": []any{}}
				if bundleVersion {
					context["bundle_version"] = 42
				}
				response := map[string]any{"decision": rule.reason == "policy.permit", "context": context}
				valid := bundleVersionAllowed(rule.bundleVersion, bundleVersion)
				err := validate(t, sch, response)
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
