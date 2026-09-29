# Standard decision wrapper for Rego policies: White Tower decision profile v1alpha1,
# combining algorithm wt-deny-overrides-v1 (docs/contracts/module-contract-v0.1.md, section 6.5).
#
# Each White Tower policy is one Rego package under data.whitetower.policies, named in
# the bundle manifest, and may define two boolean rules:
#   deny  - true when the policy forbids the request;
#   allow - true when the policy permits it.
# The input document is the AuthZEN evaluation request of the profile.
#
# The engine evaluates data.whitetower.decision.response. An evaluation error, or an
# undefined response, is a denial (error.evaluation).
package whitetower.decision

import rego.v1

# Policies whose deny rule holds.
forbids contains name if {
	some name
	data.whitetower.policies[name].deny == true
}

# Policies whose allow rule holds.
permits contains name if {
	some name
	data.whitetower.policies[name].allow == true
}

# Deny overrides allow, and nothing is allowed by default.
default allow := false

allow if {
	count(forbids) == 0
	count(permits) > 0
}

reason := "policy.forbid" if count(forbids) > 0

reason := "policy.permit" if {
	count(forbids) == 0
	count(permits) > 0
}

reason := "policy.no_permit" if {
	count(forbids) == 0
	count(permits) == 0
}

determining := sort(forbids) if count(forbids) > 0

determining := sort(permits) if {
	count(forbids) == 0
	count(permits) > 0
}

determining := [] if {
	count(forbids) == 0
	count(permits) == 0
}

# The AuthZEN evaluation response. The enforcement point adds bundle_version and maps
# package names to White Tower policy IDs.
response := {
	"decision": allow,
	"context": {
		"reason": reason,
		"policies": determining,
	},
}
