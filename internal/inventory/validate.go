package inventory

import (
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

// The rules of the API's request schemas, which the generated server does not
// check: the inventory checks every request against them.
var (
	slugPattern     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	labelKeyPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9._/-]{0,61}[a-z0-9])?$`)

	agentKinds      = []string{"in_house", "third_party"}
	riskTiers       = []string{"low", "medium", "high", "critical"}
	classifications = []string{"prohibited", "high_risk", "limited", "minimal", "not_assessed"}
	haltModes       = []string{"block", "interrupt", "terminate"}
)

const (
	maxLabels         = 64
	maxLabelValue     = 255
	maxEnvironments   = 16
	maxDataCategories = 32
	maxCategory       = 63
)

func contains(list []string, s string) bool { return slices.Contains(list, s) }

// required refuses a text that is blank or longer than max characters.
func required(field, value string, maxLen int) error {
	if strings.TrimSpace(value) == "" {
		return refuse(Invalid, "%s is required", field)
	}
	return optional(field, value, maxLen)
}

// optional refuses a text longer than max characters.
func optional(field, value string, maxLen int) error {
	if utf8.RuneCountInString(value) > maxLen {
		return refuse(Invalid, "%s has more than %d characters", field, maxLen)
	}
	return nil
}

// oneOf refuses a value that is not among the allowed ones.
func oneOf(field, value string, allowed []string) error {
	if !contains(allowed, value) {
		return refuse(Invalid, "%s must be one of %s", field, strings.Join(allowed, ", "))
	}
	return nil
}

// environments refuses a missing, long or malformed list of environments.
func environments(list []string) error {
	if len(list) == 0 || len(list) > maxEnvironments {
		return refuse(Invalid, "environments needs 1 to %d entries", maxEnvironments)
	}
	for i, e := range list {
		if !slugPattern.MatchString(e) {
			return refuse(Invalid, "environment %q must have lowercase letters, digits and inner hyphens", e)
		}
		if slices.Contains(list[:i], e) {
			return refuse(Invalid, "environment %q is listed twice", e)
		}
	}
	return nil
}

// dataCategories refuses a missing, long or repeated list of categories, and
// an empty or long category, which the decision request's schema refuses too
// (CORE-17); checkCategories then checks them against the setting.
func dataCategories(list []string) error {
	if len(list) == 0 || len(list) > maxDataCategories {
		return refuse(Invalid, "dataCategories needs 1 to %d entries", maxDataCategories)
	}
	for i, c := range list {
		if n := utf8.RuneCountInString(c); n == 0 || n > maxCategory {
			return refuse(Invalid, "data category %q must have 1 to %d characters", c, maxCategory)
		}
		if slices.Contains(list[:i], c) {
			return refuse(Invalid, "data category %q is listed twice", c)
		}
	}
	return nil
}

// labels refuses too many labels, or a malformed key or value. Labels reach
// enforcement points, which build the subject of each decision request from
// them, so they follow the syntax and the bounds of the request's schema
// (module contracts, section 6.2 and CORE-17): a test keeps labelKeyPattern,
// the schema's pattern and the OpenAPI document's the same.
func labels(set map[string]string) error {
	if len(set) > maxLabels {
		return refuse(Invalid, "an agent has at most %d labels", maxLabels)
	}
	for k, v := range set {
		if !labelKeyPattern.MatchString(k) {
			return refuse(Invalid, "label key %q must have 1 to 63 lowercase letters, digits and inner '.', '_', '-' or '/'", k)
		}
		if utf8.RuneCountInString(v) > maxLabelValue {
			return refuse(Invalid, "the value of label %q has more than %d characters", k, maxLabelValue)
		}
	}
	return nil
}
