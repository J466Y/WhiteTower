package profile_test

import (
	"errors"
	"testing"

	"github.com/J466Y/WhiteTower/test/conformance/profile"
	"github.com/J466Y/WhiteTower/test/conformance/tooling"
)

// FuzzGenerateRules checks that the generator either refuses a policy's rules
// with ErrUsageRule, or writes statements that parse and that the check of
// generated text accepts, for a global and for an agent-specific policy.
func FuzzGenerateRules(f *testing.F) {
	for _, seed := range []string{
		`[{"id":"no-push-to-main","description":"Pushes to main go through pull requests","tools":["github/push_files"],"when":[{"arg":"branch","op":"in","values":["main","master"]}]}]`,
		`[{"id":"r","description":"d","tools":["github/push_files","agent/send_email"],"when":[{"arg":"labels","op":"not_in","values":["a\"b\\c"],"if_absent":"no_match"},{"arg":"n","op":"less_than","values":[-9223372036854775808]}]}]`,
		`[{"id":"p","description":"d","tools":["github/push_files"],"when":[{"arg":"to","transform":"email_domain","op":"matches","values":["*.example","*\\*"]}]}]`,
		`[{"id":"b","description":"d","tools":["agent/send_email"],"when":[{"arg":"options.force","op":"equals","values":[true]},{"arg":"sizes","op":"in","values":[1,9223372036854775807]}]}]`,
		`[{"id":"x","id":"y","description":"d","tools":["github/push_files"],"when":[{"arg":"n","op":"equals","values":[1.0]}]}]`,
	} {
		f.Add(seed, false)
	}
	args := []tooling.Argument{
		{Name: "branch", Path: []string{"branch"}, Type: "String"},
		{Name: "labels", Path: []string{"labels"}, Type: "Set<String>"},
		{Name: "to:email_domain", Path: []string{"to"}, Transform: "email_domain", Type: "String"},
		{Name: "n", Path: []string{"n"}, Type: "Long"},
		{Name: "sizes", Path: []string{"sizes"}, Type: "Set<Long>"},
		{Name: "options.force", Path: []string{"options", "force"}, Type: "Bool"},
	}
	catalog := &tooling.Catalog{Tools: []tooling.CatalogTool{
		{Key: "github/push_files", Args: args},
		{Key: "agent/send_email", Args: args},
	}}
	f.Fuzz(func(t *testing.T, rules string, agent bool) {
		scope := "global"
		if agent {
			scope = "agent"
		}
		statements, err := profile.GenerateRules([]byte(rules), catalog, scope)
		if err != nil {
			if !errors.Is(err, profile.ErrUsageRule) {
				t.Fatalf("%q: %v, which does not wrap ErrUsageRule", rules, err)
			}
			return
		}
		if err := profile.CheckRules(statements, catalog, scope); err != nil {
			t.Fatalf("%q: the check refuses the generator's statements: %v\n%s", rules, err, statements)
		}
	})
}
