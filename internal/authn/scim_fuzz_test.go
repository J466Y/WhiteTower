package authn

import (
	"encoding/json"
	"testing"
)

// The SCIM filter comes from the identity provider's client: parsing it never
// panics, and a userName that it gives parses again, quoted, to itself.
func FuzzSCIMFilter(f *testing.F) {
	for _, seed := range []string{
		`userName eq "ruth@example.test"`,
		`USERNAME EQ "ruth@example.test"`,
		`userName eq "ruth@example.test"`,
		`userName eq "a\"b\\c"`,
		`userName eq "\ud800"`,
		`userName eq "a" or userName eq "b"`,
		`emails.value eq "ruth@example.test"`,
		`userName eq "ruth@example.test`,
		`userName eq ruth`,
		``,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, filter string) {
		userName, ok := parseUserNameFilter(filter)
		if !ok {
			return
		}
		quoted, err := json.Marshal(userName)
		if err != nil {
			t.Fatal(err)
		}
		if again, ok := parseUserNameFilter("userName eq " + string(quoted)); !ok || again != userName {
			t.Errorf("%q gives %q, whose filter %s gives %q, %v", filter, userName, quoted, again, ok)
		}
	})
}
