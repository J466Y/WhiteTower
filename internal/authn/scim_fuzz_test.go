package authn

import (
	"bytes"
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

// A SCIM patch comes from the identity provider's client: reading whether it
// changes the external ID never panics, and a patch that names no external ID
// changes none.
func FuzzSCIMPatch(f *testing.F) {
	for _, seed := range []string{
		`{"Operations":[{"op":"replace","path":"active","value":false}]}`,
		`{"Operations":[{"op":"replace","path":"externalId","value":"idp-ruth"}]}`,
		`{"Operations":[{"op":"add","path":"urn:ietf:params:scim:schemas:core:2.0:User:externalId","value":"idp-una"}]}`,
		`{"Operations":[{"op":"replace","value":{"externalId":"idp-una","active":true}}]}`,
		`{"Operations":[{"op":"remove","path":"externalId"}]}`,
		`{"Operations":[{"op":"replace","path":"externalId","value":7}]}`,
		`{"Operations":[{"op":"replace","value":[1,2]},{}]}`,
		`{}`,
	} {
		f.Add([]byte(seed), "idp-ruth")
	}
	f.Fuzz(func(t *testing.T, body []byte, current string) {
		var patch scimPatchOp
		if json.Unmarshal(body, &patch) != nil {
			return
		}
		changesExternalID(patch, nil)
		// The patch as decoded, with no escape left in its names.
		decoded, err := json.Marshal(patch)
		if err != nil {
			t.Fatal(err)
		}
		if changesExternalID(patch, &current) && !bytes.Contains(bytes.ToLower(decoded), []byte("externalid")) {
			t.Errorf("%s changes the external ID %q, though it names none", decoded, current)
		}
	})
}
