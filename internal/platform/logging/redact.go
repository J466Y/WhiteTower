package logging

import (
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"strings"
)

// Redacted stands in for a secret wherever it would be shown.
const Redacted = "[REDACTED]"

// Secret holds a token, a key or a password. Whatever shows it, slog, fmt,
// encoding/json or YAML, shows [REDACTED]; only Reveal returns the value. The
// value sits behind a pointer: fmt prints a Secret held in an unexported
// field by reflection, without its methods, and then shows an address.
type Secret struct{ value *string }

// NewSecret wraps a secret value.
func NewSecret(value string) Secret { return Secret{value: &value} }

// Reveal returns the secret value, for the code that uses it.
func (s Secret) Reveal() string {
	if s.value == nil {
		return ""
	}
	return *s.value
}

// LogValue implements slog.LogValuer.
func (Secret) LogValue() slog.Value { return slog.StringValue(Redacted) }

// String implements fmt.Stringer.
func (Secret) String() string { return Redacted }

// Format implements fmt.Formatter, so that every verb prints [REDACTED].
func (Secret) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, Redacted) }

// MarshalText implements encoding.TextMarshaler, which encoding/json uses too.
func (Secret) MarshalText() ([]byte, error) { return []byte(Redacted), nil }

// MarshalYAML implements the YAML encoder's Marshaler interface.
func (Secret) MarshalYAML() (any, error) { return Redacted, nil }

// Header returns h ready to log, with the values of the headers that carry
// credentials, such as Authorization, Cookie and Set-Cookie, replaced by
// [REDACTED].
func Header(h http.Header) slog.LogValuer { return header(h) }

type header http.Header

func (h header) LogValue() slog.Value {
	attrs := make([]slog.Attr, 0, len(h))
	for _, name := range slices.Sorted(maps.Keys(h)) {
		value := strings.Join(h[name], ", ")
		if credentialHeader(name) {
			value = Redacted
		}
		attrs = append(attrs, slog.String(name, value))
	}
	return slog.GroupValue(attrs...)
}

// credentialWords mark the header names that carry credentials: Authorization,
// Cookie, X-Api-Key, X-Amz-Security-Token and the like.
var credentialWords = []string{"auth", "cookie", "token", "secret", "password", "key", "session", "signature", "credential"}

func credentialHeader(name string) bool {
	name = strings.ToLower(name)
	return slices.ContainsFunc(credentialWords, func(w string) bool { return strings.Contains(name, w) })
}
