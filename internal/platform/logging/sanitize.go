package logging

import (
	"fmt"
	"unicode/utf8"
)

// MaxSanitized is the longest part of a value that Sanitize keeps, in bytes.
const MaxSanitized = 1024

// Sanitize returns a value that comes from outside the server, such as a URL
// path, an HTTP method or a status line, ready for the logs, the traces or a
// terminal. Anything but printable characters is escaped as in a Go string
// literal, without the quotes: a line break cannot forge a record, a control
// sequence cannot drive a terminal, and invisible or bidirectional characters
// show. Backslashes and double quotes are escaped too, so that an escape in
// the result always stands for the character it names. A value longer than
// MaxSanitized bytes is cut, at a character boundary, and marked.
func Sanitize(s string) string {
	truncated := len(s) > MaxSanitized
	if truncated {
		n := MaxSanitized
		for n > 0 && !utf8.RuneStart(s[n]) {
			n--
		}
		s = s[:n]
	}
	// The escaping of strconv.Quote, through %q, which static analysis
	// (CodeQL) also recognizes as a log sanitizer.
	q := fmt.Sprintf("%q", s)
	q = q[1 : len(q)-1]
	if truncated {
		q += "[truncated]"
	}
	return q
}
