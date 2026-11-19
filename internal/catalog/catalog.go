// Package catalog is the organization's catalog of the MCP servers, tools
// and models that governed agents have (plan P1-16; RFC-0002): its entries,
// with their keys and references, the definitions of tools and the digests of
// models, and what reports of enforcement points bring to it. Reports only
// inform: a report never approves, enables or unblocks anything, and never
// changes a pinned definition or digest (CORE-10). What they bring is
// untrusted text, bounded where it enters, stored for those who may view the
// catalog, and never copied into an audit event or a log in clear.
package catalog

import (
	"fmt"

	"github.com/J466Y/WhiteTower/internal/audit"
	"github.com/J466Y/WhiteTower/internal/platform/clock"
	"github.com/J466Y/WhiteTower/internal/platform/db"
)

// Options are what the catalog needs from the rest of the core.
type Options struct {
	// DB holds the catalog.
	DB *db.DB
	// Clock dates what reports bring: the times compared later come from
	// it, never from the database.
	Clock clock.Clock
	// Writer records the audit event of every change.
	Writer *audit.Writer
}

// Catalog keeps the MCP servers, tools and models of the organization.
type Catalog struct {
	db     *db.DB
	clk    clock.Clock
	writer *audit.Writer
}

// New returns the catalog.
func New(opts Options) *Catalog {
	return &Catalog{db: opts.DB, clk: opts.Clock, writer: opts.Writer}
}

// RefusalKind says why the catalog refuses a request, so that each API maps
// it to its own codes.
type RefusalKind int

const (
	// Invalid is a request or a report that is malformed, or over a limit.
	Invalid RefusalKind = iota + 1
	// NotFound names an entry or a definition that does not exist.
	NotFound
	// Forbidden is a request that the caller may not make, such as a report
	// about an agent outside the reporting instance's scope.
	Forbidden
)

// Refusal is a request that the catalog refuses. Its detail tells the caller
// why, names nothing internal, and quotes no reported text.
type Refusal struct {
	Kind   RefusalKind
	Detail string
}

func (r *Refusal) Error() string { return r.Detail }

func refuse(kind RefusalKind, format string, args ...any) *Refusal {
	return &Refusal{Kind: kind, Detail: fmt.Sprintf(format, args...)}
}
