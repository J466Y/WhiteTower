package catalog

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/J466Y/WhiteTower/internal/catalog/catalogdb"
)

// The reads of the catalog. Whoever may view the catalog sees every entry,
// with its reference and the rest of what reports brought: the public API
// requires catalog.view for each of them (RFC-0002, Privacy).

// maxPage bounds a page of a list, as the public API does.
const maxPage = 200

// Seen is when an entry was first and last reported, and the agent whose
// report first brought it.
type Seen struct {
	FirstAgent uuid.UUID
	First      time.Time
	Last       time.Time
}

// Server is an MCP server of the catalog. Its reference, announced name and
// version and display form were reported: untrusted text.
type Server struct {
	ID               uuid.UUID
	Key              string
	Reference        string
	Transport        string
	AnnouncedName    string // empty when the server announced none
	AnnouncedVersion string // empty when the server announced none
	DisplayForm      string // empty when the report gave none
	Status           string
	PendingReview    bool
	Flags            []string
	Seen             Seen
	// Version is the version of the server's row, which its ETag carries
	// (API-03). Reports never change it.
	Version int64
}

// Tool is a tool of the catalog: an MCP tool names its server, the agent's
// own tool its agent, and a built-in tool its provider and type. Its name was
// reported: untrusted text.
type Tool struct {
	ID       uuid.UUID
	Key      string
	Kind     string
	Name     string
	Server   *uuid.UUID
	Agent    *uuid.UUID
	Provider string // empty but for a built-in tool
	Type     string // empty but for a built-in tool
	Status   string
	// Definition is the pinned definition hash, empty until an approval
	// pins one, and for a built-in tool.
	Definition string
	// PendingDefinitions are the reported definitions that differ from the
	// pinned one, which wait for review.
	PendingDefinitions []string
	PendingReview      bool
	Seen               Seen
	Version            int64
}

// Model is a model of the catalog. Its endpoint and name were reported:
// untrusted text.
type Model struct {
	ID       uuid.UUID
	Key      string
	Provider string
	Endpoint string
	Name     string
	Status   string
	// Digest is the pinned digest of the weights, empty when none is
	// pinned.
	Digest string
	// PendingDigests are the reported digests that differ from the pinned
	// one, which wait for review.
	PendingDigests []string
	PendingReview  bool
	Flags          []string
	Seen           Seen
	Version        int64
}

// Filter selects entries: each field set must hold, and a field left empty
// selects every entry.
type Filter struct {
	// Statuses are discovered, approved, or both.
	Statuses []string
	// PendingReview selects the entries that wait for review, themselves or
	// by a new definition or digest, or the others.
	PendingReview *bool
	// Key is an exact key.
	Key string
}

// ServerFilter selects servers.
type ServerFilter struct {
	Filter
	// Flags are the flags that every server selected carries.
	Flags []string
}

// ToolFilter selects tools.
type ToolFilter struct {
	Filter
	// Server and Agent select the tools of an MCP server and the own tools
	// of an agent.
	Server *uuid.UUID
	Agent  *uuid.UUID
	// Kinds are the kinds selected.
	Kinds []string
}

// ToolPosition is where a page of tools starts: after the tool with this key
// and ID. The agent's own tools can share a key, so the ID orders them.
type ToolPosition struct {
	Key string
	ID  uuid.UUID
}

// ModelFilter selects models.
type ModelFilter struct {
	Filter
	// Flags are the flags that every model selected carries.
	Flags []string
	// Provider is an exact provider.
	Provider string
}

// ListServers returns a page of at most size servers that match the filter,
// by key, after the key given, and whether more follow.
func (c *Catalog) ListServers(ctx context.Context, f ServerFilter, after string, size int) ([]Server, bool, error) {
	limit, err := pageLimit(size)
	if err != nil {
		return nil, false, err
	}
	if err := firstError(f.check(), checkFlags(f.Flags)); err != nil {
		return nil, false, err
	}
	rows, err := catalogdb.New(c.db).ListServers(ctx, catalogdb.ListServersParams{
		Statuses: f.Statuses, PendingReview: f.PendingReview, Flags: nonNil(f.Flags), Key: nonEmpty(f.Key),
		After: nonEmpty(after), PageLimit: limit,
	})
	if err != nil {
		return nil, false, fmt.Errorf("listing servers: %w", err)
	}
	servers := make([]Server, len(rows))
	for i := range rows {
		servers[i] = serverOf(rows[i])
	}
	servers, more := page(servers, size)
	return servers, more, nil
}

// GetServer returns a server.
func (c *Catalog) GetServer(ctx context.Context, id uuid.UUID) (*Server, error) {
	rows, err := catalogdb.New(c.db).ListServers(ctx, catalogdb.ListServersParams{ID: &id, Flags: []string{}, PageLimit: 1})
	if err != nil {
		return nil, fmt.Errorf("reading a server: %w", err)
	}
	if len(rows) == 0 {
		return nil, refuse(NotFound, "no server has this ID")
	}
	s := serverOf(rows[0])
	return &s, nil
}

// ListTools returns a page of at most size tools that match the filter, by
// key and ID, after the position given, and whether more follow.
func (c *Catalog) ListTools(ctx context.Context, f ToolFilter, after *ToolPosition, size int) ([]Tool, bool, error) {
	limit, err := pageLimit(size)
	if err != nil {
		return nil, false, err
	}
	if err := f.check(); err != nil {
		return nil, false, err
	}
	for _, k := range f.Kinds {
		if err := oneOf("kind", k, "function", "mcp", "builtin", "http", "other"); err != nil {
			return nil, false, err
		}
	}
	params := catalogdb.ListToolsParams{
		Statuses: f.Statuses, PendingReview: f.PendingReview, Key: nonEmpty(f.Key), ServerID: f.Server,
		AgentID: f.Agent, Kinds: f.Kinds, PageLimit: limit,
	}
	if after != nil {
		params.AfterKey, params.AfterID = &after.Key, &after.ID
	}
	rows, err := catalogdb.New(c.db).ListTools(ctx, params)
	if err != nil {
		return nil, false, fmt.Errorf("listing tools: %w", err)
	}
	tools := make([]Tool, len(rows))
	for i := range rows {
		tools[i] = toolOf(rows[i])
	}
	tools, more := page(tools, size)
	return tools, more, nil
}

// GetTool returns a tool.
func (c *Catalog) GetTool(ctx context.Context, id uuid.UUID) (*Tool, error) {
	rows, err := catalogdb.New(c.db).ListTools(ctx, catalogdb.ListToolsParams{ID: &id, PageLimit: 1})
	if err != nil {
		return nil, fmt.Errorf("reading a tool: %w", err)
	}
	if len(rows) == 0 {
		return nil, refuse(NotFound, "no tool has this ID")
	}
	t := toolOf(rows[0])
	return &t, nil
}

// ListModels returns a page of at most size models that match the filter, by
// key, after the key given, and whether more follow.
func (c *Catalog) ListModels(ctx context.Context, f ModelFilter, after string, size int) ([]Model, bool, error) {
	limit, err := pageLimit(size)
	if err != nil {
		return nil, false, err
	}
	if err := firstError(f.check(), checkFlags(f.Flags)); err != nil {
		return nil, false, err
	}
	rows, err := catalogdb.New(c.db).ListModels(ctx, catalogdb.ListModelsParams{
		Statuses: f.Statuses, PendingReview: f.PendingReview, Flags: nonNil(f.Flags), Key: nonEmpty(f.Key),
		Provider: nonEmpty(f.Provider), After: nonEmpty(after), PageLimit: limit,
	})
	if err != nil {
		return nil, false, fmt.Errorf("listing models: %w", err)
	}
	models := make([]Model, len(rows))
	for i := range rows {
		models[i] = modelOf(rows[i])
	}
	models, more := page(models, size)
	return models, more, nil
}

// GetModel returns a model.
func (c *Catalog) GetModel(ctx context.Context, id uuid.UUID) (*Model, error) {
	rows, err := catalogdb.New(c.db).ListModels(ctx, catalogdb.ListModelsParams{ID: &id, Flags: []string{}, PageLimit: 1})
	if err != nil {
		return nil, fmt.Errorf("reading a model: %w", err)
	}
	if len(rows) == 0 {
		return nil, refuse(NotFound, "no model has this ID")
	}
	m := modelOf(rows[0])
	return &m, nil
}

// Definition returns a stored tool definition: the bytes of its canonical
// JSON, exactly as stored, whose SHA-256 is the hash given. They were
// reported: untrusted text.
func (c *Catalog) Definition(ctx context.Context, sha256 string) ([]byte, error) {
	if !isSHA256(sha256) {
		return nil, refuse(Invalid, "a definition hash is a lowercase hexadecimal SHA-256")
	}
	hash, err := hex.DecodeString(sha256)
	if err != nil {
		return nil, fmt.Errorf("decoding a definition hash: %w", err)
	}
	canonical, err := catalogdb.New(c.db).GetDefinition(ctx, hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, refuse(NotFound, "the catalog stores no definition with this hash")
	}
	if err != nil {
		return nil, fmt.Errorf("reading a definition: %w", err)
	}
	return canonical, nil
}

// check refuses a status that the catalog does not know.
func (f *Filter) check() error {
	for _, s := range f.Statuses {
		if err := oneOf("status", s, "discovered", "approved"); err != nil {
			return err
		}
	}
	return nil
}

// checkFlags refuses a flag that the catalog does not know.
func checkFlags(fs []string) error {
	for _, f := range fs {
		if err := oneOf("flag", f, flags...); err != nil {
			return err
		}
	}
	return nil
}

// pageLimit returns how many rows to read for a page of size items: one more,
// which tells whether more follow.
func pageLimit(size int) (int32, error) {
	if size < 1 || size > maxPage {
		return 0, fmt.Errorf("a page of %d entries: want 1 to %d", size, maxPage)
	}
	return int32(size + 1), nil //nolint:gosec // G115: size is at most maxPage
}

// page cuts the rows read for a page to its size, and tells whether more
// follow.
func page[T any](items []T, size int) ([]T, bool) {
	if len(items) > size {
		return items[:size], true
	}
	return items, false
}

func serverOf(row catalogdb.ListServersRow) Server {
	return Server{
		ID: row.ID, Key: row.Key, Reference: row.Reference, Transport: row.Transport,
		AnnouncedName: value(row.AnnouncedName), AnnouncedVersion: value(row.AnnouncedVersion),
		DisplayForm: value(row.DisplayForm), Status: row.Status, PendingReview: row.PendingReview,
		Flags: row.Flags, Seen: Seen{FirstAgent: row.FirstAgentID, First: row.FirstSeenAt, Last: row.LastSeenAt},
		Version: row.Version,
	}
}

func toolOf(row catalogdb.ListToolsRow) Tool {
	t := Tool{
		ID: row.ID, Key: row.Key, Kind: row.Kind, Name: row.Name, Server: row.ServerID, Agent: row.AgentID,
		Provider: value(row.Provider), Type: value(row.Type), Status: row.Status,
		PendingDefinitions: make([]string, len(row.PendingDefinitions)), PendingReview: row.PendingReview,
		Seen:    Seen{FirstAgent: row.FirstAgentID, First: row.FirstSeenAt, Last: row.LastSeenAt},
		Version: row.Version,
	}
	if row.DefinitionSha256 != nil {
		t.Definition = hex.EncodeToString(row.DefinitionSha256)
	}
	for i, d := range row.PendingDefinitions {
		t.PendingDefinitions[i] = hex.EncodeToString(d)
	}
	return t
}

func modelOf(row catalogdb.ListModelsRow) Model {
	return Model{
		ID: row.ID, Key: row.Key, Provider: row.Provider, Endpoint: row.Endpoint, Name: row.Name, Status: row.Status,
		Digest: value(row.Digest), PendingDigests: nonNil(row.PendingDigests), PendingReview: row.PendingReview,
		Flags: row.Flags, Seen: Seen{FirstAgent: row.FirstAgentID, First: row.FirstSeenAt, Last: row.LastSeenAt},
		Version: row.Version,
	}
}
