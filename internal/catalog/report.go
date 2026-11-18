package catalog

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/gowebpki/jcs"

	"github.com/J466Y/WhiteTower/internal/audit"
	"github.com/J466Y/WhiteTower/internal/catalog/catalogdb"
	"github.com/J466Y/WhiteTower/internal/platform/db"
)

// The limits of a tooling report (RFC-0002, section 4.2; contracts, section
// 4.10). A report over any of them is refused as a whole: an enforcement
// point leaves out what does not fit them (EP-13).
const (
	MaxReportServers = 256
	MaxReportTools   = 4096
	MaxReportModels  = 256
	// maxReference bounds references, endpoints and display forms, in
	// bytes; maxName names; and maxShort versions, providers, built-in
	// tools' types and digests.
	maxReference = 2048
	maxName      = 256
	maxShort     = 128
)

// maxEventEntries is how many entries one event lists, so that it stays
// within the 64 KiB of an event: more take several events (RFC-0002, section
// 9).
const maxEventEntries = 100

// seenEvery is how often an entry's last seen time moves: an entry that many
// agents report is written at most once a minute, not on every report.
const seenEvery = time.Minute

// maxKeyAttempts bounds how often a new entry looks for a free key when
// concurrent reports take the one it chose.
const maxKeyAttempts = 5

// ReportCaller is the enforcement point instance that reports, as the module
// API authenticated it (contracts, section 4.3).
type ReportCaller struct {
	// Instance is the reporting instance, which the events of its reports
	// name.
	Instance uuid.UUID
	// Agents are the agents in the instance's scope.
	Agents []uuid.UUID
}

// Report is what an enforcement point reports of one agent's tooling: what
// the agent is configured with (contracts, section 4.10, EP-13). Its strings
// were redacted by the enforcement point (EP-14), and are untrusted.
type Report struct {
	// Agent is the agent the tooling belongs to.
	Agent   uuid.UUID
	Servers []ReportedServer
	Tools   []ReportedTool
	Models  []ReportedModel
}

// ReportedServer is an MCP server that the agent launches or connects to, or
// that its model provider calls for it.
type ReportedServer struct {
	// Reference is a normalized URL, a connector: name or a stdio: command
	// line (contracts, section 4.10).
	Reference string
	// Transport is stdio or http, and Origin agent or provider.
	Transport string
	Origin    string
	// Name and Version are what the server announces, and Display its URL
	// or command line; each is empty when the report has none.
	Name    string
	Version string
	Display string
}

// ReportedTool is a tool that the agent's models can call.
type ReportedTool struct {
	// Kind is function, mcp, builtin, http or other, and Origin agent or
	// provider.
	Kind   string
	Origin string
	// Server is an MCP tool's server, by its position in the report's
	// servers; nil for any other tool.
	Server *int
	// Provider and Type are a built-in tool's, empty for any other.
	Provider string
	Type     string
	Name     string
	// Definition is the hash of the tool's definition, in lowercase
	// hexadecimal; empty for a built-in tool, and for a definition that has
	// no hash.
	Definition string
}

// ReportedModel is a model that the agent calls.
type ReportedModel struct {
	Provider string
	// Endpoint is the normalized base URL of the endpoint the agent calls.
	Endpoint string
	Name     string
	// Digest is the digest of the model's weights, empty when the runtime
	// reports none.
	Digest string
}

// Recorded counts what a report brought that the catalog did not have: new
// entries, and new definitions and digests that wait for review.
type Recorded struct {
	Servers, Tools, Models int
	Definitions, Digests   int
}

// RecordReport records what a tooling report brings to the catalog
// (RFC-0002, section 4.2). A server, a tool or a model that the catalog does
// not have becomes a discovered entry, the agent's own tools entries of that
// agent, and a definition or a digest that the catalog does not have for its
// entry is recorded: one that differs from the entry's pinned one waits for
// review, while the pinned one stays (RFC-0002, section 7.1). It never
// approves, enables or unblocks anything (CORE-10). It refuses as a whole a
// report about an agent outside the caller's scope, and a report that is
// malformed or over a limit, before it reads anything. New entries go into
// catalog.discovered events, and definitions or digests that differ from a
// pinned one into catalog.definition_changed events: by key and by the
// SHA-256 of their references, never by a reference in clear (NFR-20).
func (c *Catalog) RecordReport(ctx context.Context, caller ReportCaller, report Report) (Recorded, error) {
	if !slices.Contains(caller.Agents, report.Agent) {
		return Recorded{}, refuse(Forbidden, "the agent is not in the reporting instance's scope")
	}
	if err := report.validate(); err != nil {
		return Recorded{}, err
	}
	var recorded Recorded
	err := c.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		now := c.clk.Now().UTC()
		r := &recording{q: catalogdb.New(tx), agent: report.Agent, now: now, staleBefore: now.Add(-seenEvery)}
		servers, err := r.servers(ctx, report.Servers)
		if err != nil {
			return err
		}
		if err := r.tools(ctx, report, servers); err != nil {
			return err
		}
		if err := r.models(ctx, report.Models); err != nil {
			return err
		}
		recorded = r.recorded
		return c.recordEvents(ctx, tx, caller.Instance, report.Agent, r)
	})
	if err != nil {
		return Recorded{}, err
	}
	return recorded, nil
}

// recording is what one report's transaction found and added.
type recording struct {
	q           *catalogdb.Queries
	agent       uuid.UUID
	now         time.Time
	staleBefore time.Time
	recorded    Recorded
	discovered  []discoveredEntry
	changed     []changedEntry
}

// discoveredEntry is an entry of a catalog.discovered event.
type discoveredEntry struct {
	Type            string `json:"type"`
	Key             string `json:"key"`
	ReferenceSHA256 string `json:"reference_sha256"`
}

// changedEntry is an entry of a catalog.definition_changed event: a tool's
// definitions or a model's digests.
type changedEntry struct {
	Type               string `json:"type"`
	Key                string `json:"key"`
	ReferenceSHA256    string `json:"reference_sha256"`
	ApprovedDefinition string `json:"approved_definition,omitempty"`
	ReportedDefinition string `json:"reported_definition,omitempty"`
	ApprovedDigest     string `json:"approved_digest,omitempty"`
	ReportedDigest     string `json:"reported_digest,omitempty"`
}

// serverEntry is a server of the catalog that a report names.
type serverEntry struct {
	id        uuid.UUID
	key       string
	reference string
}

// servers finds or adds the report's servers, by their references.
func (r *recording) servers(ctx context.Context, reported []ReportedServer) (map[string]serverEntry, error) {
	first := map[string]ReportedServer{}
	var refs []string
	for _, s := range reported {
		if _, ok := first[s.Reference]; !ok {
			first[s.Reference] = s
			refs = append(refs, s.Reference)
		}
	}
	entries := map[string]serverEntry{}
	if len(refs) == 0 {
		return entries, nil
	}
	slices.Sort(refs)
	rows, err := r.q.ServersByReference(ctx, refs)
	if err != nil {
		return nil, fmt.Errorf("reading the reported servers: %w", err)
	}
	var seen []uuid.UUID
	for _, row := range rows {
		entries[row.Reference] = serverEntry{id: row.ID, key: row.Key, reference: row.Reference}
		seen = append(seen, row.ID)
	}
	for _, ref := range refs {
		if _, ok := entries[ref]; ok {
			continue
		}
		e, added, err := r.addServer(ctx, first[ref])
		if err != nil {
			return nil, err
		}
		entries[ref] = e
		if !added {
			seen = append(seen, e.id)
			continue
		}
		r.recorded.Servers++
		r.discovered = append(r.discovered, discoveredEntry{Type: "server", Key: e.key, ReferenceSHA256: sha256Hex(ref)})
	}
	if err := r.q.SeeServers(ctx, catalogdb.SeeServersParams{SeenAt: r.now, Ids: seen, StaleBefore: r.staleBefore}); err != nil {
		return nil, fmt.Errorf("recording when the servers were seen: %w", err)
	}
	return entries, nil
}

// addServer adds a discovered server with a free key. A concurrent report
// may add the same server, or take the key, first: it then returns the
// server that report added, or tries the next free key.
func (r *recording) addServer(ctx context.Context, s ReportedServer) (serverEntry, bool, error) {
	base := serverSlug(s.Reference, s.Name)
	for range maxKeyAttempts {
		taken, err := r.q.ServerKeysFrom(ctx, keyPrefix("", base, "", maxSlug))
		if err != nil {
			return serverEntry{}, false, fmt.Errorf("reading the servers' keys: %w", err)
		}
		key := freeKey("", base, "", maxSlug, set(taken), reservedServerKey)
		id, err := uuid.NewV7()
		if err != nil {
			return serverEntry{}, false, fmt.Errorf("generating a server's ID: %w", err)
		}
		n, err := r.q.InsertServer(ctx, catalogdb.InsertServerParams{
			ID: id, Key: key, Reference: s.Reference, Transport: s.Transport,
			AnnouncedName: nonEmpty(s.Name), AnnouncedVersion: nonEmpty(s.Version), DisplayForm: nonEmpty(s.Display),
			Flags: serverFlags(s.Reference), FirstAgentID: r.agent, SeenAt: r.now,
		})
		if err != nil {
			return serverEntry{}, false, fmt.Errorf("adding a server: %w", err)
		}
		if n == 1 {
			return serverEntry{id: id, key: key, reference: s.Reference}, true, nil
		}
		rows, err := r.q.ServersByReference(ctx, []string{s.Reference})
		if err != nil {
			return serverEntry{}, false, fmt.Errorf("reading a reported server: %w", err)
		}
		if len(rows) == 1 {
			return serverEntry{id: rows[0].ID, key: rows[0].Key, reference: rows[0].Reference}, false, nil
		}
	}
	return serverEntry{}, false, fmt.Errorf("no free key for a server in %d attempts", maxKeyAttempts)
}

// toolIdentity is what makes a tool one entry of the catalog: its server and
// name, its agent and name, or its provider and type.
type toolIdentity struct {
	server, agent uuid.UUID
	name          string
	provider, typ string
}

// toolEntry is a tool of the catalog that a report names: what the report
// says of it, and what the catalog holds.
type toolEntry struct {
	identity    toolIdentity
	kind        string
	name        string
	key         string
	reference   string
	definitions []string
	id          uuid.UUID
	pinned      []byte
}

// tools finds or adds the report's tools, and records their definitions.
func (r *recording) tools(ctx context.Context, report Report, servers map[string]serverEntry) error {
	byIdentity := map[toolIdentity]*toolEntry{}
	var order []*toolEntry
	for _, t := range report.Tools {
		e, err := r.toolEntry(t, report.Servers, servers)
		if err != nil {
			return err
		}
		if prev, ok := byIdentity[e.identity]; ok {
			e = prev
		} else {
			byIdentity[e.identity] = e
			order = append(order, e)
		}
		if t.Definition != "" && !slices.Contains(e.definitions, t.Definition) {
			e.definitions = append(e.definitions, t.Definition)
		}
	}
	if len(order) == 0 {
		return nil
	}
	slices.SortFunc(order, func(a, b *toolEntry) int { return strings.Compare(a.key, b.key) })
	if err := r.findTools(ctx, order, byIdentity); err != nil {
		return err
	}
	var seen []uuid.UUID
	for _, e := range order {
		if e.id != uuid.Nil {
			seen = append(seen, e.id)
			continue
		}
		added, err := r.addTool(ctx, e, byIdentity)
		if err != nil {
			return err
		}
		if !added {
			seen = append(seen, e.id)
			continue
		}
		r.recorded.Tools++
		r.discovered = append(r.discovered, discoveredEntry{Type: "tool", Key: e.key, ReferenceSHA256: sha256Hex(e.reference)})
	}
	if err := r.q.SeeTools(ctx, catalogdb.SeeToolsParams{SeenAt: r.now, Ids: seen, StaleBefore: r.staleBefore}); err != nil {
		return fmt.Errorf("recording when the tools were seen: %w", err)
	}
	return r.definitions(ctx, order)
}

// toolEntry returns what a report says of a tool: its identity, key and
// reference. The report is valid.
func (r *recording) toolEntry(t ReportedTool, reported []ReportedServer, servers map[string]serverEntry) (*toolEntry, error) {
	e := &toolEntry{kind: t.Kind, name: t.Name}
	var parts map[string]string
	switch t.Kind {
	case "mcp":
		server := servers[reported[*t.Server].Reference]
		e.identity = toolIdentity{server: server.id, name: t.Name}
		e.key = mcpToolKey(server.key, t.Name)
		parts = map[string]string{"name": t.Name, "server": server.reference}
	case "builtin":
		e.identity = toolIdentity{provider: t.Provider, typ: t.Type}
		e.key = builtinToolKey(t.Provider, t.Type)
		parts = map[string]string{"provider": t.Provider, "type": t.Type}
	default:
		e.identity = toolIdentity{agent: r.agent, name: t.Name}
		e.key = agentToolKey(t.Name)
		parts = map[string]string{"name": t.Name}
	}
	var err error
	e.reference, err = stringForm(parts)
	return e, err
}

// identityOf returns the identity of a tool of the catalog.
func identityOf(row catalogdb.ReportedToolsRow) toolIdentity {
	switch {
	case row.ServerID != nil:
		return toolIdentity{server: *row.ServerID, name: row.Name}
	case row.AgentID != nil:
		return toolIdentity{agent: *row.AgentID, name: row.Name}
	default:
		return toolIdentity{provider: value(row.Provider), typ: value(row.Type)}
	}
}

// findTools fills in the catalog's tools among those given.
func (r *recording) findTools(ctx context.Context, tools []*toolEntry, byIdentity map[toolIdentity]*toolEntry) error {
	var params catalogdb.ReportedToolsParams
	params.AgentID = &r.agent
	for _, e := range tools {
		switch {
		case e.identity.server != uuid.Nil:
			params.ServerIds = append(params.ServerIds, e.identity.server)
			params.ServerToolNames = append(params.ServerToolNames, e.identity.name)
		case e.identity.agent != uuid.Nil:
			params.AgentToolNames = append(params.AgentToolNames, e.identity.name)
		default:
			params.Providers = append(params.Providers, e.identity.provider)
			params.Types = append(params.Types, e.identity.typ)
		}
	}
	rows, err := r.q.ReportedTools(ctx, params)
	if err != nil {
		return fmt.Errorf("reading the reported tools: %w", err)
	}
	for _, row := range rows {
		if e, ok := byIdentity[identityOf(row)]; ok {
			e.id, e.pinned = row.ID, row.DefinitionSha256
		}
	}
	return nil
}

// addTool adds a discovered tool. A concurrent report may add the same tool
// first: it then fills in the tool that report added.
func (r *recording) addTool(ctx context.Context, e *toolEntry, byIdentity map[toolIdentity]*toolEntry) (bool, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return false, fmt.Errorf("generating a tool's ID: %w", err)
	}
	params := catalogdb.InsertToolParams{
		ID: id, Key: e.key, Kind: e.kind, Name: e.name, FirstAgentID: r.agent, SeenAt: r.now,
	}
	switch {
	case e.identity.server != uuid.Nil:
		params.ServerID = &e.identity.server
	case e.identity.agent != uuid.Nil:
		params.AgentID = &e.identity.agent
	default:
		params.Provider, params.Type = &e.identity.provider, &e.identity.typ
	}
	n, err := r.q.InsertTool(ctx, params)
	if err != nil {
		return false, fmt.Errorf("adding a tool: %w", err)
	}
	if n == 1 {
		e.id = id
		return true, nil
	}
	if err := r.findTools(ctx, []*toolEntry{e}, byIdentity); err != nil {
		return false, err
	}
	if e.id == uuid.Nil {
		return false, fmt.Errorf("adding a tool: another tool has the key of one that the catalog lacks")
	}
	return false, nil
}

// definitions records the definitions that the report names for its tools.
// One that differs from its tool's pinned definition waits for review; for an
// approved tool, it is a changed definition, which the tool's pinned one
// stays in place of until it is approved.
func (r *recording) definitions(ctx context.Context, tools []*toolEntry) error {
	params := catalogdb.RecordReportedDefinitionsParams{FirstAgentID: r.agent, SeenAt: r.now}
	byID := map[uuid.UUID]*toolEntry{}
	for _, e := range tools {
		byID[e.id] = e
		for _, d := range e.definitions {
			hash, err := hex.DecodeString(d)
			if err != nil {
				return fmt.Errorf("decoding a definition hash: %w", err)
			}
			params.ToolIds = append(params.ToolIds, e.id)
			params.Hashes = append(params.Hashes, hash)
		}
	}
	if len(params.ToolIds) == 0 {
		return nil
	}
	rows, err := r.q.RecordReportedDefinitions(ctx, params)
	if err != nil {
		return fmt.Errorf("recording the reported definitions: %w", err)
	}
	for _, row := range rows {
		e := byID[row.ToolID]
		if slices.Equal(row.DefinitionSha256, e.pinned) {
			continue
		}
		r.recorded.Definitions++
		if e.pinned != nil {
			r.changed = append(r.changed, changedEntry{
				Type: "tool", Key: e.key, ReferenceSHA256: sha256Hex(e.reference),
				ApprovedDefinition: hex.EncodeToString(e.pinned), ReportedDefinition: hex.EncodeToString(row.DefinitionSha256),
			})
		}
	}
	return nil
}

// modelIdentity is what makes a model one entry of the catalog.
type modelIdentity struct{ provider, endpoint, name string }

// modelEntry is a model of the catalog that a report names, as the report
// names it.
type modelEntry struct {
	identity modelIdentity
	digests  []string
	id       uuid.UUID
	key      string
	pinned   *string
}

// models finds or adds the report's models, and records their digests.
func (r *recording) models(ctx context.Context, reported []ReportedModel) error {
	byIdentity := map[modelIdentity]*modelEntry{}
	var order []*modelEntry
	var params catalogdb.ReportedModelsParams
	for _, m := range reported {
		id := modelIdentity{provider: m.Provider, endpoint: m.Endpoint, name: m.Name}
		e, ok := byIdentity[id]
		if !ok {
			e = &modelEntry{identity: id}
			byIdentity[id] = e
			order = append(order, e)
			params.Endpoints = append(params.Endpoints, m.Endpoint)
			params.Names = append(params.Names, m.Name)
		}
		if m.Digest != "" && !slices.Contains(e.digests, m.Digest) {
			e.digests = append(e.digests, m.Digest)
		}
	}
	if len(order) == 0 {
		return nil
	}
	slices.SortFunc(order, func(a, b *modelEntry) int {
		return cmp.Or(strings.Compare(a.identity.provider, b.identity.provider),
			strings.Compare(a.identity.endpoint, b.identity.endpoint), strings.Compare(a.identity.name, b.identity.name))
	})
	if err := r.findModels(ctx, params, byIdentity); err != nil {
		return err
	}
	var seen []uuid.UUID
	for _, e := range order {
		if e.id != uuid.Nil {
			seen = append(seen, e.id)
			continue
		}
		added, err := r.addModel(ctx, e, byIdentity)
		if err != nil {
			return err
		}
		if !added {
			seen = append(seen, e.id)
			continue
		}
		ref, err := e.reference()
		if err != nil {
			return err
		}
		r.recorded.Models++
		r.discovered = append(r.discovered, discoveredEntry{Type: "model", Key: e.key, ReferenceSHA256: sha256Hex(ref)})
	}
	if err := r.q.SeeModels(ctx, catalogdb.SeeModelsParams{SeenAt: r.now, Ids: seen, StaleBefore: r.staleBefore}); err != nil {
		return fmt.Errorf("recording when the models were seen: %w", err)
	}
	return r.digests(ctx, order)
}

// reference returns the string form of a model's reference.
func (e *modelEntry) reference() (string, error) {
	return stringForm(map[string]string{"endpoint": e.identity.endpoint, "name": e.identity.name, "provider": e.identity.provider})
}

// findModels fills in the catalog's models among those given.
func (r *recording) findModels(ctx context.Context, params catalogdb.ReportedModelsParams, byIdentity map[modelIdentity]*modelEntry) error {
	rows, err := r.q.ReportedModels(ctx, params)
	if err != nil {
		return fmt.Errorf("reading the reported models: %w", err)
	}
	for _, row := range rows {
		if e, ok := byIdentity[modelIdentity{provider: row.Provider, endpoint: row.Endpoint, name: row.Name}]; ok {
			e.id, e.key, e.pinned = row.ID, row.Key, row.Digest
		}
	}
	return nil
}

// addModel adds a discovered model with a free key. A concurrent report may
// add the same model, or take the key, first: it then fills in the model
// that report added, or tries the next free key.
func (r *recording) addModel(ctx context.Context, e *modelEntry, byIdentity map[modelIdentity]*modelEntry) (bool, error) {
	first, second := modelSlugs(e.identity.provider, e.identity.endpoint, e.identity.name)
	prefix := first + "/"
	for range maxKeyAttempts {
		taken, err := r.q.ModelKeysFrom(ctx, keyPrefix(prefix, second, ".", maxNameSlug))
		if err != nil {
			return false, fmt.Errorf("reading the models' keys: %w", err)
		}
		key := freeKey(prefix, second, ".", maxNameSlug, set(taken), "")
		id, err := uuid.NewV7()
		if err != nil {
			return false, fmt.Errorf("generating a model's ID: %w", err)
		}
		var modelFlags []string
		if secretInPath(e.identity.endpoint) {
			modelFlags = []string{FlagSecretInPath}
		}
		n, err := r.q.InsertModel(ctx, catalogdb.InsertModelParams{
			ID: id, Key: key, Provider: e.identity.provider, Endpoint: e.identity.endpoint, Name: e.identity.name,
			Flags: nonNil(modelFlags), FirstAgentID: r.agent, SeenAt: r.now,
		})
		if err != nil {
			return false, fmt.Errorf("adding a model: %w", err)
		}
		if n == 1 {
			e.id, e.key = id, key
			return true, nil
		}
		single := catalogdb.ReportedModelsParams{Endpoints: []string{e.identity.endpoint}, Names: []string{e.identity.name}}
		if err := r.findModels(ctx, single, byIdentity); err != nil {
			return false, err
		}
		if e.id != uuid.Nil {
			return false, nil
		}
	}
	return false, fmt.Errorf("no free key for a model in %d attempts", maxKeyAttempts)
}

// digests records the digests that the report names for its models. One
// that differs from its model's pinned digest waits for review; for a model
// with a pinned digest, it is a changed digest, which the pinned one stays in
// place of until it is approved.
func (r *recording) digests(ctx context.Context, models []*modelEntry) error {
	params := catalogdb.RecordReportedDigestsParams{FirstAgentID: r.agent, SeenAt: r.now}
	byID := map[uuid.UUID]*modelEntry{}
	for _, e := range models {
		byID[e.id] = e
		for _, d := range e.digests {
			params.ModelIds = append(params.ModelIds, e.id)
			params.Digests = append(params.Digests, d)
		}
	}
	if len(params.ModelIds) == 0 {
		return nil
	}
	rows, err := r.q.RecordReportedDigests(ctx, params)
	if err != nil {
		return fmt.Errorf("recording the reported digests: %w", err)
	}
	for _, row := range rows {
		e := byID[row.ModelID]
		if e.pinned != nil && row.Digest == *e.pinned {
			continue
		}
		r.recorded.Digests++
		if e.pinned == nil {
			continue
		}
		ref, err := e.reference()
		if err != nil {
			return err
		}
		r.changed = append(r.changed, changedEntry{
			Type: "model", Key: e.key, ReferenceSHA256: sha256Hex(ref), ApprovedDigest: *e.pinned, ReportedDigest: row.Digest,
		})
	}
	return nil
}

// recordEvents records what a report brought, in as many events as
// eventChunks makes. Their actor is the system, and they have no subject, so
// that owners' audit reads, which filter on the agent, never show them.
func (c *Catalog) recordEvents(ctx context.Context, tx *db.Tx, instance, agent uuid.UUID, r *recording) error {
	system := map[string]any{"type": "system"}
	discovered, err := eventChunks(r.discovered)
	if err != nil {
		return err
	}
	for _, chunk := range discovered {
		if err := c.writer.Record(ctx, tx, audit.Event{Type: "whitetower.catalog.discovered.v1", Data: map[string]any{
			"instance_id": instance.String(), "agent_id": agent.String(), "entries": chunk, "actor": system,
		}}); err != nil {
			return fmt.Errorf("recording the discovered entries: %w", err)
		}
	}
	changed, err := eventChunks(r.changed)
	if err != nil {
		return err
	}
	for _, chunk := range changed {
		if err := c.writer.Record(ctx, tx, audit.Event{Type: "whitetower.catalog.definition_changed.v1", Data: map[string]any{
			"instance_id": instance.String(), "agent_id": agent.String(), "changes": chunk, "actor": system,
		}}); err != nil {
			return fmt.Errorf("recording the changed definitions: %w", err)
		}
	}
	return nil
}

// maxEventEntriesBytes bounds the JSON of the entries of one event, leaving
// the rest of the 64 KiB of an event to its envelope and its other members.
const maxEventEntriesBytes = audit.MaxEventSize * 7 / 8

// eventChunks splits the entries of a report's events into the lists of
// successive events: at most maxEventEntries entries each, and at most
// maxEventEntriesBytes of their JSON, so that an event stays within the 64
// KiB of an event however long the reported names in its keys are. Go's JSON
// of an entry is never shorter than its canonical JSON, which the audit log
// stores.
func eventChunks[T any](entries []T) ([][]T, error) {
	var chunks [][]T
	start, size := 0, 0
	for i, e := range entries {
		b, err := json.Marshal(e)
		if err != nil {
			return nil, fmt.Errorf("encoding an entry of an event: %w", err)
		}
		if i > start && (i-start == maxEventEntries || size+len(b) > maxEventEntriesBytes) {
			chunks = append(chunks, entries[start:i])
			start, size = i, 0
		}
		size += len(b) + 1
	}
	if start < len(entries) {
		chunks = append(chunks, entries[start:])
	}
	return chunks, nil
}

// validate refuses a report that is malformed or over a limit, naming the
// member at fault by its position, never by what it holds.
func (rep *Report) validate() error {
	switch {
	case len(rep.Servers) > MaxReportServers:
		return refuse(Invalid, "a report holds at most %d servers", MaxReportServers)
	case len(rep.Tools) > MaxReportTools:
		return refuse(Invalid, "a report holds at most %d tools", MaxReportTools)
	case len(rep.Models) > MaxReportModels:
		return refuse(Invalid, "a report holds at most %d models", MaxReportModels)
	}
	for i, s := range rep.Servers {
		if err := s.validate(fmt.Sprintf("servers[%d]", i)); err != nil {
			return err
		}
	}
	for i, t := range rep.Tools {
		if err := t.validate(fmt.Sprintf("tools[%d]", i), len(rep.Servers)); err != nil {
			return err
		}
	}
	for i, m := range rep.Models {
		if err := m.validate(fmt.Sprintf("models[%d]", i)); err != nil {
			return err
		}
	}
	return nil
}

func (s *ReportedServer) validate(at string) error {
	if err := firstError(
		checkText(at+".reference", s.Reference, maxReference, true, false),
		oneOf(at+".transport", s.Transport, "stdio", "http"),
		oneOf(at+".origin", s.Origin, "agent", "provider"),
		checkText(at+".name", s.Name, maxName, false, false),
		checkText(at+".version", s.Version, maxShort, false, false),
		checkText(at+".display", s.Display, maxReference, false, false),
	); err != nil {
		return err
	}
	_, local := stdioCommand(s.Reference)
	remote := strings.HasPrefix(s.Reference, "connector:")
	if _, ok := urlHost(s.Reference); ok {
		remote = true
	}
	if s.Transport == "stdio" && !local || s.Transport == "http" && !remote {
		return refuse(Invalid, "%s.reference: not a reference of a server of its transport", at)
	}
	return nil
}

func (t *ReportedTool) validate(at string, servers int) error {
	if err := firstError(
		oneOf(at+".kind", t.Kind, "function", "mcp", "builtin", "http", "other"),
		oneOf(at+".origin", t.Origin, "agent", "provider"),
		checkText(at+".name", t.Name, maxName, true, true),
	); err != nil {
		return err
	}
	switch {
	case t.Kind == "mcp" && (t.Server == nil || *t.Server < 0 || *t.Server >= servers):
		return refuse(Invalid, "%s.server: an MCP tool names a server of the report", at)
	case t.Kind != "mcp" && t.Server != nil:
		return refuse(Invalid, "%s.server: only an MCP tool names a server", at)
	case t.Kind == "builtin" && t.Definition != "":
		return refuse(Invalid, "%s.definition: a built-in tool has no definition", at)
	case t.Definition != "" && !isSHA256(t.Definition):
		return refuse(Invalid, "%s.definition: not a lowercase hexadecimal SHA-256", at)
	case t.Kind == "builtin":
		return firstError(
			checkText(at+".provider", t.Provider, maxShort, true, true),
			checkText(at+".type", t.Type, maxShort, true, true),
		)
	case t.Provider != "" || t.Type != "":
		return refuse(Invalid, "%s: only a built-in tool has a provider and a type", at)
	}
	return nil
}

func (m *ReportedModel) validate(at string) error {
	if err := firstError(
		checkText(at+".provider", m.Provider, maxShort, true, true),
		checkText(at+".endpoint", m.Endpoint, maxReference, true, false),
		checkText(at+".name", m.Name, maxName, true, true),
		checkText(at+".digest", m.Digest, maxShort, false, true),
	); err != nil {
		return err
	}
	if _, ok := urlHost(m.Endpoint); !ok {
		return refuse(Invalid, "%s.endpoint: not an http or https URL", at)
	}
	return nil
}

// checkText refuses a reported string that is not UTF-8, or that holds a
// lone surrogate, which UTF-8 cannot; that holds a NUL, which the database
// cannot store, or a noncharacter, which a catalog file, being I-JSON, cannot
// hold; that is longer than its limit in bytes; or that is empty when it is
// required. A string that becomes part of a key, or a digest, also holds no
// control character (U+0000 to U+001F, U+007F), which the generator of usage
// rules refuses in a tool's key (contracts, section 6.11).
func checkText(field, s string, maxBytes int, required, inKey bool) error {
	switch {
	case required && s == "":
		return refuse(Invalid, "%s: required", field)
	case len(s) > maxBytes:
		return refuse(Invalid, "%s: longer than %d bytes", field, maxBytes)
	case !utf8.ValidString(s):
		return refuse(Invalid, "%s: not UTF-8, or holds a lone surrogate", field)
	}
	for _, r := range s {
		switch {
		case r == 0:
			return refuse(Invalid, "%s: holds a NUL", field)
		case r >= 0xFDD0 && r <= 0xFDEF || r&0xFFFE == 0xFFFE:
			return refuse(Invalid, "%s: holds a noncharacter", field)
		case inKey && (r < 0x20 || r == 0x7F):
			return refuse(Invalid, "%s: holds a control character", field)
		}
	}
	return nil
}

// oneOf refuses a value that is not one of those given.
func oneOf(field, v string, allowed ...string) error {
	if !slices.Contains(allowed, v) {
		return refuse(Invalid, "%s: must be one of %s", field, strings.Join(allowed, ", "))
	}
	return nil
}

// firstError returns the first error that is not nil.
func firstError(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// isSHA256 reports whether s is a SHA-256 in lowercase hexadecimal.
func isSHA256(s string) bool {
	return len(s) == 2*sha256.Size && strings.Trim(s, "0123456789abcdef") == ""
}

// stdioCommand returns the command line of a local server's reference: the
// canonical JSON of the array of its command and arguments, after stdio:.
func stdioCommand(reference string) ([]string, bool) {
	rest, ok := strings.CutPrefix(reference, "stdio:")
	var command []string
	if !ok || json.Unmarshal([]byte(rest), &command) != nil || len(command) == 0 {
		return nil, false
	}
	return command, true
}

// serverFlags returns the flags of a server, from its reference: an unpinned
// package for a local server, and a path segment that looks like a secret in
// a remote server's URL or in a URL of a local server's command line.
func serverFlags(reference string) []string {
	f := []string{}
	command, local := stdioCommand(reference)
	if local && unpinnedPackage(command) {
		f = append(f, FlagUnpinnedPackage)
	}
	urls := []string{reference}
	if local {
		urls = command
	}
	if slices.ContainsFunc(urls, secretInPath) {
		f = append(f, FlagSecretInPath)
	}
	return f
}

// stringForm returns the string form of a reference with several parts: the
// canonical JSON (RFC 8785) of an object of those parts (contracts, section
// 4.10).
func stringForm(parts map[string]string) (string, error) {
	raw, err := json.Marshal(parts)
	if err != nil {
		return "", fmt.Errorf("encoding a reference: %w", err)
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return "", fmt.Errorf("encoding a reference: %w", err)
	}
	return string(canonical), nil
}

// sha256Hex returns the SHA-256 of a reference's string form, in lowercase
// hexadecimal, as events and blocks name references (RFC-0002, section 3).
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// set returns the strings given as a set.
func set(values []string) map[string]bool {
	s := make(map[string]bool, len(values))
	for _, v := range values {
		s[v] = true
	}
	return s
}

// nonEmpty returns nil for an empty string, which the database stores as
// NULL.
func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// nonNil returns an empty slice for nil, which the database would store as
// NULL.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// value returns the string of an optional column, empty for NULL.
func value(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
