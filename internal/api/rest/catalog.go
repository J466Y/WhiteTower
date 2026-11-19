package rest

import (
	"context"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/J466Y/WhiteTower/internal/api/rest/gen"
	"github.com/J466Y/WhiteTower/internal/api/rest/problem"
	"github.com/J466Y/WhiteTower/internal/catalog"
)

// The operations of the catalog of MCP servers, tools and models, and of
// agents' tooling (plan P1-16). Their contract was agreed before they are
// built (step 1), so that the console and the CLI can work against it: each
// one not built yet answers not_implemented until the pull request of its
// step builds it (the plan's progress notes). The authorizer requires
// catalog.view for every one of them, besides its own permission, since
// their answers carry references and reported text (RFC-0002, Privacy).

// toolPosition is the position that the cursor of a page of tools carries.
// The agent's own tools can share a key, so the ID orders them.
type toolPosition struct {
	AfterKey string    `json:"afterKey"`
	AfterID  uuid.UUID `json:"afterId"`
}

// checkCatalog answers an internal problem when the server has no catalog.
func (s Server) checkCatalog() error {
	if s.catalog == nil {
		return problem.New(problem.Internal, "")
	}
	return nil
}

// catalogError answers a refusal of the catalog with its problem; any other
// error is internal, and its cause goes to the log only.
func catalogError(err error) error {
	var r *catalog.Refusal
	if !errors.As(err, &r) {
		return err
	}
	switch r.Kind {
	case catalog.Invalid:
		return problem.New(problem.BadRequest, r.Detail)
	case catalog.NotFound:
		return problem.New(problem.NotFound, r.Detail)
	case catalog.Forbidden:
		return problem.New(problem.Forbidden, r.Detail)
	default:
		return err
	}
}

// catalogFilter reads the filters that every list of the catalog takes.
func catalogFilter(status *gen.CatalogStatusFilter, pending *bool, key *string) catalog.Filter {
	f := catalog.Filter{PendingReview: pending, Key: value(key)}
	if status != nil {
		for _, s := range *status {
			f.Statuses = append(f.Statuses, string(s))
		}
	}
	return f
}

// catalogPage reads a list's limit, and the position that its cursor
// carries.
func catalogPage(limit *int, cursor *string, position any) (int, error) {
	size, err := PageSize(limit)
	if err != nil {
		return 0, err
	}
	if cursor != nil {
		if err := DecodeCursor(*cursor, position); err != nil {
			return 0, err
		}
	}
	return size, nil
}

// ListCatalogServers lists a page of MCP servers, by key (P1-16, step 2).
func (s Server) ListCatalogServers(ctx context.Context, request gen.ListCatalogServersRequestObject) (gen.ListCatalogServersResponseObject, error) {
	if err := s.checkCatalog(); err != nil {
		return nil, err
	}
	params := request.Params
	var pos slugPosition
	size, err := catalogPage(params.Limit, params.Cursor, &pos)
	if err != nil {
		return nil, err
	}
	f := catalog.ServerFilter{Filter: catalogFilter(params.Status, params.PendingReview, params.Key)}
	if params.Flag != nil {
		f.Flags = *params.Flag
	}
	servers, more, err := s.catalog.ListServers(ctx, f, pos.After, size)
	if err != nil {
		return nil, catalogError(err)
	}
	res := gen.ListCatalogServers200JSONResponse{Servers: make([]gen.CatalogServer, len(servers))}
	for i := range servers {
		res.Servers[i] = catalogServerOf(&servers[i])
	}
	if more {
		next, err := EncodeCursor(slugPosition{After: servers[len(servers)-1].Key})
		if err != nil {
			return nil, err
		}
		res.NextCursor = &next
	}
	return res, nil
}

// GetCatalogServer returns an MCP server, with its ETag (P1-16, step 2).
func (s Server) GetCatalogServer(ctx context.Context, request gen.GetCatalogServerRequestObject) (gen.GetCatalogServerResponseObject, error) {
	if err := s.checkCatalog(); err != nil {
		return nil, err
	}
	server, err := s.catalog.GetServer(ctx, request.Id)
	if err != nil {
		return nil, catalogError(err)
	}
	return gen.GetCatalogServer200JSONResponse{
		Body: catalogServerOf(server), Headers: gen.GetCatalogServer200ResponseHeaders{ETag: ETag(server.Version)},
	}, nil
}

// ApproveCatalogServer approves an MCP server, and some of its tools with it
// (P1-16, step 2).
func (Server) ApproveCatalogServer(context.Context, gen.ApproveCatalogServerRequestObject) (gen.ApproveCatalogServerResponseObject, error) {
	return nil, notBuilt()
}

// DeclineCatalogServer declines a discovered MCP server (P1-16, step 2).
func (Server) DeclineCatalogServer(context.Context, gen.DeclineCatalogServerRequestObject) (gen.DeclineCatalogServerResponseObject, error) {
	return nil, notBuilt()
}

// ListCatalogTools lists a page of tools, by key and ID (P1-16, step 2).
func (s Server) ListCatalogTools(ctx context.Context, request gen.ListCatalogToolsRequestObject) (gen.ListCatalogToolsResponseObject, error) {
	if err := s.checkCatalog(); err != nil {
		return nil, err
	}
	params := request.Params
	var pos toolPosition
	size, err := catalogPage(params.Limit, params.Cursor, &pos)
	if err != nil {
		return nil, err
	}
	f := catalog.ToolFilter{
		Filter: catalogFilter(params.Status, params.PendingReview, params.Key), Server: params.ServerId, Agent: params.AgentId,
	}
	if params.Kind != nil {
		for _, k := range *params.Kind {
			f.Kinds = append(f.Kinds, string(k))
		}
	}
	var after *catalog.ToolPosition
	if params.Cursor != nil {
		after = &catalog.ToolPosition{Key: pos.AfterKey, ID: pos.AfterID}
	}
	tools, more, err := s.catalog.ListTools(ctx, f, after, size)
	if err != nil {
		return nil, catalogError(err)
	}
	res := gen.ListCatalogTools200JSONResponse{Tools: make([]gen.CatalogTool, len(tools))}
	for i := range tools {
		res.Tools[i] = catalogToolOf(&tools[i])
	}
	if more {
		last := tools[len(tools)-1]
		next, err := EncodeCursor(toolPosition{AfterKey: last.Key, AfterID: last.ID})
		if err != nil {
			return nil, err
		}
		res.NextCursor = &next
	}
	return res, nil
}

// GetCatalogTool returns a tool, with its ETag (P1-16, step 2).
func (s Server) GetCatalogTool(ctx context.Context, request gen.GetCatalogToolRequestObject) (gen.GetCatalogToolResponseObject, error) {
	if err := s.checkCatalog(); err != nil {
		return nil, err
	}
	tool, err := s.catalog.GetTool(ctx, request.Id)
	if err != nil {
		return nil, catalogError(err)
	}
	return gen.GetCatalogTool200JSONResponse{
		Body: catalogToolOf(tool), Headers: gen.GetCatalogTool200ResponseHeaders{ETag: ETag(tool.Version)},
	}, nil
}

// ApproveCatalogTool approves a tool or one of its new definitions, with its
// classification and declared arguments (P1-16, step 2).
func (Server) ApproveCatalogTool(context.Context, gen.ApproveCatalogToolRequestObject) (gen.ApproveCatalogToolResponseObject, error) {
	return nil, notBuilt()
}

// DeclineCatalogTool declines a discovered tool or one of its new
// definitions (P1-16, step 2).
func (Server) DeclineCatalogTool(context.Context, gen.DeclineCatalogToolRequestObject) (gen.DeclineCatalogToolResponseObject, error) {
	return nil, notBuilt()
}

// GetToolDefinition returns a stored tool definition, exactly as stored
// (P1-16, step 2).
func (s Server) GetToolDefinition(ctx context.Context, request gen.GetToolDefinitionRequestObject) (gen.GetToolDefinitionResponseObject, error) {
	if err := s.checkCatalog(); err != nil {
		return nil, err
	}
	canonical, err := s.catalog.Definition(ctx, request.Sha256)
	if err != nil {
		return nil, catalogError(err)
	}
	return storedDefinition{canonical: canonical, etag: `"` + request.Sha256 + `"`}, nil
}

// storedDefinition answers getToolDefinition with a definition's canonical
// bytes, exactly as stored, so that the SHA-256 of the body is the hash in
// the path. The generated answer would decode and encode them again, which
// would round integers beyond 2^53. The bytes were reported: they go out as
// JSON only, never sniffed as anything else.
type storedDefinition struct {
	canonical []byte
	etag      string
}

// VisitGetToolDefinitionResponse writes the definition's bytes.
func (d storedDefinition) VisitGetToolDefinitionResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("ETag", d.etag)
	w.WriteHeader(http.StatusOK)
	_, err := w.Write(d.canonical)
	return err
}

// ListCatalogModels lists a page of models, by key (P1-16, step 2).
func (s Server) ListCatalogModels(ctx context.Context, request gen.ListCatalogModelsRequestObject) (gen.ListCatalogModelsResponseObject, error) {
	if err := s.checkCatalog(); err != nil {
		return nil, err
	}
	params := request.Params
	var pos slugPosition
	size, err := catalogPage(params.Limit, params.Cursor, &pos)
	if err != nil {
		return nil, err
	}
	f := catalog.ModelFilter{Filter: catalogFilter(params.Status, params.PendingReview, params.Key), Provider: value(params.Provider)}
	if params.Flag != nil {
		f.Flags = *params.Flag
	}
	models, more, err := s.catalog.ListModels(ctx, f, pos.After, size)
	if err != nil {
		return nil, catalogError(err)
	}
	res := gen.ListCatalogModels200JSONResponse{Models: make([]gen.CatalogModel, len(models))}
	for i := range models {
		res.Models[i] = catalogModelOf(&models[i])
	}
	if more {
		next, err := EncodeCursor(slugPosition{After: models[len(models)-1].Key})
		if err != nil {
			return nil, err
		}
		res.NextCursor = &next
	}
	return res, nil
}

// GetCatalogModel returns a model, with its ETag (P1-16, step 2).
func (s Server) GetCatalogModel(ctx context.Context, request gen.GetCatalogModelRequestObject) (gen.GetCatalogModelResponseObject, error) {
	if err := s.checkCatalog(); err != nil {
		return nil, err
	}
	model, err := s.catalog.GetModel(ctx, request.Id)
	if err != nil {
		return nil, catalogError(err)
	}
	return gen.GetCatalogModel200JSONResponse{
		Body: catalogModelOf(model), Headers: gen.GetCatalogModel200ResponseHeaders{ETag: ETag(model.Version)},
	}, nil
}

// ApproveCatalogModel approves a model or one of its new digests (P1-16,
// step 2).
func (Server) ApproveCatalogModel(context.Context, gen.ApproveCatalogModelRequestObject) (gen.ApproveCatalogModelResponseObject, error) {
	return nil, notBuilt()
}

// DeclineCatalogModel declines a discovered model or one of its new digests
// (P1-16, step 2).
func (Server) DeclineCatalogModel(context.Context, gen.DeclineCatalogModelRequestObject) (gen.DeclineCatalogModelResponseObject, error) {
	return nil, notBuilt()
}

// DeclinePendingFromAgent declines everything an agent's reports brought that
// waits for review (P1-16, step 2).
func (Server) DeclinePendingFromAgent(context.Context, gen.DeclinePendingFromAgentRequestObject) (gen.DeclinePendingFromAgentResponseObject, error) {
	return nil, notBuilt()
}

// ListCatalogBlocks lists a page of blocks (P1-16, step 7).
func (Server) ListCatalogBlocks(context.Context, gen.ListCatalogBlocksRequestObject) (gen.ListCatalogBlocksResponseObject, error) {
	return nil, notBuilt()
}

// IssueCatalogBlock blocks a server, a tool or models (P1-16, step 7).
func (Server) IssueCatalogBlock(context.Context, gen.IssueCatalogBlockRequestObject) (gen.IssueCatalogBlockResponseObject, error) {
	return nil, notBuilt()
}

// GetCatalogBlock returns a block, with its spread (P1-16, step 7).
func (Server) GetCatalogBlock(context.Context, gen.GetCatalogBlockRequestObject) (gen.GetCatalogBlockResponseObject, error) {
	return nil, notBuilt()
}

// RequestCatalogUnblock asks that a block be lifted (P1-16, step 7).
func (Server) RequestCatalogUnblock(context.Context, gen.RequestCatalogUnblockRequestObject) (gen.RequestCatalogUnblockResponseObject, error) {
	return nil, notBuilt()
}

// ApproveCatalogUnblock approves a request to lift a block (P1-16, step 7).
func (Server) ApproveCatalogUnblock(context.Context, gen.ApproveCatalogUnblockRequestObject) (gen.ApproveCatalogUnblockResponseObject, error) {
	return nil, notBuilt()
}

// DeclineCatalogUnblock declines a request to lift a block (P1-16, step 7).
func (Server) DeclineCatalogUnblock(context.Context, gen.DeclineCatalogUnblockRequestObject) (gen.DeclineCatalogUnblockResponseObject, error) {
	return nil, notBuilt()
}

// CompileUsageRules writes the Cedar statements of a policy's usage rules
// (P1-16, step 6).
func (Server) CompileUsageRules(context.Context, gen.CompileUsageRulesRequestObject) (gen.CompileUsageRulesResponseObject, error) {
	return nil, notBuilt()
}

// ListAgentTooling lists a page of an agent's tooling (P1-16, steps 3 and 4).
func (Server) ListAgentTooling(context.Context, gen.ListAgentToolingRequestObject) (gen.ListAgentToolingResponseObject, error) {
	return nil, notBuilt()
}

// DisableAgentTooling disables an agent's tooling at once (P1-16, step 3).
func (Server) DisableAgentTooling(context.Context, gen.DisableAgentToolingRequestObject) (gen.DisableAgentToolingResponseObject, error) {
	return nil, notBuilt()
}

// ListAgentToolingRequests lists an agent's requests to enable tooling
// (P1-16, step 3).
func (Server) ListAgentToolingRequests(context.Context, gen.ListAgentToolingRequestsRequestObject) (gen.ListAgentToolingRequestsResponseObject, error) {
	return nil, notBuilt()
}

// RequestAgentTooling asks that tooling be enabled for an agent (P1-16,
// step 3).
func (Server) RequestAgentTooling(context.Context, gen.RequestAgentToolingRequestObject) (gen.RequestAgentToolingResponseObject, error) {
	return nil, notBuilt()
}

// ApproveAgentToolingRequest approves a request to enable tooling (P1-16,
// step 3).
func (Server) ApproveAgentToolingRequest(context.Context, gen.ApproveAgentToolingRequestRequestObject) (gen.ApproveAgentToolingRequestResponseObject, error) {
	return nil, notBuilt()
}

// DeclineAgentToolingRequest declines a request to enable tooling (P1-16,
// step 3).
func (Server) DeclineAgentToolingRequest(context.Context, gen.DeclineAgentToolingRequestRequestObject) (gen.DeclineAgentToolingRequestResponseObject, error) {
	return nil, notBuilt()
}

// GetAgentDeclaredTooling returns the tooling declared for an agent (P1-16,
// step 3).
func (Server) GetAgentDeclaredTooling(context.Context, gen.GetAgentDeclaredToolingRequestObject) (gen.GetAgentDeclaredToolingResponseObject, error) {
	return nil, notBuilt()
}

// DeclareAgentTooling replaces the tooling declared for an agent (P1-16,
// step 3).
func (Server) DeclareAgentTooling(context.Context, gen.DeclareAgentToolingRequestObject) (gen.DeclareAgentToolingResponseObject, error) {
	return nil, notBuilt()
}

// catalogServerOf is how the API shows an MCP server. No block covers an
// entry until blocks are built (P1-16, step 7).
func catalogServerOf(s *catalog.Server) gen.CatalogServer {
	return gen.CatalogServer{
		Id: s.ID, Key: s.Key, Reference: s.Reference, Transport: gen.CatalogServerTransport(s.Transport),
		AnnouncedName: optionalText(s.AnnouncedName), AnnouncedVersion: optionalText(s.AnnouncedVersion),
		DisplayForm: optionalText(s.DisplayForm), Status: gen.CatalogStatus(s.Status), PendingReview: s.PendingReview,
		Flags: listOf(s.Flags), FirstAgentId: s.Seen.FirstAgent, FirstSeenAt: s.Seen.First, LastSeenAt: s.Seen.Last,
	}
}

// catalogToolOf is how the API shows a tool. Its classification and the
// arguments policies may see come with approvals (P1-16, pull request 1c).
func catalogToolOf(t *catalog.Tool) gen.CatalogTool {
	return gen.CatalogTool{
		Id: t.ID, Key: t.Key, Kind: gen.ToolKind(t.Kind), Name: t.Name, ServerId: t.Server, AgentId: t.Agent,
		Provider: optionalText(t.Provider), Type: optionalText(t.Type), Status: gen.CatalogStatus(t.Status),
		PendingReview: t.PendingReview, DefinitionSha256: optionalText(t.Definition),
		PendingDefinitions: listOf(t.PendingDefinitions), Arguments: []gen.ToolArgument{},
		FirstAgentId: t.Seen.FirstAgent, FirstSeenAt: t.Seen.First, LastSeenAt: t.Seen.Last,
	}
}

// catalogModelOf is how the API shows a model.
func catalogModelOf(m *catalog.Model) gen.CatalogModel {
	return gen.CatalogModel{
		Id: m.ID, Key: m.Key, Provider: m.Provider, Endpoint: m.Endpoint, Name: m.Name, Status: gen.CatalogStatus(m.Status),
		PendingReview: m.PendingReview, Flags: listOf(m.Flags), Digest: optionalText(m.Digest),
		PendingDigests: listOf(m.PendingDigests), FirstAgentId: m.Seen.FirstAgent, FirstSeenAt: m.Seen.First,
		LastSeenAt: m.Seen.Last,
	}
}
