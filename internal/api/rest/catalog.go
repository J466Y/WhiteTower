package rest

import (
	"context"

	"github.com/J466Y/WhiteTower/internal/api/rest/gen"
)

// The operations of the catalog of MCP servers, tools and models, and of
// agents' tooling (plan P1-16). Their contract was agreed before they are
// built (step 1), so that the console and the CLI can work against it: each
// one answers not_implemented until the pull request of its step builds it
// (the plan's progress notes).

// ListCatalogServers lists a page of MCP servers (P1-16, step 2).
func (Server) ListCatalogServers(context.Context, gen.ListCatalogServersRequestObject) (gen.ListCatalogServersResponseObject, error) {
	return nil, notBuilt()
}

// GetCatalogServer returns an MCP server (P1-16, step 2).
func (Server) GetCatalogServer(context.Context, gen.GetCatalogServerRequestObject) (gen.GetCatalogServerResponseObject, error) {
	return nil, notBuilt()
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

// ListCatalogTools lists a page of tools (P1-16, step 2).
func (Server) ListCatalogTools(context.Context, gen.ListCatalogToolsRequestObject) (gen.ListCatalogToolsResponseObject, error) {
	return nil, notBuilt()
}

// GetCatalogTool returns a tool (P1-16, step 2).
func (Server) GetCatalogTool(context.Context, gen.GetCatalogToolRequestObject) (gen.GetCatalogToolResponseObject, error) {
	return nil, notBuilt()
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

// GetToolDefinition returns a stored tool definition, as stored (P1-16,
// step 2).
func (Server) GetToolDefinition(context.Context, gen.GetToolDefinitionRequestObject) (gen.GetToolDefinitionResponseObject, error) {
	return nil, notBuilt()
}

// ListCatalogModels lists a page of models (P1-16, step 2).
func (Server) ListCatalogModels(context.Context, gen.ListCatalogModelsRequestObject) (gen.ListCatalogModelsResponseObject, error) {
	return nil, notBuilt()
}

// GetCatalogModel returns a model (P1-16, step 2).
func (Server) GetCatalogModel(context.Context, gen.GetCatalogModelRequestObject) (gen.GetCatalogModelResponseObject, error) {
	return nil, notBuilt()
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
