package rest

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/J466Y/WhiteTower/internal/api/rest/gen"
	"github.com/J466Y/WhiteTower/internal/api/rest/problem"
	"github.com/J466Y/WhiteTower/internal/inventory"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
)

// The operations of the inventory and the inbox (plan P1-04). Their contract
// was agreed before they are built (step 1), so that the console and the CLI
// can work against it: each one not built yet answers not_implemented until
// the pull request of its step builds it (the plan's progress notes).

// notBuilt is the answer of an operation that is agreed but not built yet.
func notBuilt() error {
	return problem.New(problem.NotImplemented, "this operation is agreed but not built yet")
}

// The positions that the cursors of the inventory's lists carry.
type (
	slugPosition struct {
		After string `json:"after"`
	}
	idPosition struct {
		Before uuid.UUID `json:"before"`
	}
)

// inventoryCaller returns the principal that the middleware authenticated,
// for an operation of the inventory.
func (s Server) inventoryCaller(ctx context.Context) (*auth.Principal, error) {
	if s.inventory == nil {
		return nil, problem.New(problem.Internal, "")
	}
	p := auth.PrincipalFrom(ctx)
	if p == nil {
		return nil, problem.New(problem.Unauthenticated, "this operation needs a session or an API token")
	}
	return p, nil
}

// inventoryError answers a refusal of the inventory with its problem; any
// other error is internal, and its cause goes to the log only.
func inventoryError(err error) error {
	var r *inventory.Refusal
	if !errors.As(err, &r) {
		return err
	}
	switch r.Kind {
	case inventory.Invalid:
		return problem.New(problem.BadRequest, r.Detail)
	case inventory.NotFound:
		return problem.New(problem.NotFound, r.Detail)
	case inventory.Forbidden:
		return problem.New(problem.Forbidden, r.Detail)
	case inventory.Conflict:
		return problem.New(problem.Conflict, r.Detail)
	case inventory.Stale:
		return Stale()
	default:
		return err
	}
}

// filtersNotBuilt refuses the filters and the text search of the lists, which
// step 9 of plan P1-04 builds, rather than ignore them.
func filtersNotBuilt() error {
	return problem.New(problem.NotImplemented, "filters and search are agreed but not built yet")
}

// ListAgents lists a page of agents, by slug (P1-04, step 2). Its filters
// come with step 9.
func (s Server) ListAgents(ctx context.Context, request gen.ListAgentsRequestObject) (gen.ListAgentsResponseObject, error) {
	p, err := s.inventoryCaller(ctx)
	if err != nil {
		return nil, err
	}
	params := request.Params
	if params.State != nil || params.OwnerId != nil || params.RiskTier != nil || params.Environment != nil ||
		params.Coverage != nil || params.Label != nil || params.UseCaseId != nil || params.Q != nil {
		return nil, filtersNotBuilt()
	}
	size, err := PageSize(params.Limit)
	if err != nil {
		return nil, err
	}
	var pos slugPosition
	if params.Cursor != nil {
		if err := DecodeCursor(*params.Cursor, &pos); err != nil {
			return nil, err
		}
	}
	agents, more, err := s.inventory.List(ctx, *p, pos.After, size)
	if err != nil {
		return nil, inventoryError(err)
	}
	res := gen.ListAgents200JSONResponse{Agents: make([]gen.Agent, len(agents))}
	for i := range agents {
		res.Agents[i] = agentOf(&agents[i])
	}
	if more {
		next, err := EncodeCursor(slugPosition{After: agents[len(agents)-1].Slug})
		if err != nil {
			return nil, err
		}
		res.NextCursor = &next
	}
	return res, nil
}

// ProposeAgent registers an agent as a draft, transition T1 (P1-04, step 2).
func (s Server) ProposeAgent(ctx context.Context, request gen.ProposeAgentRequestObject) (gen.ProposeAgentResponseObject, error) {
	p, err := s.inventoryCaller(ctx)
	if err != nil {
		return nil, err
	}
	b := request.Body
	in := inventory.NewAgent{
		Slug:               b.Slug,
		Name:               b.Name,
		Description:        b.Description,
		Kind:               string(b.Kind),
		Vendor:             value(b.Vendor),
		Framework:          value(b.Framework),
		DeploymentLocation: b.DeploymentLocation,
		Environments:       b.Environments,
		RiskTier:           string(b.RiskTier),
		DataCategories:     b.DataCategories,
		UseCaseID:          b.UseCaseId,
	}
	if b.AiActClassification != nil {
		in.AIActClassification = string(*b.AiActClassification)
	}
	if b.Labels != nil {
		in.Labels = *b.Labels
	}
	if b.Harness != nil {
		in.Harness = &inventory.Harness{Description: b.Harness.Description}
	}
	if b.HaltMode != nil {
		in.HaltMode = string(*b.HaltMode)
	}
	if b.DrillEligible != nil {
		in.DrillEligible = *b.DrillEligible
	}
	a, err := s.inventory.Propose(ctx, *p, in)
	if err != nil {
		return nil, inventoryError(err)
	}
	return gen.ProposeAgent201JSONResponse{Body: agentOf(a), Headers: gen.ProposeAgent201ResponseHeaders{ETag: ETag(a.Version)}}, nil
}

// ExportAgents streams the agents that match the filters as CSV or JSON
// (P1-04, step 9).
func (Server) ExportAgents(context.Context, gen.ExportAgentsRequestObject) (gen.ExportAgentsResponseObject, error) {
	return nil, notBuilt()
}

// GetAgent returns an agent, with its ETag (P1-04, step 2).
func (s Server) GetAgent(ctx context.Context, request gen.GetAgentRequestObject) (gen.GetAgentResponseObject, error) {
	p, err := s.inventoryCaller(ctx)
	if err != nil {
		return nil, err
	}
	a, err := s.inventory.Get(ctx, *p, request.Id)
	if err != nil {
		return nil, inventoryError(err)
	}
	return gen.GetAgent200JSONResponse{Body: agentOf(a), Headers: gen.GetAgent200ResponseHeaders{ETag: ETag(a.Version)}}, nil
}

// EditAgent changes an agent's metadata, at the version that If-Match names
// (P1-04, step 2).
func (s Server) EditAgent(ctx context.Context, request gen.EditAgentRequestObject) (gen.EditAgentResponseObject, error) {
	p, err := s.inventoryCaller(ctx)
	if err != nil {
		return nil, err
	}
	version, err := IfMatch(value(request.Params.IfMatch))
	if err != nil {
		return nil, err
	}
	b := request.Body
	ch := inventory.AgentChanges{
		Name:                b.Name,
		Description:         b.Description,
		Vendor:              b.Vendor,
		Framework:           b.Framework,
		DeploymentLocation:  b.DeploymentLocation,
		Environments:        b.Environments,
		RiskTier:            (*string)(b.RiskTier),
		AIActClassification: (*string)(b.AiActClassification),
		DataCategories:      b.DataCategories,
		UseCaseID:           b.UseCaseId,
		HaltMode:            (*string)(b.HaltMode),
		DrillEligible:       b.DrillEligible,
	}
	if b.Labels != nil {
		labels := map[string]string(*b.Labels)
		ch.Labels = &labels
	}
	if b.Harness != nil {
		ch.Harness = &inventory.Harness{Description: b.Harness.Description}
	}
	a, err := s.inventory.Edit(ctx, *p, request.Id, version, ch)
	if err != nil {
		return nil, inventoryError(err)
	}
	return gen.EditAgent200JSONResponse{Body: agentOf(a), Headers: gen.EditAgent200ResponseHeaders{ETag: ETag(a.Version)}}, nil
}

// GetAgentActions says which lifecycle actions the caller may take on an
// agent, and what refuses the others (P1-04, step 5).
func (Server) GetAgentActions(context.Context, gen.GetAgentActionsRequestObject) (gen.GetAgentActionsResponseObject, error) {
	return nil, notBuilt()
}

// ListAgentTransitions lists an agent's lifecycle history (P1-04, step 5).
func (Server) ListAgentTransitions(context.Context, gen.ListAgentTransitionsRequestObject) (gen.ListAgentTransitionsResponseObject, error) {
	return nil, notBuilt()
}

// TransitionAgent takes a lifecycle action on an agent (P1-04, step 5).
func (Server) TransitionAgent(context.Context, gen.TransitionAgentRequestObject) (gen.TransitionAgentResponseObject, error) {
	return nil, notBuilt()
}

// ListAgentInstances lists the module instances that serve an agent (P1-04,
// step 8).
func (Server) ListAgentInstances(context.Context, gen.ListAgentInstancesRequestObject) (gen.ListAgentInstancesResponseObject, error) {
	return nil, notBuilt()
}

// ListAgentOwners lists an agent's owner assignments, current and ended
// (P1-04, step 3).
func (Server) ListAgentOwners(context.Context, gen.ListAgentOwnersRequestObject) (gen.ListAgentOwnersResponseObject, error) {
	return nil, notBuilt()
}

// ReassignAgentOwner makes another principal an agent's primary owner at once
// (P1-04, step 3).
func (Server) ReassignAgentOwner(context.Context, gen.ReassignAgentOwnerRequestObject) (gen.ReassignAgentOwnerResponseObject, error) {
	return nil, notBuilt()
}

// AddAgentDelegate makes a principal a delegate of an agent (P1-04, step 3).
func (Server) AddAgentDelegate(context.Context, gen.AddAgentDelegateRequestObject) (gen.AddAgentDelegateResponseObject, error) {
	return nil, notBuilt()
}

// RemoveAgentDelegate ends a delegate's assignment (P1-04, step 3).
func (Server) RemoveAgentDelegate(context.Context, gen.RemoveAgentDelegateRequestObject) (gen.RemoveAgentDelegateResponseObject, error) {
	return nil, notBuilt()
}

// RequestOwnershipTransfer offers an agent's ownership to another principal
// (P1-04, step 3).
func (Server) RequestOwnershipTransfer(context.Context, gen.RequestOwnershipTransferRequestObject) (gen.RequestOwnershipTransferResponseObject, error) {
	return nil, notBuilt()
}

// CancelOwnershipTransfer cancels a pending ownership transfer (P1-04, step 3).
func (Server) CancelOwnershipTransfer(context.Context, gen.CancelOwnershipTransferRequestObject) (gen.CancelOwnershipTransferResponseObject, error) {
	return nil, notBuilt()
}

// AcceptOwnershipTransfer makes the principal a transfer names the agent's
// primary owner (P1-04, step 3).
func (Server) AcceptOwnershipTransfer(context.Context, gen.AcceptOwnershipTransferRequestObject) (gen.AcceptOwnershipTransferResponseObject, error) {
	return nil, notBuilt()
}

// DeclineOwnershipTransfer declines a pending ownership transfer (P1-04,
// step 3).
func (Server) DeclineOwnershipTransfer(context.Context, gen.DeclineOwnershipTransferRequestObject) (gen.DeclineOwnershipTransferResponseObject, error) {
	return nil, notBuilt()
}

// ListUseCases lists a page of use cases, newest first (P1-04, step 4). Its
// filters come with step 9.
func (s Server) ListUseCases(ctx context.Context, request gen.ListUseCasesRequestObject) (gen.ListUseCasesResponseObject, error) {
	p, err := s.inventoryCaller(ctx)
	if err != nil {
		return nil, err
	}
	params := request.Params
	if params.Status != nil || params.Q != nil {
		return nil, filtersNotBuilt()
	}
	size, err := PageSize(params.Limit)
	if err != nil {
		return nil, err
	}
	before, err := beforeOf(params.Cursor)
	if err != nil {
		return nil, err
	}
	useCases, more, err := s.inventory.ListUseCases(ctx, *p, before, size)
	if err != nil {
		return nil, inventoryError(err)
	}
	res := gen.ListUseCases200JSONResponse{UseCases: make([]gen.UseCase, len(useCases))}
	for i := range useCases {
		res.UseCases[i] = useCaseOf(&useCases[i])
	}
	if more {
		next, err := EncodeCursor(idPosition{Before: useCases[len(useCases)-1].ID})
		if err != nil {
			return nil, err
		}
		res.NextCursor = &next
	}
	return res, nil
}

// CreateUseCase creates a use case as a draft (P1-04, step 4).
func (s Server) CreateUseCase(ctx context.Context, request gen.CreateUseCaseRequestObject) (gen.CreateUseCaseResponseObject, error) {
	p, err := s.inventoryCaller(ctx)
	if err != nil {
		return nil, err
	}
	b := request.Body
	in := inventory.NewUseCase{
		Title:                 b.Title,
		Description:           b.Description,
		BusinessJustification: b.BusinessJustification,
		DataCategories:        b.DataCategories,
		AffectedPersons:       value(b.AffectedPersons),
		Conditions:            value(b.Conditions),
	}
	if b.AiActClassification != nil {
		in.AIActClassification = string(*b.AiActClassification)
	}
	uc, err := s.inventory.CreateUseCase(ctx, *p, in)
	if err != nil {
		return nil, inventoryError(err)
	}
	return gen.CreateUseCase201JSONResponse{Body: useCaseOf(uc), Headers: gen.CreateUseCase201ResponseHeaders{ETag: ETag(uc.Version)}}, nil
}

// GetUseCase returns a use case, with its ETag (P1-04, step 4).
func (s Server) GetUseCase(ctx context.Context, request gen.GetUseCaseRequestObject) (gen.GetUseCaseResponseObject, error) {
	p, err := s.inventoryCaller(ctx)
	if err != nil {
		return nil, err
	}
	uc, err := s.inventory.GetUseCase(ctx, *p, request.Id)
	if err != nil {
		return nil, inventoryError(err)
	}
	return gen.GetUseCase200JSONResponse{Body: useCaseOf(uc), Headers: gen.GetUseCase200ResponseHeaders{ETag: ETag(uc.Version)}}, nil
}

// EditUseCase changes a use case that no decision has made final, at the
// version that If-Match names (P1-04, step 4).
func (s Server) EditUseCase(ctx context.Context, request gen.EditUseCaseRequestObject) (gen.EditUseCaseResponseObject, error) {
	p, err := s.inventoryCaller(ctx)
	if err != nil {
		return nil, err
	}
	version, err := IfMatch(value(request.Params.IfMatch))
	if err != nil {
		return nil, err
	}
	b := request.Body
	uc, err := s.inventory.EditUseCase(ctx, *p, request.Id, version, inventory.UseCaseChanges{
		Title:                 b.Title,
		Description:           b.Description,
		BusinessJustification: b.BusinessJustification,
		DataCategories:        b.DataCategories,
		AffectedPersons:       b.AffectedPersons,
		AIActClassification:   (*string)(b.AiActClassification),
		Conditions:            b.Conditions,
	})
	if err != nil {
		return nil, inventoryError(err)
	}
	return gen.EditUseCase200JSONResponse{Body: useCaseOf(uc), Headers: gen.EditUseCase200ResponseHeaders{ETag: ETag(uc.Version)}}, nil
}

// ListUseCaseDecisions lists the advisory committee's decisions on a use case
// (P1-04, step 4).
func (s Server) ListUseCaseDecisions(ctx context.Context, request gen.ListUseCaseDecisionsRequestObject) (gen.ListUseCaseDecisionsResponseObject, error) {
	p, err := s.inventoryCaller(ctx)
	if err != nil {
		return nil, err
	}
	size, err := PageSize(request.Params.Limit)
	if err != nil {
		return nil, err
	}
	before, err := beforeOf(request.Params.Cursor)
	if err != nil {
		return nil, err
	}
	decisions, more, err := s.inventory.Decisions(ctx, *p, request.Id, before, size)
	if err != nil {
		return nil, inventoryError(err)
	}
	res := gen.ListUseCaseDecisions200JSONResponse{Decisions: make([]gen.UseCaseDecision, len(decisions))}
	for i, d := range decisions {
		res.Decisions[i] = gen.UseCaseDecision{
			Id:        d.ID,
			Decision:  gen.UseCaseDecisionDecision(d.Decision),
			Comment:   d.Comment,
			AgentId:   d.AgentID,
			DecidedBy: personOf(d.DecidedBy),
			DecidedAt: d.DecidedAt,
		}
	}
	if more {
		next, err := EncodeCursor(idPosition{Before: decisions[len(decisions)-1].ID})
		if err != nil {
			return nil, err
		}
		res.NextCursor = &next
	}
	return res, nil
}

// ListDataCategories lists the data categories that agents and use cases may
// name (P1-04, step 2).
func (s Server) ListDataCategories(ctx context.Context, _ gen.ListDataCategoriesRequestObject) (gen.ListDataCategoriesResponseObject, error) {
	if _, err := s.inventoryCaller(ctx); err != nil {
		return nil, err
	}
	categories, err := s.inventory.DataCategories(ctx)
	if err != nil {
		return nil, err
	}
	return gen.ListDataCategories200JSONResponse{DataCategories: categories}, nil
}

// ListAgentReviews lists an agent's periodic reviews (P1-04, step 6).
func (Server) ListAgentReviews(context.Context, gen.ListAgentReviewsRequestObject) (gen.ListAgentReviewsResponseObject, error) {
	return nil, notBuilt()
}

// ListReviews lists the periodic reviews that match the filters (P1-04,
// step 6).
func (Server) ListReviews(context.Context, gen.ListReviewsRequestObject) (gen.ListReviewsResponseObject, error) {
	return nil, notBuilt()
}

// GetReview returns a periodic review, with its candidates to disable (P1-04,
// step 6).
func (Server) GetReview(context.Context, gen.GetReviewRequestObject) (gen.GetReviewResponseObject, error) {
	return nil, notBuilt()
}

// CompleteReview records the owner's attestation of a review (P1-04, step 6).
func (Server) CompleteReview(context.Context, gen.CompleteReviewRequestObject) (gen.CompleteReviewResponseObject, error) {
	return nil, notBuilt()
}

// SignOffReview records the advisory committee's sign-off of a review (P1-04,
// step 6).
func (Server) SignOffReview(context.Context, gen.SignOffReviewRequestObject) (gen.SignOffReviewResponseObject, error) {
	return nil, notBuilt()
}

// ListInboxItems lists the work that waits for the caller (P1-04, step 10).
func (Server) ListInboxItems(context.Context, gen.ListInboxItemsRequestObject) (gen.ListInboxItemsResponseObject, error) {
	return nil, notBuilt()
}

// beforeOf reads the position of a cursor of a list that goes newest first.
func beforeOf(cursor *gen.Cursor) (*uuid.UUID, error) {
	if cursor == nil {
		return nil, nil
	}
	var pos idPosition
	if err := DecodeCursor(*cursor, &pos); err != nil {
		return nil, err
	}
	return &pos.Before, nil
}

// agentOf is how the API shows an agent.
func agentOf(a *inventory.Agent) gen.Agent {
	out := gen.Agent{
		Id:                  a.ID,
		Slug:                a.Slug,
		Name:                a.Name,
		Description:         a.Description,
		Kind:                gen.AgentKind(a.Kind),
		Source:              gen.AgentSource(a.Source),
		Vendor:              optionalText(a.Vendor),
		Framework:           optionalText(a.Framework),
		DeploymentLocation:  optionalText(a.DeploymentLocation),
		Environments:        listOf(a.Environments),
		RiskTier:            gen.RiskTier(a.RiskTier),
		AiActClassification: gen.AiActClassification(a.AIActClassification),
		DataCategories:      listOf(a.DataCategories),
		UseCaseId:           a.UseCaseID,
		LifecycleState:      gen.LifecycleState(a.LifecycleState),
		RunState:            gen.Running,
		Coverage:            gen.CoverageLevel(a.Coverage),
		Labels:              gen.Labels(a.Labels),
		HaltMode:            gen.HaltMode(a.HaltMode),
		DrillEligible:       a.DrillEligible,
		PrimaryOwner:        personOf(a.PrimaryOwner),
		Delegates:           make([]gen.PrincipalRef, len(a.Delegates)),
		CreatedBy:           personOf(a.CreatedBy),
		CreatedAt:           a.CreatedAt,
		UpdatedAt:           a.UpdatedAt,
		ActivatedAt:         a.ActivatedAt,
		RetiredAt:           a.RetiredAt,
	}
	if a.Halted {
		out.RunState = gen.Halted
	}
	for i, d := range a.Delegates {
		out.Delegates[i] = personOf(d)
	}
	if a.Suspension != nil {
		out.Suspension = &gen.Suspension{
			From:   gen.SuspensionFrom(a.Suspension.From),
			Reason: gen.SuspensionReason(a.Suspension.Reason),
			At:     a.Suspension.At,
		}
	}
	if a.Harness != nil {
		out.Harness = &gen.Harness{Description: a.Harness.Description}
	}
	return out
}

// useCaseOf is how the API shows a use case.
func useCaseOf(uc *inventory.UseCase) gen.UseCase {
	return gen.UseCase{
		Id:                    uc.ID,
		Title:                 uc.Title,
		Description:           uc.Description,
		BusinessJustification: uc.BusinessJustification,
		DataCategories:        listOf(uc.DataCategories),
		AffectedPersons:       optionalText(uc.AffectedPersons),
		AiActClassification:   gen.AiActClassification(uc.AIActClassification),
		Conditions:            optionalText(uc.Conditions),
		Status:                gen.UseCaseStatus(uc.Status),
		CreatedBy:             personOf(uc.CreatedBy),
		CreatedAt:             uc.CreatedAt,
		UpdatedAt:             uc.UpdatedAt,
	}
}

// personOf is how the API shows a principal that a resource names.
func personOf(p inventory.Person) gen.PrincipalRef {
	return gen.PrincipalRef{Id: p.ID, DisplayName: optionalText(p.DisplayName), Status: gen.PrincipalRefStatus(p.Status)}
}

// optionalText leaves out an empty text.
func optionalText(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// listOf shows a missing list as an empty one.
func listOf(list []string) []string {
	if list == nil {
		return []string{}
	}
	return list
}

// value reads an optional parameter, empty when absent.
func value(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
