package rest

import (
	"context"

	"github.com/J466Y/WhiteTower/internal/api/rest/gen"
	"github.com/J466Y/WhiteTower/internal/api/rest/problem"
)

// The operations of the inventory and the inbox (plan P1-04). Their contract
// was agreed before they are built (step 1), so that the console and the CLI
// can work against it: each answers not_implemented until the pull request of
// its step builds it (the plan's progress notes).

// notBuilt is the answer of an operation that is agreed but not built yet.
func notBuilt() error {
	return problem.New(problem.NotImplemented, "this operation is agreed but not built yet")
}

// ListAgents lists the agents that match the filters (P1-04, steps 2 and 9).
func (Server) ListAgents(context.Context, gen.ListAgentsRequestObject) (gen.ListAgentsResponseObject, error) {
	return nil, notBuilt()
}

// ProposeAgent registers an agent as a draft, transition T1 (P1-04, step 2).
func (Server) ProposeAgent(context.Context, gen.ProposeAgentRequestObject) (gen.ProposeAgentResponseObject, error) {
	return nil, notBuilt()
}

// ExportAgents streams the agents that match the filters as CSV or JSON
// (P1-04, step 9).
func (Server) ExportAgents(context.Context, gen.ExportAgentsRequestObject) (gen.ExportAgentsResponseObject, error) {
	return nil, notBuilt()
}

// GetAgent returns an agent (P1-04, step 2).
func (Server) GetAgent(context.Context, gen.GetAgentRequestObject) (gen.GetAgentResponseObject, error) {
	return nil, notBuilt()
}

// EditAgent changes an agent's metadata (P1-04, step 2).
func (Server) EditAgent(context.Context, gen.EditAgentRequestObject) (gen.EditAgentResponseObject, error) {
	return nil, notBuilt()
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

// ListUseCases lists the use cases that match the filters (P1-04, step 4).
func (Server) ListUseCases(context.Context, gen.ListUseCasesRequestObject) (gen.ListUseCasesResponseObject, error) {
	return nil, notBuilt()
}

// CreateUseCase creates a use case as a draft (P1-04, step 4).
func (Server) CreateUseCase(context.Context, gen.CreateUseCaseRequestObject) (gen.CreateUseCaseResponseObject, error) {
	return nil, notBuilt()
}

// GetUseCase returns a use case (P1-04, step 4).
func (Server) GetUseCase(context.Context, gen.GetUseCaseRequestObject) (gen.GetUseCaseResponseObject, error) {
	return nil, notBuilt()
}

// EditUseCase changes a use case that no decision has made final (P1-04,
// step 4).
func (Server) EditUseCase(context.Context, gen.EditUseCaseRequestObject) (gen.EditUseCaseResponseObject, error) {
	return nil, notBuilt()
}

// ListUseCaseDecisions lists the advisory committee's decisions on a use case
// (P1-04, step 4).
func (Server) ListUseCaseDecisions(context.Context, gen.ListUseCaseDecisionsRequestObject) (gen.ListUseCaseDecisionsResponseObject, error) {
	return nil, notBuilt()
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

// ListDataCategories lists the data categories that agents and use cases may
// name (P1-04, step 2).
func (Server) ListDataCategories(context.Context, gen.ListDataCategoriesRequestObject) (gen.ListDataCategoriesResponseObject, error) {
	return nil, notBuilt()
}

// ListInboxItems lists the work that waits for the caller (P1-04, step 10).
func (Server) ListInboxItems(context.Context, gen.ListInboxItemsRequestObject) (gen.ListInboxItemsResponseObject, error) {
	return nil, notBuilt()
}
