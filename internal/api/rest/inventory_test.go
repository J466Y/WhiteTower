package rest

import (
	"io"
	"testing"

	"github.com/J466Y/WhiteTower/internal/api/rest/problem"
)

// unbuilt lists the operations of plan P1-04 whose server side is not built
// yet. The pull request that builds one removes it from here.
var unbuilt = []string{
	"listAgents", "proposeAgent", "exportAgents", "getAgent", "editAgent",
	"getAgentActions", "listAgentTransitions", "transitionAgent", "listAgentInstances",
	"listAgentOwners", "reassignAgentOwner", "addAgentDelegate", "removeAgentDelegate",
	"requestOwnershipTransfer", "cancelOwnershipTransfer", "acceptOwnershipTransfer",
	"declineOwnershipTransfer", "listUseCases", "createUseCase", "getUseCase", "editUseCase",
	"listUseCaseDecisions", "listDataCategories", "listAgentReviews", "listReviews", "getReview",
	"completeReview", "signOffReview", "listInboxItems",
}

// An operation that is agreed but not built answers not_implemented to a
// caller the authorizer lets through, whatever the request holds.
func TestAgreedOperationsAnswerNotImplementedUntilBuilt(t *testing.T) {
	permitted := &allow{ops: map[string]bool{}}
	for _, id := range unbuilt {
		permitted.ops[id] = true
	}
	opts := options(io.Discard)
	opts.Authorizer = permitted
	h := Handler(opts)
	ops := operations()
	for _, id := range unbuilt {
		t.Run(id, func(t *testing.T) {
			op, ok := ops[operationKey(id)]
			if !ok {
				t.Fatalf("%s is not an operation of the document", id)
			}
			path, body := target(op)
			problemOf(t, call(h, op.Method, path, olivia, nil, body()), problem.NotImplemented)
		})
	}
}
