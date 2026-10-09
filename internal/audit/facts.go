package audit

import (
	"fmt"
	"strings"
)

// facts are what the audit log indexes of an event besides its envelope: who
// acted, what was done, how it ended and why. They are read from the event by
// its type's rule, never given apart from it, so that the columns of
// audit_events say what its canonical bytes say.
type facts struct {
	actorType string
	actorID   string // none for the system
	action    string
	outcome   string // none when the type tells no outcome
	reason    string // none when the type tells no reason
}

// rule says where the facts of a type's events are, by members of their data.
type rule struct {
	// actor names who acted, as {"type", "id"}. Without it, the emitter
	// acted, as the event's source tells.
	actor string
	// action names what was done. Without it, the type's name does.
	action string
	// outcome tells how it ended, as outcomes reads it; fixed is the
	// outcome of every event of the type.
	outcome, fixed string
	// reason tells why.
	reason string
}

// rules index every type of the event catalog; LoadCatalog refuses a type
// without one. A plan that adds a type adds its rule.
var rules = map[string]rule{
	// Enforcement points and runtime control: the emitter acted.
	"whitetower.decision.made.v1":      {action: "action", outcome: "decision", reason: "reason"},
	"whitetower.action.executed.v1":    {action: "action", outcome: "outcome"},
	"whitetower.instance.started.v1":   {},
	"whitetower.instance.halted.v1":    {},
	"whitetower.bundle.activated.v1":   {fixed: "success"},
	"whitetower.bundle.rejected.v1":    {fixed: "failure", reason: "reason"},
	"whitetower.lease.expired.v1":      {},
	"whitetower.quarantine.applied.v1": {fixed: "success"},
	"whitetower.quarantine.lifted.v1":  {fixed: "success"},
	// The core: the data names who acted.
	"whitetower.agent.created.v1":           {actor: "actor"},
	"whitetower.agent.lifecycle_changed.v1": {actor: "actor", action: "action"},
	"whitetower.policy.version_approved.v1": {actor: "approver"},
	"whitetower.halt.issued.v1":             {actor: "issuer", reason: "reason"},
	"whitetower.halt.released.v1":           {actor: "approved_by", reason: "reason"},
	"whitetower.audit.checkpoint.v1":        {},
}

// outcomes maps the outcomes that events tell to those the audit log
// indexes.
var outcomes = map[string]string{
	"allow": "allow", "deny": "deny",
	"succeeded": "success", "failed": "failure", "cancelled": "cancelled", //nolint:misspell // the contracts' spelling
}

// factsOf reads the facts of an event of type t, decoded and checked.
func factsOf(t eventType, event map[string]any) (facts, error) {
	data, _ := event["data"].(map[string]any)
	member := func(name string) string {
		s, _ := data[name].(string)
		return s
	}
	var f facts
	if t.rule.actor != "" {
		actor, _ := data[t.rule.actor].(map[string]any)
		f.actorType, _ = actor["type"].(string)
		f.actorID, _ = actor["id"].(string)
	} else {
		source, _ := event["source"].(string)
		f.actorType, f.actorID = emitter(source)
	}
	if f.action = member(t.rule.action); t.rule.action == "" {
		name, _ := event["type"].(string)
		f.action = action(name)
	}
	f.outcome = t.rule.fixed
	if t.rule.outcome != "" {
		told := member(t.rule.outcome)
		if f.outcome = outcomes[told]; f.outcome == "" {
			return facts{}, fmt.Errorf("the audit log indexes no outcome %q", told)
		}
	}
	f.reason = member(t.rule.reason)
	return f, nil
}

// emitter returns who emitted an event from its source (contracts, section
// 8.2): the agent of an enforcement point inside it, a module, or the core.
func emitter(source string) (actorType, actorID string) {
	parts := strings.Split(strings.TrimPrefix(source, "/"), "/")
	switch {
	case len(parts) == 4 && parts[0] == "agents" && parts[2] == "ep":
		return "agent", parts[1]
	case len(parts) == 3 && parts[0] == "modules":
		return "module", parts[1]
	default:
		return "system", ""
	}
}

// action returns what a type's name says was done: "halt.issued" for
// whitetower.halt.issued.v1.
func action(typeName string) string {
	name := strings.TrimPrefix(typeName, "whitetower.")
	if i := strings.LastIndex(name, ".v"); i > 0 {
		name = name[:i]
	}
	return name
}
