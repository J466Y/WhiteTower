// Spike S4 (plan P0-05): what does a policy decision cost in Go?
//
// With the policy shapes of spike S1 (a global forbid plus agent permits, 1,
// 10 and 100 policies in total), it measures:
//
//  1. cedar-go in process, with the policy set parsed once per bundle;
//  2. OPA embedded, with the contract's Rego wrapper, prepared once per bundle;
//  3. a remote decision point: an AuthZEN evaluation endpoint in front of
//     cedar-go, called over HTTP on localhost with keep-alive.
//
// It also measures what activating a bundle costs: parsing or preparing the
// policies. Run from this directory: go run .
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	"github.com/open-policy-agent/opa/v1/rego"
)

var (
	iterations = flag.Int("n", 2000, "decisions per measurement")
	warmup     = flag.Int("warmup", 200, "decisions before measuring")
	wrapper    = flag.String("wrapper", "../../../api/policy/rego/decision.rego", "the contract's Rego wrapper")
)

// stats summarizes a latency distribution.
type stats struct{ p50, p99, max time.Duration }

func measure(fn func() error) (stats, error) {
	for range *warmup {
		if err := fn(); err != nil {
			return stats{}, err
		}
	}
	samples := make([]time.Duration, 0, *iterations)
	for range *iterations {
		start := ticks()
		if err := fn(); err != nil {
			return stats{}, err
		}
		samples = append(samples, elapsed(start, ticks()))
	}
	slices.Sort(samples)
	return stats{
		p50: samples[len(samples)/2],
		p99: samples[len(samples)*99/100-1],
		max: samples[len(samples)-1],
	}, nil
}

func ms(d time.Duration) string { return fmt.Sprintf("%.3f", float64(d.Microseconds())/1000) }

// cedarPolicies returns the S1 shapes: one global forbid and n-1 agent
// permits, or a single permit when n is 1, so tool_0 is always allowed.
func cedarPolicies(n int) string {
	var b strings.Builder
	if n > 1 {
		b.WriteString(`forbid (principal, action == WhiteTower::Action::"tool.invoke", resource == WhiteTower::Tool::"send_email");` + "\n")
	}
	for i := range max(n-1, 1) {
		fmt.Fprintf(&b, `permit (principal, action == WhiteTower::Action::"tool.invoke", resource == WhiteTower::Tool::"tool_%d");`+"\n", i)
	}
	return b.String()
}

// regoModules returns the same policies as Rego packages under the wrapper's
// convention.
func regoModules(n int) map[string]string {
	mods := map[string]string{}
	if n > 1 {
		mods["global.rego"] = "package whitetower.policies.global_no_external_email\nimport rego.v1\n" +
			"deny if {\n\tinput.action.name == \"tool.invoke\"\n\tinput.resource.id == \"send_email\"\n}\n"
	}
	for i := range max(n-1, 1) {
		mods[fmt.Sprintf("agent_%d.rego", i)] = fmt.Sprintf("package whitetower.policies.agent_tool_%d\nimport rego.v1\n"+
			"allow if {\n\tinput.action.name == \"tool.invoke\"\n\tinput.resource.id == \"tool_%d\"\n}\n", i, i)
	}
	return mods
}

// request is an AuthZEN evaluation request of the profile, for tool_0, which
// every set permits.
var request = map[string]any{
	"subject": map[string]any{
		"type": "agent", "id": "0192f1c2-7a3b-7c4d-8e5f-000000000001",
		"properties": map[string]any{
			"slug": "invoice-triage", "kind": "in_house", "risk_tier": "high", "environment": "production",
			"data_categories": []any{"customer data"}, "owner": "0192f1c2-7a3b-7c4d-8e5f-0000000000a1",
			"labels": map[string]any{"team": "finance"},
		},
	},
	"action":   map[string]any{"name": "tool.invoke"},
	"resource": map[string]any{"type": "tool", "id": "tool_0", "properties": map[string]any{"kind": "function"}},
	"context":  map[string]any{"time": "2026-09-29T10:00:00.000Z"},
}

// toCedar maps the request to a Cedar request and entities, as an enforcement
// point does for every decision (profile, section 6.7).
func toCedar(req map[string]any) (cedar.Request, cedar.EntityMap, error) {
	subject := req["subject"].(map[string]any)
	props := subject["properties"].(map[string]any)
	resource := req["resource"].(map[string]any)
	at, err := time.Parse(time.RFC3339Nano, req["context"].(map[string]any)["time"].(string))
	if err != nil {
		return cedar.Request{}, nil, err
	}
	var categories []types.Value
	for _, c := range props["data_categories"].([]any) {
		categories = append(categories, types.String(c.(string)))
	}
	tags := types.RecordMap{}
	for k, v := range props["labels"].(map[string]any) {
		tags[types.String(k)] = types.String(v.(string))
	}
	principal := types.NewEntityUID("WhiteTower::Agent", types.String(subject["id"].(string)))
	tool := types.NewEntityUID("WhiteTower::Tool", types.String(resource["id"].(string)))
	entities := cedar.EntityMap{
		principal: {UID: principal, Tags: types.NewRecord(tags), Attributes: types.NewRecord(types.RecordMap{
			"slug": types.String(props["slug"].(string)), "kind": types.String(props["kind"].(string)),
			"risk_tier": types.String(props["risk_tier"].(string)), "environment": types.String(props["environment"].(string)),
			"data_categories": types.NewSet(categories...), "owner": types.String(props["owner"].(string)),
		})},
		tool: {UID: tool, Attributes: types.NewRecord(types.RecordMap{
			"kind": types.String(resource["properties"].(map[string]any)["kind"].(string)),
		})},
	}
	return cedar.Request{
		Principal: principal,
		Action:    types.NewEntityUID("WhiteTower::Action", types.String(req["action"].(map[string]any)["name"].(string))),
		Resource:  tool,
		Context:   types.NewRecord(types.RecordMap{"time": types.NewDatetime(at.UTC())}),
	}, entities, nil
}

func cedarDecide(set *cedar.PolicySet, req map[string]any) (bool, error) {
	creq, entities, err := toCedar(req)
	if err != nil {
		return false, err
	}
	decision, diag := cedar.Authorize(set, entities, creq)
	if len(diag.Errors) > 0 {
		return false, nil // rule 4: any error denies
	}
	return decision == cedar.Allow, nil
}

func parseCedar(n int) (*cedar.PolicySet, error) {
	return cedar.NewPolicySetFromBytes("bundle.cedar", []byte(cedarPolicies(n)))
}

func prepareOPA(n int, wrapperText string) (rego.PreparedEvalQuery, error) {
	opts := []func(*rego.Rego){rego.Query("data.whitetower.decision.response"), rego.Module("decision.rego", wrapperText)}
	for name, text := range regoModules(n) {
		opts = append(opts, rego.Module(name, text))
	}
	return rego.New(opts...).PrepareForEval(context.Background())
}

func opaDecide(q rego.PreparedEvalQuery) (bool, error) {
	rs, err := q.Eval(context.Background(), rego.EvalInput(request))
	if err != nil {
		return false, fmt.Errorf("evaluation: %w", err)
	}
	if len(rs) != 1 || len(rs[0].Expressions) != 1 {
		return false, fmt.Errorf("unexpected results %v", rs)
	}
	resp, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return false, fmt.Errorf("unexpected result %v", rs[0].Expressions[0].Value)
	}
	allowed, _ := resp["decision"].(bool)
	return allowed, nil
}

// serveAuthZEN starts a decision point on localhost: POST
// /access/v1/evaluation, in front of cedar-go.
func serveAuthZEN(set *cedar.PolicySet) (string, func(), error) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /access/v1/evaluation", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		allowed, err := cedarDecide(set, req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"decision": allowed, "context": map[string]any{"reason": "policy.permit"}})
	})
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	return "http://" + ln.Addr().String(), func() { _ = srv.Close() }, nil
}

func remoteDecide(client *http.Client, url string, body []byte) (bool, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url+"/access/v1/evaluation", bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		Decision bool `json:"decision"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return out.Decision, nil
}

func run() error {
	flag.Parse()
	wrapperText, err := os.ReadFile(*wrapper)
	if err != nil {
		return err
	}
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 5 * time.Second}

	fmt.Printf("Decision latency in ms (p50 / p99 / max, %d decisions after %d of warm-up)\n\n", *iterations, *warmup)
	fmt.Println("| Policies | cedar-go in process | OPA embedded | AuthZEN over HTTP, localhost |")
	fmt.Println("| --- | --- | --- | --- |")
	var activation []string
	for _, n := range []int{1, 10, 100} {
		start := ticks()
		set, err := parseCedar(n)
		if err != nil {
			return err
		}
		cedarParse := elapsed(start, ticks())
		start = ticks()
		query, err := prepareOPA(n, string(wrapperText))
		if err != nil {
			return err
		}
		opaPrepare := elapsed(start, ticks())
		activation = append(activation, fmt.Sprintf("| %d | %s | %s |", n, ms(cedarParse), ms(opaPrepare)))

		check := func(allowed bool, err error) error {
			if err == nil && !allowed {
				err = fmt.Errorf("tool_0 was denied")
			}
			return err
		}
		c, err := measure(func() error { return check(cedarDecide(set, request)) })
		if err != nil {
			return fmt.Errorf("cedar-go: %w", err)
		}
		o, err := measure(func() error { return check(opaDecide(query)) })
		if err != nil {
			return fmt.Errorf("OPA: %w", err)
		}
		url, stop, err := serveAuthZEN(set)
		if err != nil {
			return err
		}
		h, err := measure(func() error { return check(remoteDecide(client, url, body)) })
		stop()
		if err != nil {
			return fmt.Errorf("AuthZEN: %w", err)
		}
		fmt.Printf("| %d | %s / %s / %s | %s / %s / %s | %s / %s / %s |\n", n,
			ms(c.p50), ms(c.p99), ms(c.max), ms(o.p50), ms(o.p99), ms(o.max), ms(h.p50), ms(h.p99), ms(h.max))
	}
	fmt.Println("\nActivating a bundle, in ms (parse or prepare once)")
	fmt.Println()
	fmt.Println("| Policies | cedar-go parse | OPA prepare |")
	fmt.Println("| --- | --- | --- |")
	for _, line := range activation {
		fmt.Println(line)
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "s4:", err)
		os.Exit(1)
	}
}
