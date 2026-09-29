# Spike S4: policy evaluation latency

Throwaway code for [spike S4](../../../docs/spikes/S4-policy-latency.md) (plan P0-05). It is a separate Go module, so the core never builds it and its dependencies stay out of the core's `go.mod`.

```sh
cd hack/spikes/s4
go run .                          # 2,000 decisions per measurement
go run . -n 10000 -warmup 1000    # as in the report
```

It reads the contract's Rego wrapper from `api/policy/rego/decision.rego`, and on Windows it times decisions with `QueryPerformanceCounter`, because Go's monotonic clock there is too coarse for single decisions.
