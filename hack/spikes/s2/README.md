# Spike S2: watch streams, leases and halt propagation

Throwaway code for [spike S2](../../../docs/spikes/S2-watch-streams.md) (plan P0-05). It is a separate Go module; it uses the core's real migration and the real module API (`pkg/moduleapi`) through a `replace` directive.

## What runs

`s2 run` prepares the database and starts everything else as child processes of the same binary:

| Process | Role |
| --- | --- |
| `core` × 2 | Core replicas: `Watch` and `Acknowledge` over TLS and HTTP/2, fed by PostgreSQL `LISTEN/NOTIFY`; halts and releases through the real schema, with the runtime role |
| `lb` | A layer 4 load balancer, round robin, like a Kubernetes Service |
| `eps` | The enforcement point simulator: one TLS connection per enforcement point, leases on the monotonic clock, acknowledgements, reconnection backoff, simulated network partitions |

## Running it

```sh
docker run -d --name wt-s2-pg -p 127.0.0.1:15433:5432 -e POSTGRES_PASSWORD=spike postgres:17-alpine -c max_connections=200
cd hack/spikes/s2
go build -o s2.exe .
./s2.exe run -db postgres://postgres:spike@127.0.0.1:15433/postgres -n 1000
```

`run` recreates the `whitetower` schema in that database. It prints the report and writes the raw numbers to `results.json`; each process logs to a temporary directory it names at the start. Flags select the scenarios: `-agent-halts`, `-fleet-halts`, `-partition` (0 skips), `-policies` and `-storms`.
