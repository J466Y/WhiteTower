# Spike S3: audit log throughput

Throwaway code for [spike S3](../../../docs/spikes/S3-audit-throughput.md) (plan P0-05). It is a separate Go module, run as one process against a PostgreSQL database whose `whitetower` schema it recreates from the core's real migration.

What it does, in order:

1. loads events into a past month, which the retention test drops later;
2. ingests events the way the core will: de-duplication, source sequences and a queue of unsealed events, in one transaction per batch. Meanwhile a sealer appends them to an RFC 6962 Merkle tree with `golang.org/x/mod/sumdb/tlog` and signs a C2SP checkpoint every 60 s. It runs three phases:
   - 200 events per second for 3 minutes;
   - 2,000 per second for 60 s;
   - 10,000 per second for 30 s, to find the headroom;
3. grows the log to one million events with a bulk load;
4. proves the inclusion of random events and the consistency of every checkpoint with the latest, and checks the proofs;
5. verifies the whole log from the stored events against the latest signed checkpoint, reading 10,000 leaves per query;
6. drops the past month's partitions and verifies again;
7. compares the tree with a plain hash chain.

The report's numbers come from a run inside Docker, in the database container's network namespace. On Windows, reading through Docker Desktop's port forwarding is slow enough to dominate the verification time:

```sh
docker run -d --name wt-s3-pg -p 127.0.0.1:15434:5432 -e POSTGRES_PASSWORD=spike postgres:17-alpine
cd hack/spikes/s3
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o s3-linux .
docker run --rm --network container:wt-s3-pg -v "$(git rev-parse --show-toplevel):/repo" -w /repo/hack/spikes/s3 \
  --entrypoint /repo/hack/spikes/s3/s3-linux postgres:17-alpine \
  -db postgres://postgres:spike@127.0.0.1:5432/postgres -out results-1m.json
```

It can also run directly, with `go build -o s3.exe .` and `-db postgres://postgres:spike@127.0.0.1:15434/postgres`.

It prints the report and writes the raw numbers to the `-out` file. A one-million-event run needs about 3 GB of disk. `-bulk` sets the size; the other flags set the rates, durations and batch sizes. With `-shared-sources`, every publisher sends events from any source, which is how the report's deadlock rerun was made.
