# Spike S1: Microsoft AGT integration

Throwaway probes for spikes S1 and S5 of plan [P0-05](../../../docs/plans/phase-0/P0-05-spikes-and-nfr-targets.md). The findings and the recommendation are in [docs/spikes/S1-agt.md](../../../docs/spikes/S1-agt.md). This code is never built into White Tower artifacts.

## Run

With [uv](https://docs.astral.sh/uv/), which installs the versions locked in `uv.lock` into `.venv`:

```sh
uv sync
uv run probe_cedar.py    # Cedar in-process: semantics, validation, latency
uv run probe_halt.py     # halting a LangGraph agent: gate, AGT kill switch, interruption
uv run probe_events.py   # AGT events as CloudEvents, and what happens under load
```

To hide AGT's deprecation warnings, run a probe with `uv run python -W ignore::DeprecationWarning probe_cedar.py`.

## Versions

The spike ran on 2026-09-29 with LangGraph 0.6.11 and `cryptography` 49.0.0, within the limits of AGT 5.0.0: its LangGraph extra requires `langgraph<1.0`, and its core package `cryptography<50`. Those versions, and the LangGraph checkpoint and SDK packages they bring, have known vulnerabilities. On 2026-10-01 the environment moved to LangGraph 1.2.12, without the extra, which the probes do not use, and to `cryptography` 50.0.2, overriding AGT's limit in [pyproject.toml](pyproject.toml). The three probes give the same findings.
