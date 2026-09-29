# Spike S1: Microsoft AGT integration

Throwaway probes for spikes S1 and S5 of plan [P0-05](../../../docs/plans/phase-0/P0-05-spikes-and-nfr-targets.md). The findings and the recommendation are in [docs/spikes/S1-agt.md](../../../docs/spikes/S1-agt.md). This code is never built into White Tower artifacts.

## Run

```sh
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt   # Windows
.venv/bin/python -m pip install -r requirements.txt       # macOS and Linux

.venv/Scripts/python probe_cedar.py    # Cedar in-process: semantics, validation, latency
.venv/Scripts/python probe_halt.py     # halting a LangGraph agent: gate, AGT kill switch, interruption
.venv/Scripts/python probe_events.py   # AGT events as CloudEvents, and what happens under load
```

Add `-W ignore::DeprecationWarning` to hide AGT's deprecation warnings.
