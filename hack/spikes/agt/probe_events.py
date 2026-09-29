"""Spike S1, probe 3: AGT governance events as a source of audit evidence.

Questions:
  1. What does an AGT governance event look like as a CloudEvent, and how
     does it map to the White Tower event catalog?
  2. What happens to events when the sink is slower than the agent? White
     Tower requires that no governed action happens without evidence
     (requirement NFR-08, ADR-0005).

Run: .venv/Scripts/python probe_events.py
"""

from __future__ import annotations

import json
import time
from collections.abc import Sequence

from agent_os.event_sink import (
    GovernanceEvent,
    GovernanceEventKind,
    GovernanceEventProcessor,
    GovernanceEventSinkBase,
    SinkExportResult,
)


def sample_cloudevent() -> None:
    print("== 1. An AGT event as a CloudEvent")
    event = GovernanceEvent(
        kind=GovernanceEventKind.TOOL_CALL_BLOCKED,
        agent_id="invoice-triage",
        action="send_email",
        resource="mailto:someone@evil.test",
        decision="deny",
        reason="global-no-external-email",
        policy_name="whitetower-bundle-42",
        latency_ms=0.21,
    )
    print(json.dumps(event.to_cloudevent(), indent=2))


class SlowSink(GovernanceEventSinkBase):
    """A sink that needs 20 ms per batch, like a busy network."""

    def __init__(self) -> None:
        self.received = 0

    def emit(self, events: Sequence[GovernanceEvent]) -> SinkExportResult:
        time.sleep(0.02)
        self.received += len(events)
        return SinkExportResult.SUCCESS


def overflow() -> None:
    print("== 2. A burst of 5,000 decisions with the default queue (1,024)")
    processor = GovernanceEventProcessor(schedule_delay_ms=50)
    sink = SlowSink()
    processor.add_sink(sink)
    for i in range(5000):
        processor.on_event(GovernanceEvent(agent_id="invoice-triage", action=f"tool-{i}", decision="allow"))
    processor.force_flush(timeout_ms=30000)
    processor.shutdown()
    print(f"   submitted={processor.submitted_count} delivered={processor.delivered_count} "
          f"dropped={processor.dropped_count} (sink received {sink.received})")


if __name__ == "__main__":
    sample_cloudevent()
    overflow()
