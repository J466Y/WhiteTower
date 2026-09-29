"""Spike S1 and S5, probe 2: halting a running agent in LangGraph.

What a White Tower halt must achieve (requirements KIL-01 and NFR-04):
  1. no new governed action starts once the halt arrives (the gate);
  2. the action in flight is interrupted, or the process terminated;
  3. the acknowledgement says honestly which of the two happened.

The probe runs a small LangGraph graph whose nodes are a streaming "model"
and a tool, and halts it while each kind of work is in flight:
  A. an asynchronous tool (for example an HTTP call);
  B. a synchronous, blocking tool running in a worker thread;
  C. a streaming model call.
The halt goes through AGT's KillSwitch, whose termination callback cancels
the graph's asyncio task and waits for confirmation.

Run: .venv/Scripts/python probe_halt.py
"""

from __future__ import annotations

import asyncio
import threading
import time
from typing import TypedDict

from hypervisor.security.kill_switch import KillReason, KillSwitch
from langgraph.graph import END, StateGraph


class HaltedError(PermissionError):
    """Raised by the gate: White Tower halted this agent."""


class Gate:
    """The White Tower gate, consulted before every governed action."""

    def __init__(self) -> None:
        self._halted = threading.Event()
        self.denied: list[str] = []

    def check(self, action: str) -> None:
        if self._halted.is_set():
            self.denied.append(action)
            raise HaltedError(f"{action} denied: agent halted")

    def close(self) -> None:
        self._halted.set()


class State(TypedDict):
    mode: str
    tokens: int


def build_graph(gate: Gate, tool_running: threading.Event, thread_alive: list[threading.Thread]):
    async def model(state: State) -> State:
        gate.check("model.invoke")
        tokens = 0
        if state["mode"] == "stream":
            for _ in range(600):  # 30 s of streaming, 50 ms per token
                await asyncio.sleep(0.05)
                tokens += 1
        return {"mode": state["mode"], "tokens": tokens}

    async def async_tool(state: State) -> State:
        gate.check("tool.invoke")
        tool_running.set()
        await asyncio.sleep(30)
        return state

    def blocking_tool(state: State) -> State:
        gate.check("tool.invoke")
        thread_alive.append(threading.current_thread())
        tool_running.set()
        time.sleep(30)  # blocking library code: cannot be cancelled from outside
        return state

    graph = StateGraph(State)
    graph.add_node("model", model)
    graph.add_node("async_tool", async_tool)
    graph.add_node("blocking_tool", blocking_tool)
    graph.set_entry_point("model")
    graph.add_conditional_edges(
        "model",
        lambda s: {"async": "async_tool", "blocking": "blocking_tool"}.get(s["mode"], END),
    )
    graph.add_edge("async_tool", END)
    graph.add_edge("blocking_tool", END)
    return graph.compile()


async def scenario(mode: str) -> None:
    gate = Gate()
    tool_running = threading.Event()
    worker_threads: list[threading.Thread] = []
    app = build_graph(gate, tool_running, worker_threads)
    loop = asyncio.get_running_loop()
    task = loop.create_task(app.ainvoke({"mode": mode, "tokens": 0}))
    done = threading.Event()
    task.add_done_callback(lambda _: done.set())

    # Let the work get in flight.
    await asyncio.sleep(1.0)
    if mode != "stream":
        await asyncio.to_thread(tool_running.wait, 5)

    kill_switch = KillSwitch(callback_timeout=5.0)

    def terminate() -> None:
        # Cancel the graph's task from the kill switch's thread, then wait for
        # the cancellation to complete, so "terminated" means "stopped".
        loop.call_soon_threadsafe(task.cancel)
        if not done.wait(timeout=4.5):
            raise TimeoutError("the agent did not stop within 4.5 s")

    kill_switch.register_agent("did:example:invoice-triage", terminate)

    t0 = time.perf_counter()
    gate.close()
    t_gate = time.perf_counter()
    result = await asyncio.to_thread(
        kill_switch.kill, "did:example:invoice-triage", "session-1", KillReason.MANUAL
    )
    t_kill = time.perf_counter()

    # Any new governed action after the halt must be denied.
    try:
        gate.check("tool.invoke")
    except HaltedError:
        pass

    thread_still_running = any(t.is_alive() for t in worker_threads)
    print(f"== Scenario {mode}")
    print(f"   gate closed after          {1000 * (t_gate - t0):8.3f} ms")
    print(f"   kill() returned after      {1000 * (t_kill - t0):8.1f} ms  terminated={result.terminated}")
    print(f"   graph task done            {task.done()} (cancelled={task.cancelled()})")
    print(f"   blocking thread still runs {thread_still_running}")
    print(f"   actions denied after halt  {len(gate.denied)}")
    if not task.done():
        task.cancel()


async def gate_overhead() -> None:
    gate = Gate()
    n = 1_000_000
    start = time.perf_counter()
    for _ in range(n):
        gate.check("tool.invoke")
    print(f"== Gate check overhead: {1e9 * (time.perf_counter() - start) / n:.0f} ns per check")


async def main() -> None:
    await gate_overhead()
    for mode in ("async", "blocking", "stream"):
        await scenario(mode)


if __name__ == "__main__":
    asyncio.run(main())
