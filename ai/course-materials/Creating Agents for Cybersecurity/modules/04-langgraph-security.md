# Module 4 — LangGraph for Security Workflows: Graph, State, Supervisor

## 4.1 Learning objectives

- Explain LangGraph's graph + state + node + edge model and why it suits security workflows.
- Build a typed `State` for a SOC triage agent.
- Implement the **Supervisor pattern** as a LangGraph graph.
- Add conditional routing, retries, and a human-in-the-loop interrupt.
- Apply LangGraph's checkpointing for replayable, auditable runs.

## 4.2 Why LangGraph

LangGraph is the production-grade evolution of LangChain agents. Where classic LangChain agents are essentially one big while-loop, LangGraph models the workflow as a **directed graph** with **explicit state** flowing through it.

This buys you four things that matter for security work:

1. **Determinism where you want it.** Edges, conditions, and nodes are code you wrote. Only the *nodes themselves* are LLM-driven.
2. **Auditability.** Every state transition is observable and checkpointable.
3. **Human-in-the-loop is first-class.** You can `interrupt` a graph and resume it after human approval.
4. **The full taxonomy from Module 2 is expressible.** Supervisor, hierarchical, parallel, peer chat — all map onto LangGraph primitives.

LangGraph supports the diverse control flows from Module 2 — single agent, multi-agent, hierarchical, sequential — in one unified framework.

## 4.3 The mental model

```
        ┌──────┐  edge  ┌──────┐
state ─▶│ node │ ─────▶│ node │ ─▶ state
        └──────┘        └──────┘
            │              │
       (conditional)  (conditional)
            ▼              ▼
        ┌──────┐        ┌──────┐
        │ node │        │ END  │
        └──────┘        └──────┘
```

- **State** — a typed object (usually a `TypedDict` or Pydantic model) that flows through the graph. Every node receives state and returns a partial state update.
- **Node** — a function (often an LLM call) that takes state and returns an update.
- **Edge** — a transition. Can be unconditional or conditional (the routing function inspects state and picks the next node).
- **Checkpoint** — the state at a node boundary, persisted so the graph can be resumed or replayed.

## 4.4 A typed state for SOC triage

```python
from typing import TypedDict, Literal, Annotated
from operator import add

class TriageState(TypedDict):
    alert_id: str
    raw_alert: dict
    enrichment: dict           # outputs from enrichment tools
    severity: Literal["info", "low", "medium", "high", "critical", "unknown"]
    classification: str        # e.g. "phishing", "malware", "false_positive"
    rationale: str
    actions_taken: Annotated[list[str], add]  # appended across nodes
    needs_human: bool
    human_decision: str | None
```

A few opinions baked in:

- `severity` is a `Literal` — the LLM cannot invent new levels.
- `actions_taken` uses `Annotated[..., add]` so concurrent branches accumulate cleanly.
- `needs_human` is explicit; the human gate is a *field*, not a hope.

## 4.5 The Supervisor pattern in LangGraph

This is the most widely used architecture in production LangGraph deployments. The supervisor receives the goal, decides which specialist to call, and synthesizes results.

```python
from langgraph.graph import StateGraph, START, END

def supervisor(state: TriageState) -> dict:
    # LLM call: decide which worker should run next
    decision = router_llm(state)
    return {"next": decision}

def enricher(state):  ...
def classifier(state): ...
def responder(state):  ...

graph = StateGraph(TriageState)
graph.add_node("supervisor", supervisor)
graph.add_node("enricher", enricher)
graph.add_node("classifier", classifier)
graph.add_node("responder", responder)

graph.add_edge(START, "supervisor")
graph.add_conditional_edges(
    "supervisor",
    lambda s: s["next"],          # routing function
    {
        "enrich": "enricher",
        "classify": "classifier",
        "respond": "responder",
        "done": END,
    },
)
graph.add_edge("enricher",  "supervisor")
graph.add_edge("classifier","supervisor")
graph.add_edge("responder", "supervisor")

app = graph.compile(checkpointer=memory_saver)
```

Three things to notice:

1. The **supervisor** is the only LLM node that does routing. Workers focus on their narrow task.
2. The **routing dictionary** is code you control — the LLM picks a key, not a free-form next node.
3. The graph **compiles to an app** with a checkpointer; every run is resumable and replayable.

## 4.6 Conditional routing and the security value of typed routing

A common mistake in early LangGraph code is to let the supervisor return arbitrary text and `eval`-route on it. Don't. Use:

- A **finite set of route names** (`Literal["enrich", "classify", "respond", "done"]`).
- A **fallback** route to a human-handoff node when the supervisor's output doesn't parse.
- A **counter** on the state for max supervisor-turns to prevent loops.

These three things turn a fragile pattern into a production-acceptable one.

## 4.7 Human-in-the-loop interrupts

The single most important security feature LangGraph gives you: `interrupt_before` and `interrupt_after`.

```python
app = graph.compile(
    checkpointer=memory_saver,
    interrupt_before=["responder"],   # always pause before a write action
)
```

Pattern: the graph runs to the responder node, then halts. The checkpointed state is persisted. A human reviews. On approval, the graph resumes from the checkpoint with the human's decision merged into state.

For any agent that takes write actions in production, **interrupt-before-write is the baseline pattern**. Foundry's constitution puts this in stronger language: irreversible actions require human arbitration.

## 4.8 Checkpointing for audit and forensics

LangGraph checkpointers (`MemorySaver`, `SqliteSaver`, `PostgresSaver`, etc.) persist state at every node boundary. For security agents this delivers:

- **Replay.** Re-run any decision with the exact state it had.
- **Forensics.** "What did the agent see at step 4?" is now answerable.
- **Time-travel debugging.** Branch off any past checkpoint with a modified input.

Make checkpointing a default, not an option. Treat the checkpoint store like the SIEM — sensitive, retained per policy, access-controlled.

## 4.9 Common LangGraph patterns for security

- **Triage → Enrich → Classify → Respond** — the canonical SOC pipeline.
- **Scatter-Gather** — split an artifact across N analyzer agents in parallel, merge findings.
- **Reflexion loop** — an analyst-critic pair where the critic gates the analyst's verdict.
- **Tree-of-Thoughts for hypothesis testing** — branch on hypotheses, prune by evidence.

LangGraph supports all of these natively.

## 4.10 Hands-on Lab 04 — A LangGraph SOC triage graph

[`labs/lab04-langgraph-soc/`](../labs/lab04-langgraph-soc/) builds:

1. The `TriageState` shown above.
2. Four nodes: `supervisor`, `enricher` (calls a mock SIEM tool), `classifier` (LLM), `responder` (calls a mock ticket API).
3. `interrupt_before=["responder"]` so the human approves any ticket creation.
4. A SQLite checkpointer.
5. An adversarial-alert test case (Lab 03 ASI01 indirect injection) to verify the typed routing holds.

Bonus: visualize the graph with `app.get_graph().draw_mermaid()`.

## 4.11 LangGraph in production — costs and gotchas

Across the 2026 LangGraph-in-production reports the recurring lessons are:

- **Cost** is dominated by supervisor turns. Cap them.
- **Latency** is dominated by sequential nodes. Parallelize where state types allow.
- **State bloat** is a real failure mode. Trim or summarize between turns.
- **Token leakage** through traces is a real privacy failure. Configure your tracer (LangSmith or otherwise) with redaction.

## 4.12 Exercises

1. Add a `Reflexion` critic node to the SOC triage graph that re-asks the classifier when confidence is low. Where does the critic sit?
2. Convert the supervisor's routing function to use Pydantic for structured output. What attacks does this prevent?
3. Add a `max_supervisor_turns` counter to the state. What value would you pick for an alert-triage workflow, and why?
4. Design a Scatter-Gather subgraph for analyzing a suspicious binary with three parallel analyzers (static, dynamic, threat-intel).

## 4.13 Further reading

- LangChain, [LangGraph docs](https://langchain-ai.github.io/langgraph/) — *Multi-Agent Architectures*.
- *LangGraph Multi-Agent Orchestration — Official Guide 2026*.
- *LangGraph Agents in Production: Architecture, Costs & Real-World Outcomes* (2026).

---

Previous: [Module 3](03-threat-modeling-agents.md) · Next: [Module 5 — Claude Agent SDK and MCP](05-claude-agent-sdk-mcp.md).
