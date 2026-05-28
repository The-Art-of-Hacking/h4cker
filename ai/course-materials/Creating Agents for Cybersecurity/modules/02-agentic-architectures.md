# Module 2 — Agentic Architectures: Single-Agent, Planner-Executor, Multi-Agent, and the Agentic Mesh

## 2.1 Learning objectives

- Compare the major agent architecture patterns: single-agent, planner-executor, supervisor, hierarchical, peer multi-agent, and agentic mesh.
- Pick the right pattern for a given security workflow.
- Understand the security implications of each pattern (especially the **trust boundary between planner and executor**, where the PEAR benchmark and many real attacks live).
- Recognize where the Foundry Security Spec sits in this taxonomy.

## 2.2 The taxonomy

| Pattern | Topology | Best for | Main risk |
|---|---|---|---|
| Single-agent | One LLM + tools + loop | Narrow, well-scoped tasks | Step explosion; one bad turn corrupts everything |
| Planner-Executor | Planner LLM emits a plan; Executor LLM runs each step | Tasks where planning and acting need different prompts or models | Compromise of the planner–executor channel (prompt injection through plan text) |
| Supervisor (orchestrator-worker) | One supervisor routes work to specialized workers | Heterogeneous workflows: triage + analysis + remediation | Supervisor becomes a single point of compromise; worker outputs can poison the supervisor's context |
| Hierarchical | Supervisors of supervisors | Large, layered domains (e.g., enterprise SOC) | Authorization at each layer; deep call chains hide intent |
| Peer multi-agent | Agents converse to consensus | Brainstorm/critique workflows | Echo chambers; goal drift through conversational drift |
| Agentic mesh | Loosely coupled agents discovering each other across systems | Cross-team, cross-product autonomy | Trust transitivity; identity at the agent level |

Most production security systems in 2026 are **supervisor or hierarchical**, with peer-conversation patterns sprinkled in for analysis and ideation.

## 2.3 Single-agent

The simplest pattern. One LLM, a toolbelt, and the loop from Module 1.

```python
while not done and steps < MAX_STEPS:
    action = llm.decide(state, tools)
    obs    = tools.run(action)
    state  = state.update(obs)
```

**Use when** the task is narrow (one CVE to enrich, one alert to triage), the toolbelt is small (≤ ~8 tools), and the stopping condition is clear.

**Security implications.** Easiest to reason about. The full attack surface is the prompt + the toolbelt. The main failure modes are step explosion and goal drift mid-loop. Add a step budget and a "yield" condition.

## 2.4 Planner-Executor

A planner LLM produces a structured plan; an executor LLM (or deterministic runner) walks it. The two stages often run with different system prompts, different temperatures, sometimes different models.

```
       ┌──────────┐    plan    ┌──────────┐
goal ─▶│ PLANNER  │ ─────────▶ │ EXECUTOR │ ─▶ result
       └──────────┘            └──────────┘
                  ▲                  │
                  │     re-plan?     │
                  └──────────────────┘
```

The PEAR benchmark from 2026 specifically attacks this architecture. The plan is text — and text crossing from planner to executor is **untrusted data on its way to becoming instructions**. If an attacker can taint the plan (via retrieved documents, prior tool output, or social engineering of the planner), the executor will faithfully execute the attack.

**Mitigations:**
- Constrain the plan to a typed schema (no free-form fields the executor will obey as text).
- The executor only treats *fields it was designed to handle* as instructions; everything else is data.
- Add a critic between planner and executor that fact-checks the plan against scope.

## 2.5 Supervisor (orchestrator-worker)

The single most common production pattern in LangGraph deployments in 2026.

```
         ┌─────────────┐
user ──▶│ SUPERVISOR  │── routes ───┐
         └─────────────┘             │
              ▲                       ▼
              │              ┌──────┬──────┬──────┐
              │              │  W1  │  W2  │  W3  │
              │              └──────┴──────┴──────┘
              └─── results ──────────┘
```

The supervisor receives the user goal, decomposes it, dispatches to specialized worker agents, then synthesizes their outputs. Workers can be specialists (CVE-lookup agent, IR-comms agent, code-review agent).

**Why security teams love this:** specialists can be hardened independently and given narrow tool scopes. A "ticket-filer" agent only ever sees the ticket API; it does not need (or get) the SIEM key.

**The Foundry Orchestrator** ([spec §5.1](https://github.com/CiscoDevNet/foundry-security-spec/blob/main/spec.md)) is a supervisor in this taxonomy, with the substrate (work queue + finding store + budget) sitting beneath it.

## 2.6 Hierarchical

A supervisor of supervisors. A "SOC supervisor" might delegate to a "phishing supervisor" who delegates to extraction, sandbox, and notification workers.

Use sparingly. Each layer adds latency, cost, and a place for goal drift to creep in. Foundry's design pushes back on premature hierarchy: the eight core roles are flat, and the substrate (not another agent) coordinates them.

## 2.7 Peer multi-agent (group chat / debate)

Multiple agents converse until they converge. This is AutoGen's native idiom.

```
agentA ⇄ agentB ⇄ agentC
```

Useful for: synthesis tasks, red-team vs. blue-team debate, plan critique. Risky for: anything with strict scope. Conversational drift is real, and "stop conditions" in pure chat patterns are notoriously fragile.

## 2.8 The agentic mesh

A 2026 trend: agents in different products and teams discover and call each other. Anthropic's 2026 *Agentic Coding Trends Report* and the broader literature describe this as the next phase after multi-agent.

**Security challenge.** Trust transitivity. Agent A in team 1 trusts agent B in team 2. Agent B is compromised. Now agent A is too. Treat mesh interactions like a federated identity problem — every cross-boundary call needs its own identity, scope, and audit. We will look at this in Module 9.

## 2.9 Choosing the right architecture for a security workflow

A practical decision tree:

```
Is the task narrow and the toolbelt small (≤8 tools)?
  └── YES → single-agent.
  └── NO ↓
Do planning and acting need very different reasoning?
  └── YES → planner-executor (with a typed plan schema).
  └── NO ↓
Are there clear specialists (each with a narrow toolbelt)?
  └── YES → supervisor / orchestrator-worker.
  └── NO ↓
Is the workflow inherently exploratory or argumentative?
  └── YES → peer multi-agent (with a hard message budget).
```

When in doubt, prefer fewer agents. Every agent boundary is a new attack surface.

## 2.10 Where Foundry Security Spec sits

Foundry is best understood as a **supervisor architecture with a coordination substrate**. The spec defines:

- One **Orchestrator** (supervisor).
- A **substrate**: work queue, finding store, sandbox, budget, dashboard.
- Seven specialized worker roles around the orchestrator (Indexer, Cartographer, Detector, Triager, Validator, Coverage-Guide, Reporter).
- Five optional extension roles (Deep-Tester, Variant-Hunter, Attack-Mapper, Remediator, Self-Improver).

Why a substrate and not a chatty bus? Because the substrate is where the **invariants** live: atomic claim, heartbeat liveness, finding fingerprinting, budget enforcement. Putting the invariants in code (the substrate) rather than in prompts (chat) is one of the spec's most important design choices.

## 2.11 Hands-on Lab 02 — Planner-Executor for log triage

In [`labs/lab02-planner-executor/`](../labs/lab02-planner-executor/) you will:

1. Implement a typed `Plan` schema (Pydantic).
2. Build a Planner agent that emits `Plan` objects.
3. Build an Executor that consumes `Plan` and runs each typed step.
4. Inject an adversarial log line containing prompt-injection text and confirm the typed schema neutralizes it.

## 2.12 Exercises

1. For each of the following security workflows, pick an architecture and defend the choice:
   - Daily phishing-email triage.
   - Quarterly internal pentest of a microservice.
   - Continuous deception (honey-token) monitoring.
   - Cross-team incident response.
2. Sketch a "minimum viable supervisor" for an alert-triage system: one supervisor, three workers. What is each worker's toolbelt?
3. Identify a place in the planner-executor architecture where indirect prompt injection could land. How do you defend it?

## 2.13 Further reading

- LangChain, *Multi-Agent Architectures* (LangGraph docs).
- Anthropic, *Building Effective Agents* (2024–2026 updates).
- Cisco Foundry Security Spec, [§4 System Overview](https://github.com/CiscoDevNet/foundry-security-spec/blob/main/spec.md).
- PEAR benchmark paper (planner-executor security).

---

Previous: [Module 1](01-ai-agents-101.md) · Next: [Module 3 — Threat Modeling Agents](03-threat-modeling-agents.md).
