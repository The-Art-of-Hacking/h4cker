# Module 1 — AI Agents 101: Loops, Tools, Memory, and Why Security Cares

> "A full agentic system is the antidote to chaos: it wraps the model in orchestration, roles, and guardrails so that detection, validation, and coverage are designed up front instead of improvised in a chat window."
> — Omar Santos, *Announcing Foundry Security Spec*

## 1.1 Learning objectives

By the end of this module you will be able to:

- Define an **AI agent** precisely (vs. a chat assistant, a RAG pipeline, or a script).
- Trace the **agent loop** end-to-end: perceive → reason → act → observe.
- Explain the role of **tools**, **memory**, and **planning** in an agent.
- Recognize the three things that make agents a different security problem than plain LLMs: **autonomy**, **tool reach**, and **state**.
- Run a minimal ReAct-style security agent in Lab 01.

## 1.2 What is an AI agent?

A working definition for this course:

> An **AI agent** is a system in which an LLM is given a goal, a set of tools, a memory, and the autonomy to decide what action to take next — repeating that loop until the goal is satisfied or a stop condition is reached.

The important words are *goal*, *tools*, *autonomy*, and *loop*.

A few clarifying contrasts:

- A **chatbot** answers one prompt at a time with no tools or persistent intent. Not an agent.
- A **RAG pipeline** retrieves context then generates. Useful, but linear — no loop, no autonomous tool selection. Not an agent.
- A **scripted workflow** that calls an LLM as one step is **agentic only if** the LLM decides what step to run next. If the script decides, the LLM is just a function call.

In 2026, the boundary between "AI feature" and "AI agent" is whether the LLM is choosing the next action.

## 1.3 The agent loop

Almost every modern agent — from Claude Code to a CrewAI crew to a LangGraph state machine — implements some variant of:

```
   ┌──────────────┐
   │     GOAL     │
   └──────┬───────┘
          │
          ▼
   ┌──────────────┐      ┌────────────────┐
   │   PERCEIVE   │◀────┤    MEMORY      │
   │ (read state) │      │ (short + long) │
   └──────┬───────┘      └────────────────┘
          │
          ▼
   ┌──────────────┐
   │    REASON    │   ← LLM plans next action
   └──────┬───────┘
          │
          ▼
   ┌──────────────┐      ┌────────────────┐
   │     ACT      │────▶│      TOOLS     │
   │ (tool call)  │      │ (APIs, code)   │
   └──────┬───────┘      └────────────────┘
          │
          ▼
   ┌──────────────┐
   │   OBSERVE    │
   │ (tool result)│
   └──────┬───────┘
          │
          ▼
       (loop)
```

The earliest documented version of this in modern LLM practice is **ReAct** (Reasoning + Acting), in which the model interleaves explicit "Thought:" steps with "Action:" calls. Modern agents do this less verbosely and more reliably, but the shape is the same.

## 1.4 Tools: the agent's hands

A **tool** is any function the agent can invoke. For security agents tools typically fall into a few buckets:

- **Read tools** — `query_siem(query)`, `fetch_cve(cve_id)`, `read_file(path)`.
- **Write tools** — `create_ticket(...)`, `quarantine_host(...)`, `open_pr(...)`.
- **Compute tools** — sandboxed shell, sandboxed Python, code interpreter.
- **Communication tools** — Slack, email, PagerDuty.
- **Meta-tools** — `spawn_subagent(...)`, `ask_human(...)`.

Tools transform an LLM from a text predictor into something that *takes actions in the world*. That single property is what creates the security problem.

### Tool security checklist (preview of Module 3)

- Does the tool *read* sensitive data? Treat its output as untrusted (it may contain indirect prompt injection).
- Does the tool *write* anywhere? It needs least-privilege scope, an audit log, and a budget.
- Does the tool execute *code*? It needs a sandbox boundary the agent cannot escape.

## 1.5 Memory

Real agents have at least three "memory" surfaces:

1. **Conversation context** — the rolling messages window.
2. **Short-term working state** — variables, scratchpads, intermediate findings.
3. **Long-term memory** — vector stores, knowledge graphs, files persisted across runs.

Each is also an attack surface. Anything that lands in memory can be replayed into a future prompt; an attacker who controls a single document in a vector store can influence every future query that retrieves it. We will return to this in Module 6.

## 1.6 Planning, reflection, and self-correction

Beyond the basic loop, modern agents typically add:

- **Planning** — produce a multi-step plan up front before acting. (See Plan-and-Execute, Tree-of-Thoughts.)
- **Reflection** — after acting, critique the action and decide whether to retry. (See Reflexion.)
- **Self-correction** — re-invoke a tool with corrected inputs when the previous attempt fails.

These add reliability but also add **autonomy budget** — more loop iterations means more chances for the agent to drift off course. Foundry's constitution explicitly addresses this with budget gates and yield-thresholds.

## 1.7 Why security cares about agents (the short version)

Three properties make agents a meaningfully different security problem than LLMs alone:

1. **Autonomy.** The agent decides what to do next. A successful attack on the *decision* (prompt injection, goal hijack) cascades into all the actions that follow.
2. **Tool reach.** Tools are real-world side effects. A compromised agent does not just produce bad text — it ships PRs, files tickets, quarantines hosts, or pages people.
3. **State.** Memory and intermediate findings persist. A poisoned memory entry can shape future runs.

The cybersecurity industry recognized this in 2026 with the publication of the **OWASP Top 10 for Agentic Applications (ASI)**, which we'll work through in Module 3. The headline new vulnerability — **Agent Goal Hijack (ASI01)** — explicitly merges prompt injection and excessive autonomy because, in agents, you cannot meaningfully separate them.

## 1.8 Hands-on Lab 01 — Minimal ReAct security agent

Goal: build a 50-line Python agent that uses a single tool (`whois_lookup`) and a single LLM call per iteration, with a hard step limit.

See [`labs/lab01-hello-agent/`](../labs/lab01-hello-agent/). The lab walks through:

1. Defining the tool schema.
2. Implementing the agent loop in plain Python.
3. Adding a step budget (`MAX_STEPS = 6`).
4. Logging every (thought, action, observation) tuple to a JSONL trace file.
5. Reflecting on the trace: what would you need to add before you trusted this agent to take *write* actions?

## 1.9 Exercises

1. Take any product description that claims "AI agent" and check it against the working definition in 1.2. How many actually qualify?
2. List five tools you would give a Tier-1 SOC analyst agent. For each, mark read / write / compute and the *minimum* permission needed.
3. Describe a scenario where short-term memory becomes an attack surface.
4. Why is a step budget a security control as well as a cost control?

## 1.10 Further reading

- Yao et al., *ReAct: Synergizing Reasoning and Acting in Language Models* (2022).
- Anthropic, *Building effective agents* — design patterns and when not to use them.
- LangChain, *Agent Architectures* — overview of the major patterns we use later.
- Omar Santos, *Announcing Foundry Security Spec*, Cisco Blogs (2026).

---

Next: [Module 2 — Agentic Architectures](02-agentic-architectures.md).
