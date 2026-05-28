# Agent Threat Model Template

Use this template for Lab 03 and for any production agent design review. Keep it short — a STRIDE + ASI table that fits on one screen is more useful than a 40-page document no one reads.

## 1. System summary

- **System name:**
- **Owner:**
- **Purpose:** one sentence.
- **Architecture pattern:** single / planner-executor / supervisor / hierarchical / multi-agent / mesh.
- **Model(s):**
- **Tools (toolbelt):** read tools | write tools | compute tools.
- **External integrations:** SIEM, ticket system, threat-intel feeds, code repos, etc.
- **Identity model:** agent identity, credential location, scopes.
- **Human-in-the-loop tier policy:** Tier 0/1/2/3 mapping.

## 2. Data-flow diagram

Sketch (mermaid, ASCII, or attached image). Show:

- Trust boundaries.
- Where untrusted data enters (user input, retrieved content, tool output).
- Where credentials live.
- Where the sandbox boundary is.

## 3. STRIDE × ASI matrix

For each cell that is in-scope, fill at least: threat description, attack scenario, current control, residual risk (L/M/H), and owner.

| Threat (STRIDE) | Agent surface | Example attack | Control(s) | Residual risk |
|---|---|---|---|---|
| Spoofing | Subagent identity | Impostor "validator" approves a finding | Distinct agent identity per role; substrate-enforced caller verification | L / M / H |
| Tampering | Plan text between planner and executor | Indirect injection in retrieved doc taints plan | Typed plan schema; critic between planner and executor | |
| Repudiation | Trace store | No record of which run filed a ticket | Per-run trace ID propagated to every tool call | |
| Information disclosure | Tool output / logs | API key leaks into a redacted-but-logged trace | Redaction policy at trace sink; secret scanning on traces | |
| Denial of service | Loop / cost | Adversarial input drives 1000 tool calls | Token / cost / wall-clock / action budgets | |
| Elevation of privilege | Tool reach | Read-only agent acquires write tool via handoff | Per-role allow-list; substrate-enforced toolbelt | |

## 4. ASI Top 10 quick mapping

| ASI item | In-scope? | Highest-leverage control | Residual risk |
|---|---|---|---|
| ASI01 Goal Hijack | Y/N | | |
| ASI02 Tool Misuse / Excess Perms | | | |
| ASI03 Identity Spoofing | | | |
| ASI04 Memory Poisoning | | | |
| ASI05 Cascading Hallucinations | | | |
| ASI06 Sandbox Escape | | | |
| ASI07 Supply Chain (tools/MCP) | | | |
| ASI08 Sensitive Info Disclosure | | | |
| ASI09 Insecure Output Handling | | | |
| ASI10 Inadequate Observability | | | |

## 5. Top 5 controls (in priority order)

1. ___
2. ___
3. ___
4. ___
5. ___

For each, document: what it is, where it lives (prompt / code / substrate / human), how it is tested, who owns it.

## 6. What we are accepting

A short paragraph naming the residual risks you are accepting, why, and the date you will revisit.

## 7. Sign-off

| Role | Name | Date |
|---|---|---|
| Author | | |
| Reviewer | | |
| Approver | | |
