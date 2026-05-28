# Module 10 — Blue Team Agents: SOC Triage, IR, Threat Intel, and Detection Engineering

## 10.1 Learning objectives

- Design and build agents for the four core blue-team workflows: alert triage, incident response, threat intelligence, and detection engineering.
- Decide which workflow steps should be agent-driven vs. agent-assisted vs. fully human.
- Apply Modules 4–9 (LangGraph, Claude SDK + MCP, identity/sandbox, HITL) to real blue-team patterns.

## 10.2 The blue-team agent landscape in 2026

The headline development in 2026 is that agentic systems crossed the productivity-vs-accuracy threshold for blue-team work. Microsoft's MDASH system (more than 100 specialized agents working together across multiple models) surpassed prior single-model systems on a leading cybersecurity benchmark by finding real-world vulnerabilities. The lesson generalizes: **specialized, coordinated agents beat one big agent** for security work.

In practice, blue-team agents fall into four families:

1. **Alert-triage agents** — first-pass disposition of SIEM/EDR/email alerts.
2. **Incident-response agents** — assist responders during active incidents.
3. **Threat-intel agents** — collect, correlate, and prioritize external intel.
4. **Detection-engineering agents** — write, test, and tune detections (Sigma, KQL, SPL, EQL).

We will sketch each.

## 10.3 Alert-triage agent — the canonical workflow

This is the workflow you have already partially built in Labs 04 and 09. The end-to-end shape:

```
ingest → deduplicate → enrich → classify → decide → respond
```

The agent's tools:

- **Read.** SIEM query, asset lookup, IP/URL reputation, sandbox detonate, identity lookup, prior-tickets search.
- **Write (tiered).** Comment on ticket (Tier 1), update severity (Tier 1), assign to analyst (Tier 1), suppress (Tier 2), quarantine host (Tier 3), reset user (Tier 3).

The agent's stops:

- Per-alert budget (tokens, cost, time).
- Per-class budget (e.g., max 10 quarantines per hour).
- Confidence floor — below it, hand off to human.

The agent's typed outputs:

- `Disposition = "true_positive" | "false_positive" | "benign_positive" | "needs_human"`
- `Severity = "info" | "low" | "medium" | "high" | "critical"`
- `Rationale` — citing evidence IDs.
- `RecommendedActions: list[TieredAction]` — Tier 2/3 only as recommendations to human.

This is the workhorse. If you build one agent for your blue team, build this one well.

## 10.4 Incident-response agent — assistance, not autonomy

During an active incident the agent's role is to *accelerate the responder*, not replace them. Useful capabilities:

- **Timeline building.** Pull events from SIEM/EDR/auth logs and stitch them into a chronological view.
- **Hypothesis generation.** "Given these IOCs, what attack chains are consistent?"
- **Lateral-movement mapping.** Graph queries against asset and identity inventories.
- **Comms drafting.** First draft of internal updates, external advisories, exec briefings — always reviewed.
- **Runbook navigation.** Find and apply the playbook for the current scenario.

What an IR agent should *not* do autonomously:

- Pull a production system out of rotation.
- Reset credentials at scale.
- Communicate externally.
- Mark the incident closed.

These are Tier 3. Propose, never dispose.

## 10.5 Threat-intel agent — the RAG + graph use case

Threat intel is where vector RAG + KG (Module 6) earns its keep. The agent's job:

1. Subscribe to feeds (OSINT, vendor, internal).
2. Extract IOCs, TTPs, actor attribution, and confidence.
3. Cluster reports by overlap (same actor, same campaign, same TTP).
4. Match against the org's asset inventory and current detections.
5. Produce a prioritized intel digest with "here is what I think you should care about and why."

The agent's value compounds: every report ingested improves correlation for the next one. The corpus is the moat.

## 10.6 Detection-engineering agent — write, test, deploy detections

This is the highest-leverage agent for many teams because every new detection prevents many future incidents. A workable pattern:

1. **From an incident postmortem** or threat-intel report, propose new detection logic.
2. **Translate** to the org's detection language(s): Sigma → SPL/KQL/EQL.
3. **Backtest** against historical data; measure precision/recall against known true positives.
4. **Stage** in a non-prod environment; collect false positive rate.
5. **Propose a PR** for the detection-as-code repo; tag the on-call detection engineer.

This is exactly Foundry's flywheel applied to detections rather than to code. A confirmed-but-rule-missed incident becomes a new detection rule that catches the whole class on the next encounter.

## 10.7 Applying Foundry to blue-team work

Foundry was written for evaluation, but its eight-role anatomy maps cleanly to blue-team workflows:

- **Orchestrator** → the SOC supervisor agent.
- **Indexer** → indexes the asset/event corpus.
- **Cartographer** → produces and maintains the attack-surface map.
- **Detector** → runs detection rules (your SIEM correlations, your SOAR triggers, your model-evaluated rules).
- **Triager** → first-pass disposition.
- **Validator** → the evidence gate. *No alert escalates without evidence.*
- **Coverage-Guide** → "what alerts/sources/classes are we and aren't we processing?"
- **Reporter** → the incident writeup, the exec brief, the customer notification.

The Foundry constitution principles transfer one-for-one: findings without evidence don't exist, irreversible actions require human approval, the substrate enforces invariants, etc.

## 10.8 Hands-on Lab 10 — Build a blue-team supervisor for alert triage

[`labs/lab10-blue-team-supervisor/`](../labs/lab10-blue-team-supervisor/) integrates the prior labs into a usable blue-team pipeline:

1. **Substrate:** SQLite work queue + finding store + budget enforcer.
2. **Orchestrator (LangGraph supervisor)** with routing to four worker subagents.
3. **Workers (Claude Agent SDK + MCP):**
   - Enricher — SIEM, VT, Shodan via MCP.
   - Classifier — LLM verdict with structured output.
   - Validator — evidence gate before any Tier 2/3 action.
   - Reporter — produces the case writeup.
4. **HITL** — `interrupt_before` Tier 2/3 actions; structured approval UI (CLI).
5. **Sandboxing + budgets** as in Lab 09.
6. **Trace store** — every decision JSONL'd to disk; a small viewer prints a readable narrative.

A success criterion that matters: rerun the same 20 sample alerts twice and verify the outputs match (modulo timestamps). Determinism within budget — that's the bar.

## 10.9 Anti-patterns

- **Single super-agent.** "One agent that does everything" is hard to bound, hard to test, hard to audit. Specialize.
- **No evidence gate.** Findings without evidence are not findings.
- **Auto-quarantine on confidence.** No automated Tier 3 action without a human, except in narrowly defined "tripwire" cases.
- **Skipping coverage.** "We triaged 80% of yesterday's alerts." Which 20% did you miss, and why?
- **Trace blind spots.** If you cannot answer "what did the agent see at step 4?" you cannot defend its decisions.

## 10.10 Exercises

1. Pick one alert class from your environment. Walk through Foundry's eight roles applied to it; mark which exist today and which don't.
2. Design a Tier 2 approval interface that respects the responder's attention. What's on the screen?
3. The threat-intel agent retrieves a fresh OSINT report that contains prompt-injection text aimed at causing the agent to delete its memory. Trace the attack and your defenses.
4. Write a detection-engineering agent's "definition of done" for a new Sigma rule.

## 10.11 Further reading

- Microsoft Security Blog, *Defense at AI speed: Microsoft's new multi-model agentic security system tops leading industry benchmark* (May 2026).
- *Multi-agent architectures in cybersecurity, the new defense paradigm for enterprises*, Kireygroup.
- SANS, *AI in the SOC* white-paper series.

---

Previous: [Module 9](09-identity-trust-governance.md) · Next: [Module 11 — Red Team and Vulnerability-Discovery Agents](11-red-team-vuln-discovery.md).
