# Module 12 — Observability, Evaluation, and Continuous Red-Teaming of Agents

## 12.1 Learning objectives

- Instrument agents with traces, metrics, and structured evaluation.
- Build a small eval harness that runs offline test cases against your agent on every change.
- Run continuous red-teaming (DeepTeam / Promptfoo / PyRIT) against your agent and feed findings back into the corpus.
- Map your evaluation results to OWASP Top 10 for LLMs / ASI Top 10, NIST AI RMF, and the EU AI Act.

## 12.2 Why this module exists

Operational metrics, continuous evaluation, scheduled evaluation, scheduled red teaming, and alerting are what separate a demo from a defensible production system. Without them, the agent is a black box that *seems* to work. With them, the agent is a system you can change, debug, and prove.

## 12.3 The three layers — traces, metrics, evals

A useful mental model:

```
              ┌──────────────────────────────┐
EVALS         │ offline + scheduled tests    │   "Is the agent right?"
              └──────────────────────────────┘
              ┌──────────────────────────────┐
METRICS       │ aggregate counts and rates   │   "Is the agent healthy?"
              └──────────────────────────────┘
              ┌──────────────────────────────┐
TRACES        │ per-run structured records   │   "What did the agent do?"
              └──────────────────────────────┘
```

You need all three. Traces are forensic. Metrics are operational. Evals are scientific.

## 12.4 Traces — what to record

Per agent run, record:

- **Identifiers** — `run_id`, `parent_run_id`, `agent_id`, `user_id`, `case_id`, `start_ts`, `end_ts`.
- **Inputs** — system prompt (hash and version), user input (with PII handling per policy).
- **Each step** — index, thought (if any), tool name, tool args, tool result, duration, token usage, cost.
- **Outputs** — final answer, structured output, decisions taken.
- **Substrate signals** — budget consumed, approvals requested/granted, errors.
- **Provenance** — model id, prompt version, rule corpus version, tool versions.

A common format is OpenTelemetry-compatible JSONL. LangSmith, Arize Phoenix, Datadog, Logfire — all viable. The important thing is that **every record carries enough provenance to be replayed and audited**.

Redact aggressively. Traces are sensitive systems.

## 12.5 Metrics — what to count

Health metrics worth dashboarding:

- Runs per hour, by agent, by outcome.
- p50/p95 latency, by agent, by node.
- Cost per run (tokens × price).
- Tool-call counts, by tool, by outcome (success/denied/timeout).
- Approval queue depth and approval latency.
- Budget-hit rate (runs that exhausted token / cost / wall-clock budgets).
- Validator confirmed/refuted/inconclusive split (for evaluation-style agents).
- Error rates by class.

Pair every dashboard with an alert. The alert defines what "broken" means.

## 12.6 Evals — proving the agent is right

A test suite for an agent has the same role as a test suite for code. Build it.

A useful structure:

- **Golden cases** — known-correct outcomes. Run on every change.
- **Adversarial cases** — prompt-injection, goal hijack, jailbreak. Run on every change.
- **Regression cases** — every production failure becomes a test that prevents its recurrence.
- **Distribution cases** — sample real production inputs (privacy-respecting) and check the agent against them.

For each case, define the *judgement*: exact match for structured outputs, LLM-as-judge for prose (with care), tool-call sequence equality, etc. LLM-as-judge needs its own evaluation set; trust but verify.

## 12.7 Continuous red-teaming

Promptfoo, DeepTeam, PyRIT, and Microsoft's AI Red Teaming Agent ship with broad vulnerability corpora — OWASP Top 10 for LLMs, ASI Top 10, MITRE ATLAS — and run them on a schedule. By 2026 the modern engines ship with 50+ vulnerabilities and 20+ attack vectors covering single-turn and multi-turn attacks, with CVSS severity scoring and reports mapped to OWASP, NIST AI RMF, and the EU AI Act.

A minimum-viable continuous red-team setup:

1. **Nightly run** of the ASI Top 10 corpus against your staging agent.
2. **Per-PR run** of a fast subset of the corpus.
3. **Triage workflow** — failures route to the agent owner.
4. **Regression intake** — every new finding becomes a test in the eval suite.

This is the exact same Foundry detection-to-prevention flywheel from Module 8, applied to your own agent's prompt and tool surface.

## 12.8 Mapping to frameworks

Map your eval results to recognized frameworks so stakeholders can read them:

- **OWASP Top 10 for LLMs** / **ASI Top 10** for agentic risks.
- **NIST AI Risk Management Framework** for governance posture.
- **EU AI Act** Articles relevant to high-risk systems (where applicable).
- **MITRE ATLAS** for adversarial ML risk.

Most modern eval platforms produce these mappings automatically. Use them in your security review and your customer trust documentation.

## 12.9 Reproducibility and time-travel

Two operational practices that pay off:

- **Pin prompts and tools to versions.** A change to the system prompt is a code change.
- **Snapshot the agent**. Model id, prompt version, tool versions, rule corpus version. Tag every run with the snapshot id.

Now any past run is replayable. "Why did the agent file this ticket six months ago?" becomes answerable.

## 12.10 Hands-on Lab 12 — Promptfoo + DeepTeam red-teaming

[`labs/lab12-promptfoo-deepteam/`](../labs/lab12-promptfoo-deepteam/):

1. Set up Promptfoo with a small custom eval set (golden cases for the SOC triage agent from Lab 10).
2. Add a DeepTeam-style ASI Top 10 red-team battery.
3. Wire it into a `make eval` target.
4. Pick one failing case; fix it (either by hardening the prompt, tightening the tool scope, or rejecting the action at the substrate); rerun until green.
5. Add that case to the regression suite.
6. Run the same suite against a deliberately weakened version of your agent (e.g., removed the validator) and observe which attacks now succeed.

## 12.11 Production rollout checklist

When you are about to put a security agent into production, run this checklist:

- [ ] Identity is distinct and revokable.
- [ ] Credentials live in a gateway, not in the agent process.
- [ ] Sandbox is enforced at process, filesystem, and network layers.
- [ ] All four budgets are set (tokens, cost, wall-clock, write actions).
- [ ] Every write tool is tiered for approval.
- [ ] Traces capture provenance and are retained per policy.
- [ ] Evals are wired to CI and to a nightly schedule.
- [ ] ASI Top 10 red-team battery is green or every red has a documented mitigation.
- [ ] An owner is named.
- [ ] A kill switch exists and has been tested.
- [ ] Every finding the agent has produced in pre-prod can be reproduced from its trace.

If any item is no, ask whether you are deploying a system or a hope.

## 12.12 Exercises

1. Sketch the schema of your trace store. What fields are queryable? Which are encrypted at rest?
2. Pick three ASI items and write one regression test each for the SOC triage agent.
3. Design the "approval queue depth" alert: what threshold, what action?
4. Your nightly red-team failed on ASI04 (memory poisoning). Walk through your investigation.

## 12.13 Further reading

- Microsoft Azure Blog, *Agent Factory: Top 5 agent observability best practices for reliable AI* (2026).
- Confident AI, *Top 6 AI Testing Platforms for All-in-One Evals, Observability, and Red Teaming in 2026*.
- Microsoft Foundry, *Observability in Generative AI*.
- OWASP Gen AI Red Teaming Guide.
- NIST AI RMF (current revision).

---

Previous: [Module 11](11-red-team-vuln-discovery.md) · Next: [Capstone](13-capstone.md).
