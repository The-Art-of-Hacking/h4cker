# Capstone — Build a Foundry-Aligned Agentic Security Evaluation System

## 13.1 The capstone, in one sentence

Build a small but real **agentic security evaluation system**, aligned to the Foundry Security Spec, that takes an authorized target and produces a bounded, prioritized, verifiable set of findings — and defend it.

## 13.2 What you will deliver

By the end of the capstone, you submit four artifacts.

### A. The implementation

A repository with:

- An **Orchestrator** (LangGraph supervisor) coordinating workers.
- At least four **core roles** — Indexer, Detector, Validator, Reporter — implemented as worker subagents (Claude Agent SDK is recommended; LangGraph nodes are also fine).
- A **substrate**: SQLite-backed work queue + finding store + sandbox + budget enforcer.
- A **rule corpus** of 5–10 detection rules (CodeGuard format or your own).
- A **trace store**: JSONL per run.
- A **report directory**: markdown per confirmed finding.

You may choose to also implement Cartographer, Triager, Coverage-Guide, and/or one extension role, but the four above are the bar.

### B. The spec-of-your-spec

A `spec.md` in your repo, derived from the Foundry seed via `/speckit.clarify` and `/speckit.specify`. It must:

- Have zero `[NEEDS CLARIFICATION]` markers remaining.
- Document the Identity & Scope, Integration, Policy, and Extension decisions you made.
- Include a Clarifications log.

### C. The constitution adoption

A `constitution.md` adopted into your project (via `/speckit.constitution`). For each of the eleven principles, write a one-sentence note describing how your implementation upholds it (or where you defer it, and why).

### D. The defense package

A short `DEFENSE.md` (1–3 pages) covering:

1. **Threat model.** STRIDE + ASI Top 10 applied to your system. Highest-leverage controls.
2. **Identity and credential model.** Where do tokens live? Who can revoke them?
3. **Budgets and gates.** All four budgets, plus the yield-and-coverage stop signal.
4. **Human-in-the-loop.** Which actions are tiered to which level. Where the human sees what.
5. **Eval and red-team results.** Your golden cases, your ASI red-team battery, your remaining mitigations.
6. **What you would do next** with another two weeks.

## 13.3 Suggested timeline (one week of focused effort, or two evenings per week for three weeks)

| Day / session | Focus |
|---|---|
| 1 | Read the Foundry spec and constitution end-to-end. Make notes. |
| 2 | Run `/speckit.constitution` and `/speckit.clarify`. Resolve all markers for your environment. |
| 3 | Build the substrate (work queue, finding store, budget). |
| 4 | Build Indexer + Detector against a small authorized target. |
| 5 | Build Validator. Get the first confirmed finding end-to-end. |
| 6 | Build Reporter. Write 3 confirmed findings to disk. |
| 7 | Wire ASI Top 10 red-team. Fix what breaks. Write DEFENSE.md. |

## 13.4 Targets you can use (authorized, intentionally vulnerable)

- **OWASP Juice Shop** — Node.js, well-instrumented, lots of CWE classes.
- **DVWA (Damn Vulnerable Web Application)** — PHP.
- **WebGoat** — Java.
- **VAmPI (Vulnerable API)** — FastAPI, Python.
- Your own deliberately-vulnerable Python project (we provide a starter in `labs/lab11-detector-validator/target/`).

Do **not** use third-party software you are not authorized to evaluate. Foundry assumes "authorized eval with source access."

## 13.5 Evaluation rubric

Your capstone is evaluated on five axes, each 0–5:

- **Architectural fidelity.** Are the roles real? Do they hand off through the substrate? Are invariants in code, not in prompts?
- **Constitutional compliance.** Honest accounting against the eleven principles.
- **Trustworthiness of findings.** Every published finding has reproducible evidence.
- **Operational safety.** Identity, sandbox, budgets, HITL — all real, none decorative.
- **Defense quality.** DEFENSE.md is concrete, specific, and honest about residual risk.

20+ / 25 is excellent. 15+ is competent. Below 15, revise.

## 13.6 Stretch goals

If you finish early:

1. **Variant-Hunter extension.** Take one confirmed finding and search the codebase for the same class.
2. **Self-Improver loop.** When exploration confirms something the rules missed, generate a new rule, add it to the corpus, re-run, verify it catches the class.
3. **Coverage-Guide.** A real coverage map and a yield-gated auto-stop.
4. **Multi-target.** Run the same harness against two different stacks; compare findings; observe what carries.
5. **CodeGuard alignment.** Convert your rule corpus to formal CodeGuard format and load it into an LLM coding assistant. Validate that prevention now fires at the keystroke for the class your Detector caught.

## 13.7 Sharing your capstone

You are encouraged to share your capstone (with the authorization scope clearly documented). Tag the Foundry repo, link the constitution adoption notes, and write up the lessons learned in a short blog post. The Foundry community grows through exactly this kind of contribution.

## 13.8 A closing thought

> "The security of our global digital infrastructure is a collective effort. We invite you to explore the Foundry Security Spec on GitHub, join the conversation in our community forums, and begin building your own agentic security evaluation system. Build on it. Adapt it. Contribute to it."
> — Omar Santos, *Announcing Foundry Security Spec*

You have spent twelve modules building the literacy to do exactly that. The capstone is where you prove — to yourself and to anyone who reads your defense package — that you can wrap a frontier LLM in the discipline of a system you would defend in front of your CISO.

Good luck.

---

Previous: [Module 12](12-observability-evaluation.md) · Back to [course outline](../README.md).
