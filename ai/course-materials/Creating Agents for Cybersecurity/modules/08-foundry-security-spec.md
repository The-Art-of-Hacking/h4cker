# Module 8 — Inside the Cisco Foundry Security Spec: 8 Roles, 11 Principles, ~130 FRs

> "Foundry Security Spec is the scaffolding that turns a frontier LLM from 'an interesting demo against your codebase' into a security evaluation system that produces a bounded, prioritized, verifiable set of findings."
> — Omar Santos, *Announcing Foundry Security Spec*

This is the centerpiece module of the course. Everything before it has been preparation; everything after it applies the pattern.

## 8.1 Learning objectives

- Explain the **problem Foundry solves** and why a spec (not a tool) is the right form factor.
- Describe the **eight core agent roles**, what each guarantees, and how they hand off.
- Recite the **eleven inviolable principles** from the constitution and the failure mode each prevents.
- Walk the **finding lifecycle** end-to-end.
- Understand the **detection-to-prevention flywheel** Foundry creates with CodeGuard.
- Use **GitHub spec-kit** to clarify and instantiate the seed for your environment.

## 8.2 The problem

Every security team with access to a frontier LLM has done the same thing at least once: thrown a repo at the model and asked it to "find the bugs." The result is a wall of unbounded, unverifiable output that mixes sharp insights with hallucinated findings. There is no way to know what was missed or when you are actually done.

The Foundry Security Spec is the antidote: an organization-neutral specification for an **agentic security evaluation system**. It produces:

- A **bounded, prioritized, verifiable** set of findings.
- A **clear "done" signal** — the conjunction of an operator-defined coverage floor and an economic yield threshold.
- An **auditable provenance chain** from detection through triage, validation, and publication.
- **Safety guardrails** at the substrate, not the prompt.

You bring a frontier LLM and a target. Foundry gives you the architecture, the invariants, and the guardrails. You build your own implementation, on your own stack, using the specification as the blueprint.

## 8.3 Why a spec, not source code

Cisco's internal implementation is tightly bound to Cisco infrastructure: their LLM gateway, issue tracker, private cloud, severity taxonomy. Open-sourcing that code would give defenders something that runs in exactly one environment.

What transfers is the **design**: which roles you need and why, what each must guarantee, how findings flow from detection to publication, what "done" means, where the quality gates go, and which shortcuts will hurt you six months in. That design is model-agnostic and infrastructure-neutral.

This is also why Foundry is meant to be consumed with [GitHub spec-kit](https://github.com/github/spec-kit) — you run the spec through a clarification step that resolves the open questions against your environment, and out the other side comes *your* spec, for *your* implementation.

## 8.4 The architecture at a glance

```
                                  OPERATOR
                                     │
                      ┌──────────────▼──────────────┐
                      │        ORCHESTRATOR         │
                      │ lifecycle  +  conversational │
                      └──────────────┬──────────────┘
                                     │
                      ════════ SUBSTRATE ════════
                       work queue · finding store
                       sandbox · budget · dashboard
                      ════════════╤═══════════════
                                  │
  knowledge layer                 │   finding pipeline               oversight
┌───────┐┌─────────┐               │ ┌────────┐┌────────┐┌─────────┐┌────────┐┌─────────┐
│INDEXER││ CARTO-  │───────────────┘ │DETECTOR││TRIAGER ││VALIDATOR││REPORTER││COVERAGE │
│       ││ GRAPHER │                 │        ││        ││         ││        ││ GUIDE   │
└───────┘└─────────┘                 └────────┘└────────┘└─────────┘└────────┘└─────────┘

       extension roles (build after core works):
       DEEP-TESTER · VARIANT-HUNTER · ATTACK-MAPPER · REMEDIATOR · SELF-IMPROVER
```

Eight core roles, each catching the previous role's failure mode. A substrate beneath them where the invariants live.

## 8.5 The eight core roles

Each role has a defined purpose, defined inputs and outputs, and a list of functional requirements with rationale. You can implement them as subprocess loops, as graph-based pipelines, as serverless functions, or as a bespoke harness. The shape is what transfers; the implementation is yours.

### 1. Orchestrator (§5.1)

Lifecycle and conversational interface. Receives the operator's goal, dispatches work, surfaces status, halts on budget/coverage signals. The only role that talks to the human directly.

### 2. Indexer (§5.2)

Turns a target (a codebase, a binary, an API spec) into a navigable corpus the other roles can query. Builds search indices, symbol tables, dependency graphs. Without a competent Indexer, every downstream role wastes tokens re-reading the same content.

### 3. Cartographer (§5.3)

Produces the maps the rest of the system reasons against: architecture, attack-surface, trust-boundary, data-flow, and threat-model documents. Cartographer's outputs are the "ground truth" the Detector and Triager consult.

### 4. Detector (§5.4)

Sweeps the target against a corpus of LLM-evaluated detection rules. This is where **CodeGuard** plugs in. Detection is systematic and repeatable; it finds what you already knew to look for. (The exploratory hunting is a job for extension roles like Variant-Hunter.)

### 5. Triager (§5.5)

Receives raw detections and decides which are worth investigating. Applies the organization's severity rubric and weakness taxonomy. The Triager's verdict can be: discard, investigate, escalate.

### 6. Validator (§5.6)

The evidence gate. A claimed finding without evidence does not exist. The Validator's job is to confirm or refute a triaged finding through reproduction, proof construction, or counter-example. This role is the single biggest reason Foundry findings are trustable.

### 7. Coverage-Guide (§5.7)

Knows what has been examined and what has not. Produces the coverage signal that lets the Orchestrator decide when to stop or where to push the Detector next. "Done" without a coverage answer is just "stopped."

### 8. Reporter (§5.8)

Produces the human-readable writeup: title, severity, evidence, reproduction, remediation, references. Reporter consumes only validated findings.

## 8.6 The five extension roles

Build these only after the eight core roles produce trustworthy findings.

- **Deep-Tester** — runs targeted exploit attempts within scope.
- **Variant-Hunter** — generalizes a confirmed finding into a class search.
- **Attack-Mapper** — places findings on an attack graph; computes by-design vs. emergent paths.
- **Remediator** — proposes (and optionally drafts) patches.
- **Self-Improver** — closes the rule-gap loop: turns confirmed-but-rule-missed findings into new detection rules.

The official guidance — "Recommended: no to all five for your first build" — is sound. Walk before you run.

## 8.7 The eleven inviolable principles (the constitution, paraphrased)

Each constitutional principle encodes a real production failure Cisco shipped, diagnosed, and fixed. Reading the original [constitution.md](https://github.com/CiscoDevNet/foundry-security-spec/blob/main/constitution.md) is mandatory; the paraphrases below are *summaries* meant to anchor discussion.

1. **Findings without evidence do not exist.** Every claim must be backed by reproducible evidence. The Validator is the gate.
2. **The substrate, not the prompt, enforces invariants.** Atomic claim, heartbeat liveness, fingerprinting, budget — these live in code, not prose.
3. **Authority flows down; trust does not flow up.** The Orchestrator decides; worker outputs are data, not commands.
4. **A human is the final arbiter for irreversible actions.** The system can propose; the human disposes.
5. **Bounded autonomy is the only safe autonomy.** Every loop has a budget and a yield gate.
6. **Fingerprint everything that can be deduplicated.** Same finding reported twice is a tax on reviewers.
7. **Provenance is part of the finding.** Where did the claim come from, which model, which rule, which trace?
8. **The corpus compounds; the harness stays stable.** Rules and templates are *your* IP; the architecture is the spec's.
9. **Operate inside a sandbox the agent cannot define.** Sandbox boundaries are not requested by the agent — they are imposed on it.
10. **A "done" signal must be defended.** No "done" without a coverage answer and a yield answer.
11. **The system must be auditable end-to-end.** If a CISO asks "how did you produce this finding," every step has an answer.

These are inviolable not because we say so, but because in production every one of them has cost someone something. When tempted to weaken one for convenience, re-read the "why this is inviolable" paragraph in the constitution before making the change.

## 8.8 The finding lifecycle

```
detected → triaged → investigated → evidence-built → validated → reported → published
                                          │
                                          ├── deduped against existing findings (fingerprint)
                                          ├── coverage map updated
                                          └── rule-gap recorded if exploration found something the rules missed
```

A finding only exists once it has been validated. Anything earlier in the chain is an "investigation in progress." This is a *cultural* shift from typical "report everything the model said" patterns and it is why Foundry findings can be defended in front of auditors.

## 8.9 The detection-to-prevention flywheel

The reason Foundry pairs with CodeGuard:

1. **CodeGuard rules sweep** every function in the target. Systematic, repeatable, catches the known.
2. **Foundry exploratory agents hunt** alongside. Creative, target-specific, catches the unknown.
3. When exploration confirms something the rules missed, Foundry **records a rule gap**.
4. The gap is generalized into a new (or revised) CodeGuard rule, and lands in the corpus.
5. The next sweep — on this target *and every future target* — catches that whole class on the first pass.
6. Because CodeGuard rules are portable, the same corpus loads into an LLM coding assistant as secure-coding guardrails: the bug class your last evaluation taught the corpus to *detect* is now *prevented* at the keystroke, in every developer's editor, before the next evaluation runs.

> "Every turn of the loop improves detection here and prevention everywhere."

## 8.10 Using the spec with GitHub spec-kit

The Foundry spec is written to be consumed by [GitHub spec-kit](https://github.com/github/spec-kit). The intended workflow:

1. **Read `constitution.md` end-to-end.** Short. Every principle has a "why this is inviolable" paragraph.
2. **Install spec-kit** in your project (`/.specify/` directory, `/speckit.*` commands).
3. **Install the constitution.** Copy `constitution.md` to `.specify/memory/`. Run `/speckit.constitution` and adopt it.
4. **Seed the spec.** Copy `spec.md` to `specs/001-foundry/`.
5. **Clarify.** Run `/speckit.clarify`. The agent walks ~36 `[NEEDS CLARIFICATION: ...]` markers grouped into Identity & Scope, Integration Choices, Policy Choices, and Extension Scope. Recommended: say *no* to all five extension roles for the first build.
6. **Specify.** `/speckit.specify` hardens the seed into a complete spec for your environment.
7. **Iterate clarify + specify** until they converge.
8. **Plan, task, implement.** `/speckit.plan`, `/speckit.tasks`, `/speckit.implement`.

The point of this workflow is that **a `[NEEDS CLARIFICATION]` that survives into the plan becomes a guess baked into your design**.

## 8.11 Hands-on Lab 08 — Map Foundry's 8 roles to a runnable scaffold

[`labs/lab08-foundry-scaffold/`](../labs/lab08-foundry-scaffold/):

1. Clone `https://github.com/CiscoDevNet/foundry-security-spec`.
2. Read `constitution.md` and write a one-paragraph summary of each principle in your own words.
3. Build a minimal Python scaffold with eight stub roles: each is a class with a `purpose` docstring, an `inputs` schema, an `outputs` schema, and a `run()` stub.
4. Use the LangGraph supervisor pattern from Lab 04 as the Orchestrator.
5. Implement just enough of Indexer + Detector + Validator + Reporter to process a single canned finding end-to-end.
6. Verify against the constitution: write a short checklist confirming each principle the scaffold honors and each it does not yet.

This is not a production harness. It is a thinking tool that makes the spec concrete in code.

## 8.12 Exercises

1. Re-read the constitution and pick one principle you find most counter-intuitive. Defend or critique it with a real or hypothetical scenario.
2. For your environment, draft the four open-question groups (Identity & Scope, Integration Choices, Policy Choices, Extension Scope) with at least one concrete answer each.
3. Sketch how a Foundry-style coverage gate would change "definition of done" for your most recent pentest.
4. Where in your current security workflow would a *Validator* role have caught a false positive?

## 8.13 Further reading (mandatory)

- Omar Santos, [*Announcing Foundry Security Spec*](https://blogs.cisco.com/ai/announcing-foundry-security-spec) — the announcement and the philosophy.
- [`CiscoDevNet/foundry-security-spec`](https://github.com/CiscoDevNet/foundry-security-spec) — the spec, constitution, and glossary.
- [Project CodeGuard](https://project-codeguard.org/) and its donation to CoSAI.
- [GitHub spec-kit](https://github.com/github/spec-kit).

---

Previous: [Module 7](07-crewai-autogen.md) · Next: [Module 9 — Identity, Trust, and Governance](09-identity-trust-governance.md).
