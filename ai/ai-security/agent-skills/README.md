# Agent Skills

An [**Agent Skill**](https://agentskills.io/home) is a self-contained, file-based package that teaches an AI agent how to do a specific job well. Think of it less as code and more as a *playbook the agent loads on demand*: when the user's request matches the skill's description, the agent reads the skill's instructions, optional reference docs, templates, and helper scripts, and uses them to produce a higher-quality, more consistent output than it could from its training data alone.

The format Anthropic introduced (and the one this repo follows) is essentially a folder containing:

- A **`SKILL.md`** file at the root, with YAML frontmatter (`name`, `description`) plus the body of instructions. The frontmatter is what the agent matches on — the `description` is the trigger.
- Optional support folders the SKILL.md can reference: `references/` (background knowledge the agent reads when needed), `templates/` (skeletons to fill in), `scripts/` (deterministic Python/Bash the agent can execute instead of "hallucinating" the same logic), and `assets/` (schemas, images, etc.).

Why this matters in practice: the agent doesn't load *all* skills into its context. It scans the descriptions, picks the relevant skill(s), and pulls in only those files. This is called **progressive disclosure** — it keeps the context window small while making large bodies of expertise available. It's also portable: the same skill folder works in Claude apps, Claude Code, the Anthropic API's Agent SDK, and any other runtime that implements the spec.

The pattern is especially powerful for security work because so much of cyber defense is *codified procedure* — detection logic, hunt hypotheses, IR runbooks, mitigation checklists — that benefits from being stored as deterministic artifacts the agent can lean on rather than improvise.

# Example: `mitre-attack-agent-skills`

In this repo at I created [`santosomar/mitre-attack-agent-skills`](https://github.com/santosomar/mitre-attack-agent-skills), I created **one Agent Skill per non-deprecated MITRE ATT&CK technique**, sourced from the official `mitre-attack/attack-stix-data` STIX bundles. The counts break down as 697 enterprise, 97 ICS, and 124 mobile techniques — **918 skills total**, organized like this:

```
mitre-attack-agent-skills/
├── enterprise/
├── mobile/
├── ics/
├── manifest.csv
├── manifest.json
└── README.md
```

Each skill folder is named with the pattern `attack-<domain>-<technique-id>-<technique-slug>` — so the skill for T1059 (Command and Scripting Interpreter) on enterprise would be something like `attack-ent-t1059-command-and-scripting-interpreter/`. Inside every skill you get a consistent structure:

- `SKILL.md` — frontmatter naming the skill and a description that includes the ATT&CK ID, technique name, domain, and defensive use cases (so the agent can match a user query like "help me hunt for PowerShell abuse" to T1059.001).
- `references/technique-profile.json` — structured technique metadata
- `references/detection-and-mitigation.md` — defensive guidance
- `references/known-threat-context.md` — threat actors and malware observed using the technique
- `templates/detection-brief.md`, `hunt-plan.md`, `incident-response-note.md`, `coverage-assessment.md` — fill-in-the-blank artifacts
- `scripts/render_brief.py` — deterministic helper for output generation
- `assets/output-schema.json` — schema the agent's output should conform to

The repo is **explicitly defensive**. It's scoped to triage, detection engineering, threat hunting, mitigation, coverage assessment, IR, and authorized validation — *not* malware development or offensive tradecraft. That scoping lives in the `SKILL.md` descriptions themselves, which is what shapes how the agent uses them.

## What this looks like in use

Imagine you're a SOC analyst and you ask a Claude-powered agent: *"We saw suspicious encoded PowerShell from a finance workstation last night. Help me write a hunt plan and a detection brief."*

The agent does roughly this:

1. Scans skill descriptions, matches `attack-ent-t1059-001-powershell` (and probably parents like T1059).
2. Loads that skill's `SKILL.md`, which tells it how to use the bundled resources.
3. Pulls in `references/known-threat-context.md` to enumerate actors known to abuse PowerShell (FIN7, APT groups, etc.) and `detection-and-mitigation.md` for the defensive playbook.
4. Fills in `templates/hunt-plan.md` and `templates/detection-brief.md` with your specific scenario, conforming to `assets/output-schema.json`.
5. Returns a structured, ATT&CK-aligned artifact you can drop into your ticket or detection-engineering pipeline.

Without the skill, the agent would still produce *something* about PowerShell hunting — but it'd be inconsistent, untethered from the canonical ATT&CK profile, and missing the standardized output shape your team expects. The skill turns "ask the LLM for advice" into "execute a vetted procedure with the LLM as the engine."

## Why this pattern is interesting for AI-for-cyber

A few things stand out about my approach that are worth stealing for your own security skills:

The **one-skill-per-technique granularity** maps cleanly to how analysts already think (in ATT&CK IDs), so retrieval is precise. Coarser skills ("help with detections") would force the LLM to do its own taxonomy work and would degrade output quality.

**Templates plus schemas equal consistency.** When 50 different analysts use the skill, they get 50 detection briefs in the same shape, which is what makes downstream automation (SIEM imports, ticketing, coverage dashboards) feasible.

**Scripts inside skills move deterministic work out of the LLM.** Rendering a brief, parsing STIX, computing coverage scores — none of that should be left to token generation. The `render_brief.py` pattern is the right instinct, and you can extend it: a skill could ship a script that queries your SIEM, runs a Sigma converter, or pulls fresh CTI before the LLM composes the final narrative.

**The defensive-only framing is intentional and load-bearing.** Skill descriptions don't just route requests — they shape what the agent will and won't help with. Putting the scope in the description means the agent self-selects out of misuse cases without the user even seeing a refusal.

If you wanted to extend this idea, natural follow-ups would be a parallel skill pack for **D3FEND** countermeasures (so the agent can pair every ATT&CK technique with a mapped defense), a pack for **Atomic Red Team** tests (for purple-team validation), or a pack mapping **CWE/CVE** to detection guidance. The repo's structure — manifest files, validation summary, per-technique folders — is a reusable scaffold for all of those.
