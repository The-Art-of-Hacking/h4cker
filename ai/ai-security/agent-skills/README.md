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

Got it — updating to reflect that.

# Another Example: Project CodeGuard

Another good example to look at is [Project CodeGuard](https://project-codeguard.org/) (`cosai-oasis/project-codeguard`). Full disclosure — I started CodeGuard at Cisco and I'm one of the core maintainers, so this is a project I know intimately. I think it's a useful counterpoint to my MITRE ATT&CK skill pack because it shows a **different shape of Agent Skill** solving a different problem, but built on the same underlying pattern.

Where my MITRE repo is a **library of many narrow skills** (one per ATT&CK technique, retrieved on demand based on what the analyst is asking about), CodeGuard is **a single broad skill** (`software-security`) that's always in the activation pool whenever code is being written or reviewed. Both are valid Agent Skill designs, and looking at them side-by-side is a good way to understand the design space.

## What it is

We started CodeGuard inside Cisco's AI-enabled Security Engineering, Security & Trust team, and then contributed it as an open project under **CoSAI** (the Coalition for Secure AI, an OASIS Open Project) so the broader community could shape it. The goal is narrow and important: **stop AI coding agents from generating insecure code by default.** AI assistants will cheerfully produce code that hardcodes secrets, concatenates SQL, picks MD5 for hashing, skips input validation, or disables certificate checks — not because the model "wants" to, but because nothing in the prompt context tells it otherwise.

We address that by shipping a corpus of **model-agnostic security rules** authored in unified Markdown, plus translators that convert them into the native rule/skill formats of every major AI coding tool — Claude Code, Cursor, Windsurf, GitHub Copilot, Google Antigravity, OpenAI Codex, OpenCode, and others. The same security knowledge, written once, ends up steering whichever agent the developer happens to be using. That portability was a deliberate design call — we didn't want to bet the project on one vendor's skill format, and a developer's choice of IDE shouldn't determine whether their AI assistant follows secure-by-default practices.

## How it's packaged as an Agent Skill

The Claude Code distribution of CodeGuard is packaged exactly as an Agent Skill, and we explicitly define the term in our docs: *"Agent Skills are model-invoked capabilities that Claude autonomously uses based on task context."* That's the same model I described in the MITRE example — the agent matches a request to a skill description, then loads the skill's instructions and supporting files only when relevant.

The plugin layout looks like this:

```
project-codeguard/
├── .claude-plugin/
│   ├── plugin.json
│   └── marketplace.json
├── sources/                     # Authored inputs
│   ├── rules/core/              # Core security rules (Markdown)
│   ├── rules/owasp/             # OWASP supplementary rules
│   └── skills/                  # Authored skill definitions
├── skills/                      # Generated Claude Code skill
│   └── software-security/
│       ├── SKILL.md             # The skill entry point
│       └── rules/               # 23 rule files Claude references
└── src/
    └── convert_to_ide_formats.py  # Translator to other agent formats
```

The `SKILL.md` for `software-security` does what every well-designed skill does: it tells Claude **when to activate** (any time code is being written, reviewed, or modified — especially when credentials, crypto, input handling, auth, APIs, cloud config, or sensitive data are involved) and **what workflow to follow** once it's active. We landed on a clean three-step pattern:

1. **Initial security check** — figure out which rules apply (language, security domains involved, whether credentials are in scope).
2. **Code generation** — apply the secure-by-default patterns from those rules and add comments explaining the security choices.
3. **Security review** — run the implementation checklists from each rule, verify no hardcoded secrets, and surface to the developer which rules were applied.

## How the rules are organized

This is where some of the design choices we made get interesting. The 22 rules split into two tiers:

**Always-apply rules (3)** — checked on *every* code operation, regardless of language or context:
- `codeguard-1-hardcoded-credentials` — no secrets, API keys, or tokens in source
- `codeguard-1-crypto-algorithms` — ban MD5/SHA-1/DES, require modern algorithms
- `codeguard-1-digital-certificates` — validate expiration, key strength, signature algorithms

**Context-specific rules (19)** — pulled in only when relevant: input validation and injection, authentication/MFA, authorization and access control, session management, API and web service security, client-side web security, data storage, privacy and data protection, logging, additional cryptography, file handling and uploads, XML and serialization, supply chain, DevOps/CI-CD/containers, cloud and Kubernetes, IaC, frameworks and languages, mobile apps, and safe C functions for memory safety.

That two-tier split was a deliberate choice — and it took a couple of iterations to get right. In v1.0.0 we had four always-apply rules; in v1.0.1 we moved `safe-c-functions` to context-specific because it doesn't make sense to load C/C++ memory-safety guidance into context when someone is writing Python. That tuning matters: every rule that's "always-apply" costs context tokens and adds noise, so we reserve that tier for things that genuinely apply to *every* line of code an AI agent might write.

## Why this is a different Agent Skill pattern than the MITRE pack

Comparing the two designs is the most useful part of looking at them together:

| Dimension | `mitre-attack-agent-skills` | `project-codeguard` |
|---|---|---|
| Granularity | One skill per technique (918 skills) | One skill, 22 rules inside it |
| Activation | Triggered by specific ATT&CK-shaped query | Activates on any code work |
| User | SOC analyst, detection engineer, IR | Developer using an AI coding agent |
| Output shape | Hunt plans, detection briefs, IR notes | Secure code + security commentary |
| Portability | Anthropic skill format only | Translated to ~8 agent formats |
| Lifecycle stage | Detect / respond | Build / shift-left |

Both are valid; they're optimized for different problems. When the user's query maps cleanly to a taxonomy with hundreds of nodes, fine-grained skills win because retrieval precision matters. When the skill needs to be *ambient* — running in the background of every code operation — a single broad skill with internal tiering wins because you can't realistically dispatch to one of 22 micro-skills on every keystroke.

## Why this matters for AI security specifically

CodeGuard sits in a part of the AI-security stack I think is underdeveloped: **shaping what AI coding agents produce**, rather than only scanning what they produce after the fact. SAST/DAST tools and AI code reviewers are necessary, but they catch problems *after* the agent has already written insecure code, after a human has potentially accepted it, and after it's potentially merged. A security skill that ships with the agent shifts that left to the moment of generation.

It's also a pattern that scales: the same skill format can encode AI/ML-specific guidance (prompt-injection-resistant code, safe LLM-calling patterns, secure agent tool definitions, MCP server hardening). That's a direction we're actively pushing the project, and it's where I see Agent Skills becoming part of the standard secure-development toolkit rather than a niche capability.

If anyone wants to contribute rules — particularly for AI/agent-specific threats — issues and discussions are open on the repo.

**The defensive-only framing is intentional and load-bearing.** Skill descriptions don't just route requests — they shape what the agent will and won't help with. Putting the scope in the description means the agent self-selects out of misuse cases without the user even seeing a refusal.

If you wanted to extend this idea, natural follow-ups would be a parallel skill pack for **D3FEND** countermeasures (so the agent can pair every ATT&CK technique with a mapped defense), a pack for **Atomic Red Team** tests (for purple-team validation), or a pack mapping **CWE/CVE** to detection guidance. The repo's structure — manifest files, validation summary, per-technique folders — is a reusable scaffold for all of those.
