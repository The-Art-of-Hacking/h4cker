# Module 9 — Identity, Trust, and Governance: Credentials, Sandboxing, Budgets, and Human-in-the-Loop

## 9.1 Learning objectives

- Apply **Zero Trust** and **least privilege** to agent identity and tool reach.
- Run an agent inside a sandbox the agent did not define.
- Implement budget gates (token, cost, wall-clock, action-count).
- Design effective human-in-the-loop checkpoints — and recognize when "human-in-the-loop" has become theater.

## 9.2 Three classic principles, applied to agents

Organizations must fold autonomous systems into their existing cybersecurity frameworks, aggressively applying Zero Trust, defense-in-depth, and least-privilege access.

- **Zero Trust.** Every tool call, every cross-agent message, every credential use is authenticated and authorized as if it came from the public internet.
- **Defense in depth.** Prompt-level controls (system prompts, instructions) sit *on top of* substrate-level controls (sandbox, policy hooks, budgets). Never rely on a single layer.
- **Least privilege.** An agent's identity, scope, and tool access are the minimum required for the current task — not the maximum the team gave them.

These are not new ideas. They are the same principles you have applied to humans and services. Agents are simply a new principal type.

## 9.3 Agent identity

An agent in production needs an identity that is:

- **Distinct** — not the developer's personal token, not a shared service account.
- **Scoped per task** — short-lived credentials minted for the run.
- **Attributable** — every action logs `(agent_id, run_id, task_id, parent_run_id)`.
- **Revokable** — kill switch at the identity layer.

For OAuth-backed integrations, prefer the **agent-as-a-distinct-principal** model: the agent has its own client_id, its own scopes, and the human grants consent for delegation rather than the agent pretending to be the human.

For multi-agent systems, every subagent should have its **own identity**, not inherit the parent's. This makes the audit trail informative and lets you apply per-role policy.

## 9.4 Credential isolation — the MCP tunnel pattern

A pattern worth restating from Module 5 because it is the production fix for the credential problem:

```
       agent process                      gateway                    tool API
   ┌────────────────────┐         ┌──────────────────────┐         ┌──────────┐
   │ LLM + agent loop   │ ──────▶│ MCP tunnel / sidecar │ ──────▶│  GitHub  │
   │ (no credentials)   │         │  • holds creds        │         └──────────┘
   └────────────────────┘         │  • enforces scope     │
                                  │  • logs every call    │
                                  └──────────────────────┘
```

The agent never sees the credential. The gateway can rotate it without touching the agent. Scope is enforced at the gateway, where the LLM cannot reason it away.

Without this pattern, a compromised agent has *every credential the agent process ever loaded*. With this pattern, a compromised agent has *the ability to ask the gateway for actions it is allowed to take*. That is a categorical reduction in blast radius.

## 9.5 Sandboxing — the agent must not define its own boundary

The Foundry constitution puts this in writing: *operate inside a sandbox the agent cannot define.* Three layers in practice:

1. **Process boundary.** The agent runs in a container or VM with seccomp/AppArmor profiles.
2. **Filesystem boundary.** Ephemeral working directory; no host mounts beyond what was explicitly granted.
3. **Network boundary.** Default-deny outbound; explicit allowlist of egress destinations.

For *code execution* tools — and most modern security agents have at least one — the sandbox is non-negotiable. Use a managed sandbox service or a hardened firecracker/gVisor setup. Do not run agent-generated code on a developer laptop with shell access.

## 9.6 Budgets and gates

A budget is a security control, not just a cost control. Adversarial inputs frequently aim to make the agent burn tokens, money, and time. Budgets cap the damage.

Pick at least three:

- **Token budget** per run (input + output).
- **Cost budget** per run, per day, per project (USD).
- **Wall-clock budget** per run.
- **Action budget** per run — count of write tool calls in particular.
- **Yield gate** — Foundry's idea: stop when incremental yield drops below a threshold the operator set.

Budgets should be enforced **outside the agent**. The LLM should not be the one deciding when to stop spending money.

## 9.7 Human-in-the-loop, done right

"Human-in-the-loop" is necessary but easy to do badly. Effective HITL has four properties:

1. **The human sees what the agent saw.** State, trace, evidence. No hidden context.
2. **The human's decision is structured.** Approve, deny, modify, escalate — not free-form chat.
3. **The decision rate respects human attention.** If you ask a human to approve 200 tool calls a day, they will approve them all without reading.
4. **The decision is recorded.** Provenance includes the human reviewer's identity and reasoning.

Foundry's constitutional principle — *a human is the final arbiter for irreversible actions* — is doing real work here. The agent can propose anything. Writes that touch production, files tickets, opens PRs, quarantines hosts — the human signs the order.

A useful pattern is **tiered approval**:

- Tier 0 (no-op, read-only): no approval.
- Tier 1 (low-impact write, reversible): silent approval but audited.
- Tier 2 (medium-impact, reversible): human notification, async approve-by-default with a configurable window.
- Tier 3 (high-impact, irreversible): synchronous human approval, two-eyes for the highest tier.

## 9.8 Governance — the rest of the program

Identity, sandbox, budget, HITL are the operational primitives. They sit inside a governance program that also includes:

- **An inventory** of agents in production: owner, purpose, model, tools, identity, scope.
- **A change process** for agent prompts and tools. Prompts are code; treat them like code.
- **An incident process** for "the agent did something we didn't want." Includes rollback, kill switch, postmortem.
- **A risk register** that maps each agent's threats (Module 3) to controls and residual risk.
- **A periodic review** of agent activity — high-cost runs, near-budget runs, denied tool calls, escalations.

Without governance, the rest is theatre.

## 9.9 The Foundry coordination substrate as a governance exemplar

Foundry's substrate is *itself* a governance exhibit:

- The work queue mediates who does what (no agent unilaterally takes work).
- The finding store enforces fingerprinting (no duplicate findings, no shadow findings).
- Atomic claim and heartbeat liveness make multi-agent coordination safe under failure.
- The budget lives at the substrate; the agents can ask for more but cannot grant themselves more.
- Auto-stop on yield-and-coverage thresholds means "done" is a defended decision.

Reading the substrate sections of the spec (§4 and the substrate parts of §5) is one of the best practical primers on agent governance available in 2026.

## 9.10 Hands-on Lab 09 — Sandboxing and budget gates

[`labs/lab09-sandbox-budgets/`](../labs/lab09-sandbox-budgets/):

1. Take the LangGraph triage agent from Lab 04.
2. Move the responder node behind a tiered approval interface.
3. Run the agent inside a Docker container with:
   - No host mounts beyond the workspace.
   - `--network none` plus an explicit egress allowlist via a tiny proxy.
   - A CPU/memory cap.
4. Add a budget enforcer that halts the run on:
   - 50k input tokens, 10k output tokens.
   - $0.50.
   - 60 seconds wall-clock.
   - 3 write actions.
5. Try to defeat each control with an adversarial prompt; document what worked and what didn't.

## 9.11 Exercises

1. Draft an "agent identity policy" for your organization. What attributes does an agent identity carry? Who issues it? How is it revoked?
2. List five tool calls in a SOC triage workflow and tier them (0–3) for human approval. Where did you draw the lines and why?
3. The agent is asked, mid-task, to perform a Tier-3 action under time pressure (an active incident). How does your HITL design handle the case where the human is unavailable?
4. Review one agent in your org against the four-property HITL definition in 9.7. Which property is the weakest?

## 9.12 Further reading

- *Five Engineering Patterns to Secure Agentic AI in 2026* (Baytech).
- *Claude agents can finally connect to enterprise APIs without leaking credentials*, VentureBeat (2026).
- NIST AI Risk Management Framework (current revision).
- Foundry Security Spec, §4 + substrate sections of §5.
- EU AI Act — operational obligations relevant to high-risk agentic systems.

---

Previous: [Module 8](08-foundry-security-spec.md) · Next: [Module 10 — Blue Team Agents](10-blue-team-agents.md).
