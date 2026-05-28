# Creating Agents for Cybersecurity

**A comprehensive, hands-on course on designing, building, evaluating, and operating AI agents and multi-agent systems for security work.**

Author: Omar Santos
Last updated: May 2026
Audience: Mixed intermediate — security practitioners familiar with general security concepts and AI/ML engineers familiar with LLMs. Comfort with Python is assumed.
Format: Balanced theory + hands-on labs. ~12 modules + capstone.
Primary frameworks covered: LangGraph / LangChain, Claude Agent SDK + MCP, CrewAI, AutoGen, and the [Cisco Foundry Security Spec](https://github.com/CiscoDevNet/foundry-security-spec).

---

## Why this course

The operating model of cybersecurity has fundamentally shifted. Frontier LLMs let attackers find vulnerabilities at machine speed, while defenders are still anchored in manual, legacy processes. The defenders' counter-move is not "use a chatbot" — it is to wrap those models inside disciplined agentic systems with clear roles, orchestration, evidence gates, and guardrails. That is what this course teaches you to build.

By the end of the course you will be able to:

1. Explain the agent loop, planner-executor patterns, tool use, memory, and the security implications of each.
2. Build a single-agent security workflow using LangGraph and the Claude Agent SDK.
3. Orchestrate multi-agent systems with CrewAI and AutoGen for SOC, vulnerability discovery, and incident response use cases.
4. Apply the Foundry Security Spec's eight core roles, eleven constitutional principles, and finding lifecycle to a real evaluation harness.
5. Threat-model and red-team your own agents against the OWASP Agentic Top 10 (ASI) and prompt-injection class attacks.
6. Operate agents responsibly: identity, least privilege, sandboxing, budget control, observability, evidence trails, and human-in-the-loop oversight.

---

## Prerequisites

- Comfort reading Python (functions, classes, async).
- General security awareness (CIA triad, OWASP Top 10, basic threat modeling).
- API key for at least one frontier LLM provider (Anthropic Claude recommended; OpenAI usable for some labs).
- Local machine with Docker, Git, Python 3.11+, and ~10 GB free disk.

You do **not** need prior LangGraph, CrewAI, or AutoGen experience.

---

## Course structure

The course is organized as **four arcs of three modules each**, plus a capstone. Every module follows the same shape:

1. **Concepts** — the why, the model, and the failure modes.
2. **Hands-on lab** — runnable code in a notebook or script.
3. **Security lens** — what can go wrong and how to defend it.
4. **Exercises and reflection questions.**

### Arc 1 — Foundations
- **Module 1.** [AI Agents 101: Loops, Tools, Memory, and Why Security Cares](modules/01-ai-agents-101.md)
- **Module 2.** [Agentic Architectures: Single-Agent, Planner-Executor, Multi-Agent, and the Agentic Mesh](modules/02-agentic-architectures.md)
- **Module 3.** [Threat Modeling Agents: OWASP ASI Top 10, Prompt Injection, and Goal Hijack](modules/03-threat-modeling-agents.md)

### Arc 2 — Frameworks
- **Module 4.** [LangGraph for Security Workflows: Graph, State, Supervisor](modules/04-langgraph-security.md)
- **Module 5.** [Claude Agent SDK and MCP: Building Secure Tool-Using Agents](modules/05-claude-agent-sdk-mcp.md)
- **Module 6.** [Memory, RAG, and Knowledge Graphs for Security Agents](modules/06-memory-rag-knowledge.md)

### Arc 3 — Multi-Agent Systems and the Foundry Security Spec
- **Module 7.** [CrewAI and AutoGen: Role-Based and Conversational Multi-Agent Patterns](modules/07-crewai-autogen.md)
- **Module 8.** [Inside the Cisco Foundry Security Spec: 8 Roles, 11 Principles, 130 FRs](modules/08-foundry-security-spec.md)
- **Module 9.** [Identity, Trust, and Governance: Credentials, Sandboxing, Budgets, and Human-in-the-Loop](modules/09-identity-trust-governance.md)

### Arc 4 — Applied Security Agents
- **Module 10.** [Blue Team Agents: SOC Triage, IR, Threat Intel, and Detection Engineering](modules/10-blue-team-agents.md)
- **Module 11.** [Red Team and Vulnerability-Discovery Agents (with Foundry's Detector and Validator)](modules/11-red-team-vuln-discovery.md)
- **Module 12.** [Observability, Evaluation, and Continuous Red-Teaming of Agents](modules/12-observability-evaluation.md)

### Capstone
- **Capstone Project.** [Build a Foundry-Aligned Agentic Security Evaluation System](modules/13-capstone.md)

---

## Labs index

Each module's lab lives in [`labs/`](labs/). Labs are runnable and progressive — a tool built in Lab 4 is reused in Lab 7, and so on.

| Lab | Title | Frameworks |
|-----|-------|------------|
| 01  | Hello, Agent — a minimal ReAct loop with a security tool | Plain Python + Anthropic SDK |
| 02  | Planner-Executor for log triage | LangChain |
| 03  | Threat-modeling your own agent design | Markdown / STRIDE |
| 04  | LangGraph SOC triage graph | LangGraph |
| 05  | Claude Agent SDK + MCP shodan/VT lookup | Claude Agent SDK, MCP |
| 06  | Vector RAG over CVE/MITRE corpus | Chroma, LangChain |
| 07  | CrewAI red-team crew vs AutoGen group chat | CrewAI, AutoGen |
| 08  | Map Foundry's 8 roles to a runnable scaffold | Plain Python |
| 09  | Sandboxing and budget gates for agents | Docker, simple substrate |
| 10  | Build a Blue-Team supervisor for alert triage | LangGraph + MCP |
| 11  | Build a Red-Team detector + validator pair | Foundry-aligned |
| 12  | Promptfoo + DeepTeam red-teaming your agent | Promptfoo, DeepTeam |
| 13  | Capstone harness | Your choice |

---

## How to use this material

- **Self-paced learner:** Work module-by-module. Each module is ~3–5 hours including the lab.
- **Workshop instructor:** The course maps cleanly to 4 half-days (one arc per session) plus a capstone day.
- **Reference reader:** Modules 3, 8, 9, and 12 are designed to be useful standalone.

---

## Repository layout

```
Creating Agents for Cybersecurity/
├── README.md                  # this file (the course outline)
├── modules/                   # the 12 module markdowns + capstone
├── labs/                      # runnable labs referenced by each module
└── resources/                 # references, glossary, threat-model templates
```

---

## Key references

- Omar Santos, ["Announcing Foundry Security Spec"](https://blogs.cisco.com/ai/announcing-foundry-security-spec), Cisco Blogs, May 2026.
- Cisco, [Foundry Security Spec repository](https://github.com/CiscoDevNet/foundry-security-spec).
- OWASP Gen AI Security Project, [Top 10 for Agentic Applications (ASI) 2026](https://genai.owasp.org/).
- [Project CodeGuard](https://project-codeguard.org/) (Cisco / CoSAI / OASIS).
- LangChain, [LangGraph docs](https://langchain-ai.github.io/langgraph/).
- Anthropic, [Claude Agent SDK overview](https://platform.claude.com/docs/en/agent-sdk/overview).
- Model Context Protocol — [https://modelcontextprotocol.io](https://modelcontextprotocol.io).
- CrewAI — [https://github.com/crewAIInc/crewAI](https://github.com/crewAIInc/crewAI).
- Microsoft AutoGen — [https://microsoft.github.io/autogen/](https://microsoft.github.io/autogen/).
- [GitHub spec-kit](https://github.com/github/spec-kit) — the spec-driven workflow Foundry is meant to be consumed with.

---

## License

Course materials are provided for educational use. Code examples are released under the MIT License unless a lab states otherwise.
