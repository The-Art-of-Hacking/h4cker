# Module 5 — Claude Agent SDK and MCP: Building Secure Tool-Using Agents

## 5.1 Learning objectives

- Use the **Claude Agent SDK** (formerly the Claude Code SDK) to build a Python or TypeScript security agent.
- Explain the **Model Context Protocol (MCP)** and why it has become the de-facto integration layer for agents in 2026.
- Connect an MCP server (Shodan, VirusTotal, GitHub, custom) to your agent.
- Apply the security patterns: MCP tunnels, scopes, sandboxes, and credential isolation.

## 5.2 The Claude Agent SDK in 30 seconds

The Claude Agent SDK provides the same tools, agent loop, and context management that power Claude Code, programmable in Python and TypeScript. Where LangGraph gives you a graph framework, the Claude Agent SDK gives you the **production agent loop Anthropic uses internally**, with hooks where you want them.

You bring:

- A goal (system prompt + user message).
- Tools (functions, MCP servers, subagents).
- Permissions (what the agent is allowed to do).
- Output handling.

The SDK manages:

- The agent loop.
- Token context window management.
- Tool-call schema validation.
- Subagent spawning.
- The streaming output protocol.

## 5.3 A minimal Claude Agent SDK security agent

Python sketch:

```python
from claude_agent_sdk import Agent, tool, AgentContext

@tool
def query_siem(query: str) -> dict:
    """Run a SIEM query and return matching events. Read-only."""
    return siem_client.search(query)

@tool
def lookup_ip(ip: str) -> dict:
    """Look up reputation data for an IP. Read-only."""
    return vt_client.ip_report(ip)

@tool(requires_approval=True)
def create_ticket(title: str, body: str, severity: str) -> dict:
    """Create a ticket. Requires human approval."""
    return jira_client.create(title=title, body=body, severity=severity)

agent = Agent(
    model="claude-sonnet-4-6",
    system_prompt="You are a Tier-1 SOC triage agent. Be terse, cite IDs, and never invent.",
    tools=[query_siem, lookup_ip, create_ticket],
)

result = agent.run(user_message="Triage alert ALRT-2026-05-28-0042 and decide next steps.")
print(result.summary)
```

Two patterns to internalize:

1. **`requires_approval=True`** on any write tool. The SDK halts and surfaces an approval request before invoking it.
2. **Docstrings are the tool contract.** Be precise about scope, side effects, and inputs — the LLM will read them.

## 5.4 MCP — the integration substrate

The **Model Context Protocol (MCP)** is an open standard for connecting AI agents to external tools and data sources. Instead of writing custom tool implementations per agent, MCP defines a server protocol: any MCP-compliant server exposes tools that any MCP-aware agent can use.

By 2026, MCP servers exist for: GitHub, GitLab, Slack, Linear, Jira, PagerDuty, Splunk, Elastic, VirusTotal, Shodan, Censys, Sysdig, Wiz, GreyNoise, and many more.

```python
agent = Agent(
    model="claude-sonnet-4-6",
    system_prompt="...",
    mcp_servers=[
        {"name": "github", "command": "npx @modelcontextprotocol/server-github"},
        {"name": "siem",   "command": "uvx mcp-server-splunk"},
    ],
)
```

Tools surfaced by an MCP server appear to the agent as ordinary tools. From the agent's perspective there is one toolbelt; the MCP layer is invisible.

## 5.5 Why MCP matters for security agents

Three reasons:

1. **Composability.** A security agent can talk to a SIEM, a ticket system, a threat-intel feed, and a code repo — all through MCP servers, often without writing code.
2. **Operational separation.** The MCP server runs in its own process (or its own host). Compromising the agent does not necessarily compromise the integration.
3. **Auditability.** MCP traffic is logged at a known interface, not buried inside ad-hoc client code.

## 5.6 The credential problem MCP exposed — and the fix

The blunt truth from 2026 enterprise reporting: in most early deployments, credentials traveled through the agent itself as it executed tool calls against internal systems. A compromised or misbehaving agent had everything it needed to cause damage.

The 2026 answer is to push credential control to the network boundary using **MCP tunnels**, **managed agents**, and **sandboxes**:

- The agent talks to a local MCP gateway.
- The gateway holds and rotates credentials; the agent never sees them.
- The gateway enforces scopes (which tools, which arguments, which targets).
- The gateway logs.

If you operate a serious security agent, this is the architecture. The naive "stuff the API key in an environment variable in the agent's process" pattern is unacceptable for write tools.

## 5.7 Subagents and parallel tasks

The Claude Agent SDK supports spawning subagents — child agents that own their own context window, run in parallel, and report back to the parent.

For security, subagents are how you implement the supervisor pattern from Module 4 without LangGraph:

```python
@tool
def triage_alert(alert_id: str) -> dict:
    """Spawn a subagent to triage one alert end-to-end."""
    sub = AgentContext.spawn(
        system_prompt="You are a focused alert triage subagent.",
        tools=[query_siem, lookup_ip],
        max_turns=8,
    )
    return sub.run(f"Triage {alert_id} and return a structured verdict.")
```

The supervisor agent decides which alerts to triage; each subagent owns a narrow loop with its own budget.

## 5.8 Permissions, hooks, and policy

Production deployments of the Claude Agent SDK plug a **policy hook** between the LLM and the tools. The hook sees every proposed tool call and can:

- Allow.
- Deny.
- Modify (e.g., scope-down a query).
- Require approval (route to human).

A useful policy starting point:

- Default-deny on write tools.
- Per-tool allow-list of argument shapes.
- Rate limits per tool, per session.
- Budget gate (USD, tokens, or wall-clock).
- A "tripwire" set of forbidden argument patterns (paths outside the workspace, internal CIDRs the agent should never touch).

## 5.9 Hands-on Lab 05 — Claude Agent SDK + MCP threat-intel agent

[`labs/lab05-claude-mcp-threat-intel/`](../labs/lab05-claude-mcp-threat-intel/) walks through:

1. Installing the Claude Agent SDK.
2. Running the GitHub MCP server locally.
3. Adding a VirusTotal MCP server (or a mock if you don't have a key).
4. Building an agent whose job is: "given a suspicious domain, gather all available reputation data and produce a risk report."
5. Adding a policy hook that:
   - Allows VT/Shodan lookups freely.
   - Requires approval before any GitHub *write* (issue, comment, PR).
   - Denies any tool call whose argument matches an internal IP range.
6. Reading the trace and writing a one-paragraph postmortem.

## 5.10 Comparing the Claude Agent SDK to LangGraph

| Dimension | Claude Agent SDK | LangGraph |
|---|---|---|
| Mental model | Agent loop + subagents | Typed state graph |
| Best for | Tool-rich, MCP-heavy agents | Workflows with explicit branching |
| Determinism | Mostly LLM-driven | You write the edges |
| Human-in-the-loop | `requires_approval` per tool | `interrupt_before/after` on nodes |
| Observability | Built-in streaming + hooks | Checkpoints + LangSmith |
| Sweet spot | A single capable agent with many tools | Multi-agent or multi-stage workflows |

In practice, real systems use both: LangGraph for the orchestration graph, Claude Agent SDK as the worker inside specific nodes.

## 5.11 Exercises

1. Convert the SOC supervisor from Lab 04 to use Claude Agent SDK subagents inside each worker node.
2. Write a docstring for a `quarantine_host` tool that minimizes the chance of prompt-injection-driven misuse. What constraints belong in the docstring vs. in the policy hook?
3. Sketch the architecture of a credential-isolating MCP gateway for a 5-tool security agent. What does each component own?
4. Pick one MCP server in the public ecosystem and review its source for trust assumptions you would not accept in production.

## 5.12 Further reading

- Anthropic, [Agent SDK overview](https://platform.claude.com/docs/en/agent-sdk/overview).
- Anthropic, [Connect to external tools with MCP](https://platform.claude.com/docs/en/agent-sdk/mcp).
- [modelcontextprotocol.io](https://modelcontextprotocol.io/) — protocol spec and server registry.
- *Claude agents can finally connect to enterprise APIs without leaking credentials*, VentureBeat (2026).

---

Previous: [Module 4](04-langgraph-security.md) · Next: [Module 6 — Memory, RAG, and Knowledge Graphs](06-memory-rag-knowledge.md).
