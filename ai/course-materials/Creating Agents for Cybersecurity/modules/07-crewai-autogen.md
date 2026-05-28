# Module 7 — CrewAI and AutoGen: Role-Based and Conversational Multi-Agent Patterns

## 7.1 Learning objectives

- Build a CrewAI "crew" with role/goal/backstory for a security task.
- Build an AutoGen group chat for the same task and compare.
- Know when to reach for CrewAI, AutoGen, or LangGraph.
- Recognize and mitigate **cascading hallucinations** (ASI05) in multi-agent systems.

## 7.2 The big three in 2026

CrewAI, LangGraph, and AutoGen dominate production multi-agent deployments in 2026. Each models multi-agent differently:

- **CrewAI** — role-based. Define agents by role/goal/backstory, define tasks, assemble a crew, let the framework coordinate. Most beginner-friendly.
- **AutoGen** — conversational. Agents participate in group chats, passing messages back and forth until a task resolves. You design the conversation topology.
- **LangGraph** — graph-based. State and transitions are explicit (see Module 4).

All three can do the same things; their mental models differ enough that the *natural* solution in each looks different.

## 7.3 CrewAI in one example — a phishing-investigation crew

```python
from crewai import Agent, Task, Crew, Process

analyst = Agent(
    role="Phishing Analyst",
    goal="Determine if the email is a phishing attempt and why.",
    backstory="Veteran SOC analyst with deep email-header expertise.",
    tools=[parse_email, lookup_url, lookup_sender, sandbox_attachment],
    verbose=True,
)

threat_intel = Agent(
    role="Threat Intel Researcher",
    goal="Find prior campaigns matching this email's TTPs.",
    backstory="Maintains TI feeds and clusters by IOC overlap.",
    tools=[search_ti, query_kg, fetch_attack_technique],
    verbose=True,
)

writer = Agent(
    role="Incident Reporter",
    goal="Produce a concise, accurate incident summary.",
    backstory="Excellent technical writer; never invents facts.",
    tools=[],
)

triage   = Task(description="Triage {email_id}.", expected_output="Verdict and reasoning.", agent=analyst)
correlate= Task(description="Correlate with known campaigns.", expected_output="Top-3 candidate campaigns.", agent=threat_intel)
report   = Task(description="Write the summary.", expected_output="Markdown report.", agent=writer)

crew = Crew(
    agents=[analyst, threat_intel, writer],
    tasks=[triage, correlate, report],
    process=Process.sequential,
)

result = crew.kickoff(inputs={"email_id": "EML-2026-05-28-0001"})
```

Notice:

- The **role/goal/backstory** triple is the prompt scaffolding. It is human-readable, which is genuinely useful for security review.
- **Sequential process** is the default; CrewAI parallel execution exists but is less mature than AutoGen/LangGraph as of 2026. For high-throughput pipelines this can be a bottleneck.
- Tasks pass their output to subsequent tasks automatically.

**Security risk to internalize:** a task's output is *text* that becomes part of the next task's prompt. If `lookup_url` returns prompt-injected page content, the analyst's "verdict" can carry injection downstream into the writer. Provenance + typed verdict objects are the mitigation.

## 7.4 AutoGen in one example — a red-team / blue-team debate

AutoGen's model is conversational. The natural fit for adversarial reasoning:

```python
import autogen

config_list = [{"model": "claude-sonnet-4-6", "api_key": "..."}]

attacker = autogen.AssistantAgent(
    name="RedTeam",
    system_message="Propose realistic attacks against the target. Be specific and ATT&CK-mapped.",
    llm_config={"config_list": config_list},
)

defender = autogen.AssistantAgent(
    name="BlueTeam",
    system_message="For each proposed attack, propose detections and mitigations. Cite the controls.",
    llm_config={"config_list": config_list},
)

judge = autogen.AssistantAgent(
    name="Judge",
    system_message="Stop when there is consensus or after 6 turns. Summarize the outcome.",
    llm_config={"config_list": config_list},
)

user = autogen.UserProxyAgent(
    name="User",
    human_input_mode="NEVER",
    code_execution_config=False,
)

groupchat = autogen.GroupChat(agents=[user, attacker, defender, judge], messages=[], max_round=8)
manager   = autogen.GroupChatManager(groupchat=groupchat, llm_config={"config_list": config_list})

user.initiate_chat(manager, message="Target: a public-facing FastAPI ingestion endpoint behind Cloudflare. Begin.")
```

Three notes:

1. The **GroupChatManager** is the policy: it picks who talks next.
2. `max_round` is a hard step budget — set it.
3. `human_input_mode` and `code_execution_config` are security controls hiding in plain sight. Default `human_input_mode="ALWAYS"` for any chat that can execute code.

## 7.5 When to pick which

A pragmatic table:

| If you need... | Reach for |
|---|---|
| Clear sequential or branching workflow with strict state | LangGraph |
| Roles with distinct expertise and a producer-consumer pipeline | CrewAI |
| Adversarial, brainstorm, or critique dynamics | AutoGen |
| All of the above in one product | Use LangGraph at the top level, CrewAI/AutoGen *inside* a node |

## 7.6 Cascading hallucinations — the multi-agent failure mode that matters

In single-agent systems, a hallucination is a bad answer. In multi-agent systems, agent B treats agent A's hallucinated text as ground truth, builds on it, and the error amplifies. By the time it reaches the writer, no one in the chain doubted it.

This is **ASI05 (Cascading Hallucinations in Multi-Agent Systems)** and it is the single biggest reliability problem in production multi-agent deployments.

Mitigations:

- **Evidence gates between agents.** No claim moves downstream without a citation to a verifiable source. Foundry's Validator role enforces exactly this.
- **Structured handoffs.** Agents hand off typed objects, not prose. The receiving agent treats unmodeled fields as data, not instructions.
- **Critic agents.** A dedicated critic re-asks the upstream agent when claims look unsupported.
- **Disagreement budgets.** If two agents diverge, escalate rather than letting one bully the other into agreement.

## 7.7 Hands-on Lab 07 — CrewAI red-team crew vs. AutoGen group chat

[`labs/lab07-crewai-autogen/`](../labs/lab07-crewai-autogen/):

1. Implement the phishing investigation in both frameworks.
2. Run both against the same 10 sample emails.
3. Compare: turn counts, token cost, time, output quality, ease of adding a "fact-check" step.
4. Inject a poisoned email (one whose linked URL returns prompt-injected content) and observe which framework's defenses hold.

## 7.8 Cross-framework patterns to remember

- **Cap turns.** Every multi-agent framework should have an explicit cap.
- **Type the handoffs.** Don't let agents pass arbitrary prose to each other if a Pydantic model will do.
- **Audit chat logs.** Multi-agent chat is the new shell history. Retain, redact, and review.
- **Restrict tools per role.** Workers should not share toolbelts. The phishing analyst does not need the ticket-create tool; the writer does not need URL lookup.

## 7.9 Exercises

1. Convert the LangGraph SOC triage graph from Lab 04 into a CrewAI crew. Where did information get lost in translation?
2. Design a 3-agent AutoGen group chat for malware analysis (static, dynamic, classifier). What stops it?
3. Add a critic agent to either implementation. Where does it sit? What does it gate?
4. Sketch a typed handoff schema between "analyst" and "writer" agents that neutralizes prose-borne prompt injection.

## 7.10 Further reading

- *CrewAI vs AutoGen vs LangGraph: Which Multi-Agent Framework in 2026?* (DEV Community).
- *Multi-Agent AI in 2026: Build Production Systems with CrewAI, LangGraph & AutoGen*.
- Microsoft, [AutoGen docs](https://microsoft.github.io/autogen/).
- [crewAI GitHub](https://github.com/crewAIInc/crewAI).

---

Previous: [Module 6](06-memory-rag-knowledge.md) · Next: [Module 8 — Inside the Cisco Foundry Security Spec](08-foundry-security-spec.md).
