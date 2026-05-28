# Glossary

A working glossary for the *Creating Agents for Cybersecurity* course. Definitions are course-scoped; canonical definitions live in the upstream specs.

- **Agent.** A system in which an LLM is given a goal, a set of tools, a memory, and the autonomy to decide what action to take next, in a loop, until the goal is satisfied or a stop condition is reached.
- **Agent loop.** The perceive → reason → act → observe cycle that an agent runs.
- **Agentic mesh.** A loosely coupled network of agents across products and teams that discover and invoke each other.
- **AutoGen.** Microsoft's open-source multi-agent framework based on group-chat patterns.
- **ASI (Agentic Security Initiative).** OWASP Gen AI Security Project's Top 10 for Agentic Applications (2026).
- **Budget.** A pre-set ceiling on a runtime resource (tokens, cost, wall-clock, write actions). A security control, not just a cost control.
- **Cartographer.** Foundry Security Spec role responsible for producing architecture, attack-surface, trust-boundary, data-flow, and threat-model documents.
- **Checkpoint.** A persisted snapshot of agent state at a graph-node boundary; enables resume, replay, time-travel.
- **CodeGuard.** Open-source rule corpus format originally from Cisco, donated to CoSAI/OASIS; the rule format Foundry's Detector typically consumes.
- **Constitution (Foundry).** A document of eleven inviolable principles each implementation of Foundry must uphold.
- **Coverage-Guide.** Foundry role tracking what has been examined and what has not; produces the coverage signal.
- **CrewAI.** Open-source role-based multi-agent framework.
- **Detector.** Foundry role that sweeps the target against a corpus of detection rules.
- **Direct prompt injection.** Attacker writes instructions in the user input that override the agent's intent.
- **Evidence gate.** A control that allows a finding to proceed only if reproducible evidence exists.
- **Finding.** A claim about a security defect; in Foundry, exists only after Validator confirmation.
- **Foundry Security Spec.** An open specification (Cisco) for agentic security evaluation systems.
- **GoalHijack (ASI01).** An attacker manipulates an agent's core objective via direct or indirect injection.
- **Group chat (AutoGen).** A multi-agent pattern where agents converse to consensus.
- **Handoff.** Transfer of control from one agent to another, typically with structured state.
- **HITL (Human-in-the-loop).** A workflow in which a human approves or overrides agent decisions.
- **Indexer.** Foundry role producing a navigable corpus of the target for other roles to query.
- **Indirect prompt injection.** Attacker plants instructions in content the agent later retrieves; the LLM treats them as instructions.
- **LangGraph.** LangChain's graph-based agent framework with typed state and explicit transitions.
- **MCP (Model Context Protocol).** Open standard for connecting AI agents to external tools and data sources.
- **MCP tunnel / gateway.** A network-boundary intermediary that holds credentials and enforces scope between the agent and the integrated tool.
- **MDASH.** Microsoft's 2026 multi-agent system that topped a leading cybersecurity benchmark.
- **Orchestrator.** Foundry role; the supervisor that drives lifecycle and talks to the operator.
- **OWASP Top 10 for LLMs.** Industry standard ranking of LLM application risks; Agentic ASI Top 10 is its 2026 agent-focused sibling.
- **Planner-Executor.** Architectural pattern: planner LLM emits a plan, executor LLM runs it.
- **Provenance.** Metadata establishing where information came from and under what conditions.
- **Promptfoo.** Eval and red-team framework popular for LLM/agent CI.
- **PyRIT.** Microsoft's open-source Python Risk Identification Tool for AI red-teaming.
- **RAG.** Retrieval-augmented generation. Retrieve relevant context then generate.
- **RAG poisoning.** Adversarial content planted in the retrieval corpus that influences future generation.
- **Reporter.** Foundry role producing human-readable writeups of confirmed findings.
- **ReAct.** Reasoning + Acting — early agent pattern alternating Thought and Action.
- **Sandbox.** A bounded execution environment imposed on the agent by the operator (not requested by the agent).
- **Spec-kit (GitHub).** A spec-driven development workflow Foundry is meant to be consumed with.
- **Substrate (Foundry).** The coordination layer — work queue, finding store, sandbox, budget, dashboard.
- **Supervisor pattern.** Single supervisor agent dispatches to specialized workers and synthesizes their outputs.
- **Tier (approval).** A graded human-approval level from 0 (no approval) to 3 (synchronous human signoff for irreversible actions).
- **Tool.** A callable function exposed to the agent.
- **Trace.** A structured record of an agent run, captured for forensics, replay, and audit.
- **Triager.** Foundry role that decides which raw detections are worth investigating.
- **Validator.** Foundry role enforcing the evidence gate — confirms or refutes triaged findings.
- **Variant-Hunter.** Foundry extension role that generalizes a confirmed finding into a class search.
- **Yield gate.** A stop condition that triggers when incremental new findings per unit cost drop below a threshold.

---

References:
- Foundry GLOSSARY: https://github.com/CiscoDevNet/foundry-security-spec/blob/main/GLOSSARY.md
- OWASP Gen AI: https://genai.owasp.org/
- MCP: https://modelcontextprotocol.io/
