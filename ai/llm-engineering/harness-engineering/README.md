## AI Harness Engineering

**Harness engineering** is the discipline of designing the runtime surrounding an LLM so it can act usefully and safely in a real environment. A useful mental model is:

AGENT = MODEL + HARNESS

The model supplies probabilistic reasoning and language generation; the harness supplies the things production systems cannot leave to probability: tool access, task state, context selection, authorization, validation, recovery, logging, and stop conditions. 

For an advanced security practitioner, treat the harness as both an **agent operating environment** and a **control plane**. It defines what the agent may observe, which actions it can attempt, how those actions are checked, and what evidence must be retained.

## Core Components

A comprehensive harness usually has these layers:

- **Task contract:** A structured goal, scope, success criteria, risk tier, budget, deadline, and explicit definition of “done.”
- **Context system:** Selects and compresses repository content, prior findings, policies, architecture data, retrieved documents, and tool results. Context must be relevant, current, provenance-tagged, and bounded.
- **Agent loop:** Coordinates planning, tool use, result interpretation, replanning, retries, escalation, and termination.
- **Tool gateway:** Exposes typed tools with schemas, input validation, least-privilege credentials, rate limits, sandboxing, and approval requirements.
- **State and memory:** Keeps durable task state separate from long-lived knowledge. Persist artifacts, decisions, evidence, and checkpoints—not unverified model assertions.
- **Controls:** Applies permissions, policy checks, resource budgets, network boundaries, human approvals, and separation of duties.
- **Verification:** Uses deterministic tests where possible, then independent checks or evaluators for ambiguity. The agent should not be its own sole judge.
- **Observability:** Records prompts, selected context, tool calls, outputs, model/provider versions, policy decisions, artifacts, and outcome metrics for audit and debugging.  
Martin Fowler frames the controls particularly well as **guides** and **sensors**: guides steer the agent before action (instructions, constraints, tool schemas, policies), while sensors observe its work afterward and trigger correction (tests, linters, reviewers, monitors).  

## Designing the Control Loop

Start with a narrow, observable workflow rather than a general autonomous agent:

1. **Receive a bounded task.** Convert it into a machine-readable contract: in-scope assets, prohibited actions, evidence standard, maximum cost, and exit criteria.
2. **Build a context packet.** Retrieve only authoritative materials needed for the next decision; label source and freshness.
3. **Plan and authorize.** Let the model propose actions, but have the harness determine whether each action is allowed under the active policy.
4. **Execute through tools.** Never permit direct implicit access to sensitive systems. Every operation should flow through a brokered, typed interface.
5. **Validate independently.** For example, a security finding needs reproducible evidence, severity rationale, and a validator result—not merely a detector claim.
6. **Update durable state.** Store evidence and decision records, then iterate only while coverage, yield, budget, and safety constraints allow.
7. **Produce an auditable outcome.** Emit a result with confidence, provenance, unresolved uncertainty, and a clear completion or escalation status.

The key design principle is: **make high-risk behavior deterministic at the boundary, even when reasoning inside the boundary is probabilistic.**

## Security Architecture

For security-sensitive agents, use defense in depth:

| Concern | Harness control |
|---|---|
| Prompt injection | Treat retrieved and tool-returned text as untrusted data; isolate instructions from content; restrict tool authority independently of model output. |
| Excessive privileges | Give tools scoped, short-lived identities; separate read, write, and destructive capabilities. |
| Data exfiltration | Apply egress allowlists, output filtering, data classification, secret detection, and isolated execution environments. |
| Unsafe tool use | Use typed APIs, schema validation, dry-run modes, transaction limits, and approvals for consequential actions. |
| False findings | Require evidence capture, reproducibility checks, independent validation, and provenance. |
| Runaway cost or loops | Enforce tool-call, token, time, retry, and monetary budgets with deterministic termination. |
| Audit gaps | Log the full action lineage, including inputs, context sources, tool responses, authorization decisions, and artifact hashes. |

Avoid relying solely on a system prompt for any control that protects production systems or sensitive data. Prompt rules are guides; the harness must enforce the boundary with permissions, isolation, and policy gates.

## Evaluation-Driven Development

A harness should be improved through behavioral evaluation, not intuition alone. Begin with one observed failure mode, encode a test that captures the desired safe outcome, run it repeatedly, and measure regression over time. For simple tasks, use precise assertions such as whether an agent invoked a required validation tool; for complex tasks, evaluate the final outcome and safety properties rather than forcing one tool sequence. Aggregate results across repeated runs because agent behavior is nondeterministic.  

Useful metrics include:

- **Task success rate:** Did the workflow meet its explicit completion criteria?
- **Verified-finding precision:** What fraction of reported findings survive independent validation?
- **Coverage:** What fraction of defined assets, attack surfaces, or test objectives were assessed?
- **Unsafe-action rate:** How often were policies violated, approvals bypassed, or harmful actions attempted?
- **Human-intervention rate:** How often must an operator repair, redirect, or reject the result?
- **Time and cost per verified outcome:** Measure economic yield, not just tokens or tool calls.
- **Evidence completeness:** Can a reviewer reproduce every material conclusion?

## Cisco Foundry Security Spec

[Cisco’s **Foundry Security Spec**](https://blogs.cisco.com/ai/announcing-foundry-security-spec) is an open-source, model- and stack-agnostic blueprint for building an agentic security-evaluation system. Cisco describes it as a seed specification designed to be used with GitHub’s `spec-kit`, where an AI agent can help implement an architecture suited to the organization’s environment. 

Its stated emphasis is not “ask a model to find vulnerabilities,” but engineer a harness that yields a **bounded, prioritized, verifiable** finding set; has an explicit completion signal; retains a provenance chain from detection through publication; and constrains unsafe behavior in the underlying substrate rather than trusting prompts alone. 

Foundry publishes two principal artifacts:

- A **[specification](https://blogs.cisco.com/ai/announcing-foundry-security-spec)** describing eight core agent roles, five extension roles, a finding lifecycle, a coordination substrate, and roughly 130 functional requirements with rationales.  
- A **[constitution](https://github.com/CiscoDevNet/foundry-security-spec/blob/main/constitution.md)** of eleven non-negotiable principles intended to survive changes in infrastructure, model provider, and deployment pattern.  
The eight core roles are **Orchestrator, Indexer, Cartographer, Detector, Triager, Validator, Coverage Guide, and Reporter**. This decomposition is valuable because it separates discovery, analysis, adjudication, coverage management, and communication—reducing the temptation to let one unconstrained agent discover, declare, and publish its own conclusions. 

## Applying Foundry’s Pattern

A practical secure-code evaluation workflow based on this pattern looks like:

1. **Indexer:** Build a searchable, versioned inventory of source, dependencies, configuration, build artifacts, and existing security signals.
2. **Cartographer:** Convert the inventory into attack-relevant structure: trust boundaries, entry points, sensitive sinks, identity flows, data paths, and exposed services.
3. **Detector:** Apply targeted detection rules and agent-led investigations to likely risk areas.
4. **Triager:** Deduplicate, prioritize, connect evidence, and distinguish hypotheses from credible findings.
5. **Validator:** Reproduce or falsify each candidate under explicitly safe testing conditions.
6. **Coverage Guide:** Tracks what has and has not been assessed, then directs remaining work toward material gaps.
7. **Reporter:** Creates consumable findings with evidence, impact, affected scope, remediation guidance, and uncertainty.
8. **Orchestrator:** Enforces budgets, schedules work, applies gates, and determines whether the done criteria have been met.

This architecture is especially suitable for large repositories and continuous evaluation pipelines, where “the agent found some issues” is not an operationally meaningful output. The desired output is a defensible queue of validated work, accompanied by coverage and cost signals.

## Build Checklist

Before deploying an AI harness, verify:

- Define a task contract and deterministic stop conditions.
- Model every tool as a capability with a typed schema and least-privilege identity.
- Separate untrusted content from control instructions.
- Require durable evidence for every consequential claim.
- Separate detection from validation and reporting.
- Implement approval gates for external, destructive, or high-impact actions.
- Bound tokens, runtime, tool calls, retries, concurrency, and financial cost.
- Maintain tamper-evident logs and artifact provenance.
- Build an evaluation corpus from real failures, near misses, and adversarial cases.
- Continuously measure verified yield, coverage, safety, and operator burden.

A strong harness does not merely make an agent more capable; it makes its work **bounded, inspectable, correctable, and governable**. Cisco’s Foundry Security Spec is a concrete example of applying that idea to high-stakes security evaluation at scale.  


## Deterministic Validation

**Deterministic validation** means checking agent outputs with rules or tools that produce the same pass/fail result for the same input. It should protect correctness and safety boundaries—rather than asking the model to judge its own work. Typical checks include JSON-schema validation, authorization decisions, policy enforcement, artifact hashes, required evidence, and test execution.  

For a security agent, define a finding as *publishable* only if it has:

- A valid structured finding schema.
- An in-scope asset identifier.
- Reproducible evidence or a test artifact.
- A severity within an allowed taxonomy.
- Provenance linking claim, source, tool execution, and artifact.
- A validator result of `pass`, `fail`, or `needs_human_review`—never an unqualified model assertion. Cisco Foundry explicitly separates detector, triage, validator, and reporter roles, supporting this separation of claim generation from claim verification.  
## What to Unit Test

Unit-test the harness—not free-form reasoning. Keep components pure or mock their nondeterministic dependencies.

| Component | Deterministic assertion |
|---|---|
| Tool gateway | Correct tool is authorized; argument object matches schema; secrets never appear in arguments or logs |
| Policy engine | An action is allowed, denied, or approval-gated for a known identity, asset, and risk tier |
| State machine | Valid transitions succeed; invalid transitions are rejected; terminal states cannot resume |
| Budget manager | Token, cost, retry, runtime, and tool-call limits terminate execution predictably |
| Context builder | Only permitted sources enter the context packet; source labels and freshness metadata are retained |
| Evidence validator | A claim without reproducible evidence cannot advance to reporting |
| Finding lifecycle | Only `validated` findings can be published; rejected findings cannot be silently revived |
| Output guard | Output conforms to a versioned JSON schema and required fields are populated |

Testing tool selection, argument construction, response format, and state-machine transitions in isolation is a recommended fast, deterministic layer before integration testing.  

## Example Test Pattern

Write each test around an invariant, not the model’s prose. For example:

```python
def test_high_impact_action_requires_approval():
    decision = policy.authorize(
        principal="agent:detector",
        action="create_pull_request",
        target="repo:payments",
        risk_tier="high",
        approval=None,
    )

    assert decision.status == "approval_required"
    assert decision.execution_permitted is False
```

For a validated security finding:

```python
def test_unreproducible_finding_cannot_publish():
    finding = Finding(
        id="F-1001",
        status="triaged",
        evidence=[],
        severity="high",
    )

    result = validator.validate(finding)

    assert result.status == "needs_human_review"
    assert reporter.is_publishable(finding, result) is False
```

The intention is not to test whether an LLM “understands security.” It is to prove that the harness refuses an unsafe or unsupported state transition.

## Test Pyramid

Use increasingly expensive layers:

1. **Unit tests:** Mock model and tools; test policies, parsers, routing, budgets, state, schemas, and provenance.
2. **Contract tests:** Verify each real tool/API still honors its schema, authentication behavior, error model, and idempotency assumptions.
3. **Integration tests:** Exercise multi-component flows with sandboxed tools and fixed fixtures.
4. **Trajectory tests:** Assert essential behaviors, such as “the agent ran a validator before completion,” without over-constraining every legitimate path.
5. **End-to-end and adversarial tests:** Run against realistic repositories, injected malicious content, denied permissions, stale data, timeouts, and conflicting evidence.

Behavioral evaluations should assert intermediate observable behavior—such as a required tool call or a created file—rather than exact natural-language output. For complex tasks, assess safe successful outcomes rather than one rigid sequence, and use repeated runs to measure stability. 

## First Engineering Step

Pick one agent failure that would be unacceptable in production and turn it into a failing unit test. A strong starting invariant for a Foundry-like security workflow is:

$$
publish(f) \Rightarrow validated(f) \land evidence-complete(f) \land provenance-complete(f)
$$

That makes “no evidence, no publication” a property enforced by code, not a preference stated in a prompt.  

Which invariant in your current agent workflow would cause the greatest damage if it were violated?
