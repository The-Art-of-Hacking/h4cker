# Module 11 — Red Team and Vulnerability-Discovery Agents (with Foundry's Detector and Validator)

## 11.1 Learning objectives

- Build vulnerability-discovery agents grounded in the Foundry Detector/Validator pattern.
- Use detection-rule corpora (CodeGuard) plus exploratory hunting.
- Understand the legal and authorization constraints that bound red-team agents.
- Recognize the dual-use nature of this material and operate within it responsibly.

## 11.2 The premise

The most consequential agentic security work of 2026 is not chatbots — it is autonomous (or human-supervised) vulnerability discovery. Microsoft's MDASH and Anthropic's prior systems showed that coordinated agents find real, novel vulnerabilities at scale. Cisco's Foundry Security Spec is the open-source distillation of what a *trustworthy* such system looks like.

Two constraints govern everything that follows:

1. **Authorization.** Vulnerability-discovery agents only operate against software you are explicitly authorized to evaluate. The Foundry spec assumes "authorized eval with source access." If you cannot say yes to that, do not run the system.
2. **Human as final arbiter.** Findings are proposed by agents and confirmed by humans. The reverse fails badly.

## 11.3 What Foundry's Detector and Validator actually do

Recap from Module 8:

- **Detector (§5.4)** — sweeps the target against a corpus of LLM-evaluated detection rules. Systematic, repeatable, finds what we already know to look for. CodeGuard is one rule format that satisfies the spec.
- **Validator (§5.6)** — the evidence gate. A claimed finding without evidence does not exist. The Validator confirms or refutes via reproduction, proof construction, or counter-example.

A Detector without a Validator is the "wall of unverifiable findings" failure mode. A Validator without a Detector is a slow, manual review. Together they produce a stream of confirmed, evidenced findings.

## 11.4 A minimal Detector design

A Detector loop, in pseudocode:

```python
for rule in rule_corpus:                        # the corpus is CodeGuard or similar
    for unit in indexer.units(rule.language):   # functions / classes / files
        verdict = llm.evaluate(rule, unit)      # structured output: hit / no-hit / unclear
        if verdict.is_hit:
            finding = Finding(
                rule_id=rule.id,
                location=unit.location,
                evidence=verdict.evidence,
                provenance=Provenance(model, rule_version, run_id, ts),
            )
            substrate.submit(finding)
```

Things to notice:

- The rule corpus drives the loop, not the LLM's curiosity. This is what makes detection reproducible.
- Evidence is structured (which lines, which dataflow, which control).
- Provenance is captured at submission.
- Submission is to a substrate (queue + store), not directly to a downstream agent.

Exploratory hunting — the Variant-Hunter and Deep-Tester extensions — runs *alongside* the rule sweep. They contribute findings into the same substrate.

## 11.5 A minimal Validator design

```python
def validate(finding: Finding) -> ValidationVerdict:
    # 1. Reproduce the conditions
    reproduction = reproduction_runner.run(finding.location, finding.evidence)
    # 2. Construct or counter-construct a proof
    proof = proof_constructor.attempt(finding, reproduction)
    if proof.holds:
        return ValidationVerdict(state="confirmed", evidence=[reproduction, proof])
    if proof.refuted:
        return ValidationVerdict(state="refuted",  evidence=[reproduction, proof])
    return ValidationVerdict(state="inconclusive", evidence=[reproduction], needs_human=True)
```

The Validator is the constitutional principle in code: *findings without evidence do not exist*. Anything `inconclusive` is *not* a finding — it is an investigation, kicked to a human or to Deep-Tester.

## 11.6 Detection-to-prevention flywheel — the practical loop

Reprised from Module 8 because this is the operating loop of a Foundry-style system:

1. CodeGuard rules sweep every function. Catches the known.
2. Exploratory agents hunt. Catches the unknown.
3. When exploration confirms something the rules missed, record a **rule gap**.
4. The gap is generalized into a CodeGuard rule.
5. Next sweep catches the class on the first pass.
6. The same rule loads into developer IDEs as a *prevention* control before the next evaluation runs.

The first time you watch this loop tighten on a real target, the value of the spec becomes obvious.

## 11.7 Red-team agents — adversarial emulation

A different shape than vulnerability discovery: red-team agents emulate adversaries against a defended environment, typically as part of purple-team exercises.

A useful architecture:

- **Campaign supervisor** — selects ATT&CK techniques per the engagement plan.
- **Technique workers** — one per technique (initial access, persistence, lateral movement, etc.), each with a narrow toolbelt.
- **Detection-mirror** — watches what the blue team detects in real-time and feeds it to the supervisor.
- **Boundary enforcer** — a hard substrate that refuses to launch any technique against assets outside the engagement scope.

The boundary enforcer is the security control that lets you sleep at night. Make it a substrate-level allow-list (target IPs, target accounts, target time window). The agent cannot reason it away.

## 11.8 Dual-use and ethics

This material is dual-use. The same agent that hardens your software can be repurposed against software you are not authorized to test. The course's stance is:

- Build these systems only against assets you own or are explicitly authorized to evaluate.
- Treat scope rules as inviolable; encode them in the substrate.
- Keep humans as the final arbiter for any irreversible action (publication, disclosure, exploitation attempt outside a sandbox).
- Disclose responsibly via the affected vendor's coordinated-disclosure process.

The Foundry spec is explicit about this: it is a starting point for *authorized* security evaluation. The responsibility for implementation, oversight, and final decision-making remains with the operator.

## 11.9 Hands-on Lab 11 — Build a Detector + Validator pair

[`labs/lab11-detector-validator/`](../labs/lab11-detector-validator/):

1. Take a small open-source target you are authorized to evaluate (we provide a vulnerable-by-design sample).
2. Use a tiny CodeGuard-style rule corpus (3–5 rules — SQLi, command injection, SSRF, IDOR, hard-coded secret).
3. Implement the Detector loop in 11.4 with structured LLM outputs.
4. Implement the Validator with a reproduction harness (a sandboxed Python runner).
5. Record provenance and write each confirmed finding as a Reporter-style markdown file with title, severity, evidence, reproduction, remediation, references.
6. Identify one finding the rules missed that exploration found. Generalize it into a new rule. Re-run. Verify the rule catches it the second time.

This is the smallest possible end-to-end Foundry-aligned system. Build it once and the rest of the spec becomes concrete.

## 11.10 Exercises

1. Pick three CWE classes most relevant to your stack. Sketch the CodeGuard-style rule for one.
2. Where does indirect prompt injection get into a Detector loop? Trace the path and the defense.
3. Design a "Deep-Tester" extension for the lab. What does it do that the Detector does not?
4. Write a one-paragraph "engagement scope" you would feed to a substrate-level boundary enforcer for a red-team agent.

## 11.11 Further reading

- Foundry Security Spec, §5.4 (Detector) and §5.6 (Validator).
- [Project CodeGuard](https://project-codeguard.org/).
- Microsoft, *AI Red Teaming Agent* — Azure Foundry documentation.
- *A Red Teaming Framework for Evaluating Robustness of AI-enabled Security Orchestration, Automation, and Response Systems*, arXiv 2026.

---

Previous: [Module 10](10-blue-team-agents.md) · Next: [Module 12 — Observability, Evaluation, and Continuous Red-Teaming](12-observability-evaluation.md).
