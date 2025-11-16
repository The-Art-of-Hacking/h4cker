## Model and GenAI Application Security Testing

This file is an entry point for **testing the security of AI/ML models and GenAI applications**. Use it together with:

- `ai_security_tools.md` – curated list of offensive and defensive AI security tools.
- `ai_risk_management/README.md` – governance, regulatory, and risk management frameworks.
- `prompt_injection/README.md` – prompt injection, jailbreak techniques, and defenses.
- `training_environment_security/README.md` – securing training and fine‑tuning environments.

### 1. Core Guidance and Taxonomies

- [OWASP GenAI Security Project](https://genai.owasp.org/)
  - **LLM Top 10 (2025)** – primary risk taxonomy for LLM and GenAI applications.
  - **AI Security Landscape** and **Solutions Reference Guide (Q2–Q3 2025)** – map risks to available controls.
  - **Threat Defense COMPASS 1.0** – consolidated view of threats, vulnerabilities, defenses, and mitigations that can be used as a checklist for model/application testing.
- [OWASP AI Security and Privacy Guide](https://owasp.org/www-project-ai-security-and-privacy-guide/)
- [OWASP Machine Learning Security Top 10](https://mltop10.info/)

### 2. Risk Maps and Secure Design Patterns

- [Coalition for Secure AI (CoSAI)](https://github.com/cosai-oasis)
  - [CoSAI Risk Map / Secure AI Tooling](https://github.com/cosai-oasis/secure-ai-tooling) – risk mapping and control framework for AI systems.
  - [Workstream 4 – Secure Design Patterns for Agentic Systems](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems) – secure patterns for autonomous/agentic workflows.
  - [Workstream 1 – Software Supply Chain Security for AI Systems](https://github.com/cosai-oasis/ws1-supply-chain) – guidance for model/dataset/supply-chain security.

### 3. Practical Testing and Tooling

See `ai_security_tools.md` for:

- **Adversarial robustness tools** (ART, Armory, Foolbox, TextAttack, etc.).
- **GenAI red teaming tools** (PyRIT, Garak, Promptfoo, Guardrail(s), jailbreak evaluation suites).
- **Prompt firewalls and redaction tools** (Cisco AI Defense, Robust Intelligence, Lakera Guard, Rebuff, LLM Guard, etc.).

These support:

- **Pre‑deployment testing** – evasion, data leakage, jailbreaks, prompt injection.
- **Runtime testing** – continuous red teaming, regression testing for guardrails, and monitoring false positives/negatives (see `monitoring.md` for observability tools like LangSmith, Langfuse, OpenLLMetry, and Graphsignal).

