# AI Monitoring and Observability Tools

This file summarizes tools and frameworks for monitoring **models**, **data**, and **LLM/GenAI applications**, and connects them to modern guidance such as the OWASP GenAI Security Project and CoSAI.

## 1. Model Monitoring Tools

- [MLflow](https://mlflow.org/)
- [TensorFlow Extended (TFX)](https://www.tensorflow.org/tfx)
- [Seldon](https://www.seldon.io/)

## 2. Data Quality Tools

- [Great Expectations](https://greatexpectations.io/)
- [Deequ](https://github.com/awslabs/deequ)

## 3. Explainability and Interpretability Tools

- [SHAP (SHapley Additive exPlanations)](https://shap.readthedocs.io/en/latest/)
- [LIME (Local Interpretable Model-agnostic Explanations)](https://github.com/marcotcr/lime)

## 4. Ethical and Bias Monitoring Tools

- [IBM's AI Fairness 360](https://www.ibm.com/opensource/open/projects/ai-fairness-360/)
- [Google's What-If Tool](https://pair-code.github.io/what-if-tool/)

## 5. Performance and Infrastructure Monitoring

- [Nagios](https://www.nagios.org/)
- [Prometheus](https://prometheus.io/)

## 6. Security Monitoring, Red Teaming, and Prompt Injection

- [CleverHans](https://github.com/cleverhans-lab/cleverhans)
- [IBM Adversarial Robustness Toolbox (ART)](https://research.ibm.com/projects/adversarial-robustness-toolbox)
- [Rebuff](https://github.com/protectai/rebuff)
- [LMQL](https://lmql.ai/)
- [Robust Intelligence](https://www.robustintelligence.com/)

## 7. LLM/GenAI Application Observability

These tools provide **tracing, metrics, and evaluation** for LLM and GenAI applications:

- [LangSmith](https://smith.langchain.com/) – tracing, dataset-based evaluation, and debugging for LangChain/LangGraph and other LLM apps.
- [Langfuse](https://langfuse.com/) – open-source observability and analytics for LLM applications (traces, sessions, prompt experiments).
- [OpenLLMetry](https://github.com/traceloop/openllmetry) – open source observability for LLM apps based on OpenTelemetry, integrates with many backends.
- [Graphsignal](https://graphsignal.com/) – observability for AI agents and LLM-powered applications (latency, cost, error monitoring, and traces).
- [OrcaReplay](https://github.com/Continuum-AI-Corp/OrcaReplay) – records an agent run's raw provider traffic (prompts, tool calls, responses, raw bytes) into a local trace and replays it offline without contacting the provider again, so a suspicious or failed execution can be re-examined, diffed against another run, or forked onto a different model while the original evidence stays local and unmodified.
- [Tracekit](https://github.com/Cygnux-Labs/Tracekit) – an out-of-process signer that decides each AI agent tool call before it runs (allow, deny, or hold it for a person) and signs every call, decision and result into a per-run hash chain, so a responder can export a run as one bundle and verify it offline; an edited record fails verification. Caveats: the record only holds up against a compromised agent when the signer runs outside the agent's reach (another user, a container or another host); calls that bypass its hooks, adapters or gateway aren't recorded; the signed record holds hashes of call content, not the content; readable content (with known secrets redacted) is kept only when a signer's content vault is on, which it is for the default dev signer: it keeps redacted arguments and results locally for 7 days for its viewer (`TRACEKIT_DEV_CONTENT=0` keeps nothing). MIT.

These tools are a natural complement to the **OWASP GenAI Security Project – Threat Defense COMPASS** and **AI Security Solution Landscape**, which describe what to monitor and defend against at a risk level for GenAI applications ([OWASP GenAI Security Project](https://genai.owasp.org/)).

