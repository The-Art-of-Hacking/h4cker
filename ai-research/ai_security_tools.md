# AI Security Tools

This is a work in progress, curated list of AI Security tools:

## Open Source Tools for AI Red Teaming

### Predictive AI
- [The Adversarial Robustness Toolbox (ART)](https://github.com/Trusted-AI/adversarial-robustness-toolbox)
- [Armory](https://github.com/twosixlabs/armory)
- [Foolbox](https://github.com/bethgelab/foolbox)
- [DeepSec](https://github.com/ryderling/DEEPSEC)
- [TextAttack](https://github.com/QData/TextAttack)

### Generative AI
- [PyRIT](https://github.com/Azure/PyRIT)
- [Garak](https://github.com/NVIDIA/garak)
- [Prompt Fuzzer](https://github.com/prompt-security/ps-fuzz)
- [Guardrail](https://github.com/guardrails-ai/guardrails)
- [Promptfoo](https://github.com/promptfoo/promptfoo)
- [PlexyGlass](https://github.com/safellama/plexiglass)
-  [PurpleLlama](https://github.com/facebookresearch/PurpleLlama)
-  [jailbreak-evaluation](https://github.com/controllability/jailbreak-evaluation)

## Prompt Firewall and Redaction

_Products that intercept prompts and responses and apply security or privacy rules to them. We've blended two categories here because some prompt firewalls just redact private data (and then reidentify in the response) while others focus on identifying and blocking attacks like injection attacks or stopping data leaks. Many of the products in this category do all of the above, which is why they've been combined._

- [Cisco AI Defense](https://www.cisco.com/site/us/en/products/security/ai-defense/index.html) - Model Evaluation, monitoring, guardrails, inventory, AI asset discovery, and more.
- [Robust Intelligence AI Firewall](https://www.robustintelligence.com/) - Now part of Cisco.
- [Protect AI Rebuff](https://playground.rebuff.ai) - A LLM prompt injection detector. [![code](https://img.shields.io/github/license/protectai/rebuff)](https://github.com/protectai/rebuff/)
- [Protect AI LLM Guard](https://protectai.com/llm-guard) - Suite of tools to protect LLM applications by helping you detect, redact, and sanitize LLM prompts and responses. [![code](https://img.shields.io/github/license/protectai/llm-guard)](https://github.com/protectai/llm-guard/)
- [HiddenLayer AI Detection and Response](https://hiddenlayer.com/aidr/) - Proactively defend against threats to your LLMs.

- [Vigil LLM](https://github.com/deadbits/vigil-llm) - Detect prompt injections, jailbreaks, and other potentially risky Large Language Model (LLM) inputs. ![code](https://img.shields.io/github/license/deadbits/vigil-llm)
- [Lakera Guard](https://www.lakera.ai/lakera-guard) - Protection from prompt injections, data loss, and toxic content.
- [Arthur Shield](https://www.arthur.ai/product/shield) - Built-in, real-time firewall protection against the biggest LLM risks.
- [Prompt Security](https://www.prompt.security) - SDK and proxy for protection against common prompt attacks.
- [Private AI](https://www.private-ai.com) - Detect, anonymize, and replace PII with less than half the error rate of alternatives.
- [DynamoGuard](https://dynamo.ai/platform/dynamoguard) - Identify / defend against any type of non-compliance as defined by your specific AI policies and catch attacks.
- [Skyflow LLM Privacy Vault](https://www.skyflow.com/product/llm-privacy-vault) - Redacts PII from prompts flowing to LLMs.
- [Guardrails AI](https://www.guardrailsai.com) - Guardrails runs Input/Output Guards in your application that detect, quantify and mitigate the presence of specific types of risks. [![code](https://img.shields.io/github/license/guardrails-ai/guardrails)](https://github.com/guardrails-ai/guardrails/)

## AI Red Teaming Guidance
- [OWASP's GenAI Red Teaming Guide](https://genaisecurityproject.com/resource/genai-red-teaming-guide/) - guide includes four areas: model evaluation, implementation testing, infrastructure assessment, and runtime behavior analysis.
- [OWASP's List of AI Security Tools](https://owaspai.org/docs/5_testing/#open-source-tools-for-predictive-ai-red-teaming)
- [Guidance from the OWASP Generative AI Security Project](https://genai.owasp.org/initiatives/#ai-redteaming)
- [Guidance from CSA](https://cloudsecurityalliance.org/artifacts/agentic-ai-red-teaming-guide)

## AI Red Teaming Datasets
- [AttaQ Dataset](https://huggingface.co/datasets/ibm/AttaQ) - a red teaming dataset consisting of 1402 carefully crafted adversarial questions
- [HarmBench: A Standardized Evaluation Framework for Automated Red Teaming and Robust Refusal](https://arxiv.org/pdf/2402.04249)

## Julia AI Security Tools

- [Oracle](https://github.com/bad-antics/oracle) - AI-powered vulnerability prediction framework using GNN-based pattern recognition, CVE trend analysis, and CVSS scoring. Integrates NVD, MITRE ATT&CK, and EPSS data.
