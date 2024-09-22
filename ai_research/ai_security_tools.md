# AI Security Tools

This is a work in progress, curated list of AI Security tools:

## Model Testing
_Products that examine or test models for security issues of various kinds._

* [HiddenLayer Model Scanner](https://hiddenlayer.com/model-scanner/) - Scan models for vulnerabilities and supply chain issues.
* [Plexiglass](https://github.com/kortex-labs/plexiglass) - A toolkit for detecting and protecting against vulnerabilities in Large Language Models (LLMs). 
* [PurpleLlama](https://github.com/facebookresearch/PurpleLlama) - Set of tools from Meta to assess and improve LLM security. 
* [Garak](https://garak.ai/) - A LLM vulnerability scanner. [code](https://github.com/leondz/garak/)
* [CalypsoAI Platform](https://calypsoai.com/platform/) - Platform for testing and launching LLM applications securely.
* [Lakera Red](https://www.lakera.ai/ai-red-teaming) - Automated safety and security assessments for your GenAI applications.
* [jailbreak-evaluation](https://github.com/controllability/jailbreak-evaluation) - Python package for language model jailbreak evaluation. 
* [Patronus AI](https://www.patronus.ai) - Automated testing of models to detect PII, copyrighted materials, and sensitive information in models.
* [Adversa Red Teaming](https://adversa.ai/ai-red-teaming-llm/) - Continuous AI red teaming for LLMs.
* [Advai](https://www.advai.co.uk) - Automates the tasks of stress-testing, red-teaming, and evaluating your AI systems for critical failure.
* [Mindgard AI](https://mindgard.ai) - Identifies and remediates risks across AI models, GenAI, LLMs along with AI-powered apps and chatbots.
* [Protect AI ModelScan](https://protectai.com/modelscan) - Scan models for serialization attacks. [code](https://github.com/protectai/modelscan)
* [Protect AI Guardian](https://protectai.com/guardian) - Scan models for security issues or policy violations with auditing and reporting.
* [TextFooler](https://github.com/jind11/TextFooler) - A model for natural language attacks on text classification and inference.
* [LLMFuzzer](https://github.com/mnns/LLMFuzzer) - Fuzzing framework for LLMs.
* [Prompt Security Fuzzer](https://www.prompt.security/fuzzer) - a fuzzer to find prompt injection vulnerabilities.
* [OpenAttack](https://github.com/thunlp/OpenAttack) - a Python-based textual adversarial attack toolkit.

## Prompt Firewall and Redaction

_Products that intercept prompts and responses and apply security or privacy rules to them. We've blended two categories here because some prompt firewalls just redact private data (and then reidentify in the response) while others focus on identifying and blocking attacks like injection attacks or stopping data leaks. Many of the products in this category do all of the above, which is why they've been combined._

- [Protect AI Rebuff](https://playground.rebuff.ai) - A LLM prompt injection detector. [![code](https://img.shields.io/github/license/protectai/rebuff)](https://github.com/protectai/rebuff/)
- [Protect AI LLM Guard](https://protectai.com/llm-guard) - Suite of tools to protect LLM applications by helping you detect, redact, and sanitize LLM prompts and responses. [![code](https://img.shields.io/github/license/protectai/llm-guard)](https://github.com/protectai/llm-guard/)
- [HiddenLayer AI Detection and Response](https://hiddenlayer.com/aidr/) - Proactively defend against threats to your LLMs.
- [Robust Intelligence AI Firewall](https://www.robustintelligence.com/platform/ai-firewall-guardrails) - Real-time protection, automatically configured to address the vulnerabilities of each model.
- [Vigil LLM](https://github.com/deadbits/vigil-llm) - Detect prompt injections, jailbreaks, and other potentially risky Large Language Model (LLM) inputs. ![code](https://img.shields.io/github/license/deadbits/vigil-llm)
- [Lakera Guard](https://www.lakera.ai/lakera-guard) - Protection from prompt injections, data loss, and toxic content.
- [Arthur Shield](https://www.arthur.ai/product/shield) - Built-in, real-time firewall protection against the biggest LLM risks.
- [Prompt Security](https://www.prompt.security) - SDK and proxy for protection against common prompt attacks.
- [Private AI](https://www.private-ai.com) - Detect, anonymize, and replace PII with less than half the error rate of alternatives.
- [DynamoGuard](https://dynamo.ai/platform/dynamoguard) - Identify / defend against any type of non-compliance as defined by your specific AI policies and catch attacks.
- [Skyflow LLM Privacy Vault](https://www.skyflow.com/product/llm-privacy-vault) - Redacts PII from prompts flowing to LLMs.
- [Guardrails AI](https://www.guardrailsai.com) - Guardrails runs Input/Output Guards in your application that detect, quantify and mitigate the presence of specific types of risks. [![code](https://img.shields.io/github/license/guardrails-ai/guardrails)](https://github.com/guardrails-ai/guardrails/)

## AI Red Teaming Datasets
- [AttaQ Dataset](https://huggingface.co/datasets/ibm/AttaQ) - a red teaming dataset consisting of 1402 carefully crafted adversarial questions

## AI Red Teaming Guidance
- [HarmBench: A Standardized Evaluation Framework for Automated Red Teaming and Robust Refusal](https://arxiv.org/pdf/2402.04249)
