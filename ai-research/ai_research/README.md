# AI Research for Cybersecurity

This directory brings together **AI, LLMs, and cybersecurity** resources, with a focus on:

- **Using AI for security** (incident response, log analysis, RAG for cyber, open‑interpreter, labs)
- **Securing AI systems** (AI risk management, red teaming, prompt injection, training environment security)
- **Foundations and frameworks** (ML fundamentals, LangChain, RAG, LLM frameworks, vector databases)

Use this file as the **navigation hub** for everything under `ai-research`.

---

## How this directory is organized

- **Foundations & ML fundamentals**
  - `ML_Fundamentals/` – core ML/AI concepts, terminology, datasets, and evaluation.
  - `datasets.rst` – large curated list of public datasets for AI/ML work.

- **Frameworks, tooling & labs**
  - `LangChain/` – tools, learning resources, RAG examples, and agent patterns. See `LangChain/README.md`.
  - `LLM-frameworks/` – overview of popular LLM and agent frameworks (Autogen, Haystack, Semantic Kernel, etc.).
  - `ollama-labs/` – complete hands-on lab path for running and building with local models via Ollama.
  - `labs/` – additional ML/LLM labs (OpenAI API basics, Gorilla, scikit-learn, TensorFlow/Keras, NLTK).
  - `open-interpreter-examples/` – examples of AI-assisted recon and automation using Open Interpreter.
  - `ai_coding_tools.md` – comparison table of modern AI coding assistants and agentic IDEs.

- **Securing AI systems (AI security, red teaming & risk management)**
  - `ai_security_tools.md` – curated list of AI security tools (red teaming, firewalls, guardrails, datasets).
  - `ai_algorithmic_red_teaming/` – methodology and visuals for AI red teaming and systemic risk testing.
  - `ai_risk_management/` – NIST AI RMF, EU AI Act, ISO 42001/23894, CSA guidance, and sector-specific risk resources.
  - `training_environment_security/` – securing AI/ML training and fine-tuning environments.
  - `prompt_injection/` – overview of prompt injection classes, techniques, and references to attack resources.
  - `model_security_testing.md` – short entry point to model/application security testing topics.
  - `monitoring.md` – monitoring, observability, and detection tools for AI systems.
  - `AI for Incident Response/` – GPT‑4o-based log analysis tool and lab for incident response.

- **Prompt engineering, RAG, GPTs & vector databases**
  - `prompt_engineering.md` – long-form guide to prompt engineering patterns, tools, and learning resources.
  - `prompt_engineering/` – practical prompt assets, including the bug bounty prompt generator.
  - `RAG/` – RAG architecture patterns, pitfalls, evaluation, and security aspects; tied to the RAG for Cybersecurity course.
  - `vector_databases/` – overview of vector DBs and security hardening references.
  - `GPTs/` – curated list of cybersecurity GPT agents and Colab notebooks.

- **Ethics, privacy, and governance**
  - `ethics_privacy/` – AI ethics, privacy, and dataset considerations (including human activity datasets).

- **Presentations and supporting material**
  - `presos/` – slide decks and PDFs used in trainings and conference talks.

---

## Quick start: recommended paths

- **If you are new to AI security**
  - Start with `ai_risk_management/README.md` for global frameworks (NIST AI RMF, EU AI Act, ISO 42001).
  - Then read `ai_security_tools.md` for hands-on tools and references.
  - Finish with `prompt_injection/README.md` and `training_environment_security/README.md` for concrete attack and defense techniques.

- **If you want to build secure AI/RAG apps**
  - Work through `LangChain/README.md`, `RAG/README.md`, and `vector_databases/README.md`.
  - Use the labs in `labs/` and `ollama-labs/` to get practical skills with APIs, local models, tool-calling, and vision.

- **If you want AI-assisted security operations**
  - See `AI for Incident Response/README.md` for log analysis with GPT‑4o.
  - Explore `open-interpreter-examples/` and `GPTs/README.md` for AI agents that support recon and security workflows.

---

## Key topical resource hubs

### LangChain, RAG, and vector databases

- `LangChain/README.md` – curated links to LangChain, LangGraph, evaluation tools, and production patterns.
- `RAG/README.md` – deep dive into RAG disadvantages, retrieval strategies, guardrails, and evaluation.
- `vector_databases/README.md` – overview of MongoDB Atlas Vector Search, Faiss, Milvus, Weaviate, Chroma, and security hardening:
  - Cisco whitepaper on securing vector databases
  - Milvus and MongoDB security references

You can also use the external **RAG for Cybersecurity** repository:

- [RAG for Cybersecurity course repository](https://github.com/santosomar/RAG-for-cybersecurity)

### AI security, risk management, and red teaming

- `ai_security_tools.md` – open source red teaming tools (e.g., ART, Armory, Foolbox, TextAttack, PyRIT, Garak, Promptfoo, Guardrails, PurpleLlama, jailbreak-evaluation) and commercial prompt firewalls/guards.
- `ai_algorithmic_red_teaming/README.md` – attack categories, evaluation metrics, and test surfaces, plus:
  - [OWASP Generative AI Security Project red teaming guidance](https://genai.owasp.org/initiatives/#ai-redteaming)
  - [Cloud Security Alliance Agentic AI Red Teaming Guide](https://cloudsecurityalliance.org/artifacts/agentic-ai-red-teaming-guide)
- `ai_risk_management/README.md` – AI risk frameworks and governance:
  - NIST AI RMF and US AI Safety Institute
  - EU AI Act and global governance frameworks
  - CSA, MITRE ATLAS, OWASP ML/LLM security lists
  - Sector-specific guidance (financial services, healthcare, automotive)
- `training_environment_security/README.md` – threats and mitigations for data poisoning, supply chain, model theft, IP protection, and infrastructure security.
- `prompt_injection/README.md` – taxonomy of prompt injection techniques, OWASP LLM Top 10 mappings, and links to prompt injection tools/lists.
- `model_security_testing.md` – entry point reference to broader model testing content in this repo.

---

## AI Security Resources from Omar's Training Sessions

This section provides a curated list of resources frequently referenced in O'Reilly live courses and workshops.

### Live training

- **Upcoming Live Cybersecurity and AI Training on O'Reilly**  
  [Browse and register](https://learning.oreilly.com/search/?q=omar%20santos&type=live-course&rows=100&language_with_transcripts=en) (free with an O'Reilly subscription).

### Reading list

These books provide a roadmap for understanding how AI, cybersecurity, privacy, and governance intersect:

- **Redefining Hacking**
  A comprehensive guide to red teaming and bug bounty in an AI‑driven world.  
  [Available on O'Reilly](https://learning.oreilly.com/library/view/redefining-hacking-a/9780138363635/)

- **Developing Cybersecurity Programs and Policies in an AI‑Driven World**  
  Strategies for building robust cybersecurity programs that account for AI risk.  
  [Available on O'Reilly](https://learning.oreilly.com/library/view/developing-cybersecurity-programs/9780138073992)

- **Beyond the Algorithm: AI, Security, Privacy, and Ethics**  
  Explores ethical, privacy, and security challenges in AI systems.  
  [Available on O'Reilly](https://learning.oreilly.com/library/view/beyond-the-algorithm/9780138268442)

- **The AI Revolution in Networking, Cybersecurity, and Emerging Technologies**  
  How AI is transforming networking, security operations, and adjacent emerging tech.  
[Available on O'Reilly](https://learning.oreilly.com/library/view/the-ai-revolution/9780138293703)

### Video courses

Hands-on courses to deepen practical cybersecurity and AI skills:

- **Building the Ultimate Cybersecurity Lab and Cyber Range (video)**  
  [Available on O'Reilly](https://learning.oreilly.com/course/building-the-ultimate/9780138319090/)

- **AI‑Enabled Programming, Networking, and Cybersecurity**  
  Learn to use AI for cybersecurity, networking, and programming tasks with practical demos.  
[Available on O'Reilly](https://learning.oreilly.com/course/ai-enabled-programming-networking/9780135402696/)

- **Securing Generative AI**
  Security for deploying and developing AI applications, RAG, agents, and ML systems end‑to‑end.  
[Available on O'Reilly](https://learning.oreilly.com/course/securing-generative-ai/9780135401804/)

- **Practical Cybersecurity Fundamentals**  
  Comprehensive coverage of foundational cybersecurity concepts.  
  [Available on O'Reilly](https://learning.oreilly.com/course/practical-cybersecurity-fundamentals/9780138037550/)

- **The Art of Hacking**  
  A series of video courses with 26+ hours of ethical hacking and penetration testing content, useful context for AI‑augmented offensive and defensive operations.  
  [Visit The Art of Hacking](https://theartofhacking.org)

---

## Awesome lists and external research

Use these to stay current with the broader AI/LLM research ecosystem:

- [Awesome-LLM](https://github.com/Hannibal046/Awesome-LLM) – large collection of GenAI and LLM resources.
- [Awesome ChatGPT Prompts](https://github.com/f/awesome-chatgpt-prompts) – prompt examples for ChatGPT‑style models.
- [awesome-chatgpt-prompts-zh](https://github.com/PlexPt/awesome-chatgpt-prompts-zh) – Chinese prompt collection.
- [Awesome ChatGPT](https://github.com/humanloop/awesome-chatgpt) – curated resources for ChatGPT and GPT‑3/4.
- [Chain-of-Thoughts Papers](https://github.com/Timothyxxx/Chain-of-ThoughtsPapers) – chain‑of‑thought prompting research.
- [LLM Reading List](https://github.com/crazyofapple/Reading_groups/) – broader LLM paper list.
- [Reasoning using Language Models](https://github.com/atfortes/LM-Reasoning-Papers) – reasoning‑focused LLM research.
- [Chain-of-Thought Hub](https://github.com/FranxYao/chain-of-thought-hub) – chain‑of‑thought benchmarking and evaluation.
- [Awesome GPT](https://github.com/formulahendry/awesome-gpt) – GPT/ChatGPT/LLM tools and projects.
- [Awesome LLM Human Preference Datasets](https://github.com/PolisAI/awesome-llm-human-preference-datasets) – datasets for RLHF and preference learning.
- [ModelEditingPapers](https://github.com/zjunlp/ModelEditingPapers) – model editing resources.
- [Awesome LLM Security](https://github.com/corca-ai/awesome-llm-security) – tools, docs, and projects focused on LLM security.
- [Awesome-Align-LLM-Human](https://github.com/GaryYufei/AlignLLMHumanSurvey) – alignment with human preferences.
- [Awesome-Code-LLM](https://github.com/huybery/Awesome-Code-LLM) – code‑focused LLMs.
- [Awesome-LLM-Compression](https://github.com/HuangOwen/Awesome-LLM-Compression) – LLM compression research and tools.
- [Awesome-LLM-Systems](https://github.com/AmberLJC/LLMSys-PaperList) – LLM systems research papers.
- [awesome-llm-webapps](https://github.com/snowfort-ai/awesome-llm-webapps) – open‑source LLM web applications.
- [Stanford AI Index Report 2025](https://hai.stanford.edu/assets/files/hai_ai-index-report-2025_chapter1_final.pdf) – data‑driven overview of global AI trends, including safety and governance.

