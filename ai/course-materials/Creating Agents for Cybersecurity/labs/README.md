# Labs — Creating Agents for Cybersecurity

Each lab corresponds to a module in [`../modules/`](../modules/). Labs are runnable, progressive (a tool built in Lab 4 is reused in Lab 7), and intentionally compact — most should run in under 15 minutes once dependencies are installed.

## How to set up

Recommended Python: 3.11+. Use a virtual environment.

```bash
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install anthropic langchain langgraph crewai pyautogen "claude-agent-sdk" \
            chromadb sentence-transformers pydantic pandas networkx promptfoo deepeval
```

Set at least one provider key:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
# optional
export OPENAI_API_KEY=...
```

## Lab index

| Lab | Module | Title |
|---|---|---|
| `lab01-hello-agent/`              | 1  | Minimal ReAct security agent |
| `lab02-planner-executor/`         | 2  | Planner-Executor for log triage with typed plan |
| `lab03-threat-model/`             | 3  | Threat-model your own agent (STRIDE + ASI worksheet) |
| `lab04-langgraph-soc/`            | 4  | LangGraph SOC triage graph with HITL interrupt |
| `lab05-claude-mcp-threat-intel/`  | 5  | Claude Agent SDK + MCP threat-intel agent |
| `lab06-rag-kg/`                   | 6  | Vector RAG + knowledge-graph hybrid over CVE/MITRE |
| `lab07-crewai-autogen/`           | 7  | CrewAI crew vs. AutoGen group chat — phishing investigation |
| `lab08-foundry-scaffold/`         | 8  | Map Foundry's 8 roles to a runnable scaffold |
| `lab09-sandbox-budgets/`          | 9  | Sandboxing + budgets + tiered approval on the SOC agent |
| `lab10-blue-team-supervisor/`     | 10 | End-to-end blue-team supervisor with substrate |
| `lab11-detector-validator/`       | 11 | Foundry Detector + Validator pair on an authorized target |
| `lab12-promptfoo-deepteam/`       | 12 | Continuous eval and ASI Top 10 red-team battery |
| `lab13-capstone/`                 | 13 | Capstone scaffolding (your implementation) |

Each lab directory contains:

- `README.md` — task description and acceptance criteria.
- `solution/` — a worked example you can study after attempting the lab.
- `tests/` — minimal verification (where it makes sense).

> **Ethics and authorization.** Labs 11 and 13 involve security evaluation against deliberately vulnerable targets bundled with the lab. Do **not** point these labs at any system you are not explicitly authorized to evaluate. The Foundry Security Spec assumes "authorized evaluation with source access" and so do these labs.
