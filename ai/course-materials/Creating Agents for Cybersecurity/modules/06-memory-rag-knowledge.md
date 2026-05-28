# Module 6 — Memory, RAG, and Knowledge Graphs for Security Agents

## 6.1 Learning objectives

- Distinguish the four memory surfaces of an agent and decide which workload belongs where.
- Build a retrieval-augmented (RAG) pipeline over a security corpus (CVE, MITRE ATT&CK, internal policy).
- Build a small knowledge graph for attack-surface reasoning.
- Recognize and defend against **RAG poisoning** and **memory poisoning** (ASI04).

## 6.2 Four memory surfaces

| Surface | Lifespan | Typical store | Security concern |
|---|---|---|---|
| Context window | Single turn | The prompt itself | Token-bound; prompt injection lives here |
| Scratchpad / working state | Single run | In-process state (LangGraph state, agent variables) | State bloat; cross-step contamination |
| Episodic memory | Many runs, short-lived | Redis / SQLite, expiring | Stale facts; poisoned writes from low-trust sources |
| Semantic / long-term memory | Indefinite | Vector store + KG | Poisoning, exfiltration via retrieved content |

A useful rule: **the longer the memory lives, the more carefully you write to it.**

## 6.3 Retrieval-augmented generation, applied to security

The canonical RAG pattern:

```
question  ──▶ embed ──▶ vector search ──▶ top-k chunks ──▶ LLM(question + chunks) ──▶ answer
```

For security work, common corpora are:

- The MITRE ATT&CK and D3FEND catalogs.
- The NVD CVE database.
- Vendor advisories.
- Internal policy and runbooks.
- Past incident write-ups (your gold).
- Threat-intel feeds.

The trick that makes security RAG actually useful is **structured retrieval**. Don't just embed prose — embed (or filter by) CVE id, CWE class, ATT&CK technique id, asset id, time window. Hybrid (semantic + keyword) retrieval consistently beats pure semantic for security questions.

## 6.4 RAG poisoning — why your corpus is an attack surface

If an attacker can plant a document in your corpus that an LLM will later retrieve, they can inject instructions across every future query that retrieves it. This is **memory poisoning at the retrieval layer**, and it is one of the easiest attacks to overlook because there is no "moment of compromise" in the user session — the malicious content was planted long before.

Likely entry points:

- A scraped public feed that includes attacker-controlled content.
- A shared internal wiki anyone can edit.
- A ticketing system where free-form fields end up in the corpus.
- The output of a tool that an earlier agent run wrote.

Defenses:

- **Provenance tagging.** Every chunk carries `source`, `author`, `signed_by`, `ingest_time`. The system prompt tells the LLM how to treat each provenance level. (This is a soft control; it helps, but it is not sufficient.)
- **Quarantine on write.** Writes from low-trust sources land in a quarantine collection that is not retrieved into customer-facing queries until reviewed.
- **Retrieval filters.** Hard filters that exclude untrusted sources from sensitive query types.
- **Content sanitization.** Strip or escape suspicious patterns (`Ignore previous instructions`, hidden Unicode, etc.) on ingest. Imperfect, but it raises the bar.
- **Output inspection.** A second-model check that compares the answer to the retrieved chunks and flags answers that contain instructions or actions not derivable from the corpus.

For deep dives, see ASI04 (Memory Poisoning) in Module 3.

## 6.5 Embeddings — quick practical guide

For a security RAG you usually want:

- A strong general embedding model for prose (OpenAI `text-embedding-3-large`, Cohere `embed-v4`, or any modern open model).
- A **separate** keyword/BM25 index for IDs (CVE-YYYY-NNNN, ATT&CK T-codes, IP/CIDR, hashes). These do not benefit from embeddings.
- Hybrid retrieval: take top-k from each and rerank.

Chunking matters more than embedding choice. For CVE/advisory text, chunk per record with overlap; for runbooks, chunk per heading; for incident reports, treat each timeline entry as its own chunk with metadata.

## 6.6 Knowledge graphs for attack-surface reasoning

Vector RAG is great for "find me text that matches." It is bad for "what assets are exposed to vulnerability X and which services they reach." For that, you want a graph.

A minimal security KG schema:

```
(Asset)-[:RUNS]->(Service)
(Service)-[:USES]->(Component)
(Component)-[:HAS]->(Vulnerability)
(Vulnerability)-[:MAPS_TO]->(ATTACK_Technique)
(Asset)-[:OWNED_BY]->(Team)
(Asset)-[:TRUSTS]->(Asset)
```

Now you can ask: "given that component X has a new critical CVE, which exposed assets are affected and who owns them?" That is a graph traversal, not a vector search.

Agents that combine vector RAG + KG retrieval consistently beat either alone for security work. The KG provides structure; the vectors provide nuance.

Foundry's Cartographer role ([spec §5.3](https://github.com/CiscoDevNet/foundry-security-spec/blob/main/spec.md)) is essentially a KG-builder for a target: it produces architecture, attack-surface, trust-boundary, data-flow, and threat-model documents that downstream roles consume.

## 6.7 Episodic memory — the short-lived in-between

Between "context window" and "vector store" there is a useful in-between: per-incident, per-user, or per-target memory that lives long enough to be useful but is bounded in time.

Examples:

- During an incident, the agent remembers facts it learned this hour, but those facts expire when the incident is closed.
- For a long-running vulnerability evaluation (Foundry's intended use case), the agent has a *finding store* and a *coverage map* that are episodic to the evaluation.

Treat episodic memory like a session: encrypted at rest, scoped per case, deleted on close (or archived to a separate evidence store).

## 6.8 Hands-on Lab 06 — Vector RAG + KG hybrid over CVE/MITRE

[`labs/lab06-rag-kg/`](../labs/lab06-rag-kg/):

1. Ingest a small slice of the NVD CVE feed and the MITRE ATT&CK catalog.
2. Build a Chroma vector index with provenance metadata.
3. Build a NetworkX (or Neo4j) graph using the schema in 6.6.
4. Wrap retrieval as two tools (`semantic_search`, `graph_query`) for the agent.
5. Inject a poisoned CVE record (a fake CVE-2026-9999 whose description contains prompt-injection text). Verify the provenance filter quarantines it before retrieval.

## 6.9 Exercises

1. Pick a question your security team asks weekly. Where does it sit on the vector-vs-graph spectrum, and why?
2. Design a quarantine workflow for new ingests from a low-trust feed. What is the review SLA?
3. The agent's chat trace itself eventually becomes a corpus (people ask "did we deal with this last month?"). What is the poisoning risk there, and how do you mitigate it?

## 6.10 Further reading

- Lewis et al., *Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks* (RAG, 2020).
- Microsoft, *GraphRAG* and follow-up papers.
- Foundry Security Spec, [§5.3 Cartographer](https://github.com/CiscoDevNet/foundry-security-spec/blob/main/spec.md).
- OWASP ASI04 — Memory Poisoning.

---

Previous: [Module 5](05-claude-agent-sdk-mcp.md) · Next: [Module 7 — CrewAI and AutoGen](07-crewai-autogen.md).
