# Coalition for Secure AI (CoSAI) Risk Map - Comprehensive Summary

> **Source:** CoSAI Risk Map Documentation, YAML Data, and Tables
> **GitHub Repository**: https://github.com/cosai-oasis/secure-ai-tooling
> **Operationalizing the CoSAI Risk Map**: https://becomingahacker.org/operationalizing-the-cosai-risk-map-cosai-rm-c47a6db128c6

---

## Table of Contents

1. [Overview](#1-overview)
2. [Getting Started](#2-getting-started)
3. [Architecture & Components](#3-architecture--components)
4. [Security Risks](#4-security-risks)
5. [Security Controls](#5-security-controls)
6. [Personas](#6-personas)
7. [Metadata & Frameworks](#7-metadata--frameworks)
8. [Development & Contribution](#8-development--contribution)
9. [Validation & CI/CD](#9-validation--cicd)
10. [Quick Reference Tables](#10-quick-reference-tables)

---

## 1. Overview

The **CoSAI Risk Map** is a comprehensive framework developed by the Coalition for Secure AI to categorize and address security risks in AI systems. It provides:

- **Structured risk taxonomy** covering supply chain, deployment, infrastructure, and runtime security
- **Security controls** mapped to specific risks and components
- **Framework mappings** to external standards (MITRE ATLAS, NIST AI RMF, STRIDE, OWASP Top 10 for LLM)
- **Visual graph generation** for understanding component relationships and control mappings
- **Self-assessment tools** for organizations to evaluate their AI security posture

### Core Concepts

The Risk Map categorizes AI development into **four key areas**:

| Area | Description |
|------|-------------|
| **Data** | Training data sources, filtering, processing, and storage |
| **Infrastructure** | Hardware, serving systems, storage, and development platforms |
| **Model** | Training, tuning, evaluation, and the model itself |
| **Application** | User-facing applications, agents, plugins, and integrations |

---

## 2. Getting Started

### Prerequisites

- **Python 3.10+** with dependencies from `requirements.txt`
- **Node.js 18+** with npm packages (prettier, mermaid-cli)
- **Chrome/Chromium** for SVG generation from Mermaid diagrams

### Setup Options

#### Option 1: VS Code Dev Container (Recommended)
```bash
# Open repo in VS Code → "Dev Containers: Reopen in Container"
# Then install pre-commit hooks:
bash ./scripts/install-precommit-hook.sh
```

#### Option 2: Manual Setup
```bash
pip install -r requirements.txt
npm install
bash ./scripts/install-precommit-hook.sh
```

### Validation Commands

```bash
# Full validation
python scripts/hooks/validate_riskmap.py --force

# Generate component graph
python scripts/hooks/validate_riskmap.py --to-graph ./preview-graph.md --force

# Generate control graph
python scripts/hooks/validate_riskmap.py --to-controls-graph ./preview-controls.md --force

# Generate risk graph
python scripts/hooks/validate_riskmap.py --to-risk-graph ./preview-risks.md --force

# Format YAML files
npx prettier --write risk-map/yaml/*.yaml
```

---

## 3. Architecture & Components

### Component Categories

The Risk Map defines **23 components** organized into hierarchical categories:

#### Infrastructure Components (Data Subcategory)
| Component ID | Title | Description |
|-------------|-------|-------------|
| `componentDataSources` | Data Sources | Original sources/repositories for training data (databases, APIs, web scraping, sensors) |
| `componentDataFilteringAndProcessing` | Data Filtering and Processing | Cleaning, transforming, and preparing raw data for training |
| `componentTrainingData` | Training Data | Final curated subset fed into models during training |
| `componentDataStorage` | Data Storage Infrastructure | Storage for training data from ingestion through usage |

#### Infrastructure Components (General)
| Component ID | Title | Description |
|-------------|-------|-------------|
| `componentModelStorage` | Model Storage | Local and published storage for model checkpoints |
| `componentModelServing` | Model Serving Infrastructure | Systems for deploying models in production |

#### Model Components (Training)
| Component ID | Title | Description |
|-------------|-------|-------------|
| `componentModelFrameworksAndCode` | Model Frameworks and Code | Code/frameworks for training and inference |
| `componentModelTrainingTuning` | Training and Tuning | Teaching models patterns through probability adjustment |
| `componentModelEvaluation` | Model Evaluation | Testing model performance during and after training |
| `componentTheModel` | The Model | Pairing of code and weights from training process |

#### Model Components (Orchestration)
| Component ID | Title | Description |
|-------------|-------|-------------|
| `componentOrchestrationInputHandling` | Input Handling | Validating/sanitizing data entering orchestration logic |
| `componentOrchestrationOutputHandling` | Output Handling | Validating/formatting data exiting to downstream components |
| `componentTools` | External Tools and Services | APIs/services agents use to take action |
| `componentMemory` | Model Memory | Context retention across interactions |
| `componentRAGContent` | RAG Content | Curated knowledge for Retrieval-Augmented Generation |

#### Application Components
| Component ID | Title | Description |
|-------------|-------|-------------|
| `componentApplication` | Application | User-facing product/feature using AI model |
| `componentApplicationInputHandling` | Input Handling | Filtering/sanitizing model outputs |
| `componentApplicationOutputHandling` | Output Handling | Filtering/sanitizing model inputs |

#### Agent Components
| Component ID | Title | Description |
|-------------|-------|-------------|
| `componentAgentUserQuery` | Agent User Query | Processed user request details |
| `componentAgentSystemInstruction` | Agent System Instructions | Agent capabilities, permissions, and limitations |
| `componentAgentInputHandling` | Input Handling | Processing inputs before reasoning core |
| `componentReasoningCore` | Agent Reasoning Core | Planning and reasoning to achieve user goals |
| `componentAgentOutputHandling` | Output Handling | Response rendering and sanitization |

---

## 4. Security Risks

The Risk Map identifies **26 security risks** across 5 categories:

### Risk Categories

| Category | Description | Risk Count |
|----------|-------------|------------|
| `risksSupplyChainAndDevelopment` | Model development, training data, and supply chain | 6 |
| `risksDeploymentAndInfrastructure` | Deployment environments and infrastructure | 6 |
| `risksRuntimeInputSecurity` | Malicious/adversarial inputs at runtime | 4 |
| `risksRuntimeDataSecurity` | Data security during model operation | 5 |
| `risksRuntimeOutputSecurity` | Insecure/malicious model outputs | 5 |

### Complete Risk Inventory

#### Supply Chain & Development Risks

| ID | Title | Description |
|----|-------|-------------|
| **DP** | Data Poisoning | Altering training data to degrade performance or create backdoors |
| **UTD** | Unauthorized Training Data | Using data not authorized for training (privacy/legal issues) |
| **MST** | Model Source Tampering | Tampering with model code, dependencies, or weights |
| **EDH** | Excessive Data Handling | Collection/retention exceeding authorized boundaries |
| **FLP** | Federated/Distributed Training Privacy | Gradient leakage in federated learning systems |
| **MLD** | Malicious Loader/Deserialization | Unsafe loaders causing RCE or integrity compromise |

#### Deployment & Infrastructure Risks

| ID | Title | Description |
|----|-------|-------------|
| **MXF** | Model Exfiltration | Unauthorized theft of AI models |
| **MDT** | Model Deployment Tampering | Unauthorized changes to deployment components |
| **MRE** | Model Reverse Engineering | Recreating models via input/output analysis |
| **IIC** | Insecure Integrated Component | Vulnerabilities in plugins/libraries interacting with models |
| **ASSC** | Accelerator and System Side-channels | Cross-tenant leakage via hardware side-channels |
| **ADI** | Adapter/PEFT Injection | Trojaned adapters bypassing safety controls |

#### Runtime Input Security Risks

| ID | Title | Description |
|----|-------|-------------|
| **PIJ** | Prompt Injection | Tricking models to execute injected commands |
| **MEV** | Model Evasion | Perturbing inputs to cause incorrect inferences |
| **DMS** | Denial of ML Service | Overloading systems with resource-intensive queries |
| **EDW** | Economic Denial of Wallet | Cost abuse via token inflation/tool loops |

#### Runtime Data Security Risks

| ID | Title | Description |
|----|-------|-------------|
| **SDD** | Sensitive Data Disclosure | Disclosure of private/confidential data via queries |
| **ISD** | Inferred Sensitive Data | Inferring personal information not in training data |
| **EDH-I** | Excessive Data Handling (Inference) | Unauthorized handling of user data during inference |
| **EBM** | Evaluation/Benchmark Manipulation | Poisoned evaluation sets misleading safety signals |
| **PCP** | Prompt/Response Cache Poisoning | Cross-user contamination via shared caches |

#### Runtime Output Security Risks

| ID | Title | Description |
|----|-------|-------------|
| **IMO** | Insecure Model Output | Unvalidated output passed to end users |
| **RA** | Rogue Actions | Unintended actions by model-based agents |
| **COV** | Covert Channels in Model Outputs | Hidden information transmission via outputs |
| **ORH** | Orchestrator/Route Hijack | Silent model swaps via configuration tampering |
| **RVP** | Retrieval/Vector Store Poisoning | Poisoning RAG corpora to steer outputs |

---

## 5. Security Controls

The Risk Map defines **28 security controls** across 6 categories:

### Control Categories

| Category | Description | Count |
|----------|-------------|-------|
| `controlsData` | Data-related controls | 6 |
| `controlsInfrastructure` | Infrastructure security | 8 |
| `controlsModel` | Model-level controls | 3 |
| `controlsApplication` | Application security | 6 |
| `controlsAssurance` | Security assurance activities | 4 |
| `controlsGovernance` | Governance and policy | 4 |

### Complete Control Inventory

#### Data Controls

| ID | Title | Description |
|----|-------|-------------|
| `controlTrainingDataSanitization` | Training Data Sanitization | Detect/remove poisoned or sensitive training data |
| `controlTrainingDataManagement` | Training Data Management | Ensure training data is authorized for intended purposes |
| `controlUserDataManagement` | User Data Management | Store/process user data in compliance with consent |
| `controlModelPrivacyEnhancingTechnologies` | Privacy Enhancing Tech (Training) | Differential privacy, federated learning, anonymization |
| `controlRuntimePrivacyEnhancingTechnologies` | Privacy Enhancing Tech (Inference) | Secure MPC, homomorphic encryption, on-device processing |
| `controlRetrievalAndVectorSystemIntegrity` | Retrieval/Vector Integrity | Protect vector databases from poisoning attacks |

#### Infrastructure Controls

| ID | Title | Description |
|----|-------|-------------|
| `controlModelAndDataInventoryManagement` | Inventory Management | Track all data, code, models, and transformation tools |
| `controlModelAndDataAccessControls` | Access Controls | Minimize internal access to models and datasets |
| `controlModelAndDataIntegrityManagement` | Integrity Management | Ensure integrity protection during development/deployment |
| `controlModelAndDataExecutionIntegrity` | Execution Integrity | Verify provenance and lineage at inference time |
| `controlSecureByDefaultMLTooling` | Secure-by-Default ML Tooling | Use secure frameworks/libraries for AI development |
| `controlIsolatedConfidentialComputing` | Isolated/Confidential Computing | TEEs, secure enclaves, hardware isolation |
| `controlOrchestratorAndRouteIntegrity` | Orchestrator/Route Integrity | Signed route manifests, configuration verification |

#### Model Controls

| ID | Title | Description |
|----|-------|-------------|
| `controlInputValidationAndSanitization` | Input Validation | Block/restrict adversarial queries |
| `controlOutputValidationAndSanitization` | Output Validation | Block/sanitize insecure model output |
| `controlAdversarialTrainingAndTesting` | Adversarial Training/Testing | Make models robust to adversarial inputs |

#### Application Controls

| ID | Title | Description |
|----|-------|-------------|
| `controlApplicationAccessManagement` | Application Access Management | Identity, authorization, rate limiting, quotas |
| `controlUserTransparencyAndControls` | User Transparency | Disclosures and data control experiences |
| `controlAgentPluginUserControl` | Agent User Control | User approval for agent actions |
| `controlAgentPluginPermissions` | Agent Permissions | Least-privilege for agentic systems |
| `controlAgentObservability` | Agent Observability | Logging for debugging and security oversight |

#### Assurance Controls

| ID | Title | Scope |
|----|-------|-------|
| `controlRedTeaming` | Red Teaming | **All** components and risks |
| `controlVulnerabilityManagement` | Vulnerability Management | **All** components and risks |
| `controlThreatDetection` | Threat Detection | **All** components and risks |
| `controlIncidentResponseManagement` | Incident Response | **All** components and risks |

#### Governance Controls

| ID | Title | Scope |
|----|-------|-------|
| `controlInternalPoliciesAndEducation` | Internal Policies | **All** risks |
| `controlUserPoliciesAndEducation` | User Policies | Specific risks |
| `controlProductGovernance` | Product Governance | **All** risks |
| `controlRiskGovernance` | Risk Governance | **All** risks |

---

## 6. Personas

The Risk Map defines two key personas:

| Persona ID | Title | Description |
|------------|-------|-------------|
| `personaModelCreator` | Model Creator | Organizations that train/tune foundation models or fine-tune for specific tasks |
| `personaModelConsumer` | Model Consumer | Organizations that build AI applications using models (via API or downloaded) without training |

### Responsibility Mapping

- **Model Creators** are primarily responsible for: Data controls, training security, model integrity
- **Model Consumers** are primarily responsible for: Application security, runtime controls, user-facing protections
- **Both** are responsible for: Governance, assurance, and universal controls

---

## 7. Metadata & Frameworks

### Lifecycle Stages

An 8-stage AI lifecycle model:

| Order | Stage | Description |
|-------|-------|-------------|
| 1 | `planning` | Initial planning, design, and architecture |
| 2 | `data-preparation` | Data collection, cleaning, labeling |
| 3 | `model-training` | Training, fine-tuning, optimization |
| 4 | `development` | Application development and integration |
| 5 | `evaluation` | Testing, validation, performance assessment |
| 6 | `deployment` | Production deployment and rollout |
| 7 | `runtime` | Active operation in production |
| 8 | `maintenance` | Monitoring, updates, retraining |

### Impact Types

**Traditional Security:**
- `confidentiality` - Protection from unauthorized disclosure
- `integrity` - Accuracy and tampering prevention
- `availability` - System accessibility
- `privacy` - Personal/sensitive information protection
- `compliance` - Regulatory adherence

**AI-Specific:**
- `safety` - Prevention of physical harm
- `fairness` - Equitable treatment, absence of bias
- `accountability` - Traceability and responsibility
- `reliability` - Consistency and dependability
- `transparency` - Explainability and interpretability

### Actor Access Levels

**Traditional:**
- `external` - No direct system access
- `api` - API endpoint access
- `user` - Authenticated user access
- `privileged` - Admin/operator access
- `physical` - Physical hardware access

**AI-Specific:**
- `agent` - AI agents with tool execution
- `supply-chain` - Position in software/data supply chain
- `infrastructure-provider` - Cloud/infrastructure access
- `service-provider` - Third-party service access

### External Framework Mappings

| Framework ID | Full Name | Description |
|--------------|-----------|-------------|
| `mitre-atlas` | MITRE ATLAS | Adversarial Threat Landscape for AI Systems |
| `nist-ai-rmf` | NIST AI RMF | AI Risk Management Framework v1.0 |
| `stride` | STRIDE | Microsoft threat modeling framework |
| `owasp-top10-llm` | OWASP Top 10 for LLM | Critical security risks for LLM applications (2025) |

---

## 8. Development & Contribution

### Contribution Workflow

1. **Create a GitHub issue** to track work
2. **Set up pre-commit hooks** (see Setup section)
3. **Make content changes** following the guides:
   - [Adding a Component](docs/guide-components.md)
   - [Adding a Control](docs/guide-controls.md)
   - [Adding a Risk](docs/guide-risks.md)
   - [Adding a Persona](docs/guide-personas.md)
   - [Adding Frameworks](docs/guide-frameworks.md)
4. **Validate changes** against all validation rules
5. **Open PR** against `develop` branch

### Best Practices

- **Always run validation** before committing: `python scripts/hooks/validate_riskmap.py --force`
- **Preview graphs visually** to see impact of changes
- **Format files**: `npx prettier --write risk-map/yaml/*.yaml`
- **Use meaningful IDs**: `component[Name]`, `control[Name]`, `persona[Name]`
- **Ensure bidirectional edges** for components
- **Ensure bidirectional control-risk references**
- **Don't list universal controls** in individual risks

### File Structure

```
risk-map/
├── yaml/                    # Primary data files
│   ├── components.yaml      # Component definitions
│   ├── controls.yaml        # Control definitions
│   ├── risks.yaml           # Risk definitions
│   ├── personas.yaml        # Persona definitions
│   ├── frameworks.yaml      # External framework mappings
│   ├── lifecycle-stage.yaml # Lifecycle stage definitions
│   ├── impact-type.yaml     # Impact type definitions
│   ├── actor-access.yaml    # Actor access level definitions
│   └── mermaid-styles.yaml  # Graph styling configuration
├── schemas/                 # JSON schemas for validation
├── tables/                  # Generated markdown tables
├── diagrams/                # Generated Mermaid diagrams
├── svg/                     # Generated SVG files
└── docs/                    # Documentation
```

---

## 9. Validation & CI/CD

### Automated Validation (Pre-commit & CI)

| Check | Description |
|-------|-------------|
| **YAML Schema Validation** | Files validated against JSON schemas |
| **Prettier Formatting** | Consistent YAML formatting |
| **Ruff Linting** | Python code quality |
| **Edge Consistency** | Bidirectional component relationships |
| **Control-Risk References** | Cross-reference validation |
| **Graph Generation** | All three graph types validated |

### Manual Validation Commands

```bash
# Component edge validation
python scripts/hooks/validate_riskmap.py --force

# Control-risk reference validation
python scripts/hooks/validate_control_risk_references.py --force

# Framework reference validation
python scripts/hooks/validate_framework_references.py --force

# Generate markdown tables
python3 scripts/hooks/yaml_to_markdown.py --all --all-formats

# Run full pre-commit suite
.git/hooks/pre-commit --force
```

### Handling CI Failures

```bash
# Regenerate graphs
python scripts/hooks/validate_riskmap.py --to-graph ./risk-map/diagrams/risk-map-graph.md --force
python scripts/hooks/validate_riskmap.py --to-controls-graph ./risk-map/diagrams/controls-graph.md --force
python scripts/hooks/validate_riskmap.py --to-risk-graph ./risk-map/diagrams/controls-to-risk-graph.md --force

# Commit updated graphs
git add risk-map/diagrams/
git commit -m "Update generated graphs"
```

---

## 10. Quick Reference Tables

### Risk-to-Control Mapping (Summary)

| Risk | Primary Controls |
|------|-----------------|
| Data Poisoning (DP) | Training Data Sanitization, Secure ML Tooling, Integrity Management |
| Prompt Injection (PIJ) | Input/Output Validation, Adversarial Training |
| Model Exfiltration (MXF) | Access Controls, Inventory Management, Confidential Computing |
| Sensitive Data Disclosure (SDD) | Privacy Technologies, Output Validation, Agent Controls |
| Rogue Actions (RA) | Agent Permissions, User Control, Output Validation |
| Model Deployment Tampering (MDT) | Execution Integrity, Secure Tooling, Route Integrity |

### Universal Controls (Apply to All Risks)

- Red Teaming
- Vulnerability Management
- Threat Detection
- Incident Response Management
- Internal Policies and Education
- Product Governance
- Risk Governance

### Self-Assessment Questions

The Risk Map includes a self-assessment with 12 questions to help organizations identify relevant risks:

1. Do you have robust training data management?
2. Can you detect/remediate malicious data changes?
3. Is sensitive user data used in training?
4. Do you manage user data according to consent?
5. Do you have a complete inventory of models/datasets?
6. Do you have robust access controls?
7. Can you ensure integrity protection?
8. Are frameworks/libraries analyzed for vulnerabilities?
9. Do you protect against large-scale malicious queries?
10. Are you using secure-by-default designs?
11. Do you perform adversarial testing?
12. Do you deploy AI-powered agents?

---

## Appendix: Key Files Reference

| File | Purpose |
|------|---------|
| `yaml/components.yaml` | 23 component definitions with edges |
| `yaml/controls.yaml` | 28 control definitions |
| `yaml/risks.yaml` | 26 risk definitions |
| `yaml/frameworks.yaml` | 4 external framework definitions |
| `yaml/personas.yaml` | 2 persona definitions |
| `yaml/mermaid-styles.yaml` | Graph styling configuration |
| `docs/developing.md` | Main documentation index |
| `docs/validation.md` | Validation tools reference |
| `docs/guide-*.md` | Content addition guides |

---

*This document was auto-generated from the CoSAI Risk Map documentation, YAML data files, and generated tables.*

