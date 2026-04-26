# Model Context Protocol (MCP) Security

[Model Context Protocol (MCP)](https://modelcontextprotocol.io/) is an open-source standard for connecting AI applications to external systems and tools. While MCP enables powerful automation by allowing AI to perform actions beyond text generation, it also introduces new attack surfaces that organizations must secure against.

## Overview

MCP uses a client-server architecture with three key components:
- **MCP Host**: The application managing clients and routing requests
- **MCP Client**: The connector communicating with MCP servers
- **MCP Server**: Programs exposing tools, resources, and prompts to clients

### Core Primitives
- **Tools**: Executable functions for actions (file operations, API calls, database queries)
- **Resources**: Data sources providing contextual information
- **Prompts**: Reusable templates for structuring model interactions

## MCP Deployment Architectures

### Local MCP Server (STDIO Connection)
```
┌─────────┐    ┌───────────────────────────────────────────────────────┐
│  User   │───▶│                Docker Container                       │
└─────────┘    │  ┌───────────────────────────────────────────────┐    │
               │  │              MCP Host                         │    │
               │  │  ┌─────────────────┐    ┌─────────────────┐   │    │
               │  │  │   MCP Client    │───▶│ 3rd Party       │   │    │
               │  │  │                 │    │ MCP Server      │   │    │
               │  │  └─────────────────┘    └─────────────────┘   │    │
               │  └───────────────────────────────────────────────┘    │
               │                              │            │           │
               │                              ▼            ▼           │
               │                    ┌─────────────┐ ┌─────────────┐    │
               │                    │File System  │ │Local Tools  │    │
               │                    └─────────────┘ └─────────────┘    │
               │                       Local Environment               │
               └───────────────────────────────────────────────────────┘
                                     ▲
                                     │ (Downloaded from)
                              ┌─────────────┐
                              │ 3rd Party   │
                              │ GitHub      │
                              │ Repo        │
                              └─────────────┘
```

### Remote MCP Server (HTTP Connection)
```
┌─────────┐    ┌─────────────────────────────┐                ┌─────────────────────┐
│  User   │───▶│     Local Environment       │                │                     │
└─────────┘    │  ┌─────────────────────┐    │                │      Cloud          │
               │  │     MCP Host        │    │                │                     │
               │  │  ┌─────────────┐    │    │   HTTP/TLS     │  ┌─────────────┐    │
               │  │  │ MCP Client  │    │    │◄──────────────▶│  │ 3rd Party   │    │
               │  │  │             │    │    │                │  │ MCP Server  │───▶│
               │  │  └─────────────┘    │    │                │  │             │    │
               │  └─────────────────────┘    │                │  └─────────────┘    │
               └─────────────────────────────┘                │         │           │
                                                              │         ▼           │
                                                              │  ┌─────────────┐    │
                                                              │  │ 3rd Party   │    │
                                                              │  │ APIs & Tools│    │
                                                              │  └─────────────┘    │
                                                              └─────────────────────┘
```

### Key Differences

| Aspect | Local (STDIO) | Remote (HTTP) |
|--------|---------------|---------------|
| **Connection** | Process-to-process via STDIO | Network-based via HTTP/TLS |
| **Latency** | Lower | Higher |
| **Security** | Container isolation, process sandboxing | Authentication, encryption, WAF |
| **Scalability** | Single instance | Multi-tenant, auto-scaling |
| **Trust Model** | Downloaded and verified locally | Remote server trust required |

## Key Security Threats

### 1. Tool Poisoning & Rug Pull Attacks
Malicious commands embedded in tool descriptions that influence LLM behavior, potentially leading to unauthorized access or file system compromise.

**Mitigations:**
- Enforce full tool transparency with complete manifests
- Sanitize descriptions for suspicious content
- Monitor tool integrity with version pinning and checksums
- Implement runtime policy enforcement with least-privilege access

### 2. Prompt Injection
Crafted malicious inputs designed to hijack model context and force unintended actions.

**Mitigations:**
- Validate and sanitize all external data and user inputs
- Use strong JSON/YAML schemas with libraries like Pydantic
- Segment contexts between users and operations

### 3. Memory Poisoning
Corruption of agent memory systems leading to false information storage and flawed decision-making.

**Mitigations:**
- Enforce validation on memory updates with anomaly scanning
- Implement Time-To-Live (TTL) on stored data
- Segment memory by session or user identity

### 4. Tool Interference
Unintended tool execution chains when using multiple MCP servers, causing data leaks or denial-of-service loops.

**Mitigations:**
- Require human-in-the-loop approval for tool execution
- Isolate context for each tool execution
- Set execution timeouts to prevent loops

## Security Best Practices

### Client Security
- **Trust Minimization**: Always validate manifests and enforce schemas
- **Sandbox Execution**: Use containers (Docker) with limited filesystem/network access
- **Just-in-Time Access**: Grant temporary, narrowly scoped permissions
- **UI Transparency**: Expose full tool descriptions and permissions
- **Incident Detection**: Monitor for unusual tool invocation patterns

### Server Discovery & Verification
- **Verify Origin**: Only connect to servers from trusted registries
- **Registry-Only Discovery**: Maintain central registry of approved servers
- **Connection Types**:
  - **STDIO (Local)**: Lower latency, easier to harden via process sandboxing
  - **Streamable HTTP (Remote)**: Use TLS/mTLS or OAuth 2.1 for authentication
- **Pin Versions**: Maintain manifests with checksums for integrity verification
- **Staged Rollout**: Test in staging environments before production deployment

### Authentication & Authorization
- **Authentication Methods**:
  - Client Credentials for system operations
  - OIDC/PKCE for user operations
  - Short-lived Personal Access Tokens when OAuth unavailable
- **Authorization Controls**:
  - Define least-permission OAuth scopes
  - Use granular, action-level permissions
  - Implement human-in-the-loop controls for new actions

## Security Tools & Utilities

### Automated Scanners
- **Invariant Labs MCP-Scan**: Scans for malicious descriptions and unsafe data flows
- **Semgrep MCP Scanner**: Static analysis for Python and Node.js dependencies
- **mcp-watch**: Vulnerability scanning for insecure credentials and tool poisoning
- **Trail Of Bits mcp-context-protector**: Security wrapper for untrusted MCP servers
- **Vijil Evaluate**: Platform for evaluating AI agent reliability and security

### Content Monitoring
- **LangKit**: Toolkit for monitoring LLM outputs
- **OpenAI Moderation API**: Inappropriate content detection
- **Invariant Labs Invariant**: Contextual guardrails for agent systems
- **LlamaFirewall**: Framework with risk scanners for LLM agents

### Infrastructure Security
- **Docker**: Containerized execution for isolation
- **OpenSSF Scorecard**: Repository maturity verification
- **Snyk**: Package health verification

## Governance Framework

### Governance Workflow
1. **Submission**: Developer submits MCP server with documentation and tool description hash
2. **Scanning**: Automated security analysis for malware and hidden instructions
3. **Review & Sign-off**: Security and domain expert approval with version pinning
4. **Deployment & Monitoring**: Staged deployment with probation period
5. **Periodic Re-validation**: Regular re-scanning and version change monitoring

### Recommended Roles
- **Submitter (Developer)**: Proposes new server integrations
- **Security Reviewer**: Validates security controls and supply chain integrity
- **Domain Owner**: Confirms functional necessity and approves scopes
- **Approver**: Joint security and domain owner sign-off
- **Operator (SRE)**: Manages rollout, monitoring, and emergency controls

## Resources

- [One of my original posts about MCP Security](http://cs.co/mcp-security)
- [OWASP CheatSheet – A Practical Guide for Securely Using Third-Party MCP Servers](https://genai.owasp.org/resource/cheatsheet-a-practical-guide-for-securely-using-third-party-mcp-servers-1-0/)
- [Model Context Protocol (MCP) Specification](https://modelcontextprotocol.io/docs/getting-started/intro)

---

*This summary is based on the [OWASP MCP Security Cheat Sheet](https://genai.owasp.org/resource/cheatsheet-a-practical-guide-for-securely-using-third-party-mcp-servers-1-0/)*