# Lesson 5-13: Using Additional Tools like Antigravity, OpenCode, Warp

> Student follow-along resources, key concepts, and references for this sublesson.

## Overview

The AI developer-tool market expands weekly. **Google Antigravity** illustrates **agent-first IDE/platform** bets from major vendors; **OpenCode** is a prominent **open, terminal-native agent** stack you can compose with multiple model providers; **Warp** embeds AI into a **modern terminal** for shell-heavy workflows. This sublesson is not a feature dump—it is a **repeatable evaluation framework** so teams adopt deliberately.

## Learning objectives

By the end of this sublesson you should be able to:

- Describe the primary UX angle for Antigravity, OpenCode, and Warp at a high level.
- Score new tools on security, licensing, data residency, integration, and support cost.
- Run a **time-boxed pilot** with measurable outcomes (defect rate, review time, MTTR).
- Articulate why a **short approved-tool list** beats unconstrained individual choice at scale.

## Key concepts

### 1. Three example directions

| Tool / category | Emphasis | Typical user |
| --- | --- | --- |
| Google Antigravity | Agentic development platform / IDE from Google | Teams in Google ecosystem evaluations |
| OpenCode | Open-source terminal agent; model-agnostic | Engineers wanting BYO model + transparency |
| Warp | Terminal with AI assistance | Shell-centric backend/devops workflows |

### 2. Evaluation scorecard

Use a simple matrix (1–5) for: **data handling**, **SSO / audit logs**, **on-prem or VPC options**, **IDE integration**, **cost predictability**, **vendor responsiveness**, and **fit for monorepo size**. Weight rows by your org’s non-negotiables.

### 3. Avoid sprawl

Allow personal experimentation on **non-customer** repos; require architecture + security signoff before **production-standard** listing. Revisit the approved list **quarterly** because model and agent capabilities shift.

## Why it matters / What's next

Lesson 5 ends with the same lesson as the whole course arc: **tools change; engineering habits persist.** Lesson **6-1** begins **Agentic AI**—designing autonomous systems with explicit oversight, tooling, and evaluation—building directly on the guardrails you practiced in Lessons 5-4 through 5-6 and 5-12.

## Glossary

- **Approved tool list** — IT/security-curated software engineers may use for production work.
- **Pilot sandbox** — Non-production environment and repos for evaluating new tooling safely.
- **Data residency** — Requirement that data stay within specific legal or geographic boundaries.

## Quick self-check

1. Name five scorecard dimensions you would use to compare two AI agents.
2. Why is “lines of code generated” a poor pilot metric?
3. What is the minimum bar before adding a tool to org-wide production standard?

## References and further reading

- Google — *Antigravity documentation.* https://antigravity.google/docs
- Google — *Antigravity product site.* https://antigravity.google/
- Google Developers Blog — *Build with Google Antigravity.* https://developers.googleblog.com/build-with-google-antigravity-our-new-agentic-development-platform/
- OpenCode — *Open source AI coding agent.* https://opencode.ai/
- OpenCode — *Documentation.* https://opencode.ai/docs/
- Warp — *Warp terminal.* https://www.warp.dev/
- Checkmarx — *AI developer tools landscape (industry survey context).* https://checkmarx.com/learn/ai-security/top-12-ai-developer-tools-in-2026-for-security-coding-and-quality/

### Omar's resources and references (course-wide)

#### Foundational cybersecurity resources in O'Reilly

This section provides a curated list of resources that delve into foundational cybersecurity concepts, frequently explored in O'Reilly training sessions and other educational offerings.

##### Live training

- **Upcoming Live Cybersecurity and AI Training in O'Reilly:** [Register before it is too late](https://learning.oreilly.com/search/?q=omar%20santos&type=live-course&rows=100&language_with_transcripts=en) (free with O'Reilly Subscription)

##### Reading list

Despite the rapidly evolving landscape of AI and technology, these books offer a comprehensive roadmap for understanding the intersection of these technologies with cybersecurity:

- **[NEW: Agentic AI for Cybersecurity: Building Autonomous Defenders and Adversaries](https://www.oreilly.com/library/view/agentic-ai-for/9780135589861/).** Unlock the power of next generation AI agents to transform cybersecurity, business operations, and productivity. [Available on O'Reilly](https://www.oreilly.com/library/view/agentic-ai-for/9780135589861/)

- **[Redefining Hacking](https://learning.oreilly.com/library/view/redefining-hacking-a/9780138363635/)** — A Comprehensive Guide to Red Teaming and Bug Bounty Hunting in an AI-driven World. [Available on O'Reilly](https://learning.oreilly.com/library/view/redefining-hacking-a/9780138363635/)

- **[AI-Powered Digital Cyber Resilience](https://www.oreilly.com/library/view/ai-powered-digital-cyber/9780135408599/)** — A practical guide to building intelligent, AI-powered cyber defenses in today's fast-evolving threat landscape. [Available on O'Reilly](https://www.oreilly.com/library/view/ai-powered-digital-cyber/9780135408599/)

- **[Developing Cybersecurity Programs and Policies in an AI-Driven World](https://learning.oreilly.com/library/view/developing-cybersecurity-programs/9780138073992)** — Explore strategies for creating robust cybersecurity frameworks in an AI-centric environment. [Available on O'Reilly](https://learning.oreilly.com/library/view/developing-cybersecurity-programs/9780138073992)

- **[Beyond the Algorithm: AI, Security, Privacy, and Ethics](https://learning.oreilly.com/library/view/beyond-the-algorithm/9780138268442)** — Gain insights into the ethical and security challenges posed by AI technologies. [Available on O'Reilly](https://learning.oreilly.com/library/view/beyond-the-algorithm/9780138268442)

- **[The AI Revolution in Networking, Cybersecurity, and Emerging Technologies](https://learning.oreilly.com/library/view/the-ai-revolution/9780138293703)** — Understand how AI is transforming networking and cybersecurity landscape. [Available on O'Reilly](https://learning.oreilly.com/library/view/the-ai-revolution/9780138293703)

##### Video courses

Enhance your practical skills with these video courses designed to deepen your understanding of cybersecurity:

- **[Building the Ultimate Cybersecurity Lab and Cyber Range](https://learning.oreilly.com/course/building-the-ultimate/9780138319090/)** (video). [Available on O'Reilly](https://learning.oreilly.com/course/building-the-ultimate/9780138319090/)

- **[Build Your Own AI Lab](https://learning.oreilly.com/course/build-your-own/9780135439616)** (video) — Hands-on guide to home and cloud-based AI labs. Learn to set up and optimize labs to research and experiment in a secure environment. [Available on O'Reilly](https://learning.oreilly.com/course/build-your-own/9780135439616)

- **[Defending and Deploying AI](https://www.oreilly.com/videos/defending-and-deploying/9780135463727/)** (video) — Comprehensive, hands-on journey into modern AI applications for technology and security professionals, covering AI-enabled programming, networking, and cybersecurity; securing generative AI (LLM security, prompt injection, red-teaming); secure AI labs; AI agents and agentic RAG for cybersecurity. [Available on O'Reilly](https://www.oreilly.com/videos/defending-and-deploying/9780135463727/)

- **[AI-Enabled Programming, Networking, and Cybersecurity](https://learning.oreilly.com/course/ai-enabled-programming-networking/9780135402696/)** — Learn to use AI for cybersecurity, networking, and programming tasks with practical, hands-on activities. [Available on O'Reilly](https://learning.oreilly.com/course/ai-enabled-programming-networking/9780135402696/)

- **[Securing Generative AI](https://learning.oreilly.com/course/securing-generative-ai/9780135401804/)** — Security for deploying and developing AI applications, RAG, agents, and other AI implementations; incorporate security at every stage of AI development, deployment, and operation. [Available on O'Reilly](https://learning.oreilly.com/course/securing-generative-ai/9780135401804/)

- **[Practical Cybersecurity Fundamentals](https://learning.oreilly.com/course/practical-cybersecurity-fundamentals/9780138037550/)** — Essential cybersecurity principles. [Available on O'Reilly](https://learning.oreilly.com/course/practical-cybersecurity-fundamentals/9780138037550/)

- **[The Art of Hacking](https://theartofhacking.org)** — Over 26 hours of training in ethical hacking and penetration testing (e.g., OSCP or CEH prep). [Visit The Art of Hacking](https://theartofhacking.org)

##### Certification related

- **CompTIA PenTest+ PT0-002 Cert Guide, 2nd Edition** — [Available on O'Reilly](https://learning.oreilly.com/library/view/comptia-pentest-pt0-002/9780137566204/)

- **Certified Ethical Hacker (CEH), Latest Edition** — Very comprehensive (19+ hours). [Available on O'Reilly](https://learning.oreilly.com/course/certified-ethical-hacker/9780135395646/)

- **Certified in Cybersecurity - CC (ISC)²** — [Available on O'Reilly](https://learning.oreilly.com/course/certified-in-cybersecurity/9780138230364/)

- **CCNP and CCIE Security Core SCOR 350-701 Official Cert Guide, 2nd Edition** — [Available on O'Reilly](https://learning.oreilly.com/library/view/ccnp-and-ccie/9780138221287/)

- **CEH Certified Ethical Hacker Cert Guide** — [Available on O'Reilly](https://learning.oreilly.com/library/view/ceh-certified-ethical/9780137489930/)

##### Additional resources

- **Hacking Scenarios (Labs) on O'Reilly** — Cloud-based labs; no local install. [https://hackingscenarios.com](https://hackingscenarios.com)

- **Personal blog** — [becomingahacker.org](https://becomingahacker.org)

- **Cisco blog** — [blogs.cisco.com/author/omarsantos](https://blogs.cisco.com/author/omarsantos)

- **GitHub repository** — [hackerrepo.org](https://hackerrepo.org)

- **WebSploit Labs** — [websploit.org](https://websploit.org)

- **NetAcad Ethical Hacker Free Course** — [NetAcad Skills for All](https://www.netacad.com/courses/ethical-hacker?courseLang=en-US)
