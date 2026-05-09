# Lesson 5-7: Deep diving into Cursor

> Student follow-along resources, key concepts, and references for this sublesson.

## Overview

Cursor packages chat, tab completions, and autonomous **agent** workflows into a single editor experience. This sublesson maps how those surfaces differ, how **project context** (indexing, @-mentions, open files) steers the model, and how **rules** plus permission settings keep multi-file work aligned with team standards. It builds on Lessons 5-3 through 5-6: you already know why quality and tokens matter; here the focus is Cursor-specific ergonomics and governance.

## Learning objectives

By the end of this sublesson you should be able to:

- Choose between inline completion, chat, and agent flows for a given task size.
- Shape context deliberately with @-references, scoped folders, and editor affordances.
- Author or consume **team rules** so defaults match security and style expectations.
- Explain how agent permissions, network use, and data settings fit enterprise policy.

## Key concepts

### 1. Three interaction modes

| Mode | Best for | Watchouts |
| --- | --- | --- |
| Inline | Micro-edits, repetitive boilerplate | May complete the wrong API without enough local context |
| Chat | Explanation, draft snippets, planning | Easy to paste too much or too little context |
| Agent | Cross-file refactors, repo search, multi-step tasks | Larger blast radius; needs diff review and tests |

### 2. Context is a steering wheel

Effective Cursor use looks like: narrow files and symbols with `@`, keep sensitive paths out of prompts when policy requires it, and prefer **indexed project knowledge** over giant manual pastes (still bounded—see Lesson 5-5 on token discipline).

### 3. Rules as shared defaults

Rules encode standing instructions (language version, test commands, “never log secrets,” etc.). Treat them like **config-as-code**: short, scoped, reviewed in pull requests, and owned by a team.

### 4. Permissions and safety

Agent features that can run terminals or touch many files should be paired with: clear allow-lists, review of proposed shell commands, branch-based work, and the same CI gates you use for human-authored changes.

## Why it matters / What's next

Cursor is representative of the **AI-native IDE** category; mastering its modes transfers to other products that separate “pair programmer,” “chat,” and “agent.” **Lesson 5-8** compares Windsurf and Cascade—another editor plus agent pairing with a different plan-and-execute UX.

## Glossary

- **Agent (IDE)** — A workflow that can take multi-step actions across files with user approvals.
- **@-reference** — Cursor context syntax to pull files, folders, or symbols into the model prompt.
- **Rules** — Persistent natural-language or structured instructions applied to sessions (often repo-scoped).
- **Indexing** — Project-wide retrieval that helps the model locate relevant code without pasting the entire tree.

## Quick self-check

1. When would you avoid agent mode even if it is available?
2. Name two ways to reduce irrelevant context in a long chat thread.
3. Who should own and review `.cursor` rules in a production team?
4. What checks must still run after an agent-generated change?

## References and further reading

- Cursor — *Documentation.* https://cursor.com/docs
- Cursor — *Rules.* https://cursor.com/docs/context/rules
- Anysphere — *Cursor homepage.* https://cursor.com/

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
