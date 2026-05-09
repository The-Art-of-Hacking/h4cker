# Lesson 2-3: Prompting Techniques

> Student follow-along resources, key concepts, and references for this sublesson.

## Overview

Lesson 2-2 covered the structural patterns of a single prompt: roles, instructions, and constraints. This sublesson moves to **techniques** that change *how* the model thinks about a task and *how* you orchestrate one or more prompts together. You will learn iterative and sequential prompting, prompt chaining, few-shot prompting, and chain-of-thought reasoning. We also briefly cover prompt techniques for image and audio generation, where the principles of specificity and positive description still apply.

## Learning objectives

By the end of this sublesson you should be able to:

- Differentiate iterative, sequential, and chained prompting and choose the right one for a task.
- Apply zero-shot, one-shot, and few-shot prompting and explain when examples help.
- Use chain-of-thought (CoT) prompting and combine it with few-shot examples for reasoning tasks.
- Recognize when to break a complex job into a pipeline of specialized prompts with checkpoints.
- Translate the principles of specificity and positive description to image and audio prompting.

## Key concepts

### 1. Iterative and sequential prompting

**Iterative prompting** treats prompting as a conversation. You send a prompt, look at the output, and send a follow-up with specific feedback: "shorten the second paragraph," "make the tone more formal," "focus on cost savings." Each round refines the result.

**Sequential prompting** breaks a single big task into smaller asks that follow a planned order. For example, when drafting a long article you might:

1. Ask for an outline.
2. Approve or edit the outline.
3. Ask for section 1 expanded.
4. Ask for section 2 expanded.
5. Ask for a polish pass on the whole document.

Both techniques work well for long-form or complex tasks where a single prompt would either be too long, too vague, or impossible to verify in one pass.

### 2. Prompt chaining

**Prompt chaining** is the production version of sequential prompting: a pipeline of prompts where the **output of one prompt becomes the input of the next**, often executed automatically rather than by a human in the loop.

```mermaid
flowchart LR
    Doc["Source document"] --> P1["Prompt 1<br/>Extract key findings"]
    P1 --> P2["Prompt 2<br/>Analyze findings"]
    P2 --> P3["Prompt 3<br/>Synthesize summary"]
    P3 --> P4["Prompt 4<br/>Format and validate"]
    P4 --> Out["Final output"]
```

Why teams chain prompts:

- **Specialization.** Each step uses a prompt (and sometimes a model) optimized for that subtask.
- **Quality checkpoints.** Intermediate outputs can be validated, filtered, or even reviewed by another model before continuing.
- **Cost and latency control.** Cheap models handle easy steps; a more capable model is reserved for the hard step.
- **Observability.** You can log, evaluate, and improve each step independently.

Chaining is now the standard pattern for production research, reporting, content, and code workflows, and it is the bridge to agentic systems that we will revisit in Lessons 2-7 and 2-8.

### 3. Zero-shot, one-shot, and few-shot prompting

The number of examples you include in a prompt directly affects how well the model captures an unusual task or format.

| Technique | Examples in prompt | When to use |
| --- | --- | --- |
| Zero-shot | None | The task is common and the instructions alone are clear. |
| One-shot | One input/output pair | You want to lock in a specific format or style with minimal tokens. |
| Few-shot | Two to about five pairs | The task or format is unusual, or zero-shot is inconsistent. |

Few-shot prompting works because LLMs are powerful pattern-matchers: shown a clear input/output pattern, they tend to reproduce it on new inputs. The standard practice is to start with zero-shot and only add examples if quality is insufficient — examples consume context window and money.

### 4. Chain-of-thought prompting

**Chain-of-thought (CoT) prompting** asks the model to show its intermediate reasoning before giving a final answer. The classic trigger phrase is "Let's think step by step," but you can also instruct the model to "first list the relevant facts, then reason through the implications, then give a final answer."

CoT is especially helpful for:

- Math and arithmetic problems.
- Multi-step logic or planning.
- Tasks where the right answer depends on combining several pieces of information.

You can combine few-shot with CoT by including examples that themselves show reasoning steps plus a final answer — sometimes called few-shot CoT.

A small caveat for 2025–2026: many flagship "reasoning models" (e.g., OpenAI's reasoning series, Anthropic's extended thinking, Google's Deep Think) now perform chain-of-thought internally. For these models, asking them to "think step by step" is often redundant or even harmful. Read the vendor's prompting guide for the model you are using.

### 5. Putting techniques together

These techniques are not mutually exclusive; the most powerful real-world prompts combine several:

- A **chained pipeline** where step 2 is a **few-shot CoT** prompt that critiques the output of step 1.
- An **iterative** loop in which a human accepts, rejects, or edits each chained step.
- A **router** prompt at the top of the chain that decides which downstream prompt to use.

### 6. Image and audio prompting

The same core principle — be specific and describe what you want — applies to other modalities, but the "vocabulary" changes.

For **image generation** (Midjourney, DALL·E, Stable Diffusion, Imagen, Adobe Firefly, etc.), strong prompts typically describe:

- **Subject:** what is in the image, including key attributes.
- **Style:** photo, oil painting, line drawing, 3D render, specific artistic genre.
- **Lighting:** soft natural light, golden hour, studio lighting, low-key, neon.
- **Composition:** wide shot, close-up, rule of thirds, symmetrical, top-down.
- **Mood and color:** moody, cheerful, pastel palette, high contrast.

Different tools have different conventions: some prefer short keyword lists, others natural language. Most modern tools support **negative prompts** ("avoid X"), but positive descriptions usually work better than long lists of negations.

For **audio and music** generation (Suno, Udio, ElevenLabs Music, Stable Audio, etc.), prompts usually describe:

- **Genre and sub-genre.**
- **Tempo and energy.**
- **Mood and atmosphere.**
- **Instruments and vocals** (with or without lyrics, language, vocal style).
- **Structure** (intro, verse, chorus, drop, outro) when the tool supports it.

Across all modalities, the iterative loop from earlier in this lesson still applies: generate, evaluate, refine.

## Why it matters / What's next

Combining patterns (Lesson 2-2) with techniques (this sublesson) is what makes prompts production-grade. The same techniques that make prompts powerful, however, also create new attack surface: an attacker who can sneak text into any of the inputs you feed your chain can hijack the model's behavior. Lesson 2-4 turns to that threat in detail with **prompt injection attack types**.

## Glossary

- **Iterative prompting** — Refining a single output through successive follow-up prompts in a conversation.
- **Sequential prompting** — Splitting a task into ordered subtasks asked in sequence, usually with a human reviewing each step.
- **Prompt chain / chaining** — A pipeline of prompts where each prompt's output is the next prompt's input, executed programmatically.
- **Zero-shot prompting** — Asking the model to perform a task without providing any worked examples.
- **Few-shot prompting** — Including a small number of input/output examples in the prompt to demonstrate the desired pattern.
- **Chain-of-thought (CoT)** — Prompting that asks the model to externalize its reasoning before giving a final answer.
- **Few-shot CoT** — Few-shot examples that themselves include reasoning steps as well as the final answer.
- **Reasoning model** — A model trained to perform extended internal reasoning (e.g., GPT reasoning series, Claude with extended thinking, Gemini Deep Think); often does not need an explicit "think step by step" instruction.
- **Negative prompt** — In image and audio generation, a description of elements the model should avoid producing.

## Quick self-check

1. Give one example each of a task best handled by iterative, sequential, and chained prompting.
2. Why might a team prefer a 4-step prompt chain over one big prompt that does everything?
3. When is few-shot prompting worth the extra tokens, and when is zero-shot enough?
4. Write a one-sentence chain-of-thought prompt for a multi-step word problem.
5. List four dimensions you would specify in an image-generation prompt and one dimension you would specify in a music-generation prompt.

## References and further reading

- OpenAI — *Prompt engineering (API guide).* https://platform.openai.com/docs/guides/prompt-engineering
- OpenAI Developers — *GPT-4.1 prompting guide (cookbook).* https://cookbook.openai.com/examples/gpt4-1_prompting_guide
- Anthropic — *Chain of thought prompting (Claude docs).* https://docs.anthropic.com/en/docs/build-with-claude/prompt-engineering/chain-of-thought
- Anthropic — *Multishot prompting (few-shot examples).* https://docs.anthropic.com/en/docs/build-with-claude/prompt-engineering/multishot-prompting
- Anthropic — *Prompt chaining.* https://docs.anthropic.com/en/docs/build-with-claude/prompt-engineering/chain-prompts
- Google Cloud — *Prompt design strategies (Vertex AI).* https://cloud.google.com/vertex-ai/generative-ai/docs/learn/prompts/prompt-design-strategies
- IBM — *Chain-of-thought prompting.* https://www.ibm.com/think/topics/chain-of-thoughts
- Wei et al. — *Chain-of-thought prompting elicits reasoning in large language models (arXiv).* https://arxiv.org/abs/2201.11903
- Prompting Guide — *Prompt engineering techniques.* https://www.promptingguide.ai/techniques
- Midjourney — *Prompt design guide.* https://docs.midjourney.com/hc/en-us/articles/32044155278989-Prompts
- Stability AI — *Stable Diffusion prompt guide.* https://stability.ai/learning-hub/prompt-templates

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
