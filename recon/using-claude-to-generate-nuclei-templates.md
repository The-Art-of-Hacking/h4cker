# Using Claude to Generate Nuclei Templates

Using **AI models** like **Claude Code** (or any strong code-capable LLM) is a powerful way to speed up **Nuclei template** development while keeping quality high. You can go from a **CVE / PoC / Burp history / manual test idea** to a working **YAML template** in minutes instead of hours, as long as you structure your prompts and review the output carefully. [Look at Project Discovery's Blog](https://projectdiscovery.io/blog/future-of-automating-nuclei-templates-with-ai)

Below is a practical, end‑to‑end guide focused on:

- How **Nuclei templates** are structured (so you know what to ask AI for).
- How to **prompt** AI (Claude Code style) to generate templates from:
  - CVEs & PoCs
  - Burp traffic
  - Manual “idea‑level” descriptions
- How to create **prompt frameworks**, **checklists**, and **validation workflows** so you can confidently use the generated templates in real scans.

***

2. **Quick refresher: How Nuclei templates work**

**Nuclei** is a fast, template‑driven vulnerability scanner that uses **YAML‑based templates** to define checks for HTTP, DNS, TCP, SSL, WebSocket, WHOIS, JS, and more. Each template describes:
- **Metadata**: `id`, `name`, `author`, `severity`, `tags`  
- **Info**: description, references, CVE IDs, CWE, vendor, etc. 
- **Requests / Flows**: one or more protocol requests with **matchers** and **extractors** 
- **DSL conditions**: logic for when to mark a target as vulnerable or interesting. 

Nuclei now also has **AI‑powered template generation** built into the ecosystem, showing that AI assistance for template creation is first‑class and expected. 

Understanding this structure is important because your AI prompts should explicitly ask for **valid YAML** that follows the official style.

Useful docs / context:

- **Nuclei overview & template concepts**: what fields exist, protocols, and DSL basics. 
- **Community templates**: thousands of examples to show AI. 
***

3. **Why use AI (Claude Code) for Nuclei templates**

Generative AI is especially good at:

- Turning **unstructured text** (blog PoC, write‑up, vendor advisory) into:
  - **Endpoints**
  - **Parameters**
  - **Payloads**
  - **Expected responses / patterns** 
- Converting **raw HTTP requests & responses** into:
  - **Multi‑step Nuclei flows**
  - **Dynamic parameter extraction**
  - **Reused variables between requests** 

Teams already use GPT‑class models in:

- Internal systems that read CVE PoCs and output Nuclei templates. 
- Burp Suite plugins that send HTTP sequences to AI for **multi‑step template generation**. 

You can reproduce the same pattern yourself with Claude Code / similar AI tools.

***

4. **Core workflow: Using AI to generate a Nuclei template from a CVE**

### 4.1. Inputs you’ll provide to the AI

For the best results, collect:

- **CVE ID & description**  
- **PoC / exploit details** – from GitHub, blog posts, CVE PoC, etc. 
- **Target protocol** – HTTP(S), TCP, DNS, etc. 

Then feed those into the AI with a **structured prompt**.

### 4.2. Base prompt skeleton (Claude Code style)

You can adapt something like this as your **standard system prompt** when working in Claude Code:

> You are an expert security researcher and Nuclei template author.  
> Your job is to generate high‑quality, production‑ready Nuclei templates in YAML.  
> Follow the official Nuclei documentation and community template style.  
> Requirements:
> - Use valid YAML syntax compatible with the latest Nuclei versions.  
> - Include: `id`, `info` (name, author, severity, description, tags, references).  
> - Use the correct protocol section (`http`, `tcp`, `dns`, etc.) and `requests`.  
> - Use **DSL matchers** for robust detection (e.g. `status_code`, `body`, `header`, regex).  
> - Avoid destructive payloads; keep checks safe and idempotent.  
> - When there are multiple steps, use multiple requests and extractors.  
> - Add comments in the YAML (starting with `#`) only where necessary to clarify complex parts.  
> - Do not include any prose outside the YAML block in your answer.

Then in the **user message**, paste the CVE description and PoC, and ask:

> Using the information below, generate a Nuclei HTTP template that detects this vulnerability in a safe, non‑destructive way.  
>  
> CVE and PoC details:  
> ```text
> [paste CVE advisory + PoC snippet]
> ```  

This pattern mirrors what internal and community systems do when extracting PoC details via AI. 

### 4.3. What you should inspect in the AI‑generated template

After AI returns a template, manually review:

- **Metadata**
  - **Solid `id`** (e.g. `cve-2026-xxxx-appname`)  
  - Accurate **severity** (per CVSS/advisory)  
  - **References** include the CVE and PoC link  
- **Request**
  - Correct **HTTP method** and **path** from PoC  
  - Parameters and payload match PoC, but are **safe**  
  - Headers: only what’s needed  
- **Matchers / DSL**
  - Conditions actually indicate a vulnerability, not just generic 200 OK  
  - Use of regex or word matchers is precise  

If something looks wrong, **copy the YAML back into AI** and ask:

> Validate this Nuclei template against the CVE description below.  
> Explain issues and produce a corrected version only if needed.

This “self‑review loop” is a common way teams refine AI‑generated templates. 

***

5. **From Burp traffic to multi‑step Nuclei templates (with AI)**

Some vulnerabilities (auth flows, CSRF bypass, chained exploits) require **multiple HTTP requests**, parameter extraction, and stateful behavior. AI is good at transforming **Burp history** into such templates. 
### 5.1. Data to capture from Burp

- The **full sequence** of HTTP requests (raw)  
- Corresponding **responses**, at least for the key steps  
- Notes: “Request 1 logs in, request 2 changes email, request 3 confirms…”  

### 5.2. Prompt pattern

> I will give you a sequence of HTTP requests and responses from Burp Suite that trigger a vulnerability.  
>  
> Goal: Generate a Nuclei template with multiple `http` requests that replicates this sequence, automatically extracting dynamic values (tokens, IDs) from responses and reusing them in subsequent requests.  
>  
> Requirements:
> - Use `extractors` to capture tokens/IDs from responses.  
> - Use those extracted values in later requests via Nuclei variables.  
> - Ensure the template is safe and only detects, not exploits, the issue.  
> - Return only the YAML.  
>  
> Here is the sequence:  
> ```http
> [Request 1 + Response 1]
> [Request 2 + Response 2]
> ...
> ```  

This mirrors how others have used GPT‑class models to build multi‑step templates from grouped Burp requests. 

### 5.3. Review checklist

- Does the template:
  - Correctly **extract** dynamic values (e.g., CSRF tokens, session IDs)? 
  - Reuse them in later requests via variables?  
  - Set proper **matchers** on the final response to signal success/vulnerability?  
- Are **secrets or access tokens** hardcoded? If so, replace with placeholders.  

***

6. **From “idea” or natural language to a Nuclei template**

You can also start with a plain English idea like:

> “Check for email leakage in responses from these endpoints.”  

Nuclei itself now supports **AI‑driven natural language template creation**, so this type of “NL → template” flow aligns well with how the ecosystem is evolving. 

### 6.1. Prompt pattern

> You are an expert Nuclei template author.  
>  
> I will describe a vulnerability or detection I want.  
> Based on that description, generate a Nuclei template in YAML.  
> Use HTTP requests only and make reasonable assumptions about endpoints and payloads.  
> Keep the check safe and non‑destructive.  
> Only output the YAML.  
>  
> Description of detection:  
> ```text
> [plain English description]
> ```  

Then review and refine:

- If endpoint is guessed wrong, tell AI:  
  “Use `/api/v1/users` instead of `/users`” and regenerate.  
- If the payload needs to be tuned, paste the exact payload you tested manually.

***

7. **Prompt engineering patterns that work well**

Based on how others have built AI systems around Nuclei, there are a few patterns that consistently improve quality: 

### 7.1. Few‑shot examples

Give AI **one or two real Nuclei templates** as examples along with your prompt:

> Here is an example template for a different vulnerability:  
> ```yaml
> [existing template 1]
> ```  
> Here is another example:  
> ```yaml
> [existing template 2]
> ```  
>  
> Now, using the style and structure above, generate a template for:  
> ```text
> [your CVE/PoC]
> ```  

This mirrors the “we provided raw HTTP + Nuclei templates as examples” approach used in other AI‑driven template generators.

### 7.2. Strict output format

Always instruct:

- “Return only YAML”
- “No explanation or markdown”
- “Validate that the YAML is syntactically correct”

This reduces clean‑up work.

### 7.3. Forced technical output

AI systems that produce reliable templates **force technical‑only output** and avoid narrative text. Make this explicit:

> Do not paraphrase or summarize the PoC.  
> Extract only the technical artifacts needed for detection:  
> - endpoints, parameters, headers  
> - payloads  
> - expected response patterns  
> and encode them into the Nuclei template.

***

8. **Building a repeatable workflow for your team**

You can turn this into a consistent process similar to what automated pipelines do: 
1. **Collect sources**
   - CVEs, PoC URLs, exploit write‑ups  
2. **Extract technical details**
   - Either manually or with an AI step that turns prose into:
     - **Endpoints**
     - **HTTP payloads**
     - **Steps** to reproduce 
3. **Template generation**
   - Feed that structured technical content to AI with your standard prompt to generate a Nuclei template. [See this](https://projectdiscovery.io/blog/future-of-automating-nuclei-templates-with-ai)
4. **QA and normalization**
   - Optional: a second AI pass focused only on **linting**, **style** and **non‑destructive behavior** (akin to internal tools that “normalize” templates before adding them to repos). 
5. **Human review**
   - Security engineer reviews and tests locally:
     - `nuclei -t template.yaml -u https://test.target`  
6. **Versioning & sharing**
   - Store in Git, follow standard naming and directory conventions (e.g., `http/vulnerabilities/…`).  

Some workflows even combine AI with automation platforms to ingest CVEs, generate templates with an AI model, and send valid ones to storage (e.g., Google Drive). 

***

9. **Guardrails & security best practices**

When using AI to write templates, add some safeguards:

- **Non‑destructive by default**
  - Avoid payloads that delete data, change state permanently, or exploit RCE fully.  
  - Ask AI explicitly: “Make the check safe and detection‑only.”  
- **No credential hardcoding**
  - Don’t paste real API keys, tokens, or cookies into prompts.  
  - Use placeholders and environment variables.  
- **False positive control**
  - Require **multiple conditions** in `matchers` (status + body + header, etc.) to mark vulnerability. 
- **Privacy / data handling**
  - Be mindful of sending sensitive HTTP logs to a cloud model. Use self‑hosted options or redaction if necessary.  

***

10. **Example end‑to‑end flow you could use with Claude Code**

Here’s how a practical session might look for you:

1. **Step 1 – Seed with examples**  
   Paste 1–2 **official Nuclei templates** similar to what you want.

2. **Step 2 – Provide CVE/PoC**  
   Paste CVE text and PoC, and ask:  
   “Generate a Nuclei template in the same style to detect this issue. Non‑destructive.”

3. **Step 3 – First review**  
   - Fix path/params based on your own testing.  
   - Clarify matchers: “Look for this specific error string / version leak.”  

4. **Step 4 – Self‑review via AI**  
   Paste the template back and ask:  
   “Validate this template and fix any mistakes while preserving behavior.”

5. **Step 5 – Local test**  
   Run it against:
   - A **known vulnerable lab** if possible  
   - A **known safe target** to check for false positives  

6. **Step 6 – Promote & share**  
   Once stable, add to your private or public template collection.

This is essentially a manual, Claude‑driven variant of the automated “From CVE to Template” pipelines some teams have built around Nuclei. 

***

11. **Bonus: Combining Nuclei’s own AI features with external AI**

Recent versions of Nuclei and the broader ecosystem introduce **AI‑powered on‑the‑fly template generation** and tools that generate templates from natural language. You can: 

- Use **Claude Code** for:
  - Complex, custom workflows
  - Multi‑step templates
  - Deep reasoning around PoCs and exploit logic 
- Use Nuclei’s **built‑in AI generation** or services like **NucleiCraft** when you just want fast NL → template conversions. 
That hybrid approach gives you both **speed** and **control**.

