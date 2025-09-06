# Bug Bounty Tips and Information

Here’s a straightforward introduction to bug bounties and a roadmap for getting started.

## What Is a Bug Bounty?

A **bug bounty** program is an offer by organizations (often via a platform like HackerOne, Bugcrowd or Synack) to reward security researchers for finding and responsibly disclosing vulnerabilities in their systems. Instead of hiring full‑time pentesters, many companies crowdsource testing to a global community, paying per valid finding.

## Why Participate?

* **Real‑world impact:** You help make widely used software more secure.
* **Skill growth:** You hone vulnerability‑finding techniques on live targets.
* **Earnings potential:** Payouts range from tens to tens of thousands of dollars per bug.
* **Community, gaining experience & reputation:** Build your resume or potentially even a hall‑of‑fame profile on bug‑bounty platforms.

## Prerequisites & Foundations

Before diving in, make sure you’ve got:

1. **Basic web and network security knowledge**

   * HTTP, DNS, SSL/TLS, common web vulnerabilities (OWASP Top 10).
2. **Familiarity with pentesting tools**

   * Burp Suite (or OWASP ZAP), nmap, curl, your browser’s dev tools.
3. **Programming/scripting comfort**

   * At least one language (Python, JavaScript, Bash) to automate tests.

## Choosing Your First Program

1. **Start small:** Look for “low‑complexity” or “public reconnaissance” targets.
2. **Read the policy:** Each program’s scope, in‑scope assets, and disallowed tests vary.
3. **Check hall of fame:** Review disclosed reports to see what others are finding.

## First Steps

1. **Sign up on a platform:** Create profiles on HackerOne, Bugcrowd, maybe GitHub’s Security Lab.
2. **Complete training labs:** Try free labs like PortSwigger Academy, OWASP Juice Shop, O'Reilly, Hack The Box, ✨[Network Academy: Ethical Hacker Free Course (34 labs!)](https://skillsforall.com/course/ethical-hacker?courseLang=en-US)
3. **Set up your toolkit:**
   * Burp (community edition is fine to start)
   * ZAP
   * nmap, nuclei, gobuster, ffuf, etc. for discovery
   * an intercepting proxy plugin or Burp extension collection
4. **Pick a target:** Navigate through the programs and pick one.
5. **Do reconnaissance:** Map out endpoints, parameters, auth flows, error messages.

## Writing Your First Report

* **Be concise and clear:** Explain how to reproduce, impact, and remediation. Probably use AI to help you with these reports.
* **Include PoC steps:** Screenshots, curl commands, or a short script.
* **Respect the disclosure timeline:** Follow the program’s guidelines for report updates and public disclosure.

## Growing Your Skills

* **Learn new vulnerability classes:** Server‑Side Request Forgery, Insecure Deserialization, XXE, etc.
* **Automate repetitive tasks:** Write simple scripts to spot injection points. Specially, nowadays with the use of AI.
* **Join the community:** Follow write‑ups on bug‑bounty blogs, Discord groups, Twitter/LinkedIn threads, etc.

## Types of Bug Bounty Programs: A Comprehensive Comparison

Understanding the different types of vulnerability programs is crucial for researchers to choose the right opportunities that align with their skills, goals, and preferences. Here's a detailed comparison of the three main program types:

### Private Bug Bounty Programs

**What they are:** Invitation-only programs where companies restrict participation to a select group of vetted researchers.

**Key Characteristics:**
- **Access:** By invitation only, typically requiring proven track record or platform reputation
- **Competition:** Lower researcher-to-target ratio, reducing competition
- **Rewards:** Often higher payouts due to reduced competition and premium positioning
- **Scope:** Usually broader scope with access to internal systems or pre-production environments
- **Response Time:** Faster triage and resolution due to dedicated security teams
- **Relationship:** More direct communication with security teams, potential for ongoing relationships

**Advantages:**
- Higher earning potential per vulnerability
- Less noise and duplicate submissions
- Better communication and feedback
- Access to unique targets not available publicly
- Opportunity to build long-term relationships with companies

**Disadvantages:**
- Requires established reputation to gain access
- Limited availability - not accessible to beginners
- May have stricter requirements and expectations
- Fewer learning opportunities from community interaction

**Best for:** Experienced researchers with proven track records looking for higher-value targets and premium rewards.

### Public Bug Bounty Programs

**What they are:** Open programs where any researcher can participate without prior approval or invitation.

**Key Characteristics:**
- **Access:** Open to all researchers, no invitation required
- **Competition:** High competition with many researchers testing the same targets
- **Rewards:** Variable payouts, often lower due to high competition
- **Scope:** Clearly defined public scope, usually production systems only
- **Response Time:** Can be slower due to volume of submissions
- **Community:** Large community interaction, shared learning experiences

**Advantages:**
- No barriers to entry - perfect for beginners
- Large variety of targets and technologies to learn from
- Community support and shared knowledge
- Transparent policies and processes
- Good for building initial reputation and portfolio

**Disadvantages:**
- High competition leading to duplicate findings
- Lower payout rates due to competition
- Potential for slower response times
- Limited scope compared to private programs
- Higher chance of program saturation

**Best for:** Beginners and intermediate researchers looking to build skills, reputation, and experience across diverse targets.

### Vulnerability Disclosure Programs (VDPs)

**What they are:** Programs that accept security reports but typically don't offer monetary rewards, focusing instead on responsible disclosure and recognition.

**Key Characteristics:**
- **Access:** Usually open to all researchers
- **Rewards:** No monetary compensation, but may offer recognition, swag, or hall of fame listings
- **Legal Protection:** Provide safe harbor for security research within defined scope
- **Scope:** Often broader than paid programs since there's no financial risk
- **Purpose:** Primarily focused on improving security rather than rewarding researchers
- **Recognition:** Public acknowledgment, certificates, or profile mentions

**Advantages:**
- No financial pressure on companies, leading to broader scopes
- Good for building reputation and demonstrating ethical behavior
- Often more lenient policies and testing permissions
- Valuable for portfolio building and resume enhancement
- Lower competition since there's no monetary incentive

**Disadvantages:**
- No direct financial compensation
- May receive lower priority from security teams
- Limited motivation for extensive testing
- Potential for slower response times
- Less structured processes compared to paid programs

**Best for:** Researchers focused on learning, building reputation, contributing to security community, or testing companies they personally use and care about.

### Platform-Specific Considerations

#### HackerOne Program Types

**Private Programs:**
- Invitation-based with reputation requirements (typically 7+ reputation points)
- Higher average payouts ($500-$10,000+ common range)
- Access to pre-production environments and internal tools
- Direct communication channels with security teams

**Public Programs:**
- Open registration with immediate access
- Wide variety of targets from startups to Fortune 500 companies
- Comprehensive disclosure policies and legal protection
- Community features like public disclosure and hacker interaction

**VDP Programs:**
- Focus on responsible disclosure without monetary rewards
- Often used by smaller companies or those new to bug bounty programs
- Good stepping stone to paid programs for the same organization

#### Bugcrowd Program Types

**Invite-Only Programs:**
- Researcher ranking system determines invitation eligibility
- Premium programs with higher payouts and exclusive access
- Often include additional perks like direct security team access

**Public Programs:**
- Crowd-sourced security testing with open participation
- Comprehensive program management and researcher support
- Integration with enterprise security workflows

**Disclosure Programs:**
- Coordinated disclosure without monetary rewards
- Focus on vulnerability management and security improvement
- Often precursors to paid bounty programs

### Choosing the Right Program Type

**For Beginners:**
1. Start with **public VDP programs** to learn responsible disclosure
2. Progress to **public bug bounty programs** to gain experience and build reputation
3. Eventually work toward **private program invitations**

**For Intermediate Researchers:**
1. Focus on **public bug bounty programs** with good reputations and fair payouts
2. Apply skills across diverse targets to build expertise
3. Aim for consistent findings to build platform reputation

**For Advanced Researchers:**
1. Prioritize **private programs** for higher-value targets and better payouts
2. Maintain presence in select **public programs** for consistent income
3. Consider **VDP programs** for companies you want to build relationships with

### Success Metrics by Program Type

| Metric | Private Programs | Public Programs | VDP Programs |
|--------|------------------|-----------------|--------------|
| Average Payout | $1,000-$15,000+ | $100-$2,000 | $0 (recognition) |
| Competition Level | Low | High | Medium |
| Learning Opportunity | High (unique targets) | High (variety) | Medium |
| Relationship Building | Excellent | Good | Good |
| Beginner Friendly | No | Yes | Yes |
| Time to First Success | Longer | Shorter | Shortest |

### Best Practices Across All Program Types

1. **Always read and understand the program policy** before testing
2. **Respect scope limitations** regardless of program type
3. **Provide clear, detailed reports** with reproduction steps
4. **Follow responsible disclosure timelines** 
5. **Build relationships** with security teams through professional communication
6. **Diversify your program portfolio** across different types and platforms
7. **Track your progress** and learn from both successful and unsuccessful submissions

The key to success in bug bounty hunting is understanding that each program type serves different purposes in your research journey. Start with programs that match your current skill level and gradually work toward more exclusive opportunities as you build experience and reputation.


## Additional Getting Started Guides

- [Bug Bounties 101](https://whitton.io/articles/bug-bounties-101-getting-started/)
- [The life of a bug bounty hunter](http://www.alphr.com/features/378577/q-a-the-life-of-a-bug-bounty-hunter)
- [Awesome list of bugbounty cheatsheets](https://github.com/EdOverflow/bugbounty-cheatsheet)
- [Getting Started - Bug Bounty Hunter Methodology](https://www.bugcrowd.com/blog/getting-started-bug-bounty-hunter-methodology)
- [How to Become a Successful Bug Bounty Hunter](https://hackerone.com/blog/what-great-hackers-share)
- [Researcher Resources - How to become a Bug Bounty Hunter](https://forum.bugcrowd.com/t/researcher-resources-how-to-become-a-bug-bounty-hunter/1102)
- [Nahamsec Resources for Beginners](https://github.com/nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters)

## Write Ups and Walkthroughs
- [Awesome Bug Bounty Writeups](https://github.com/devanshbatham/Awesome-Bugbounty-Writeups)

## Bug Bounty Platforms
- [Bugbountyjp](https://bugbounty.jp/)
- [Bugcrowd](https://bugcrowd.com/)
- [Inspectiv](https://www.inspectiv.com)
- [Cobalt](https://cobalt.io/)
- [Coder Bounty](http://www.coderbounty.com/)
- [Detectify](https://cs.detectify.com/)
- [FreedomSponsors](https://freedomsponsors.org/)
- [HackenProof](https://hackenproof.com/)
- [Hackerhive](https://hackerhive.io/)
- [HackerOne](https://hackerone.com/)
- [Hacktrophy](https://hacktrophy.com/)
- [intigriti](https://intigriti.com/)
- [RedStorm](https://redstorm.io)
- [Safehats](https://safehats.com/)
- [Synack](https://www.synack.com/)
- [YesWeHack](https://yeswehack.com/)
