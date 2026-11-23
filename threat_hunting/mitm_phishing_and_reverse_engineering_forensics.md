# Digital Forensics & Threat Hunting: Adversary-in-the-Middle (AiTM) Phishing & Session Hijacking

A deep-dive technical threat hunting and forensic investigation guide detailing Adversary-in-the-Middle (AiTM) authentication proxy infrastructure, session token exfiltration mechanics, and telemetry detection patterns.

---

## 1. Attack Lifecycle & Interception Architecture

Adversary-in-the-Middle (AiTM) reverse proxy frameworks (e.g. Evilginx, Modlishka) position attacker infrastructure directly between victim endpoints and authentic identity providers (IdPs):

```text
[ Victim Browser ] <--- TLS Session 1 ---> [ AiTM Reverse Proxy ] <--- TLS Session 2 ---> [ Legitimate IdP (OpenID / OAuth2) ]
                                                    |
                                                    +---> Intercepts Set-Cookie: session_token
                                                    +---> Bypasses Standard MFA Prompts
```

### MITRE ATT&CK Mapping:
- **T1566.002**: Phishing: Spearphishing Link
- **T1556.007**: Modify Authentication Process: Hybrid Authentication / AiTM
- **T1539**: Steal Web Session Cookie
- **T1071.001**: Application Layer Protocol: Web Protocols

---

## 2. Forensic Artifacts & Telemetry Indicators

### Identity Provider (IdP) Sign-In Telemetry
1. **MFA Satisfied without Step-Up Event**: Sign-in logs show MFA completion from an unfamiliar ASN or IP subnet matching bulletproof hosting providers rather than the user's primary ISP.
2. **Session Cookie Replay Across Geographies**: Successful authenticated requests issued within seconds from distinct geographic IP ranges using identical session tokens (`User-Agent` string anomalies).
3. **Missing Device Trust Claims**: Azure AD / Okta logs missing compliant device certificate claims or Device Registration IDs (`deviceID: null`).

---

## 3. Network & Host-Level Detection Logic

### Sigma Detection Rule Specification (AiTM Session Replay)

```yaml
title: Potential AiTM Session Token Replay
id: c4e3b129-87a1-42e5-9fa2-8b894172a392
status: experimental
description: Detects rapid user session activity from disparate ASN/IP addresses with matching session identifiers.
references:
  - https://attack.mitre.org/techniques/T1556/007/
tags:
  - attack.credential_access
  - attack.t1556.007
  - attack.t1539
logsource:
  category: authentication
  product: entra_id
detection:
  selection:
    AppDisplayName: "Office 365 Exchange Online"
    ResultType: 0
  filter_known_subnets:
    IPAddress|startswith:
      - "10."
      - "192.168."
  condition: selection and not filter_known_subnets | count(IPAddress) by UserId > 1
falsepositives:
  - Legitimate corporate VPN roaming across multi-region egress gateways
level: high
```

---

## 4. Defensive Hardening Strategies

- **FIDO2 / WebAuthn Hardware Security Keys**: Enforce origin-bound phishing-resistant credentials where browser cryptographic challenges bind to the legitimate TLS server hostname.
- **Continuous Access Evaluation (CAE)**: Enable token revocation based on real-time location/IP drift events.
- **Conditional Access Device Compliance**: Require managed device trust attributes before authorizing access to cloud resources.
