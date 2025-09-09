## 🧪 Shodan Exploration Lab: "The Search Engine for Hackers"

### 🧭 **Lab Objective**
Learn how to use [Shodan.io](https://shodan.io/) for discovering exposed devices, services, vulnerabilities, and misconfigurations across the internet.

---

## 🧰 **Pre-requisites**
- A Shodan account (free or student-licensed)
- Browser access to [https://shodan.io](https://shodan.io)
- Optional: Shodan CLI (`pip install shodan`) + API Key

---

## 🧠 Learning Outcomes
By the end of this lab, students will be able to:
1. Perform basic and advanced Shodan searches
2. Identify open ports and services
3. Discover insecure IoT devices
4. Use filters to narrow down results
5. Understand the ethical implications of scanning exposed systems

---

## 🔬 Lab Sections

### ✅ Part 1: Shodan Basics – "First Contact"
1. Go to [https://shodan.io](https://shodan.io) and create/login to your account.
2. Search for the following:
   - `apache`
   - `nginx`
   - `ftp`
3. Record:
   - Number of results
   - Countries with the most instances
   - Common open ports

📝 **Task:** What do the results tell you about global web server deployment?

---

### ✅ Part 2: Discovering Devices – "What's Exposed?"
Try the following queries:
- `port:22 country:"US"`
- `default password`
- `webcamxp`
- `product:"GoAhead-Webs"`
- `org:"Amazon.com"`

📝 **Task:** Choose one result and analyze the metadata (IP, ISP, location, OS, open ports, banner info). Does anything appear insecure?

---

### ✅ Part 3: Filter Power – "Precision Hacking (Legally)"
Use filters like:
- `org:` – filter by company/ISP
- `os:` – filter by OS
- `product:` – filter by product name
- `after:` – to narrow down by crawl date

Try:
- `apache country:"IN" port:80 after:"2024-01-01"`
- `ssh os:"Linux" port:22`

📝 **Task:** How do filters help narrow down results for targeted reconnaissance?

---

### ✅ Part 4: CVEs & Vulnerability Search – "Exposure Analytics"
Search for:
- `vuln:CVE-2021-44228` (Log4Shell)
- `vuln:CVE-2017-5638` (Apache Struts)

📝 **Task:** What kind of devices are still vulnerable? Discuss why some vulnerabilities stay unpatched.

---

### ✅ Part 5: Shodan Maps and Reports (Optional)
- Explore [https://exploits.shodan.io](https://exploits.shodan.io) and [https://maps.shodan.io](https://maps.shodan.io)
- See real-time exposed devices
- Create a saved search and export a report

📝 **Task:** What industries or device types show up most in your search? Why?

---

## 🚨 Ethics and Guidelines
- **DO NOT** attempt to connect, log in, or exploit discovered systems.
- Shodan is a reconnaissance tool; accessing systems without permission is **illegal and unethical**.
- This lab is for **educational** and **defensive** awareness only.

---

## 🎯 Final Challenge
Your company asks you to investigate if their infrastructure is exposed. Choose a public organization (e.g., university, ISP, small business) and simulate what a red teamer might find using Shodan queries—**without interacting with any systems**.

📝 **Deliverable:** A 1-page report summarizing:
- Tools used
- Query examples
- Findings (IP ranges, services, ports, exposure)
- Defensive recommendations

---

## 📦 Bonus: Shodan CLI Mini Exercise (Optional)
Install CLI:
```bash
pip install shodan
shodan init <your-api-key>
shodan search apache country:US --fields ip_str,port,org
```

Try using:
```bash
shodan host <IP_ADDRESS>
```

