"""The "About" text shown at the bottom of every page: the README overview and its agents table, word for word.

``tests/test_about.py`` checks this against README.md, so the two cannot drift apart.
"""

ABOUT_TITLE = "About Cyber Security AI Agent"

ABOUT_MD = """### Overview

**What it is:** 

SecAgents is a multi-agent cyber security assistant powered by **Five AI agents (Log Monitor, Threat Intelligence, Vulnerability Scanner, Incident Response and Policy Checker)** work together to find attacks, check whether you're affected, and tell you what to fix.

**How it works:** 

A **LangGraph** supervisor runs the agents in dependency order, and **Agentic RAG** grounds them in **CVE, MITRE ATT&CK and NIST / ISO 27001 / SOC 2** knowledge. Detection is rule-based first, with an LLM adding narrative and remediation. It works with **OpenRouter, Claude or OpenAI**, with automatic fallback, and still runs fully offline with no API key.

**What you get:** 

An assessment from your logs, code, dependencies, Dockerfile and config. It covers a prioritized incident playbook (NIST SP 800-61), compliance scores per framework, and a report you can download as **Word, Excel, PDF, Markdown or JSON**.

**Real-time:** 

The **Streamlit** dashboard has a Live scan that follows log files as they grow and alerts the first time each attack appears. It also has a Simulation mode and a paste box for trying attack lines.

**Where it runs:** 

The dashboard runs on a long-lived **Streamlit** host, and the project ships with an automated test suite.

| Agent | What it does |
|---|---|
| 📜 **Log Monitor** | Parses auth, web and firewall logs. Detects brute force and password spraying, login-after-brute-force, privilege escalation, backdoor accounts, SQLi / path traversal / XSS / command injection / Log4Shell, scanners, port scans and outbound C2 traffic. Maps each detection to MITRE ATT&CK and writes an attack narrative. |
| 🔍 **Vulnerability Scanner** | Runs Bandit SAST on code, finds hardcoded secrets, lints the Dockerfile (EOL base image, root user, secrets in ENV...), builds a software inventory, uses Trivy if installed, and suggests code fixes. |
| 🌐 **Threat Intelligence** | Answers *"are we affected?"*: version-matches the inventory against CVEs, uses agentic RAG to identify which CVE an exploit attempt targets and whether that component is deployed, correlates attacks in the logs with weaknesses in the code, and checks IOCs. |
| 🚨 **Incident Response** | Declares prioritized incidents and generates a NIST SP 800-61 playbook (analysis, containment, eradication, recovery, post-incident) with concrete commands for the actual attacker IPs, accounts and hosts. |
| 📋 **Policy Checker** | Evaluates 20 technical checks against 40 controls in NIST 800-53, NIST CSF 2.0, ISO 27001:2022 and SOC 2; scores each framework and writes a remediation roadmap ranked by how many controls each fix closes. |
"""
