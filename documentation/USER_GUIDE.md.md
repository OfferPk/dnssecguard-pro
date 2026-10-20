\# DNSSECGuard Pro: User Guide & CI/CD Integration

\#\# Overview  
DNSSECGuard Pro operates both as a 100% client-side web application and as a standalone Python CLI tool to audit DNSSEC zones, verify parent-child chain of trust, simulate failure modes, and synthesize authoritative configurations.

\---

\#\# 1\. Web Studio Quickstart  
1\. Open \`source-code/index.html\` in any modern web browser (no local web server or internet connection required).  
2\. Choose an architecture preset from the dropdown:  
   \- \*\*Apex FinBank\*\*: Fully hardened ECDSA P-256 with DANE TLSA pinning (Grade A+).  
   \- \*\*CloudPulse SaaS\*\*: Cloudflare/Route53 NSEC3 optimized setup (Grade A+).  
   \- \*\*Legacy Corp Portal\*\*: Broken DS chain with deprecated RSASHA1 (Grade F).  
3\. Click \*\*Audit DNSSEC\*\* to view the live 10-point scorecard.  
4\. Review the \*\*Interactive DNSSEC Outage & Zone-Walking Simulator\*\* to visualize chain break outages and zone walking prevention.  
5\. Select a configuration target (\*\*BIND 9\*\*, \*\*Registrar DS\*\*, \*\*DANE TLSA\*\*, or \*\*Python Resolver\*\*) and click \*\*Copy Configuration\*\*.

\---

\#\# 2\. Standalone Python CLI Tool

The CLI tool requires Python 3.8+ with zero external package dependencies.

\#\#\# Command Reference

\`\`\`bash  
\# Audit a DNSSEC zone configuration preset  
python3 build/dnssecguard-cli.py audit \-p presets/enterprise-bank-ecdsa-dane.json

\# Audit with strict CI/CD gating (exits with code 1 on failures or score \< 90\)  
python3 build/dnssecguard-cli.py audit \-p presets/enterprise-bank-ecdsa-dane.json \--strict

\# Inspect zone parameters as raw JSON  
python3 build/dnssecguard-cli.py inspect \-p presets/enterprise-bank-ecdsa-dane.json  
\`\`\`

\---

\#\# 3\. CI/CD Pre-Commit / Pre-Deployment Pipeline

Integrate DNSSECGuard Pro into GitHub Actions or GitLab CI to prevent deploying DNS zones with broken DS delegations or deprecated algorithms:

\`\`\`yaml  
\# .github/workflows/dnssec-guard.yml  
name: DNSSEC Chain-of-Trust & Delegation Verification  
on: \[push, pull\_request\]

jobs:  
  dnssec-audit:  
    runs-on: ubuntu-latest  
    steps:  
      \- uses: actions/checkout@v4  
      \- name: Set up Python  
        uses: actions/setup-python@v5  
        with:  
          python-version: '3.11'  
      \- name: Run DNSSECGuard Strict Audit  
        run: |  
          python3 build/dnssecguard-cli.py audit \\  
            \-p presets/enterprise-bank-ecdsa-dane.json \\  
            \--strict  
\`\`\`  
