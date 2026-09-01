# Security Visibility Assessment Platform

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Graduation Project](https://img.shields.io/badge/Status-Graduation%20Project-brightgreen)]()

---

## 🎯 Overview

**Security Visibility Assessment Platform** is an intelligent tool that scans your organization's security tool configurations (SIEM, EDR, Firewall, Sysmon, Windows Event Log) and identifies **detection blind spots** — the attacks you wouldn't see coming.

Instead of telling you "your configuration is wrong," it tells you:
- **What attacks you'd miss** (BLIND SPOT)
- **What attacks you'd detect too late** (PARTIAL VISIBILITY)
- **What you're already detecting well** (COVERED)
- **How to fix the gaps** (Step-by-step remediation)

---

## 🚀 Quick Start

### Option 1: Run Locally

```bash
# Clone/download the project
cd security_visibility_platform

# Install dependencies
pip install -r requirements.txt

# Run the web app
streamlit run app.py
```

Visit: `http://localhost:8501`

### Option 2: Docker

```bash
# Build and run with Docker Compose
docker-compose up --build

# Access at http://localhost:80
```

---

## 📋 Features

### 🔍 5-Page Web Application

1. **Onboarding** — Step-by-step guides for exporting configs from each tool
2. **Upload** — Upload JSON configurations and validate them
3. **Dashboard** — View overall coverage % and browse techniques
4. **Search** — Find specific techniques and test your detection
5. **Detail** — Deep dive into each technique with remediation steps

### 🛡️ 20+ ATT&CK Techniques Covered

- **Credential Access**: LSASS Dumping, SAM Registry, DCSync, Keylogging
- **Execution**: PowerShell, Command Shell, Malicious Links
- **Persistence**: Scheduled Tasks, Registry Run Keys, Startup Folder
- **Defense Evasion**: Disable AV/EDR, Clear Event Logs, Masquerading
- **Lateral Movement**: RDP, Admin Shares
- **Command & Control**: DNS C2, HTTP/HTTPS C2
- **Exfiltration**: Data Exfiltration Over C2
- **Discovery**: Account Discovery, System Information Discovery

### 📊 Quality-Aware Assessment

Not just "is logging enabled?" but:
- ✅ **COVERED** — Logging + Alert Rule = Real-time detection
- ⚠️ **PARTIAL** — Logging exists but no alert = Detection too late
- ❌ **BLIND SPOT** — No logging = Completely invisible

### 📥 PDF Export

Export professional reports for stakeholders, management, or incident response teams.

### 🔌 Config Parsers

Automatically parse:
- Sysmon XML configuration
- Windows Event Log / GPO audit policy
- EDR configuration exports

---

## 📂 Project Structure

```
security_visibility_platform/
├── app.py                    # Main Streamlit web application
├── gap_engine.py             # Core assessment logic (20 techniques)
├── config_parsers.py         # Sysmon, Event Log, EDR parsers
├── pdf_export.py             # PDF report generation
├── requirements.txt          # Python dependencies
├── Dockerfile                # Docker container config
├── docker-compose.yml        # Multi-container setup
├── .streamlit/
│   └── config.toml          # Streamlit settings
└── README.md                # This file
```

---

## 🎓 How It Works

### The Gap Engine Logic

```
For each ATT&CK technique:
  1. Load requirements from Knowledge Base
     (e.g., "T1003.001 needs: Sysmon Event 10 OR EDR LSASS Protection")
  
  2. Check client's actual configuration
     (e.g., "Client has Sysmon Event 10 enabled but no SIEM alert rule")
  
  3. Compare and score:
     - No requirements met → BLIND SPOT
     - Some met, some missing quality → PARTIAL
     - All met with alerts → COVERED
  
  4. Calculate coverage %
     Covered=100%, Partial=50%, Blind=0%
     Overall = weighted average
```

### Example Output

```
[❌ BLIND SPOT] T1071.004 — DNS C2 Communication

Why it matters:
DNS is a covert channel for C2. Attackers encode commands in DNS queries.

Your status:
✗ Firewall DNS logging disabled
✗ No EDR network protection

Impact:
C2 beaconing over DNS blends into normal traffic. No detection possible.

Remediation:
1. Enable DNS query logging on firewall/DNS server
2. Forward logs to SIEM with anomaly detection
3. Enable EDR network protection module
```

---

## 📊 Sample Configurations

### Scenario 1: Small Business (43% Coverage)

```json
{
  "windows_event_logs": {
    "powershell_script_block_logging": true,
    "registry_audit": false,
    "scheduled_task_creation": true
  },
  "edr": {
    "lsass_protection": false,
    "tamper_protection": true
  },
  "firewall": {
    "dns_logging": false
  },
  "siem": {
    "correlation_rules": ["failed_login_burst"]
  }
}
```

Result: **3 blind spots, 2 partial visibility, 2 covered**

### Scenario 2: Enterprise (100% Coverage)

```json
{
  "windows_event_logs": {
    "powershell_script_block_logging": true,
    "registry_audit": true,
    "scheduled_task_creation": true
  },
  "edr": {
    "lsass_protection": true,
    "tamper_protection": true,
    "network_protection": true
  },
  "firewall": {
    "dns_logging": true
  },
  "siem": {
    "correlation_rules": ["all_major_alerts"]
  }
}
```

Result: **0 blind spots, 0 partial, all 7 covered ✅**

---

## 🔧 Extending the Knowledge Base

Want to add more techniques? It's easy:

```python
# In gap_engine.py, add to KNOWLEDGE_BASE:

Technique(
    technique_id="T1021.001",
    name="Remote Desktop Protocol",
    tactic="Lateral Movement",
    why_relevant="RDP is a common lateral movement vector...",
    impact_if_blind="Attacker moves laterally without detection...",
    requirements=[
        Requirement("Windows Event Log", "Remote logon (4624 LogonType=10)",
                    lambda c: get(c, "windows_event_logs", "remote_logon") is True),
    ],
    remediation=[
        "Enable audit for remote logon (Event 4624)",
        "Alert on RDP from unexpected sources",
    ],
),
```

---

## 🐛 Configuration Format

### Required Fields

```json
{
  "windows_event_logs": {
    "powershell_script_block_logging": boolean,
    "registry_audit": boolean,
    "scheduled_task_creation": boolean,
    "ad_replication_audit": boolean,
    "process_command_line": boolean,
    "remote_logon_audit": boolean,
    "log_clear_audit": boolean,
    "file_audit": boolean,
    "share_access_audit": boolean
  },
  "sysmon": {
    "installed": boolean,
    "event_id_1_process_creation": boolean,
    "event_id_10_process_access": boolean,
    "registry_set_value_event": boolean,
    "file_create_event": boolean,
    "image_load_event": boolean,
    "network_connection_event": boolean
  },
  "edr": {
    "product": string,
    "lsass_protection": boolean,
    "tamper_protection": boolean,
    "real_time_protection": boolean,
    "network_protection": boolean,
    "code_integrity_check": boolean,
    "behavioral_detection": boolean,
    "malware_detection": boolean,
    "keyboard_input_monitoring": boolean
  },
  "firewall": {
    "outbound_logging": boolean,
    "dns_logging": boolean,
    "https_inspection": boolean
  },
  "siem": {
    "ingested_sources": [string],
    "correlation_rules": [string],
    "log_retention_days": number
  },
  "email_security": {
    "url_sandboxing": boolean
  }
}
```

---

## 🎯 Real-World Use Cases

### 1. Security Audit
Management asks: "Are we protected against ransomware?"
Platform shows: "You'd detect these attacks, but these you'd miss..."

### 2. Incident Response
After a breach: "How did the attacker move laterally undetected?"
Platform shows: "You had no detection for T1021.001 (RDP lateral movement)"

### 3. Security Roadmap
Planning security investments: "What should we buy/configure first?"
Platform shows: "Add this SIEM rule, enable that EDR feature, configure this logging..."

### 4. Compliance Reporting
Auditors ask: "What's your detection coverage?"
Platform generates: PDF report with detailed findings

---

## 📈 Development Roadmap

### Phase 1 ✅ DONE
- Core Gap Engine (20 techniques)
- Web application (5 pages)
- Config parsers
- PDF export

### Phase 2 (Future)
- EDR API connectors (live Defender data)
- Firewall API integrations
- Multi-environment aggregation
- 50+ techniques coverage

### Phase 3 (Long-term)
- Atomic Red Team integration (live validation)
- ML-based anomaly detection
- Graphical dashboard with metrics
- User authentication + multi-tenant support

---

## 📝 Testing

### Run Unit Tests

```bash
python -m pytest tests/ -v
```

### Test with Sample Config

```bash
python -c "
from gap_engine import assess
import json

config = json.load(open('sample_config.json'))
results = assess(config)

for r in results:
    print(f'{r[\"status\"]}: {r[\"technique_id\"]}')
"
```

---

## 🚀 Deployment

### Local Deployment

```bash
streamlit run app.py
```

### Production Deployment (AWS/DigitalOcean/Heroku)

```bash
# Build Docker image
docker build -t blindspot-platform .

# Push to registry
docker tag blindspot-platform:latest myregistry/blindspot-platform:latest
docker push myregistry/blindspot-platform:latest

# Deploy to container service (ECS, K8s, etc.)
```

---

## 📞 Support & Contributions

### Report Issues
Found a bug? Create an issue with:
- Platform version
- Configuration used
- Expected vs actual output

### Add Techniques
Want to add more ATT&CK techniques?
1. Fork the repo
2. Add technique to `gap_engine.py`
3. Submit a pull request

---

## 📄 License

MIT License — See LICENSE file for details

---

## 🙏 Acknowledgments

- MITRE ATT&CK Framework
- DeTT&CT (inspiration)
- Sysmon (Windows Sysinternals)
- Streamlit (web framework)

---

## 👤 Author

**Abdullah** — Cybersecurity Student, Blue Team / SOC Analysis
- Medium Blog: [@abdullmst](https://medium.com/@abdullmst)
- Focus: Agentic AI for Blue Team Operations

---

## ⭐ Show Your Support

If this project helped you, give it a ⭐ and share it with your team!

---

**Last Updated:** August 31, 2026
**Version:** 3.0 (Graduation Release)
