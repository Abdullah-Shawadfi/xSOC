# 🎉 Security Visibility Assessment Platform

## ⚡ START HERE

### 🚀 Quick Start (2 minutes)

```bash
# 1. Install
pip install -r requirements.txt

# 2. Run
streamlit run app.py

# 3. Open browser
# Go to http://localhost:8501
```

**That's it!** Upload `sample_config.json` and you'll see the platform working.

---

## 📁 What You Have

### 🎯 **Main Files** (What You Need)

1. **app.py** — The web application
   - 5 pages: Onboarding → Upload → Dashboard → Search → Detail
   - Everything you see in the browser

2. **gap_engine.py** — The brain
   - 20 ATT&CK techniques/sub-techniques
   - Assessment logic (BLIND/PARTIAL/COVERED)
   - Quality checking

3. **config_parsers.py** — Input handlers
   - Parses Sysmon XML
   - Reads Windows Event Log configs
   - Extracts EDR settings

4. **pdf_export.py** — Report generator
   - Creates professional PDF reports
   - Includes all findings + remediation

### ⚙️ **Setup Files**

- **requirements.txt** — Python dependencies
- **Dockerfile** — Docker container config
- **docker-compose.yml** — Multi-container setup
- **.streamlit/config.toml** — Streamlit settings
- **sample_config.json** — Example to test with

### 📚 **Documentation**

- **README.md** — Full project documentation
- **GETTING_STARTED.md** — Extended getting started guide
- **PROJECT_SUMMARY.md** — Business overview
- **IMPLEMENTATION_GUIDE.md** — How to extend
- **PROJECT_COMPLETE.txt** — Completion summary
- **START_HERE.md** — This file

---

## 🎯 What The App Does

### Input
```
Upload JSON config with security tool settings
(Sysmon, Windows Event Log, EDR, Firewall, SIEM)
```

### Processing
```
Gap Engine assesses configuration against
20 ATT&CK techniques + sub-techniques
```

### Output
```
Dashboard shows:
✅ COVERED — You detect this attack
⚠️ PARTIAL — You log it but don't alert
❌ BLIND SPOT — You'd never see this attack

Coverage % + Remediation steps for each gap
```

---

## 🧪 Test It (Right Now)

### Option 1: Use Sample Config
```bash
streamlit run app.py
# Then upload sample_config.json in the app
# You'll see: 56% coverage, 5 blind spots, 3 partial, 6 covered
```

### Option 2: Test The Logic Directly
```bash
python3 -c "
from gap_engine import assess
import json

config = json.load(open('sample_config.json'))
results = assess(config)

for r in results:
    print(f\"{r['status']}: {r['technique_id']}\")
"
```

---

## 📊 The 20 Techniques

**Credential Access:**
- T1003.001 — LSASS Memory
- T1003.002 — SAM Registry
- T1003.006 — DCSync
- T1056.001 — Keylogging

**Execution:**
- T1059.001 — PowerShell
- T1059.003 — Command Shell
- T1204.001 — Malicious Link

**Persistence:**
- T1053.005 — Scheduled Task
- T1547.001 — Registry Run Key
- T1547.014 — Startup Folder

**Defense Evasion:**
- T1562.001 — Disable AV/EDR
- T1070.001 — Clear Event Logs
- T1036.001 — Masquerading

**Lateral Movement:**
- T1021.001 — RDP
- T1021.006 — Admin Shares

**Command & Control:**
- T1071.004 — DNS C2
- T1071.001 — HTTP/HTTPS C2

**Exfiltration:**
- T1041 — Data Exfil Over C2

**Discovery:**
- T1087.001 — Local Account Discovery
- T1082 — System Information Discovery

---

## 🌐 The 5 Pages

### Page 1: Onboarding
- How to export configs from Sysmon
- How to export configs from Windows Event Log
- How to export configs from EDR (Defender)
- How to export configs from Firewall
- How to export configs from SIEM
- Download sample config

### Page 2: Upload
- Upload JSON file
- Parse Sysmon XML file
- Paste JSON text directly
- Validation + checklist

### Page 3: Dashboard
- **Coverage %** (big number at top)
- Tabs for: All / Blind Spots / Partial / Covered
- Click any technique → go to detail page
- Download PDF report

### Page 4: Search
- Search for technique (e.g., "PowerShell", "T1003")
- See status + coverage + remediation
- Focused detail view

### Page 5: Detail
- Complete information about one technique
- Why it matters
- Impact if you don't detect it
- Step-by-step remediation
- Download PDF

---

## ✨ Key Innovation: Quality Checking

Most tools ask: "Is logging enabled?"

**Our tool asks:**
- ✅ Logging enabled + SIEM alert rule = **COVERED** (Real-time detection)
- ⚠️ Logging enabled but no alert rule = **PARTIAL** (Late detection)
- ❌ Logging disabled = **BLIND SPOT** (No detection)

Example:
```
T1059.001 — PowerShell Execution

Scenario 1 (COVERED):
✓ PowerShell Script Block Logging enabled
✓ SIEM alert rule configured
→ Real-time detection of malicious PowerShell

Scenario 2 (PARTIAL):
✓ PowerShell Script Block Logging enabled
✗ No SIEM alert rule
→ Logs exist but nobody's watching
→ Detection happens days later during forensics

Scenario 3 (BLIND SPOT):
✗ PowerShell Script Block Logging disabled
→ No data at all
→ Attacker executes PowerShell freely
```

---

## 🐳 Docker (Optional)

```bash
# Option A: Build and run
docker build -t blindspot .
docker run -p 8501:8501 blindspot

# Option B: Docker Compose
docker-compose up --build

# Then open http://localhost:8501 or http://localhost:80
```

---

## 📝 How To Use Your Own Config

1. **Export Sysmon config:**
   ```powershell
   sysmon -c | Out-File sysmon_config.xml
   ```

2. **Export Windows Event Log settings:**
   - Group Policy Editor → Audit Policy → Export as GPO report

3. **Export EDR config:**
   ```powershell
   Get-MpPreference | ConvertTo-Json > defender.json
   ```

4. **Export Firewall config:**
   ```powershell
   Get-NetFirewallProfile | ConvertTo-Json > firewall.json
   ```

5. **List SIEM correlation rules:**
   - Export from your SIEM console

6. **Combine into one JSON file** (use sample_config.json as template)

7. **Upload to the app**

---

## 🎓 For Examiners/Presenters

### What Makes This Project Stand Out

1. **Automated** — Reads actual configs, not manual entry
2. **Quality-Aware** — Detects "data exists but no alerting" (PARTIAL)
3. **Plain-Language** — Says "You'd miss this attack" not "Your config is wrong"
4. **Practical** — Gives specific remediation steps
5. **Extensible** — Easy to add more techniques
6. **Professional** — PDF reports, web UI, Docker deployment

### Quick Pitch (30 seconds)
> "Most security tools don't tell you what you're NOT seeing. We scan your tool configs and tell you which attacks would slip through, why, and how to fix it. We're different from static audits because we're automated, repeatable, and we understand quality gaps—like when you're logging data but have no alert rule on top of it."

---

## 🆘 Troubleshooting

### "ModuleNotFoundError: streamlit"
```bash
pip install streamlit==1.28.1
```

### "Port 8501 already in use"
```bash
streamlit run app.py --server.port 8502
```

### JSON validation errors
Make sure your config has all required keys (see sample_config.json)

---

## 📞 Next Steps

1. ✅ Install dependencies
2. ✅ Run the app
3. ✅ Test with sample config
4. ✅ Try uploading your own config
5. ✅ Download PDF report
6. ✅ Read the code (it's documented!)
7. ✅ Deploy with Docker (optional)

---

## 📖 More Info

- **Full Documentation:** `README.md`
- **Implementation Guide:** `IMPLEMENTATION_GUIDE.md`
- **Project Summary:** `PROJECT_SUMMARY.md`
- **Completion Status:** `PROJECT_COMPLETE.txt`

---

## ✅ Project Status

**Version:** 3.0 (Graduation Release)
**Status:** ✅ COMPLETE & READY TO USE
**Date:** August 31, 2026

---

**Enjoy! 🚀**
