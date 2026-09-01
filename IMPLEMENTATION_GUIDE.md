# Security Visibility Assessment Platform — Implementation Guide

## ✅ ما الموجود دلوقتي (Phase 1: DONE)

### الملفات الموجودة:

1. **blindspot_assessor_v2.py** — الـ Gap Engine الشغال 100%
   - Logic سليم + معالج للـ edge cases
   - 7 techniques/sub-techniques بسياق عملي
   - Quality checking (detects PARTIAL VISIBILITY)
   - اتنين scenario مختلفة للـ testing

2. **PROJECT_SUMMARY.md** — توثيق كامل للفكرة
   - شرح مفصل لكل مفهوم
   - الفرق عن الموجود
   - الـ Architecture
   - الـ Roadmap

3. **scenario_1_assessment.json** و **scenario_2_assessment.json** — outputs فعلية

---

## 🎯 الخطوات القادمة (Phase 2: Weeks 3-4 للـ Graduation)

### الأولوية الأولى: Streamlit Dashboard

**File to create:** `app.py`

```python
import streamlit as st
from blindspot_assessor_v2 import assess, print_report
import json

st.set_page_config(page_title="Security Visibility", layout="wide")

st.title("🔍 Security Visibility Assessment Platform")

# Page 1: Onboarding (if no config uploaded)
# Page 2: Upload config JSON
# Page 3: Show dashboard with coverage %
# Page 4: Search technique
# Page 5: Detailed report
```

**Timeline:** 3-4 days

**Output:** Web interface شغال يقبل JSON ويطلع التقرير

---

### الأولوية الثانية: Config Collectors

**File to create:** `collectors/sysmon_parser.py`

```python
import xml.etree.ElementTree as ET

def parse_sysmon_config(xml_path):
    """
    Read Sysmon config XML and extract enabled events
    Returns: dict with Event IDs
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()
    
    enabled_events = []
    for event in root.findall(".//Event[@enabled='true']"):
        event_id = event.get('id')
        enabled_events.append(int(event_id))
    
    return {
        "sysmon": {
            "installed": True,
            "event_id_1_process_creation": 1 in enabled_events,
            "event_id_10_process_access": 10 in enabled_events,
            # ... etc
        }
    }
```

**Timeline:** 2-3 days

**Output:** Script يقرأ XML files من Sysmon config

---

### الأولوية الثالثة: Expand Knowledge Base

**File to update:** `blindspot_assessor_v2.py` → add 10-15 techniques

**Techniques to add:**
- T1021.001 — RDP (Remote Service)
- T1087 — Account Discovery
- T1087.001 — Local Account
- T1087.002 — Domain Account
- T1010 — Application Window Discovery
- T1217 — Browser Bookmark Discovery
- T1580 — Cloud Infrastructure Discovery
- T1083 — File and Directory Discovery
- T1046 — Network Service Discovery
- T1135 — Network Share Discovery
- T1040 — Network Sniffing
- T1566.001 — Phishing: Spearphishing Attachment
- T1598.001 — Phishing for Information: Spearphishing Link
- T1199 — Trusted Relationship

**Timeline:** 1-2 days (قصات وملصقات من نفس الـ template)

---

## 📋 Implementation Checklist (Week by Week)

### Week 1-2: BASE (DONE ✅)
- ✅ Core Gap Engine logic
- ✅ Knowledge Base with 7 techniques
- ✅ JSON input/output
- ✅ Quality checking (PARTIAL detection)
- ✅ Prototype testing with 2 scenarios

### Week 3: STREAMLIT + COLLECTORS
- [ ] Streamlit app scaffold (Pages 1-3)
- [ ] JSON upload + validation
- [ ] Sysmon XML parser
- [ ] Basic Windows Event Log reader
- [ ] Link parser output to Gap Engine

### Week 4: EXPAND + POLISH
- [ ] Add 10-15 more techniques to KB
- [ ] Complete all 5 pages in Streamlit
- [ ] Search functionality
- [ ] Export to PDF
- [ ] Better formatting + styling

---

## 🔧 How to Extend Knowledge Base

### Template (copy-paste this):

```python
Technique(
    technique_id="T1021.001",
    name="Remote Desktop Protocol",
    tactic="Lateral Movement",
    why_relevant="RDP is a common lateral movement vector. Attackers use valid credentials to RDP into other systems.",
    impact_if_blind="Attacker moves laterally via RDP without detection → compromises additional systems in the network.",
    requirements=[
        Requirement("Windows Event Log", "RDP Connection Events (Event 4624 with LogonType=10)",
                    lambda c: get(c, "windows_event_logs", "remote_logon_audit") is True),
        Requirement("EDR", "RDP lateral movement detection",
                    lambda c: "rdp_lateral_movement_alert" in (get(c, "siem", "correlation_rules_enabled") or [])),
    ],
    remediation=[
        "Enable audit for remote logon events (Event 4624 LogonType=10)",
        "Add SIEM alert on RDP logon from unexpected sources",
        "Consider restricting RDP to jump hosts only",
    ],
),
```

**Just fill in these 4 fields:**
1. `technique_id` — from MITRE ATT&CK
2. `why_relevant` — 1-2 sentences about why it matters
3. `impact_if_blind` — what happens if you don't detect it
4. `remediation` — 3-5 concrete steps to fix

---

## 📊 Testing Your Changes

After you add techniques or modify logic:

```bash
# Run the prototype
python3 blindspot_assessor_v2.py

# Check the output
# Scenario 1 should show more blind spots
# Scenario 2 should still show 100% coverage
```

If a technique is showing BLIND when it should be COVERED:
1. Check if sample_env has the required field
2. Check if requirement.check() is correct
3. Debug the lambda function

---

## 🚀 Deployment (After Graduation)

### For Phase 3+ (Optional):

```bash
# Dockerize
docker build -t blindspot-platform .
docker run -p 8501:8501 blindspot-platform

# Deploy to cloud
# Push to Heroku / AWS / DigitalOcean
```

### Sample Dockerfile:

```dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY . .
RUN pip install streamlit pandas
EXPOSE 8501
CMD streamlit run app.py
```

---

## 📝 Deliverables for Graduation Project

### Must-have:
- ✅ Core Gap Engine (DONE)
- ✅ Knowledge Base with 15-20 techniques (WIP)
- ⏳ Streamlit dashboard with 5 pages
- ⏳ Config parsers (Sysmon, Event Log)
- ⏳ PDF export capability
- ⏳ Documentation + README

### Nice-to-have:
- [ ] EDR API integration
- [ ] Multiple environment support
- [ ] Database for storing past assessments
- [ ] User authentication
- [ ] Comparison between environments

---

## 🎓 How to Present This (For Examiners)

**Pitch (2 minutes):**
> "Most security tools don't tell you what you're *not* seeing. Our platform reads your tool configurations and tells you which attacks you'd miss, why you'd miss them, and how to fix it. It generates a clear impact narrative instead of just listing config mismatches."

**Demo Flow:**
1. Show the 2 scenarios (Partial vs Full coverage)
2. Explain BLIND SPOT vs PARTIAL vs COVERED
3. Show a single technique's full report (why/impact/remediation)
4. Run a new config through it live

**Key talking points:**
- Automated (not manual audit)
- Quality-aware (detects PARTIAL too)
- Plain-English output (business-readable)
- Extensible (easy to add techniques)

---

## 🐛 Common Issues & Fixes

### Issue: "ModuleNotFoundError: streamlit"
```bash
pip install streamlit pandas
```

### Issue: Technique shows wrong status
- Check `requirement.check()` logic
- Verify sample_env has the field
- Add debug print: `print(f"Checking {requirement.field}: {result}")`

### Issue: JSON won't parse
- Make sure client config matches the schema
- Use `json.loads()` with error handling:
```python
try:
    config = json.load(f)
except json.JSONDecodeError:
    print("Invalid JSON")
```

---

## 📚 Resources

- **MITRE ATT&CK:** https://attack.mitre.org/
- **Streamlit docs:** https://docs.streamlit.io/
- **Sysmon config:** https://github.com/SwiftOnSecurity/sysmon-config
- **Windows Event IDs:** https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/

---

## 🎯 Success Criteria (For Your Graduation)

By end of Week 4, you should have:

✅ **Proof of concept:** Gap Engine working with 15+ techniques

✅ **Web interface:** Streamlit app with at least 3 pages working

✅ **Real config parsing:** At least Sysmon XML parser functional

✅ **Documentation:** README.md explaining how to use

✅ **Test cases:** 2-3 scenarios showing different coverage levels

✅ **Clear narrative:** Can explain the difference between BLIND/PARTIAL/COVERED in 30 seconds

---

## 💡 Pro Tips

1. **Reuse the template:** Once you have one technique working, the rest are copypasta + config tweaks

2. **Test incrementally:** Add 3 techniques, run `blindspot_assessor_v2.py`, verify output, then add 3 more

3. **Use GitHub:** Commit early, commit often. Examiners like seeing the progression

4. **Document everything:** Comments in code + README = examiners understand your thinking

5. **Keep the prototype simple:** Fancy UI comes later. Solid logic matters now.

---

**You've got this. Start with Week 3 priorities and you'll crush it. 💪**
