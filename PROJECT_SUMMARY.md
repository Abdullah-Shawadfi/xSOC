# Security Visibility Assessment Platform — المشروع كامل

## 🎯 الفكرة باختصار

المنصة بتفحص إعدادات أدوات الأمن عند الشركة (SIEM، EDR، Firewall، Sysmon، Windows Event Log) وتقول:
- **ايه التقنيات الهجومية اللي أنت قادر تلقطها** ✅
- **ايه اللي في نصها** ⚠️  
- **ايه اللي ضايع تماماً** ❌

---

## 📊 الفرق عن الموجود (DeTT&CT)

| المعيار | DeTT&CT | مشروعنا |
|--------|---------|---------|
| جمع البيانات | يدوي (YAML) | تلقائي من الأدوات (APIs, exports) |
| الـ Output | رقم تغطية بس | رقم + شرح واضح للـ business |
| Quality Gaps | لا يميز | يفرق بين "لا data" و"data بلا alert" |
| الـ Impact | معلومة جافة | narrative: "لو حدث X، هتفوتك" |

---

## 🔧 كيفية عمل المنصة

### الـ Input: Config Snapshot من الـ Client
```json
{
  "windows_event_logs": {
    "powershell_script_block_logging": true,
    "process_creation_with_cmdline": false
  },
  "sysmon": {
    "event_id_10_process_access": true
  },
  "edr": {
    "lsass_protection_enabled": false
  },
  "firewall": {
    "dns_query_logging": false
  },
  "siem": {
    "correlation_rules_enabled": [
      "failed_login_burst",
      "security_service_stopped"
    ]
  }
}
```

### الـ Knowledge Base: قائمة التقنيات والـ Requirements
```
T1003.001 — LSASS Memory Dumping
├── Requirements:
│   ├── Sysmon Event 10 on lsass.exe
│   └── EDR LSASS Protection
├── Why: Attacker steals cached credentials
└── Impact: Silent lateral movement

T1059.001 — PowerShell Execution
├── Requirements:
│   ├── PowerShell Script Block Logging (Event 4104)
│   └── SIEM Alert Rule on Suspicious Flags
├── Why: Primary vector for post-exploitation
└── Impact: Malicious commands executed undetected
```

### الـ Gap Engine: المقارنة والـ Assessment
```
Loop كل technique:
1. جيب الـ requirements
2. تفتش عنهم في client configs
3. قارن:
   - مش موجود → BLIND SPOT ❌
   - موجود بس بلا alert → PARTIAL ⚠️
   - موجود + alert rule → COVERED ✅
4. احسب التأثير والـ remediation
```

### الـ Output: تقرير واضح
```
[❌ BLIND SPOT] T1071.004 — DNS C2 Communication

Why: DNS is a covert channel for C2 and data exfiltration

Impact: Attacker uses DNS queries to communicate with C2 servers
        while blending into normal traffic — you have no visibility

Remediation:
  1. Enable DNS query logging on firewall/DNS server
  2. Forward logs to SIEM
  3. Add detection rule for high-entropy DNS queries
```

---

## 📱 الـ Pages والـ Workflow

| الصفحة | الوصف | الإدخال | الإخراج |
|-------|-------|--------|--------|
| **Page 1: Onboarding** | تعليم المستخدم كيفية تحميل الإعدادات | — | Export guides |
| **Page 2: Upload** | رفع JSON configs، validation | JSON file | Checklist |
| **Page 3: Dashboard** | عرض النتائج الإجمالية + قائمة الـ techniques | — | Coverage %، جداول |
| **Page 4: Search** | بحث عن technique معينة واختبارها | Technique ID | Status + Coverage % |
| **Page 5: Detail** | تقرير مفصل عن technique واحدة | — | Why + Impact + Remediation |

---

## 🏗️ Architecture

```
Config Collectors          Normalizer         Knowledge Base
(Sysmon XML,      →     (Unified JSON)  →   (Templates)
 EDR API,                 Schema              ↓
 GPO Report,                              Gap Engine
 Firewall Config)                         (Comparison)
                                              ↓
                                           Results Cache
                                              ↓
                                         Web Dashboard
                                       (Streamlit/React)
```

---

## 📈 مراحل التطوير

### Phase 1: MVP Prototype (Weeks 1-2) ✅ DONE
- Rule-based Gap Engine
- 5 ATT&CK techniques
- CLI output

### Phase 2: Web Dashboard (Weeks 3-4) — GRADUATION SCOPE
- Streamlit dashboard (Pages 1-5)
- Sysmon XML parser
- Windows Event Log reader
- 15-20 techniques in KB
- Search feature

### Phase 3: Multi-Tool Integration (Months 2-3)
- EDR API collectors
- Firewall config reader
- SIEM data-source integrator
- Expand KB to 50 techniques
- Global coverage aggregation

### Phase 4: Validation (Months 4+)
- Atomic Red Team integration
- Live SIEM validation
- 100+ techniques coverage

---

## 🎯 Key Concepts

### BLIND SPOT ❌
```
Logging disabled + No detection possible
= Attacker completely invisible
```

### PARTIAL VISIBILITY ⚠️
```
Logging enabled + No alert rule
= Data exists but nobody's watching
= Detection happens days/weeks later (too late)
```

### COVERED ✅
```
Logging enabled + Alert rule active
= Real-time detection
= Attacker caught immediately
```

---

## 💡 ليه الـ Sub-techniques مهمة؟

```
T1003 — OS Credential Dumping (الـ parent)
├── T1003.001 — LSASS Memory         (Status: COVERED ✅)
├── T1003.002 — SAM Registry         (Status: PARTIAL ⚠️)
├── T1003.003 — NTDS Database        (Status: BLIND ❌)
└── T1003.004 — LSA Secrets          (Status: BLIND ❌)

يعني بعض الـ techniques محموية، بعضها ناقص
→ اسمها "Coverage مش كامل"
```

---

## 🔑 الفرق الأساسي بين المشروع والـ Audit العادي

| Audit العادي | مشروعنا |
|-----------|---------|
| "إعدادك ده غلط" | "لو حدث هجوم PowerShell، أنت مش هتشوفه لأن..." |
| جاف + تقني | واضح + مفهوم لغير المتخصصين |
| لا أولويات | ترتيب حسب الـ impact |
| يدوي + بطيء | تلقائي + سريع |

---

## 📊 مثال على التقرير

```
═══════════════════════════════════════════════════════════
SECURITY VISIBILITY ASSESSMENT REPORT

Overall Coverage: 65%
├── Covered:     6 techniques (35%)
├── Partial:     4 techniques (20%)
└── Blind:       10 techniques (45%)

═══════════════════════════════════════════════════════════

[❌ BLIND SPOT] T1003.002 — SAM Registry Dumping

Why it matters:
Attacker reads SAM database to steal local account hashes

Your status:
✗ Registry access logging disabled
✗ No EDR ASR rule for registry access

Impact:
Attacker extracts local account hashes → brute force attacks
or pass-the-hash attacks. You won't detect this at all.

Remediation:
1. Enable Windows Audit for "Object Access" (registry)
2. Forward Event ID 4663 to SIEM
3. Create SIEM alert on SAM registry access by non-admins

═══════════════════════════════════════════════════════════

[⚠️ PARTIAL VISIBILITY] T1059.001 — PowerShell Execution

Your status:
✓ PowerShell Script Block Logging enabled
✗ But NO SIEM alert rule on suspicious flags

Impact:
You ARE logging commands, but without real-time alerts,
attackers have time to move laterally before detection.

Remediation:
Add SIEM rule to alert on: -enc, -nop, -w hidden, IEX

═══════════════════════════════════════════════════════════

[✅ COVERED] T1053.005 — Scheduled Task Creation

Your status:
✓ Event ID 4698 enabled
✓ SIEM alert rule active

You're detecting this technique in real-time. Good job.

═══════════════════════════════════════════════════════════
```

---

## 🛠️ التكنولوجيا

**Backend:**
- Python 3.9+
- FastAPI (للـ API، لاحقاً)

**Frontend (Phase 2):**
- Streamlit (MVP)
- React (Scale)

**Knowledge Base:**
- JSON templates (structured)
- Pulled from MITRE ATT&CK

**Deployment:**
- Docker
- GitHub Pages (for docs)

---

## 📝 ملاحظات مهمة

1. **المنصة محدودة بـ Knowledge Base:** لو التقنية مش موجودة في KB، المنصة مش قادرة تقول حاجة عنها. الحل: توسيع الـ KB بتدريج.

2. **الـ Quality Checks مهمة:** الفرق بين "data exists" و"data exists with no alert" هو اللي بيميز مشروعنا عن الـ tools التانية.

3. **Sub-techniques بتاخد template منفصلة:** كل sub-technique = entry منفصلة في الـ KB مع requirements خاصة بيها.

4. **المنصة بتقارن template مع config:** الـ Gap Engine بتحفر في client configs وتبحث عن requirements الـ template.

---

## ✅ الخلاصة

**المشروع بسيط في الفكرة بس قوي في الـ Execution:**

1. Client يرفع configs
2. Gap Engine بتقارن مع templates
3. Platform بتطلع report واضح: ايه اللي محموي، ايه اللي ناقص، ايه اللي تماماً ضايع
4. اسمها "Blind Spot Assessment" لأنها بتشوف اللي أنت مش شايفه

**من الآخر: أداة تقول للشركة "هنا أنت ضعيف ومحتاج تقوي الدفاع بتاعك هنا."**
