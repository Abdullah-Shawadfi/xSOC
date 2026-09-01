#!/usr/bin/env python3
"""
Security Visibility Assessment Platform — Prototype v0.1
----------------------------------------------------------------
Idea: instead of grading a tool's config as "good/bad", map each
config item to the ATT&CK technique(s) it enables detection for.
If none of the required data points exist -> BLIND SPOT.
If some exist but with quality gaps (retention, no alert rule,
noisy/uncorrelated) -> PARTIAL VISIBILITY.

Input : a JSON "environment snapshot" describing what's actually
        configured across SIEM / EDR / Sysmon / Windows Event Log /
        Firewall.
Output: a blind-spot report — technique, why, detection impact,
        remediation steps — plus an overall visibility %.
"""

import json
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class Requirement:
    tool: str
    description: str
    check: Callable[[dict], bool]
    quality_check: Optional[Callable[[dict], Optional[str]]] = None
    # quality_check returns None if fine, or a string describing the gap


@dataclass
class Technique:
    technique_id: str
    name: str
    tactic: str
    why_relevant: str
    impact_if_blind: str
    requirements: list  # list[Requirement] — technique visible if ANY is satisfied
    remediation: list   # list[str]


def get(cfg, *path, default=None):
    node = cfg
    for p in path:
        if not isinstance(node, dict) or p not in node:
            return default
        node = node[p]
    return node


# ---------------------------------------------------------------
# Knowledge base: ATT&CK technique -> what would actually detect it
# (starter set — this table is the real IP of the project; it should
# grow to cover the full ATT&CK Enterprise matrix over time)
# ---------------------------------------------------------------
KNOWLEDGE_BASE = [
    Technique(
        technique_id="T1003.001",
        name="OS Credential Dumping: LSASS Memory",
        tactic="Credential Access",
        why_relevant="Attacker reads LSASS process memory to steal cached creds/hashes.",
        impact_if_blind="Credential theft goes unseen -> attacker moves laterally with valid accounts, "
                         "no alert fires until those accounts are abused elsewhere.",
        requirements=[
            Requirement("Sysmon", "Event ID 10 (ProcessAccess) targeting lsass.exe",
                        lambda c: get(c, "sysmon", "event_id_10_process_access") is True,
                        lambda c: "enabled but no filter/alert on lsass.exe target" if
                                  get(c, "sysmon", "event_id_10_process_access") is True and
                                  not get(c, "siem", "correlation_rules_enabled", default=[]).__contains__("lsass_access")
                                  else None),
            Requirement("EDR", "LSASS protection / credential-theft ASR rule",
                        lambda c: get(c, "edr", "lsass_protection_enabled") is True),
        ],
        remediation=[
            "Enable Sysmon Event ID 10 with a filter on lsass.exe as TargetImage.",
            "Enable EDR 'Block credential stealing from LSASS memory' (ASR rule) or equivalent.",
            "Add a SIEM correlation rule that alerts on any non-whitelisted process opening lsass.exe.",
        ],
    ),
    Technique(
        technique_id="T1059.001",
        name="Command and Scripting Interpreter: PowerShell",
        tactic="Execution",
        why_relevant="Most post-exploitation tooling (Mimikatz wrappers, C2 stagers, recon scripts) runs via PowerShell.",
        impact_if_blind="Attacker executes obfuscated PowerShell; only generic process creation is logged "
                         "with no script content, so the actual malicious command is invisible to hunters.",
        requirements=[
            Requirement("Windows Event Log", "PowerShell Script Block Logging (4104)",
                        lambda c: get(c, "windows_event_logs", "powershell_script_block_logging") is True),
            Requirement("Windows Event Log", "PowerShell Module Logging (4103)",
                        lambda c: get(c, "windows_event_logs", "powershell_module_logging") is True),
        ],
        remediation=[
            "Enable Script Block Logging via GPO (records de-obfuscated script content).",
            "Forward Event ID 4104/4103 to the SIEM, not just 4688.",
            "Add detection for suspicious PowerShell flags (-enc, -nop, -w hidden) on top of the raw logs.",
        ],
    ),
    Technique(
        technique_id="T1562.001",
        name="Impair Defenses: Disable or Modify Tools",
        tactic="Defense Evasion",
        why_relevant="Attacker disables AV/EDR/logging as a first step to operate freely.",
        impact_if_blind="The disabling action itself is the highest-value alert in the whole kill chain, "
                         "and it silently fails to fire.",
        requirements=[
            Requirement("EDR", "Tamper protection enabled",
                        lambda c: get(c, "edr", "tamper_protection_enabled") is True),
            Requirement("SIEM", "Alert rule for security service stop/config change events",
                        lambda c: "security_service_stopped" in get(c, "siem", "correlation_rules_enabled", default=[])),
        ],
        remediation=[
            "Enable EDR tamper protection so agent/service cannot be stopped by an admin-level process.",
            "Add a SIEM rule on Event ID 7040 (service state change) and 104 (log cleared).",
            "Alert on Windows Defender status change events (5001, 5010, 5012).",
        ],
    ),
    Technique(
        technique_id="T1071.004",
        name="Application Layer Protocol: DNS (C2 / Exfiltration)",
        tactic="Command and Control",
        why_relevant="DNS is rarely inspected but is a common covert channel for C2 and data exfiltration.",
        impact_if_blind="C2 beaconing over DNS blends into normal traffic; no visibility means no baseline "
                         "to detect volume/entropy anomalies.",
        requirements=[
            Requirement("Firewall", "DNS query logging enabled",
                        lambda c: get(c, "firewall", "dns_query_logging") is True),
            Requirement("EDR", "Network protection / DNS inspection module",
                        lambda c: get(c, "edr", "network_protection") is True),
        ],
        remediation=[
            "Enable DNS query logging on the firewall/DNS server and forward to SIEM.",
            "Enable EDR network protection (blocks/logs connections to known-bad domains).",
            "Add a detection rule for high-entropy / high-volume DNS queries per host.",
        ],
    ),
    Technique(
        technique_id="T1053.005",
        name="Scheduled Task/Job (Persistence)",
        tactic="Persistence",
        why_relevant="Common, low-noise persistence mechanism after initial access.",
        impact_if_blind="Attacker re-establishes access after reboot/cleanup with no alert on task creation.",
        requirements=[
            Requirement("Windows Event Log", "Task Scheduler operational log (Event ID 4698)",
                        lambda c: get(c, "windows_event_logs", "scheduled_task_creation_4698") is True),
            Requirement("Sysmon", "Event ID 1 correlated with schtasks.exe / taskeng.exe",
                        lambda c: get(c, "sysmon", "event_id_1_process_creation") is True),
        ],
        remediation=[
            "Enable Task Scheduler operational logging (4698/4699/4700/4702).",
            "Forward these events to SIEM and alert on task creation by non-admin users or from temp paths.",
        ],
    ),
]


def assess(cfg: dict):
    results = []
    for tech in KNOWLEDGE_BASE:
        satisfied = [r for r in tech.requirements if r.check(cfg)]
        quality_notes = []
        for r in satisfied:
            if r.quality_check:
                note = r.quality_check(cfg)
                if note:
                    quality_notes.append(f"{r.tool}: {note}")

        if not satisfied:
            status = "BLIND SPOT"
        elif quality_notes:
            status = "PARTIAL VISIBILITY"
        else:
            status = "COVERED"

        results.append({
            "technique_id": tech.technique_id,
            "name": tech.name,
            "tactic": tech.tactic,
            "status": status,
            "why": tech.why_relevant,
            "impact": tech.impact_if_blind if status != "COVERED" else None,
            "quality_gaps": quality_notes,
            "remediation": tech.remediation if status != "COVERED" else [],
        })
    return results


def print_report(results):
    covered = sum(1 for r in results if r["status"] == "COVERED")
    partial = sum(1 for r in results if r["status"] == "PARTIAL VISIBILITY")
    blind = sum(1 for r in results if r["status"] == "BLIND SPOT")
    total = len(results)
    score = (covered + 0.5 * partial) / total * 100

    print("=" * 70)
    print(f"SECURITY VISIBILITY REPORT — Overall Detection Coverage: {score:.0f}%")
    print(f"Covered: {covered} | Partial: {partial} | Blind spots: {blind} (of {total} techniques checked)")
    print("=" * 70)

    for r in results:
        if r["status"] == "COVERED":
            continue
        print(f"\n[{r['status']}] {r['technique_id']} — {r['name']}  (Tactic: {r['tactic']})")
        print(f"  Why it matters : {r['why']}")
        print(f"  Impact         : {r['impact']}")
        if r["quality_gaps"]:
            print(f"  Quality gaps   : {'; '.join(r['quality_gaps'])}")
        print("  Remediation    :")
        for step in r["remediation"]:
            print(f"    - {step}")


if __name__ == "__main__":
    # Example environment snapshot — this is what a real collector
    # would pull from Sysmon config, EDR API/console, Windows GPO
    # report, firewall config export, and SIEM data-source list.
    sample_env = {
        "windows_event_logs": {
            "powershell_script_block_logging": False,
            "powershell_module_logging": True,
            "scheduled_task_creation_4698": False,
            "security_log_retention_days": 15,
        },
        "sysmon": {
            "installed": True,
            "event_id_1_process_creation": True,
            "event_id_10_process_access": True,
            "event_id_3_network_connection": True,
            "event_id_11_file_create": True,
        },
        "edr": {
            "product": "Microsoft Defender for Endpoint",
            "lsass_protection_enabled": False,
            "tamper_protection_enabled": True,
            "real_time_protection": True,
            "network_protection": False,
        },
        "firewall": {
            "outbound_logging_enabled": True,
            "dns_query_logging": False,
        },
        "siem": {
            "ingested_sources": ["windows_security", "sysmon", "edr_alerts"],
            "correlation_rules_enabled": ["failed_login_burst", "security_service_stopped"],
            "log_retention_days": 30,
        },
    }

    results = assess(sample_env)
    print_report(results)

    with open("assessment_output.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
