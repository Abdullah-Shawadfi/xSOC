#!/usr/bin/env python3
"""
Security Visibility Assessment Platform — Prototype v2.0
Enhanced: Sub-techniques support, Quality checking, Better narratives

Flow:
  1. Client uploads config JSON
  2. Gap Engine loops through Knowledge Base
  3. For each technique/sub-technique:
     - Check if requirements are met
     - Check for quality issues
     - Assign status: COVERED / PARTIAL / BLIND
  4. Generate report
  5. Calculate overall coverage %
"""

import json
from dataclasses import dataclass, field
from typing import Callable, Optional, List
from enum import Enum


class Status(Enum):
    COVERED = "COVERED"
    PARTIAL = "PARTIAL VISIBILITY"
    BLIND = "BLIND SPOT"


@dataclass
class Requirement:
    """A single requirement for detecting a technique"""
    tool: str  # Sysmon, EDR, Windows Event Log, etc.
    field: str  # Which field/setting to check
    check: Callable[[dict], bool]  # Function that checks if requirement is met
    quality_check: Optional[Callable[[dict], Optional[str]]] = None
    # quality_check returns None if quality is good, or a string describing the gap


@dataclass
class Technique:
    """A single technique (or sub-technique) from ATT&CK"""
    technique_id: str  # T1003.001, T1059.001, etc.
    name: str  # LSASS Memory, PowerShell Execution, etc.
    tactic: str  # Credential Access, Execution, etc.
    why_relevant: str  # Why this technique matters
    impact_if_blind: str  # What happens if you don't detect it
    requirements: List[Requirement]  # List of requirements to detect it
    remediation: List[str]  # Steps to fix/improve detection


def get(cfg, *path, default=None):
    """Helper to safely navigate nested dicts"""
    node = cfg
    for p in path:
        if not isinstance(node, dict) or p not in node:
            return default
        node = node[p]
    return node


# ═════════════════════════════════════════════════════════════════════════
# KNOWLEDGE BASE v2.0 — WITH SUB-TECHNIQUES
# ═════════════════════════════════════════════════════════════════════════

KNOWLEDGE_BASE = [
    # ═══ T1003 — OS Credential Dumping ═══
    Technique(
        technique_id="T1003.001",
        name="LSASS Memory",
        tactic="Credential Access",
        why_relevant="Attacker reads LSASS process memory to steal cached credentials and NTLM hashes. "
                     "This is a critical credential access vector used in 80%+ of breach campaigns.",
        impact_if_blind="Attacker steals hashes without detection → uses them for lateral movement → "
                        "compromises multiple systems before you notice.",
        requirements=[
            Requirement("Sysmon", "Event ID 10 (ProcessAccess) on lsass.exe",
                        lambda c: get(c, "sysmon", "event_id_10_process_access") is True,
                        lambda c: "enabled but no SIEM alert rule" if
                                  get(c, "sysmon", "event_id_10_process_access") is True and
                                  "lsass_process_access_alert" not in (get(c, "siem", "correlation_rules_enabled") or [])
                                  else None),
            Requirement("EDR", "LSASS Protection (Credential Guard / ASR rule)",
                        lambda c: get(c, "edr", "lsass_protection_enabled") is True),
        ],
        remediation=[
            "Enable Sysmon Event ID 10 with filter on lsass.exe as TargetImage",
            "Enable EDR 'Block credential stealing from LSASS memory' ASR rule",
            "Add SIEM correlation rule: Alert on any non-whitelisted process accessing lsass.exe",
            "Optional: Enable Windows Defender Credential Guard for domain-joined machines",
        ],
    ),

    Technique(
        technique_id="T1003.002",
        name="SAM Registry",
        tactic="Credential Access",
        why_relevant="Attacker accesses SAM (Security Account Manager) registry hive to extract local account hashes. "
                     "This is common in lateral movement after initial access.",
        impact_if_blind="Attacker extracts local account hashes → uses them for lateral movement to other systems. "
                        "Detection happens days later during forensics.",
        requirements=[
            Requirement("Windows Event Log", "Registry Access Audit (Event 4663)",
                        lambda c: get(c, "windows_event_logs", "registry_access_audit") is True),
            Requirement("SIEM", "Alert rule on SAM registry access",
                        lambda c: "sam_registry_access_alert" in (get(c, "siem", "correlation_rules_enabled") or [])),
        ],
        remediation=[
            "Enable 'Object Access' audit policy for registry via GPO",
            "Forward Event ID 4663 to SIEM",
            "Add SIEM correlation rule: Alert on SAM registry access (\\Registry\\Machine\\SAM) by non-System users",
            "Set alert severity: HIGH",
        ],
    ),

    Technique(
        technique_id="T1003.006",
        name="DCSync",
        tactic="Credential Access",
        why_relevant="Attacker uses Directory Replication Service to request password hashes from domain controller. "
                     "No credentials needed — only user rights (often obtained via compromised admin account).",
        impact_if_blind="Attacker extracts all AD password hashes silently → can crack them offline. "
                        "Entire domain compromised.",
        requirements=[
            Requirement("Windows Event Log", "Active Directory Replication Events (4662, 4663, 4662)",
                        lambda c: get(c, "windows_event_logs", "ad_replication_audit") is True),
            Requirement("SIEM", "Alert rule on unusual replication requests",
                        lambda c: "dcsync_alert" in (get(c, "siem", "correlation_rules_enabled") or [])),
        ],
        remediation=[
            "Enable audit for Active Directory replication (Event 4662, 4663)",
            "Forward to SIEM and alert on non-DC accounts requesting directory replication",
            "Restrict 'Replicate Directory Changes' and 'Replicate Directory Changes All' permissions to DC machine accounts",
            "Monitor for Kerberoasting and DCSync tools in logs",
        ],
    ),

    # ═══ T1059 — Command and Scripting Interpreter ═══
    Technique(
        technique_id="T1059.001",
        name="PowerShell Execution",
        tactic="Execution",
        why_relevant="PowerShell is the primary execution vector for post-exploitation. "
                     "Most C2 frameworks, credential dumping tools, and lateral movement use PowerShell.",
        impact_if_blind="Attacker executes obfuscated PowerShell; you only see generic 'powershell.exe started'. "
                        "Actual malicious command is invisible → attacker operates freely.",
        requirements=[
            Requirement("Windows Event Log", "PowerShell Script Block Logging (Event 4104)",
                        lambda c: get(c, "windows_event_logs", "powershell_script_block_logging") is True,
                        lambda c: "enabled but no SIEM alert rule" if
                                  get(c, "windows_event_logs", "powershell_script_block_logging") is True and
                                  "powershell_suspicious_flags_alert" not in (get(c, "siem", "correlation_rules_enabled") or [])
                                  else None),
            Requirement("SIEM", "Alert rule on suspicious PowerShell flags",
                        lambda c: "powershell_suspicious_flags_alert" in (get(c, "siem", "correlation_rules_enabled") or [])),
        ],
        remediation=[
            "Enable PowerShell Script Block Logging via GPO (records de-obfuscated script content)",
            "Forward Event ID 4104 to SIEM",
            "Add detection rule for: -enc, -EncodedCommand, -nop, -NoProfile, -w hidden, IEX, DownloadString, DownloadFile",
            "Set alert to HIGH severity",
            "Optional: Enable PowerShell transcription for additional logging",
        ],
    ),

    # ═══ T1071 — Application Layer Protocol (C2) ═══
    Technique(
        technique_id="T1071.004",
        name="DNS (C2 / Exfiltration)",
        tactic="Command and Control",
        why_relevant="DNS is rarely inspected but is a common covert channel for C2 beaconing and data exfiltration. "
                     "Attackers encode commands in DNS queries → hard to detect without baseline.",
        impact_if_blind="C2 beaconing over DNS blends into normal traffic. No baseline exists to detect volume/entropy anomalies. "
                        "Attacker maintains persistence and can issue commands to compromised systems.",
        requirements=[
            Requirement("Firewall", "DNS query logging enabled",
                        lambda c: get(c, "firewall", "dns_query_logging") is True,
                        lambda c: "enabled but no anomaly detection" if
                                  get(c, "firewall", "dns_query_logging") is True and
                                  "dns_anomaly_detection" not in (get(c, "siem", "correlation_rules_enabled") or [])
                                  else None),
            Requirement("EDR", "Network protection / DNS inspection",
                        lambda c: get(c, "edr", "network_protection") is True),
        ],
        remediation=[
            "Enable DNS query logging on firewall/DNS server",
            "Forward logs to SIEM and build baseline of normal DNS queries",
            "Add detection rule for: high-entropy DNS queries, unusual query volume per host, queries to suspicious domains",
            "Consider DNS sinkhole service for known C2 domains",
            "Enable EDR network protection to block known malicious DNS queries",
        ],
    ),

    # ═══ T1053 — Scheduled Task/Job ═══
    Technique(
        technique_id="T1053.005",
        name="Scheduled Task Creation",
        tactic="Persistence",
        why_relevant="Scheduled tasks are low-noise persistence mechanism. "
                     "After initial access, attacker creates task to re-establish access on reboot/cleanup.",
        impact_if_blind="Attacker creates scheduled task for persistence. Task runs silently with system privileges. "
                        "Even if you remove attacker's access, scheduled task brings them back.",
        requirements=[
            Requirement("Windows Event Log", "Task Scheduler Creation (Event 4698, 4699)",
                        lambda c: get(c, "windows_event_logs", "scheduled_task_creation") is True),
            Requirement("SIEM", "Alert rule on task creation",
                        lambda c: "scheduled_task_alert" in (get(c, "siem", "correlation_rules_enabled") or [])),
        ],
        remediation=[
            "Enable Task Scheduler operational logging (Events 4698, 4699, 4700, 4701, 4702)",
            "Forward to SIEM and alert on: task creation by non-admin users, tasks pointing to temp paths, tasks with suspicious names",
            "Review existing scheduled tasks regularly for anomalies",
            "Restrict Task Scheduler access via GPO if possible",
        ],
    ),

    # ═══ T1562 — Impair Defenses ═══
    Technique(
        technique_id="T1562.001",
        name="Disable or Modify Tools",
        tactic="Defense Evasion",
        why_relevant="Disabling AV/EDR is the first step of any breach. "
                     "This is the highest-value alert in the kill chain.",
        impact_if_blind="Attacker disables Defender silently. You don't even know. "
                        "Attacker then operates with zero fear of detection.",
        requirements=[
            Requirement("EDR", "Tamper protection enabled",
                        lambda c: get(c, "edr", "tamper_protection_enabled") is True),
            Requirement("SIEM", "Alert rule for security service stop/modification",
                        lambda c: "security_service_modification_alert" in (get(c, "siem", "correlation_rules_enabled") or [])),
        ],
        remediation=[
            "Enable EDR tamper protection so service/agent cannot be stopped by user-level process",
            "Add SIEM rule on Event 7040 (service state change), 104 (log cleared), 5001-5012 (Defender status changes)",
            "Alert with CRITICAL severity on any security tool modification",
            "Consider running EDR in kernel mode to prevent tampering",
        ],
    ),
]


def assess(client_configs: dict):
    """
    Main assessment function.
    
    Args:
        client_configs: JSON snapshot of client's security tool configurations
    
    Returns:
        list of assessment results for each technique
    """
    results = []

    for technique in KNOWLEDGE_BASE:
        # Step 1: Check which requirements are satisfied
        satisfied = []
        quality_notes = []

        for requirement in technique.requirements:
            if requirement.check(client_configs):
                satisfied.append(requirement)
                # Check for quality issues in this satisfied requirement
                if requirement.quality_check:
                    note = requirement.quality_check(client_configs)
                    if note:
                        quality_notes.append(f"{requirement.tool}: {note}")

        # Step 2: Determine status based on satisfaction and quality
        if not satisfied:
            status = Status.BLIND
        elif quality_notes:
            status = Status.PARTIAL
        else:
            status = Status.COVERED

        # Step 3: Build result
        result = {
            "technique_id": technique.technique_id,
            "name": technique.name,
            "tactic": technique.tactic,
            "status": status.value,
            "why": technique.why_relevant,
            "impact": technique.impact_if_blind if status != Status.COVERED else None,
            "quality_gaps": quality_notes,
            "remediation": technique.remediation if status != Status.COVERED else [],
            "satisfied_requirements": [r.tool + ": " + r.field for r in satisfied],
        }

        results.append(result)

    return results


def print_report(results):
    """Print a formatted report"""
    covered = sum(1 for r in results if r["status"] == "COVERED")
    partial = sum(1 for r in results if r["status"] == "PARTIAL VISIBILITY")
    blind = sum(1 for r in results if r["status"] == "BLIND SPOT")
    total = len(results)

    # Calculate coverage percentage
    coverage = (covered + 0.5 * partial) / total * 100 if total > 0 else 0

    print("\n" + "=" * 80)
    print("SECURITY VISIBILITY ASSESSMENT REPORT")
    print("=" * 80)
    print(f"\nOVERALL DETECTION COVERAGE: {coverage:.0f}%")
    print(f"Covered: {covered}/{total} | Partial: {partial}/{total} | Blind: {blind}/{total}")
    print("=" * 80)

    # Print blind spots
    print("\n[❌ BLIND SPOTS] — Immediate attention required\n")
    blind_count = 0
    for r in results:
        if r["status"] == "BLIND SPOT":
            blind_count += 1
            print(f"({blind_count}) [{r['technique_id']}] {r['name']} — {r['tactic'].upper()}")
            print(f"    Why: {r['why']}")
            print(f"    Impact: {r['impact']}")
            print(f"    Remediation:")
            for i, step in enumerate(r["remediation"], 1):
                print(f"      {i}. {step}")
            print()

    # Print partial visibility
    print("\n[⚠️ PARTIAL VISIBILITY] — Add alert rules\n")
    partial_count = 0
    for r in results:
        if r["status"] == "PARTIAL VISIBILITY":
            partial_count += 1
            print(f"({partial_count}) [{r['technique_id']}] {r['name']}")
            print(f"    Issue: {'; '.join(r['quality_gaps'])}")
            print(f"    Satisfied: {', '.join(r['satisfied_requirements'])}")
            print(f"    Fix: Add SIEM correlation rule and real-time alerting")
            print()

    # Print covered
    print("\n[✅ COVERED] — Good job\n")
    covered_count = 0
    for r in results:
        if r["status"] == "COVERED":
            covered_count += 1
            print(f"({covered_count}) [{r['technique_id']}] {r['name']} — {r['tactic']}")

    print("\n" + "=" * 80)


def save_json_report(results, filename="assessment_output_v2.json"):
    """Save results as JSON"""
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n✓ JSON report saved: {filename}")


if __name__ == "__main__":
    # ═══════════════════════════════════════════════════════════════
    # SAMPLE SCENARIO 1: Partially Configured Environment
    # ═══════════════════════════════════════════════════════════════
    print("\n" + "█" * 80)
    print("█ SCENARIO 1: Company with partial security tooling")
    print("█" * 80)

    sample_env_1 = {
        "windows_event_logs": {
            "powershell_script_block_logging": True,  # ✓ Good
            "registry_access_audit": False,  # ✗ Missing
            "scheduled_task_creation": True,  # ✓ Good
            "ad_replication_audit": False,  # ✗ Missing
        },
        "sysmon": {
            "installed": True,
            "event_id_10_process_access": True,  # ✓ LSASS monitoring
            "event_id_1_process_creation": True,
        },
        "edr": {
            "product": "Microsoft Defender for Endpoint",
            "lsass_protection_enabled": False,  # ✗ Missing
            "tamper_protection_enabled": True,  # ✓ Good
            "real_time_protection": True,
            "network_protection": False,  # ✗ Missing
        },
        "firewall": {
            "outbound_logging_enabled": True,
            "dns_query_logging": False,  # ✗ Missing
        },
        "siem": {
            "ingested_sources": ["windows_security", "sysmon"],
            "correlation_rules_enabled": [
                "failed_login_burst",
                "security_service_stopped",
                # ⚠️ Missing: lsass alert, powershell alert, dcsync alert, scheduled_task alert
            ],
            "log_retention_days": 30,
        },
    }

    results_1 = assess(sample_env_1)
    print_report(results_1)
    save_json_report(results_1, "/mnt/user-data/outputs/scenario_1_assessment.json")

    # ═══════════════════════════════════════════════════════════════
    # SAMPLE SCENARIO 2: Well-Hardened Environment
    # ═══════════════════════════════════════════════════════════════
    print("\n" + "█" * 80)
    print("█ SCENARIO 2: Enterprise with comprehensive security")
    print("█" * 80)

    sample_env_2 = {
        "windows_event_logs": {
            "powershell_script_block_logging": True,
            "registry_access_audit": True,
            "scheduled_task_creation": True,
            "ad_replication_audit": True,
        },
        "sysmon": {
            "installed": True,
            "event_id_10_process_access": True,
            "event_id_1_process_creation": True,
        },
        "edr": {
            "product": "CrowdStrike Falcon",
            "lsass_protection_enabled": True,  # ✓
            "tamper_protection_enabled": True,
            "real_time_protection": True,
            "network_protection": True,  # ✓
        },
        "firewall": {
            "outbound_logging_enabled": True,
            "dns_query_logging": True,  # ✓
        },
        "siem": {
            "ingested_sources": ["windows_security", "sysmon", "edr", "firewall"],
            "correlation_rules_enabled": [
                "failed_login_burst",
                "security_service_stopped",
                "lsass_process_access_alert",
                "powershell_suspicious_flags_alert",
                "sam_registry_access_alert",
                "dcsync_alert",
                "scheduled_task_alert",
                "dns_anomaly_detection",
            ],
            "log_retention_days": 90,
        },
    }

    results_2 = assess(sample_env_2)
    print_report(results_2)
    save_json_report(results_2, "/mnt/user-data/outputs/scenario_2_assessment.json")

    print("\n✅ Assessment complete. Check output files.\n")
