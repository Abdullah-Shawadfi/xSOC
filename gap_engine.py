#!/usr/bin/env python3
"""
Security Visibility Assessment Platform — Gap Engine v3.0
Complete with 20 techniques, quality checking, and sub-technique support

Usage:
    from gap_engine import assess, KNOWLEDGE_BASE
    results = assess(client_config_dict)
"""

from dataclasses import dataclass
from typing import Callable, Optional, List, Dict, Any
from enum import Enum
import json
import os


class Status(Enum):
    COVERED = "COVERED"
    PARTIAL = "PARTIAL VISIBILITY"
    BLIND = "BLIND SPOT"
    UNKNOWN = "COVERAGE UNKNOWN"


@dataclass
class Requirement:
    """Single detection requirement"""
    tool: str
    field: str
    check: Callable[[Dict], bool]
    quality_check: Optional[Callable[[Dict], Optional[str]]] = None


@dataclass
class Technique:
    """ATT&CK Technique or Sub-technique"""
    technique_id: str
    name: str
    tactic: str
    why_relevant: str
    impact_if_blind: str
    requirements: List[Requirement]
    remediation: List[str]


def get(cfg, *path, default=None):
    """Safely navigate nested dicts"""
    node = cfg
    for p in path:
        if not isinstance(node, dict) or p not in node:
            return default
        node = node[p]
    return node


# ════════════════════════════════════════════════════════════════════════════
# KNOWLEDGE BASE v3.0 — 20 TECHNIQUES/SUB-TECHNIQUES
# ════════════════════════════════════════════════════════════════════════════

KNOWLEDGE_BASE = [
    # ═══ CREDENTIAL ACCESS ═══
    Technique(
        technique_id="T1003.001",
        name="LSASS Memory Dumping",
        tactic="Credential Access",
        why_relevant="Attacker reads LSASS memory to steal cached credentials and NTLM hashes. Used in 80%+ of breach campaigns.",
        impact_if_blind="Attacker steals hashes → lateral movement across domain → multiple systems compromised.",
        requirements=[
            Requirement("Sysmon", "Event ID 10 on lsass.exe",
                        lambda c: get(c, "sysmon", "event_id_10_process_access") is True,
                        lambda c: "no SIEM alert rule" if
                                  get(c, "sysmon", "event_id_10_process_access") and
                                  "lsass_access_alert" not in (get(c, "siem", "correlation_rules") or [])
                                  else None),
            Requirement("EDR", "LSASS Protection ASR",
                        lambda c: get(c, "edr", "lsass_protection") is True),
        ],
        remediation=[
            "Enable Sysmon Event 10 with lsass.exe filter",
            "Enable EDR 'Block credential stealing from LSASS' ASR",
            "Add SIEM alert on lsass.exe process access",
        ],
    ),

    Technique(
        technique_id="T1003.002",
        name="SAM Registry Dumping",
        tactic="Credential Access",
        why_relevant="Attacker accesses SAM registry to extract local account password hashes. Common in lateral movement.",
        impact_if_blind="Local account hashes extracted → brute force attacks or pass-the-hash. No detection.",
        requirements=[
            Requirement("Windows Event Log", "Registry audit (4663)",
                        lambda c: get(c, "windows_event_logs", "registry_audit") is True),
            Requirement("SIEM", "SAM registry alert",
                        lambda c: "sam_access_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Object Access audit for registry via GPO",
            "Forward Event 4663 to SIEM",
            "Alert on SAM registry access by non-System users",
        ],
    ),

    Technique(
        technique_id="T1003.006",
        name="DCSync (Directory Replication)",
        tactic="Credential Access",
        why_relevant="Attacker uses DRS to request all AD password hashes from DC. Requires admin rights (obtained from compromise).",
        impact_if_blind="Entire domain password database stolen. All accounts compromised.",
        requirements=[
            Requirement("Windows Event Log", "AD Replication audit (4662)",
                        lambda c: get(c, "windows_event_logs", "ad_replication_audit") is True),
            Requirement("SIEM", "DCSync alert",
                        lambda c: "dcsync_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable audit for AD replication (Event 4662, 4663)",
            "Alert on non-DC accounts requesting replication",
            "Restrict replication permissions to DC accounts only",
        ],
    ),

    Technique(
        technique_id="T1056.001",
        name="Keylogging",
        tactic="Collection",
        why_relevant="Attacker installs keylogger to capture passwords and sensitive input. Often used with RAT.",
        impact_if_blind="User passwords, API keys, credit cards typed are all captured. No detection.",
        requirements=[
            Requirement("EDR", "Keystroke monitoring / Hook detection",
                        lambda c: get(c, "edr", "keyboard_input_monitoring") is True),
            Requirement("Sysmon", "Hook injection detection (Event 11+)",
                        lambda c: get(c, "sysmon", "image_load_event") is True),
        ],
        remediation=[
            "Enable EDR keystroke monitoring and hook detection",
            "Enable Sysmon image load events to detect DLL injections",
            "Monitor for suspicious registry changes related to input hooking",
        ],
    ),

    # ═══ EXECUTION ═══
    Technique(
        technique_id="T1059.001",
        name="PowerShell Execution",
        tactic="Execution",
        why_relevant="Primary vector for post-exploitation. Most C2 frameworks and lateral movement tools use PowerShell.",
        impact_if_blind="Attacker executes obfuscated PowerShell. You only see generic process creation. Actual command invisible.",
        requirements=[
            Requirement("Windows Event Log", "Script Block Logging (4104)",
                        lambda c: get(c, "windows_event_logs", "powershell_script_block_logging") is True,
                        lambda c: "no SIEM alert rule" if
                                  get(c, "windows_event_logs", "powershell_script_block_logging") and
                                  "powershell_suspicious_alert" not in (get(c, "siem", "correlation_rules") or [])
                                  else None),
            Requirement("SIEM", "PowerShell suspicious flags alert",
                        lambda c: "powershell_suspicious_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable PowerShell Script Block Logging (Event 4104)",
            "Add SIEM rule for: -enc, -nop, -w hidden, IEX",
            "Enable PowerShell transcription for additional logging",
        ],
    ),

    Technique(
        technique_id="T1059.003",
        name="Windows Command Shell (cmd.exe)",
        tactic="Execution",
        why_relevant="Command shell used for execution, especially in Windows environments. Common in script-based attacks.",
        impact_if_blind="Attacker runs commands via cmd.exe. No visibility into what commands were executed.",
        requirements=[
            Requirement("Windows Event Log", "Process creation with command line (4688)",
                        lambda c: get(c, "windows_event_logs", "process_command_line") is True),
            Requirement("SIEM", "Suspicious command execution alert",
                        lambda c: "cmd_suspicious_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable 4688 with command line argument auditing",
            "Add SIEM detection for suspicious cmd patterns",
            "Monitor for rare cmd.exe usage patterns",
        ],
    ),

    Technique(
        technique_id="T1204.001",
        name="Malicious Link in Email",
        tactic="Initial Access",
        why_relevant="User clicks malicious link in phishing email → infected with malware or credential theft.",
        impact_if_blind="User compromised via email link. No alert on click, only on post-compromise behavior.",
        requirements=[
            Requirement("Email Security", "URL click tracking / sandboxing",
                        lambda c: get(c, "email_security", "url_sandboxing") is True),
            Requirement("EDR", "Initial compromise detection",
                        lambda c: get(c, "edr", "malware_detection") is True),
        ],
        remediation=[
            "Enable email URL sandboxing and click tracking",
            "Enable EDR behavioral detection for first-stage malware",
            "Add SIEM alerts for unusual user behavior post-email",
        ],
    ),

    # ═══ PERSISTENCE ═══
    Technique(
        technique_id="T1053.005",
        name="Scheduled Task Creation",
        tactic="Persistence",
        why_relevant="Attacker creates scheduled task to re-establish access after cleanup/reboot. Low-noise persistence.",
        impact_if_blind="Scheduled task runs silently with SYSTEM privileges. Even if you remove attacker, task brings them back.",
        requirements=[
            Requirement("Windows Event Log", "Task creation (4698)",
                        lambda c: get(c, "windows_event_logs", "scheduled_task_creation") is True),
            Requirement("SIEM", "Task creation alert",
                        lambda c: "task_creation_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Task Scheduler operational logging (4698-4702)",
            "Alert on task creation by non-admin users or from temp paths",
            "Regularly audit existing scheduled tasks",
        ],
    ),

    Technique(
        technique_id="T1547.001",
        name="Registry Run Key Persistence",
        tactic="Persistence",
        why_relevant="Attacker adds entry to HKLM\\SOFTWARE\\Microsoft\\Windows\\Run to achieve persistence.",
        impact_if_blind="Registry persistence runs on every system startup. No alert fired during setup.",
        requirements=[
            Requirement("Windows Event Log", "Registry modification audit",
                        lambda c: get(c, "windows_event_logs", "registry_audit") is True),
            Requirement("Sysmon", "Registry event (Event 13)",
                        lambda c: get(c, "sysmon", "registry_set_value_event") is True),
        ],
        remediation=[
            "Monitor registry Run keys via audit or Sysmon",
            "Add detection for suspicious executable paths in Run keys",
            "Periodically audit HKLM\\Run and HKCU\\Run",
        ],
    ),

    Technique(
        technique_id="T1547.014",
        name="Startup Folder Persistence",
        tactic="Persistence",
        why_relevant="Attacker drops malware in Windows Startup folder. Executes on every system reboot.",
        impact_if_blind="Malware in startup folder persists across reboots. No alert on placement.",
        requirements=[
            Requirement("Windows Event Log", "File creation audit (4656)",
                        lambda c: get(c, "windows_event_logs", "file_audit") is True),
            Requirement("Sysmon", "File creation (Event 11)",
                        lambda c: get(c, "sysmon", "file_create_event") is True),
        ],
        remediation=[
            "Monitor Startup folder for suspicious files (Sysmon Event 11)",
            "Alert on .exe, .bat, .vbs in Startup folder",
            "Regular auditing of Startup folder contents",
        ],
    ),

    # ═══ DEFENSE EVASION ═══
    Technique(
        technique_id="T1562.001",
        name="Disable Antivirus/EDR",
        tactic="Defense Evasion",
        why_relevant="Disabling AV/EDR is the first step. Highest-value alert in the kill chain.",
        impact_if_blind="Attacker disables Defender. SOC doesn't know. Attacker operates with zero fear.",
        requirements=[
            Requirement("EDR", "Tamper protection enabled",
                        lambda c: get(c, "edr", "tamper_protection") is True),
            Requirement("SIEM", "Security service modification alert",
                        lambda c: "service_stop_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable EDR tamper protection (kernel mode)",
            "Alert on Event 7040 (service change), 104 (log clear), 5001-5012 (Defender status)",
            "Set alert severity: CRITICAL",
        ],
    ),

    Technique(
        technique_id="T1070.001",
        name="Clear Windows Event Logs",
        tactic="Defense Evasion",
        why_relevant="Attacker clears event logs to hide their tracks. Event ID 104 = log cleared.",
        impact_if_blind="Attacker removes all evidence of their activities. Forensics becomes impossible.",
        requirements=[
            Requirement("Windows Event Log", "Log clear audit (104)",
                        lambda c: get(c, "windows_event_logs", "log_clear_audit") is True),
            Requirement("SIEM", "Log clear alert",
                        lambda c: "log_clear_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable audit for clearing security log (Event 104)",
            "Forward to SIEM with immediate alert (severity: HIGH)",
            "Consider immutable logging (send logs to external syslog)",
        ],
    ),

    Technique(
        technique_id="T1036.001",
        name="Masquerading: Invalid Code Signature",
        tactic="Defense Evasion",
        why_relevant="Attacker signs malware with stolen certificate or fakes signature to bypass detection.",
        impact_if_blind="Malware appears legitimate. Bypasses code signature validation checks.",
        requirements=[
            Requirement("EDR", "Code signature verification",
                        lambda c: get(c, "edr", "code_integrity_check") is True),
            Requirement("Sysmon", "Image load event (13+)",
                        lambda c: get(c, "sysmon", "image_load_event") is True),
        ],
        remediation=[
            "Enable EDR code signature enforcement",
            "Monitor Sysmon for unsigned or invalid-signature binaries",
            "Whitelist known-good signatures, alert on others",
        ],
    ),

    # ═══ LATERAL MOVEMENT ═══
    Technique(
        technique_id="T1021.001",
        name="Remote Desktop Protocol (RDP)",
        tactic="Lateral Movement",
        why_relevant="Attacker uses RDP with stolen credentials to move to other systems.",
        impact_if_blind="Lateral movement via RDP goes undetected. Attacker compromises additional systems.",
        requirements=[
            Requirement("Windows Event Log", "Remote logon (4624 LogonType=10)",
                        lambda c: get(c, "windows_event_logs", "remote_logon_audit") is True),
            Requirement("SIEM", "RDP lateral movement alert",
                        lambda c: "rdp_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable audit for remote logon (Event 4624 LogonType=10)",
            "Alert on RDP from unexpected sources",
            "Restrict RDP to jump hosts only",
        ],
    ),

    Technique(
        technique_id="T1021.006",
        name="Windows Admin Shares (C$, IPC$)",
        tactic="Lateral Movement",
        why_relevant="Attacker uses admin shares to move between systems. Requires admin credentials.",
        impact_if_blind="Lateral movement via admin shares not detected. Attacker spreads silently.",
        requirements=[
            Requirement("Windows Event Log", "Network share connection audit (5140)",
                        lambda c: get(c, "windows_event_logs", "share_access_audit") is True),
            Requirement("Sysmon", "Network connection (Event 3)",
                        lambda c: get(c, "sysmon", "network_connection_event") is True),
        ],
        remediation=[
            "Enable audit for network share access (Event 5140)",
            "Monitor for unusual admin share access patterns",
            "Alert on access from non-admin accounts to admin shares",
        ],
    ),

    # ═══ COMMAND & CONTROL ═══
    Technique(
        technique_id="T1071.004",
        name="DNS C2 Communication",
        tactic="Command and Control",
        why_relevant="DNS is covert C2 channel. Attacker encodes commands in DNS queries. Hard to detect.",
        impact_if_blind="C2 beaconing over DNS blends into traffic. No baseline = no anomaly detection.",
        requirements=[
            Requirement("Firewall", "DNS query logging",
                        lambda c: get(c, "firewall", "dns_logging") is True,
                        lambda c: "no anomaly detection" if
                                  get(c, "firewall", "dns_logging") and
                                  "dns_anomaly_alert" not in (get(c, "siem", "correlation_rules") or [])
                                  else None),
            Requirement("EDR", "Network protection / DNS filtering",
                        lambda c: get(c, "edr", "network_protection") is True),
        ],
        remediation=[
            "Enable DNS query logging on firewall/DNS server",
            "Add detection for high-entropy DNS queries",
            "Monitor unusual DNS query volume per host",
            "Use DNS sinkhole for known C2 domains",
        ],
    ),

    Technique(
        technique_id="T1071.001",
        name="HTTP/HTTPS C2",
        tactic="Command and Control",
        why_relevant="Attacker uses HTTP/HTTPS as C2 channel. Blends into normal web traffic.",
        impact_if_blind="C2 beaconing appears as normal browsing. No detection.",
        requirements=[
            Requirement("Firewall/Proxy", "HTTPS inspection and logging",
                        lambda c: get(c, "firewall", "https_inspection") is True),
            Requirement("SIEM", "C2 domain detection",
                        lambda c: "c2_domain_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable HTTPS inspection on firewall/proxy",
            "Use threat intelligence for known C2 domains",
            "Monitor for unusual HTTPS traffic patterns",
            "Alert on connections to malicious IP/domain reputation lists",
        ],
    ),

    # ═══ EXFILTRATION ═══
    Technique(
        technique_id="T1041",
        name="Exfiltration Over C2 Channel",
        tactic="Exfiltration",
        why_relevant="Attacker exfiltrates data over C2 channel (HTTP/HTTPS, DNS, etc.). Uses existing channel.",
        impact_if_blind="Data exfiltration goes undetected. Attacker steals confidential information.",
        requirements=[
            Requirement("Firewall", "Outbound traffic monitoring",
                        lambda c: get(c, "firewall", "outbound_logging") is True),
            Requirement("SIEM", "Data exfiltration alert (volume/patterns)",
                        lambda c: "exfil_volume_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable outbound connection logging on firewall",
            "Monitor for unusual outbound data volume per host",
            "Alert on connections to suspicious external IPs",
            "Use DLP (Data Loss Prevention) for sensitive data",
        ],
    ),

    # ═══ DISCOVERY ═══
    Technique(
        technique_id="T1087.001",
        name="Local Account Discovery",
        tactic="Discovery",
        why_relevant="Attacker enumerates local accounts on compromised system. Used in lateral movement planning.",
        impact_if_blind="Attacker maps local account structure. No alert on enumeration.",
        requirements=[
            Requirement("Windows Event Log", "Process creation (4688) with command line",
                        lambda c: get(c, "windows_event_logs", "process_command_line") is True),
            Requirement("SIEM", "Account discovery tool detection",
                        lambda c: "discovery_tool_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Monitor for 'net user', 'Get-LocalUser', 'getent' commands",
            "Alert on account enumeration from unexpected processes",
            "Consider restricting access to account enumeration APIs",
        ],
    ),

    Technique(
        technique_id="T1082",
        name="System Information Discovery",
        tactic="Discovery",
        why_relevant="Attacker discovers system info (OS, hardware, running services). Used in exploitation planning.",
        impact_if_blind="Attacker maps system capabilities. No alert on discovery.",
        requirements=[
            Requirement("Windows Event Log", "Process creation with command line",
                        lambda c: get(c, "windows_event_logs", "process_command_line") is True),
            Requirement("EDR", "Suspicious process behavior detection",
                        lambda c: get(c, "edr", "behavioral_detection") is True),
        ],
        remediation=[
            "Monitor for 'systeminfo', 'Get-ComputerInfo', 'uname -a' commands",
            "Alert on rapid-fire discovery commands from single process",
            "Enable EDR behavioral analysis for discovery patterns",
        ],
    ),
]


# ════════════════════════════════════════════════════════════════════════════
# REFERENCE CATALOG — full MITRE ATT&CK Enterprise technique list (pulled from
# MITRE's official STIX data). These techniques have NO custom check logic
# written against this project's config schema yet, so they are surfaced as
# Status.UNKNOWN ("Coverage Unknown") rather than BLIND SPOT — we genuinely
# don't know if the client's tools cover them, we just haven't built the
# detection-mapping logic for them yet. Search/browse only; excluded from the
# main coverage % calculation.
# ════════════════════════════════════════════════════════════════════════════

_KB_IDS = {t.technique_id for t in KNOWLEDGE_BASE}
_CATALOG_PATH = os.path.join(os.path.dirname(__file__), "mitre_catalog.json")

try:
    with open(_CATALOG_PATH, encoding="utf-8") as f:
        _raw_catalog = json.load(f)
except FileNotFoundError:
    _raw_catalog = []

REFERENCE_CATALOG = [
    {
        "technique_id": t["technique_id"],
        "name": t["name"],
        "tactic": (t["tactics"][0].replace("-", " ").title() if t["tactics"] else "Unknown"),
        "description": t["description"],
        "log_sources": t["log_sources"],
        "detection_summary": t["detection_summary"],
    }
    for t in _raw_catalog
    if t["technique_id"] not in _KB_IDS
]


def assess(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Assess client configuration against all techniques in Knowledge Base.
    
    Args:
        config: Client configuration dict
    
    Returns:
        List of assessment results (one per technique)
    """
    results = []

    for technique in KNOWLEDGE_BASE:
        satisfied = []
        quality_notes = []

        for req in technique.requirements:
            if req.check(config):
                satisfied.append(req)
                if req.quality_check:
                    note = req.quality_check(config)
                    if note:
                        quality_notes.append(f"{req.tool}: {note}")

        # Determine status
        if not satisfied:
            status = Status.BLIND
        elif quality_notes:
            status = Status.PARTIAL
        else:
            status = Status.COVERED

        results.append({
            "technique_id": technique.technique_id,
            "name": technique.name,
            "tactic": technique.tactic,
            "status": status.value,
            "why": technique.why_relevant,
            "impact": technique.impact_if_blind if status != Status.COVERED else None,
            "quality_gaps": quality_notes,
            "remediation": technique.remediation if status != Status.COVERED else [],
            "satisfied_requirements": [f"{r.tool}: {r.field}" for r in satisfied],
        })

    return results


def calculate_coverage(results: List[Dict]) -> float:
    """Calculate overall coverage percentage (assessed techniques only)"""
    if not results:
        return 0.0
    covered = sum(1 for r in results if r["status"] == "COVERED")
    partial = sum(1 for r in results if r["status"] == "PARTIAL VISIBILITY")
    return (covered + 0.5 * partial) / len(results) * 100


def search_techniques(query: str) -> List[Dict[str, Any]]:
    """
    Search across BOTH the fully-assessed KNOWLEDGE_BASE (20 techniques with
    real detection logic) and the REFERENCE_CATALOG (677 MITRE techniques,
    browsable but not yet mapped to this project's config schema).
    Matches on technique_id (exact/prefix) or name (substring).
    """
    query = (query or "").strip().lower()
    if not query:
        return []

    results = []

    for t in KNOWLEDGE_BASE:
        if query in t.technique_id.lower() or query in t.name.lower():
            results.append({
                "technique_id": t.technique_id,
                "name": t.name,
                "tactic": t.tactic,
                "assessed": True,
            })

    for t in REFERENCE_CATALOG:
        if query in t["technique_id"].lower() or query in t["name"].lower():
            results.append({
                "technique_id": t["technique_id"],
                "name": t["name"],
                "tactic": t["tactic"],
                "assessed": False,
            })

    results.sort(key=lambda r: (not r["technique_id"].lower().startswith(query), r["technique_id"]))
    return results
