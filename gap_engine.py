#!/usr/bin/env python3
"""
Security Visibility Assessment Platform — Gap Engine v3.1
24 fully-assessed techniques (custom detection logic) + 679 MITRE reference
techniques (browsable, no custom logic yet — see REFERENCE_CATALOG)

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

    # ═══ PRIVILEGE ESCALATION ═══
    Technique(
        technique_id="T1055",
        name="Process Injection",
        tactic="Privilege Escalation",
        why_relevant="Attacker injects code into a legitimate process to run with its privileges and evade process-based detection. Common in malware and post-exploitation tooling.",
        impact_if_blind="Malicious code runs hidden inside a trusted process (e.g. explorer.exe). No process-creation alert fires because no new suspicious process appears.",
        requirements=[
            Requirement("Sysmon", "Process Access (Event 10) — CreateRemoteThread/WriteProcessMemory",
                        lambda c: get(c, "sysmon", "event_id_10_process_access") is True,
                        lambda c: "no SIEM alert rule" if
                                  get(c, "sysmon", "event_id_10_process_access") and
                                  "process_injection_alert" not in (get(c, "siem", "correlation_rules") or [])
                                  else None),
            Requirement("EDR", "Behavioral detection of injection APIs",
                        lambda c: get(c, "edr", "behavioral_detection") is True),
            Requirement("SIEM", "Process injection correlation alert",
                        lambda c: "process_injection_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon Event ID 10 (Process Access) with a filter on suspicious grantedAccess masks",
            "Enable EDR behavioral/memory-injection detection",
            "Add SIEM correlation rule for VirtualAllocEx + WriteProcessMemory + CreateRemoteThread chains",
        ],
    ),

    Technique(
        technique_id="T1134.001",
        name="Token Impersonation/Theft",
        tactic="Privilege Escalation",
        why_relevant="Attacker steals or impersonates an access token (e.g. via runas, DuplicateTokenEx) to act as a higher-privileged user without needing their password.",
        impact_if_blind="Attacker moves from a low-privilege foothold to SYSTEM or Domain Admin context silently — no logon event reflects the real source of the privilege change.",
        requirements=[
            Requirement("Windows Event Log", "Process creation with command line (4688)",
                        lambda c: get(c, "windows_event_logs", "process_command_line") is True),
            Requirement("Sysmon", "Process creation (Event 1)",
                        lambda c: get(c, "sysmon", "event_id_1_process_creation") is True),
            Requirement("SIEM", "Token theft/impersonation correlation alert",
                        lambda c: "token_theft_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable process command-line auditing (4688) to catch 'runas' and similar",
            "Enable Sysmon process creation logging",
            "Add SIEM rule correlating DuplicateToken/DuplicateTokenEx/ImpersonateLoggedOnUser API use with a new process under a different security context",
        ],
    ),

    Technique(
        technique_id="T1548.002",
        name="Bypass User Account Control",
        tactic="Privilege Escalation",
        why_relevant="Attacker abuses auto-elevating Windows binaries (e.g. eventvwr.exe, sdclt.exe) or registry hijacking to run code with admin rights without a UAC prompt.",
        impact_if_blind="Attacker silently gains admin privileges on the endpoint. No UAC prompt is shown to the user and no alert fires.",
        requirements=[
            Requirement("Sysmon", "Registry value set (Event 13) on UAC-related keys",
                        lambda c: get(c, "sysmon", "event_id_13_registry_set_value") is True),
            Requirement("Windows Event Log", "Registry audit policy enabled",
                        lambda c: get(c, "windows_event_logs", "registry_audit") is True),
            Requirement("SIEM", "UAC bypass correlation alert",
                        lambda c: "uac_bypass_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon Event ID 13 with a filter on HKCU\\Software\\Classes\\* and UAC-related registry keys",
            "Enable Windows registry auditing (Object Access)",
            "Add SIEM rule for known auto-elevate binaries spawning unexpected child processes",
        ],
    ),

    Technique(
        technique_id="T1068",
        name="Exploitation for Privilege Escalation",
        tactic="Privilege Escalation",
        why_relevant="Attacker exploits a vulnerability in the OS or a running service/driver to jump from a low-privilege foothold to SYSTEM/root.",
        impact_if_blind="A single unpatched vulnerability gives the attacker full control of the host, with no detection until they act on that access.",
        requirements=[
            Requirement("EDR", "Malware/exploit detection",
                        lambda c: get(c, "edr", "malware_detection") is True),
            Requirement("EDR", "Behavioral detection of exploit patterns",
                        lambda c: get(c, "edr", "behavioral_detection") is True),
            Requirement("SIEM", "Exploit attempt correlation alert",
                        lambda c: "exploit_attempt_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Keep EDR exploit-protection and malware signatures up to date",
            "Enable EDR behavioral detection for post-exploitation process/token anomalies",
            "Add SIEM rule for crash-then-elevated-process patterns (a common exploit signature)",
            "Patch known-vulnerable drivers and services promptly",
        ],
    ),

    # ═══ INITIAL ACCESS ═══
    Technique(
        technique_id="T1566.001",
        name="Spearphishing Attachment",
        tactic="Initial Access",
        why_relevant="Most common entry point for SMB compromises — a malicious Office/PDF attachment that drops a payload when opened.",
        impact_if_blind="Attacker gets initial code execution on an endpoint with no record of the delivery vector, making incident scoping much harder.",
        requirements=[
            Requirement("Email Security", "URL/attachment sandboxing",
                        lambda c: get(c, "email_security", "url_sandboxing") is True),
            Requirement("Windows Event Log", "Process creation with command line (Office spawning child process)",
                        lambda c: get(c, "windows_event_logs", "process_command_line") is True),
            Requirement("EDR", "Malware detection on dropped payload",
                        lambda c: get(c, "edr", "malware_detection") is True),
        ],
        remediation=[
            "Enable attachment/URL sandboxing on the email gateway",
            "Enable process command-line logging to catch Office apps spawning cmd/powershell/mshta",
            "Ensure EDR is scanning files dropped by email clients",
        ],
    ),

    Technique(
        technique_id="T1190",
        name="Exploit Public-Facing Application",
        tactic="Initial Access",
        why_relevant="Attacker exploits a vulnerable internet-facing service (web app, VPN gateway) to gain a foothold without any user interaction.",
        impact_if_blind="Compromise happens directly from the internet with no phishing/user-action trail — often the hardest entry vector to notice.",
        requirements=[
            Requirement("Sysmon", "Process creation (Event 1) — web server spawning shell",
                        lambda c: get(c, "sysmon", "event_id_1_process_creation") is True),
            Requirement("Windows Event Log", "Process command line for webshell/child-process detection",
                        lambda c: get(c, "windows_event_logs", "process_command_line") is True),
            Requirement("SIEM", "Webshell / unexpected child process alert",
                        lambda c: "webshell_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon process creation logging on internet-facing servers",
            "Enable command-line auditing on web/app servers",
            "Add SIEM rule for web server processes (w3wp.exe, httpd, nginx) spawning cmd/powershell/bash",
        ],
    ),

    # ═══ EXECUTION ═══
    Technique(
        technique_id="T1204.002",
        name="Malicious File (User Execution)",
        tactic="Execution",
        why_relevant="A user is tricked into manually running a malicious file (fake invoice, cracked software, etc.) — very common initial trigger.",
        impact_if_blind="Payload executes with the user's own permissions and no alert distinguishes it from legitimate file activity.",
        requirements=[
            Requirement("Sysmon", "File creation (Event 11)",
                        lambda c: get(c, "sysmon", "event_id_11_file_create") is True),
            Requirement("EDR", "Malware detection on execution",
                        lambda c: get(c, "edr", "malware_detection") is True),
            Requirement("SIEM", "Malicious file execution alert",
                        lambda c: "malicious_file_execution_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon file creation logging in Downloads/Temp folders",
            "Ensure EDR scans files on execution, not just on write",
            "Add SIEM rule correlating recently-downloaded files with immediate execution",
        ],
    ),

    Technique(
        technique_id="T1047",
        name="Windows Management Instrumentation",
        tactic="Execution",
        why_relevant="WMI is a built-in, dual-use Windows feature attackers use to execute commands remotely while blending in with normal admin activity.",
        impact_if_blind="Attacker runs commands on remote systems using a trusted native tool — no malware binary is dropped for AV/EDR to catch.",
        requirements=[
            Requirement("Windows Event Log", "Process command line for wmic/WMI activity",
                        lambda c: get(c, "windows_event_logs", "process_command_line") is True),
            Requirement("Sysmon", "Process creation (Event 1)",
                        lambda c: get(c, "sysmon", "event_id_1_process_creation") is True),
            Requirement("SIEM", "WMI execution correlation alert",
                        lambda c: "wmi_execution_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable process command-line auditing to catch wmic.exe / WmiPrvSE.exe usage",
            "Enable Sysmon process creation logging",
            "Add SIEM rule for WmiPrvSE.exe spawning unexpected child processes",
        ],
    ),

    # ═══ PERSISTENCE ═══
    Technique(
        technique_id="T1543.003",
        name="Create or Modify System Process: Windows Service",
        tactic="Persistence",
        why_relevant="Attacker installs a malicious Windows service that survives reboots and often runs as SYSTEM.",
        impact_if_blind="Attacker maintains SYSTEM-level persistence across reboots with no alert on the new service's creation.",
        requirements=[
            Requirement("Windows Event Log", "Process command line (sc.exe / New-Service)",
                        lambda c: get(c, "windows_event_logs", "process_command_line") is True),
            Requirement("Sysmon", "Registry value set (Event 13) on service keys",
                        lambda c: get(c, "sysmon", "event_id_13_registry_set_value") is True),
            Requirement("SIEM", "New service creation alert",
                        lambda c: "new_service_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable process command-line auditing to catch 'sc.exe create' / New-Service",
            "Enable Sysmon registry monitoring on HKLM\\SYSTEM\\CurrentControlSet\\Services",
            "Add SIEM rule for new service creation followed immediately by service start",
        ],
    ),

    Technique(
        technique_id="T1136.001",
        name="Create Account: Local Account",
        tactic="Persistence",
        why_relevant="Attacker creates a new local admin account as a persistence fallback that doesn't depend on maintaining an implant.",
        impact_if_blind="Attacker can log back in any time using legitimate-looking credentials, even after the original malware is cleaned up.",
        requirements=[
            Requirement("Windows Event Log", "Process command line (net user / New-LocalUser)",
                        lambda c: get(c, "windows_event_logs", "process_command_line") is True),
            Requirement("SIEM", "Local account creation alert",
                        lambda c: "account_creation_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable command-line auditing to catch 'net user /add' / New-LocalUser",
            "Add SIEM rule alerting on any new local account creation, especially added to Administrators",
        ],
    ),

    Technique(
        technique_id="T1098",
        name="Account Manipulation",
        tactic="Persistence",
        why_relevant="Attacker adds an existing account to a privileged group or changes its permissions to maintain elevated access.",
        impact_if_blind="A previously low-privilege (possibly already-known-compromised) account silently becomes a standing admin backdoor.",
        requirements=[
            Requirement("Windows Event Log", "Process command line (net group / Add-ADGroupMember)",
                        lambda c: get(c, "windows_event_logs", "process_command_line") is True),
            Requirement("SIEM", "Account/group manipulation alert",
                        lambda c: "account_manipulation_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable command-line auditing for group membership changes",
            "Add SIEM rule for additions to privileged groups (Domain Admins, local Administrators)",
        ],
    ),

    # ═══ PRIVILEGE ESCALATION ═══
    Technique(
        technique_id="T1078.003",
        name="Valid Accounts: Local Accounts",
        tactic="Privilege Escalation",
        why_relevant="Attacker uses a legitimate local account (often reused/default credentials) to escalate or move without triggering malware alerts.",
        impact_if_blind="Access looks like normal admin activity in the logs — nothing distinguishes the attacker's logon from a real administrator's.",
        requirements=[
            Requirement("Windows Event Log", "Remote logon auditing (4624/4625)",
                        lambda c: get(c, "windows_event_logs", "remote_logon_audit") is True),
            Requirement("SIEM", "Anomalous logon pattern alert",
                        lambda c: "anomalous_logon_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable remote logon auditing on all endpoints, not just domain controllers",
            "Add SIEM rule for logons at unusual hours or from unusual source hosts for a given account",
            "Disable/rotate default local admin accounts (or use LAPS)",
        ],
    ),

    # ═══ DEFENSE EVASION ═══
    Technique(
        technique_id="T1112",
        name="Modify Registry",
        tactic="Defense Evasion",
        why_relevant="Attacker changes registry settings to disable security tools, hide persistence, or alter system behavior.",
        impact_if_blind="Security controls can be silently weakened (e.g. disabling Defender via registry) with no record of the change.",
        requirements=[
            Requirement("Sysmon", "Registry value set (Event 13)",
                        lambda c: get(c, "sysmon", "event_id_13_registry_set_value") is True),
            Requirement("Windows Event Log", "Registry audit policy enabled",
                        lambda c: get(c, "windows_event_logs", "registry_audit") is True),
            Requirement("SIEM", "Registry modification correlation alert",
                        lambda c: "registry_modification_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon Event ID 13 with filters on security-relevant registry keys",
            "Enable Windows registry object access auditing",
            "Add SIEM rule for changes to Defender/AV/firewall-related registry keys",
        ],
    ),

    Technique(
        technique_id="T1027",
        name="Obfuscated Files or Information",
        tactic="Defense Evasion",
        why_relevant="Attacker encodes or packs payloads (base64, packers, encryption) to slip past signature-based detection.",
        impact_if_blind="Malware that would otherwise be caught by simple signature matching passes through undetected.",
        requirements=[
            Requirement("EDR", "Behavioral/heuristic detection (not signature-only)",
                        lambda c: get(c, "edr", "behavioral_detection") is True),
            Requirement("EDR", "Malware detection engine active",
                        lambda c: get(c, "edr", "malware_detection") is True),
            Requirement("SIEM", "Obfuscated payload execution alert",
                        lambda c: "obfuscated_payload_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Ensure EDR behavioral/heuristic detection is enabled, not just signature-based AV",
            "Add SIEM rule for high-entropy command lines or known encoding flags (-enc, base64)",
        ],
    ),

    Technique(
        technique_id="T1218.011",
        name="System Binary Proxy Execution: Rundll32",
        tactic="Defense Evasion",
        why_relevant="Attacker uses the trusted, signed rundll32.exe to run malicious code, blending in with legitimate Windows activity ('living off the land').",
        impact_if_blind="Malicious code execution is attributed to a trusted Microsoft binary, making it far less likely to be flagged.",
        requirements=[
            Requirement("Sysmon", "Process creation (Event 1)",
                        lambda c: get(c, "sysmon", "event_id_1_process_creation") is True),
            Requirement("Windows Event Log", "Process command line for rundll32 arguments",
                        lambda c: get(c, "windows_event_logs", "process_command_line") is True),
            Requirement("SIEM", "LOLBin abuse correlation alert",
                        lambda c: "lolbin_abuse_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon process creation and command-line logging",
            "Add SIEM rule for rundll32.exe with unusual DLL paths or no expected export function",
        ],
    ),

    # ═══ CREDENTIAL ACCESS ═══
    Technique(
        technique_id="T1110.001",
        name="Brute Force: Password Guessing",
        tactic="Credential Access",
        why_relevant="Attacker repeatedly tries passwords against a valid account, often via RDP or a web login, until one works.",
        impact_if_blind="A successful compromise looks like a single normal logon — the failed attempts that preceded it go unnoticed.",
        requirements=[
            Requirement("Windows Event Log", "Remote logon auditing (4624/4625)",
                        lambda c: get(c, "windows_event_logs", "remote_logon_audit") is True),
            Requirement("SIEM", "Failed login burst alert",
                        lambda c: "failed_login_burst" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable logon success/failure auditing on all externally-reachable accounts",
            "Add SIEM rule for repeated failed logons followed by a success (already partially covered if failed_login_burst exists)",
            "Enforce account lockout policy and MFA on remote-access accounts",
        ],
    ),

    Technique(
        technique_id="T1552.001",
        name="Unsecured Credentials: Credentials In Files",
        tactic="Credential Access",
        why_relevant="Attacker searches local files (scripts, config files, browser data) for hardcoded passwords or API keys.",
        impact_if_blind="Credentials left in plaintext files are harvested silently, often granting access far beyond the original foothold.",
        requirements=[
            Requirement("Sysmon", "File creation/access (Event 11)",
                        lambda c: get(c, "sysmon", "event_id_11_file_create") is True),
            Requirement("EDR", "Behavioral detection of mass file access/search",
                        lambda c: get(c, "edr", "behavioral_detection") is True),
            Requirement("SIEM", "Credential file access alert",
                        lambda c: "credential_file_access_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon file access logging in common credential-storage locations",
            "Add SIEM rule for a single process reading an unusually large number of files in a short time",
            "Adopt a secrets manager instead of storing credentials in plaintext files",
        ],
    ),

    Technique(
        technique_id="T1558.003",
        name="Kerberoasting",
        tactic="Credential Access",
        why_relevant="Attacker requests Kerberos service tickets for accounts with weak passwords and cracks them offline to get plaintext credentials.",
        impact_if_blind="Service account passwords (often highly privileged) are cracked offline with zero interaction with the target after ticket request — very quiet.",
        requirements=[
            Requirement("Windows Event Log", "Logon/ticket-request auditing (approximated via remote logon audit)",
                        lambda c: get(c, "windows_event_logs", "remote_logon_audit") is True,
                        lambda c: "this only approximates Kerberos ticket (4769) auditing — for full coverage enable dedicated Kerberos service ticket logging" if
                                  get(c, "windows_event_logs", "remote_logon_audit") else None),
            Requirement("SIEM", "Kerberoasting correlation alert",
                        lambda c: "kerberoast_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Kerberos service ticket auditing (Event 4769) on domain controllers",
            "Add SIEM rule for a single account requesting many RC4 service tickets in a short window",
            "Use long, random passwords (or gMSAs) for service accounts",
        ],
    ),

    # ═══ DISCOVERY ═══
    Technique(
        technique_id="T1018",
        name="Remote System Discovery",
        tactic="Discovery",
        why_relevant="Attacker enumerates other hosts on the network to plan lateral movement.",
        impact_if_blind="Attacker maps your entire network layout before moving — with no visibility into which systems they've already scoped out.",
        requirements=[
            Requirement("Windows Event Log", "Process command line (net view / nltest / ping sweep tools)",
                        lambda c: get(c, "windows_event_logs", "process_command_line") is True),
            Requirement("SIEM", "Discovery tool detection",
                        lambda c: "discovery_tool_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable command-line auditing to catch 'net view', 'nltest', 'ping' sweeps",
            "Add SIEM rule for a single host generating many outbound connection attempts to internal IPs in a short window",
        ],
    ),

    Technique(
        technique_id="T1046",
        name="Network Service Discovery",
        tactic="Discovery",
        why_relevant="Attacker port-scans internal hosts to find exploitable or interesting services (RDP, SMB, databases).",
        impact_if_blind="Attacker identifies your most valuable/vulnerable internal targets before ever touching them, with no scan alert to warn you.",
        requirements=[
            Requirement("Firewall", "Outbound/internal connection logging",
                        lambda c: get(c, "firewall", "outbound_logging") is True),
            Requirement("SIEM", "Internal port scan alert",
                        lambda c: "port_scan_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable logging on internal firewall/segmentation rules, not just perimeter",
            "Add SIEM rule for one host connecting to many ports/hosts in a short time window",
        ],
    ),

    Technique(
        technique_id="T1057",
        name="Process Discovery",
        tactic="Discovery",
        why_relevant="Attacker lists running processes to identify security tools to evade and interesting targets to attack (e.g. lsass.exe).",
        impact_if_blind="Attacker learns exactly which EDR/AV product you run and tailors evasion accordingly, with no alert on the reconnaissance itself.",
        requirements=[
            Requirement("Sysmon", "Process creation (Event 1)",
                        lambda c: get(c, "sysmon", "event_id_1_process_creation") is True),
            Requirement("Windows Event Log", "Process command line (tasklist / Get-Process)",
                        lambda c: get(c, "windows_event_logs", "process_command_line") is True),
            Requirement("SIEM", "Discovery tool detection",
                        lambda c: "discovery_tool_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon and command-line logging to catch tasklist/Get-Process/ps enumeration",
            "Add SIEM rule for process-enumeration commands immediately followed by credential-access attempts",
        ],
    ),

    # ═══ LATERAL MOVEMENT ═══
    Technique(
        technique_id="T1570",
        name="Lateral Tool Transfer",
        tactic="Lateral Movement",
        why_relevant="Attacker copies tools (mimikatz, PsExec, custom malware) to other hosts over the network to expand their foothold.",
        impact_if_blind="Attacker's toolkit spreads across your network with no record of when/where each tool arrived.",
        requirements=[
            Requirement("Sysmon", "File creation (Event 11) on remote shares",
                        lambda c: get(c, "sysmon", "event_id_11_file_create") is True),
            Requirement("Windows Event Log", "Share access auditing",
                        lambda c: get(c, "windows_event_logs", "share_access_audit") is True),
            Requirement("SIEM", "Lateral tool transfer alert",
                        lambda c: "lateral_tool_transfer_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon file creation logging on file servers and workstations",
            "Enable Windows share access auditing (Event 5140/5145)",
            "Add SIEM rule for executable files written to admin shares (C$, ADMIN$)",
        ],
    ),

    Technique(
        technique_id="T1021.002",
        name="Remote Services: SMB/Windows Admin Shares",
        tactic="Lateral Movement",
        why_relevant="Attacker uses built-in Windows admin shares (C$, ADMIN$) with stolen credentials to move between systems — a very common lateral movement technique (e.g. PsExec-style).",
        impact_if_blind="Attacker moves host-to-host using native Windows features that look identical to legitimate remote administration.",
        requirements=[
            Requirement("Windows Event Log", "Share access auditing (5140/5145)",
                        lambda c: get(c, "windows_event_logs", "share_access_audit") is True),
            Requirement("SIEM", "Admin share access alert",
                        lambda c: "admin_share_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable share access auditing on all hosts, not just servers",
            "Add SIEM rule for connections to ADMIN$/C$ from unexpected source hosts or accounts",
            "Restrict admin share usage to dedicated jump hosts where possible",
        ],
    ),

    # ═══ COLLECTION ═══
    Technique(
        technique_id="T1113",
        name="Screen Capture",
        tactic="Collection",
        why_relevant="Attacker captures screenshots to harvest sensitive on-screen information (dashboards, credentials, financial data).",
        impact_if_blind="Visual data that never touches disk or the clipboard is captured with no trace beyond process behavior.",
        requirements=[
            Requirement("EDR", "Behavioral detection of screen/graphics API abuse",
                        lambda c: get(c, "edr", "behavioral_detection") is True),
            Requirement("Sysmon", "Image load event (for injected capture libraries)",
                        lambda c: get(c, "sysmon", "image_load_event") is True),
            Requirement("SIEM", "Screen capture correlation alert",
                        lambda c: "screen_capture_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable EDR behavioral detection covering screen/graphics API calls",
            "Enable Sysmon image load logging to catch injected capture DLLs",
            "Add SIEM rule for unusual processes calling screen-capture APIs",
        ],
    ),

    Technique(
        technique_id="T1560.001",
        name="Archive Collected Data via Utility",
        tactic="Collection",
        why_relevant="Attacker compresses/encrypts stolen data (via 7zip, WinRAR, tar) before exfiltrating it, to reduce size and evade DLP.",
        impact_if_blind="Staged data theft — a strong pre-exfiltration signal — goes unnoticed until the data has already left.",
        requirements=[
            Requirement("Sysmon", "Process creation (Event 1) — archive utility launched",
                        lambda c: get(c, "sysmon", "event_id_1_process_creation") is True),
            Requirement("Windows Event Log", "Process command line for archive tool arguments",
                        lambda c: get(c, "windows_event_logs", "process_command_line") is True),
            Requirement("SIEM", "Archive utility staging alert",
                        lambda c: "archive_utility_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon and command-line logging for archive utilities (7z, rar, tar, zip)",
            "Add SIEM rule for archive creation of unusually large files/folders shortly before outbound traffic spikes",
        ],
    ),

    # ═══ COMMAND AND CONTROL ═══
    Technique(
        technique_id="T1105",
        name="Ingress Tool Transfer",
        tactic="Command and Control",
        why_relevant="Attacker downloads additional tools/malware onto the compromised host from external infrastructure.",
        impact_if_blind="The attacker's full toolkit lands on your network with no record of what was downloaded or from where.",
        requirements=[
            Requirement("Sysmon", "Network connection (Event 3) + file creation (Event 11)",
                        lambda c: get(c, "sysmon", "event_id_3_network_connection") is True and
                                  get(c, "sysmon", "event_id_11_file_create") is True),
            Requirement("SIEM", "Tool transfer / download correlation alert",
                        lambda c: "tool_transfer_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon network connection and file creation logging together",
            "Add SIEM rule correlating an outbound connection immediately followed by a new executable file being written",
        ],
    ),

    Technique(
        technique_id="T1572",
        name="Protocol Tunneling",
        tactic="Command and Control",
        why_relevant="Attacker tunnels C2 traffic inside an allowed protocol (DNS, HTTPS) to blend in with normal traffic and bypass firewall rules.",
        impact_if_blind="C2 traffic looks like ordinary DNS/HTTPS traffic and sails past a firewall that only blocks by port/protocol.",
        requirements=[
            Requirement("Firewall", "Outbound connection logging",
                        lambda c: get(c, "firewall", "outbound_logging") is True),
            Requirement("Sysmon", "Network connection (Event 3)",
                        lambda c: get(c, "sysmon", "event_id_3_network_connection") is True),
            Requirement("SIEM", "Protocol tunneling correlation alert",
                        lambda c: "tunneling_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable outbound firewall logging with payload/volume metadata, not just allow/deny",
            "Enable Sysmon network connection logging on endpoints",
            "Add SIEM rule for abnormal volume/frequency on 'trusted' protocols like DNS",
        ],
    ),

    # ═══ EXFILTRATION ═══
    Technique(
        technique_id="T1567.002",
        name="Exfiltration to Cloud Storage",
        tactic="Exfiltration",
        why_relevant="Attacker uploads stolen data to a legitimate cloud storage service (Dropbox, Google Drive, MEGA) to blend in with normal SaaS traffic.",
        impact_if_blind="Data leaves over HTTPS to a 'trusted' cloud domain, invisible to firewalls that only inspect by destination category.",
        requirements=[
            Requirement("Firewall", "Outbound connection logging",
                        lambda c: get(c, "firewall", "outbound_logging") is True),
            Requirement("Firewall", "HTTPS inspection",
                        lambda c: get(c, "firewall", "https_inspection") is True),
            Requirement("SIEM", "Cloud storage exfiltration alert",
                        lambda c: "cloud_exfil_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable outbound firewall logging with destination category visibility",
            "Enable HTTPS inspection (or at minimum SNI logging) on the perimeter firewall/proxy",
            "Add SIEM rule for large uploads to consumer cloud storage domains",
        ],
    ),

    Technique(
        technique_id="T1048.003",
        name="Exfiltration Over Unencrypted Non-C2 Protocol",
        tactic="Exfiltration",
        why_relevant="Attacker sends stolen data out over a separate, often plaintext, protocol (FTP, raw sockets) rather than the original C2 channel.",
        impact_if_blind="A large, unusual outbound data transfer completes with nothing but a firewall allow-log entry to show for it.",
        requirements=[
            Requirement("Firewall", "Outbound connection logging",
                        lambda c: get(c, "firewall", "outbound_logging") is True),
            Requirement("Sysmon", "Network connection (Event 3)",
                        lambda c: get(c, "sysmon", "event_id_3_network_connection") is True),
            Requirement("SIEM", "Exfiltration volume alert",
                        lambda c: "exfil_volume_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable outbound firewall logging with byte-count/volume metadata",
            "Enable Sysmon network connection logging on endpoints",
            "Add SIEM rule for unusually large outbound transfers, especially on non-standard ports",
        ],
    ),

    # ═══ IMPACT ═══
    Technique(
        technique_id="T1486",
        name="Data Encrypted for Impact (Ransomware)",
        tactic="Impact",
        why_relevant="The final, most damaging stage for most SMB attacks — files across the network are encrypted for ransom. Detecting this early (before full encryption) is critical.",
        impact_if_blind="Ransomware runs to completion across the network before anyone notices — the difference between one encrypted folder and total business shutdown.",
        requirements=[
            Requirement("Sysmon", "File creation (Event 11) — mass file modification pattern",
                        lambda c: get(c, "sysmon", "event_id_11_file_create") is True),
            Requirement("EDR", "Behavioral detection (ransomware/mass-encryption pattern)",
                        lambda c: get(c, "edr", "behavioral_detection") is True),
            Requirement("EDR", "Malware detection engine active",
                        lambda c: get(c, "edr", "malware_detection") is True),
            Requirement("SIEM", "Ransomware / mass encryption alert",
                        lambda c: "ransomware_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon file creation logging to catch mass file rewrite/rename patterns",
            "Ensure EDR behavioral (not just signature) ransomware protection is enabled",
            "Add SIEM rule for a single process modifying an abnormally high number of files in a short window",
            "Maintain offline/immutable backups as a last line of defense",
        ],
    ),

    Technique(
        technique_id="T1489",
        name="Service Stop",
        tactic="Impact",
        why_relevant="Attacker disables security services (AV, backup agents, Volume Shadow Copy service) right before deploying ransomware or destructive payloads.",
        impact_if_blind="Your last line of defense is silently switched off moments before the real damage happens.",
        requirements=[
            Requirement("Sysmon", "Process creation (Event 1) — net stop / sc stop commands",
                        lambda c: get(c, "sysmon", "event_id_1_process_creation") is True),
            Requirement("SIEM", "Security service stopped alert",
                        lambda c: "service_stop_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon process creation logging to catch 'net stop'/'sc stop' on security services",
            "Add SIEM rule that immediately alerts when AV/EDR/backup services stop unexpectedly",
            "Set EDR tamper protection so security services can't be stopped by non-admin processes",
        ],
    ),

    Technique(
        technique_id="T1490",
        name="Inhibit System Recovery",
        tactic="Impact",
        why_relevant="Attacker deletes Volume Shadow Copies and disables Windows recovery options right before ransomware deployment, to prevent easy restoration.",
        impact_if_blind="Backups/restore points are wiped moments before encryption — you find out you can't recover at the worst possible time.",
        requirements=[
            Requirement("Sysmon", "Process creation (Event 1) — vssadmin/wbadmin/bcdedit commands",
                        lambda c: get(c, "sysmon", "event_id_1_process_creation") is True),
            Requirement("Windows Event Log", "Process command line for recovery-disabling commands",
                        lambda c: get(c, "windows_event_logs", "process_command_line") is True),
            Requirement("SIEM", "Shadow copy / recovery deletion alert",
                        lambda c: "shadow_copy_deletion_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon and command-line logging to catch vssadmin delete shadows / wbadmin delete catalog / bcdedit",
            "Add SIEM rule that treats any shadow-copy deletion as a high-severity alert",
            "Keep at least one backup copy offline/immutable, unreachable from the production network",
        ],
    ),

    # ═══ CREDENTIAL ACCESS (batch 2) ═══
    Technique(
        technique_id="T1003.003",
        name="OS Credential Dumping: NTDS",
        tactic="Credential Access",
        why_relevant="Attacker steals the entire Active Directory database (ntds.dit), instantly compromising every domain account's password hash.",
        impact_if_blind="A single successful dump gives the attacker offline access to crack every password in the organization — the worst-case credential access event.",
        requirements=[
            Requirement("Windows Event Log", "AD replication auditing (DCSync-style access)",
                        lambda c: get(c, "windows_event_logs", "ad_replication_audit") is True),
            Requirement("Windows Event Log", "Process command line (ntdsutil.exe / vssadmin)",
                        lambda c: get(c, "windows_event_logs", "process_command_line") is True),
            Requirement("SIEM", "NTDS dump correlation alert",
                        lambda c: "ntds_dump_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable AD replication/directory service access auditing on all domain controllers",
            "Enable command-line auditing to catch ntdsutil.exe or shadow-copy-based ntds.dit extraction",
            "Add SIEM rule for ntdsutil.exe execution or shadow copy creation on a domain controller",
        ],
    ),

    Technique(
        technique_id="T1555.003",
        name="Credentials from Password Stores: Credentials from Web Browsers",
        tactic="Credential Access",
        why_relevant="Attacker extracts saved passwords directly from Chrome/Edge/Firefox's local credential store — often yields dozens of live accounts at once.",
        impact_if_blind="Every password a user ever saved in their browser (email, banking, SaaS admin panels) is harvested silently.",
        requirements=[
            Requirement("Sysmon", "File creation/access (Event 11) on browser credential stores",
                        lambda c: get(c, "sysmon", "event_id_11_file_create") is True),
            Requirement("EDR", "Behavioral detection of credential-store access",
                        lambda c: get(c, "edr", "behavioral_detection") is True),
            Requirement("SIEM", "Browser credential theft alert",
                        lambda c: "browser_credential_theft_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon file access logging on browser profile directories (Login Data, cookies)",
            "Add SIEM rule for non-browser processes reading browser credential/cookie files",
            "Enforce an enterprise password manager instead of browser-saved passwords",
        ],
    ),

    Technique(
        technique_id="T1621",
        name="Multi-Factor Authentication Request Generation",
        tactic="Credential Access",
        why_relevant="Attacker with stolen credentials spams MFA push notifications ('MFA fatigue') hoping the user eventually approves one by accident or fatigue.",
        impact_if_blind="A user's momentary annoyance-click bypasses MFA entirely — the attacker gets in despite having 'proper' second-factor protection in place.",
        requirements=[
            Requirement("Windows Event Log", "Remote logon auditing (captures repeated auth attempts)",
                        lambda c: get(c, "windows_event_logs", "remote_logon_audit") is True),
            Requirement("SIEM", "MFA fatigue / push-bombing alert",
                        lambda c: "mfa_fatigue_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable authentication attempt logging at the identity provider/MFA layer",
            "Add SIEM rule for an abnormal number of MFA prompts to one user in a short window",
            "Switch to number-matching MFA instead of simple push-approve",
        ],
    ),

    # ═══ PERSISTENCE (batch 2) ═══
    Technique(
        technique_id="T1547.004",
        name="Boot or Logon Autostart Execution: Winlogon Helper DLL",
        tactic="Persistence",
        why_relevant="Attacker hijacks Winlogon registry keys (Shell, Userinit) so their code runs automatically at every user logon.",
        impact_if_blind="Malware re-launches every single time any user logs on, with the persistence mechanism hidden in a rarely-audited registry location.",
        requirements=[
            Requirement("Sysmon", "Registry value set (Event 13) on Winlogon keys",
                        lambda c: get(c, "sysmon", "event_id_13_registry_set_value") is True),
            Requirement("SIEM", "Winlogon persistence alert",
                        lambda c: "winlogon_persistence_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon registry monitoring on HKLM\\...\\Winlogon (Shell, Userinit values)",
            "Add SIEM rule for any modification to Winlogon Shell/Userinit registry values",
        ],
    ),

    Technique(
        technique_id="T1546.003",
        name="Event Triggered Execution: WMI Event Subscription",
        tactic="Persistence",
        why_relevant="Attacker creates a WMI event subscription that silently re-executes their payload whenever a chosen system event occurs (e.g. every reboot).",
        impact_if_blind="A fileless, hard-to-find persistence mechanism keeps re-launching the payload — nothing shows up in Startup folders or Run keys.",
        requirements=[
            Requirement("Windows Event Log", "Process command line (wmic /NAMESPACE:\\\\root\\subscription)",
                        lambda c: get(c, "windows_event_logs", "process_command_line") is True),
            Requirement("SIEM", "WMI persistence correlation alert",
                        lambda c: "wmi_persistence_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable command-line auditing to catch WMI subscription creation via wmic/PowerShell",
            "Add SIEM rule for new __EventFilter / __EventConsumer / __FilterToConsumerBinding creation",
        ],
    ),

    # ═══ PRIVILEGE ESCALATION (batch 2) ═══
    Technique(
        technique_id="T1055.012",
        name="Process Injection: Process Hollowing",
        tactic="Privilege Escalation",
        why_relevant="Attacker starts a legitimate process suspended, hollows out its memory, and replaces it with malicious code — a classic AV/EDR evasion technique.",
        impact_if_blind="Malicious code runs under the name and privileges of a completely legitimate process (e.g. svchost.exe), defeating simple process-name allowlisting.",
        requirements=[
            Requirement("Sysmon", "Process access (Event 10) — hollowing memory writes",
                        lambda c: get(c, "sysmon", "event_id_10_process_access") is True),
            Requirement("EDR", "Behavioral detection of hollowed processes",
                        lambda c: get(c, "edr", "behavioral_detection") is True),
            Requirement("SIEM", "Process hollowing correlation alert",
                        lambda c: "process_hollowing_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon Event ID 10 with a filter for suspicious grantedAccess to newly-created suspended processes",
            "Ensure EDR includes memory-integrity/hollowing detection, not just signature scanning",
            "Add SIEM rule for a process's memory image not matching its on-disk file (a hollowing indicator)",
        ],
    ),

    Technique(
        technique_id="T1574.001",
        name="Hijack Execution Flow: DLL Search Order Hijacking",
        tactic="Privilege Escalation",
        why_relevant="Attacker plants a malicious DLL with the same name as a legitimate one, earlier in Windows' search path, so a trusted program loads it instead.",
        impact_if_blind="A completely legitimate, signed application unknowingly loads and executes attacker code — no suspicious binary ever runs on its own.",
        requirements=[
            Requirement("Sysmon", "Image load event (Event 7)",
                        lambda c: get(c, "sysmon", "image_load_event") is True),
            Requirement("SIEM", "DLL hijacking correlation alert",
                        lambda c: "dll_hijack_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon image load logging (Event 7) for signed-application processes",
            "Add SIEM rule for DLLs loaded from unusual paths (user-writable directories) by system processes",
        ],
    ),

    # ═══ DEFENSE EVASION (batch 2) ═══
    Technique(
        technique_id="T1036.003",
        name="Masquerading: Rename Legitimate Utilities",
        tactic="Defense Evasion",
        why_relevant="Attacker renames a dual-use tool (e.g. renaming powershell.exe to update.exe) to slip past simple name-based detection rules.",
        impact_if_blind="Detection rules keyed on process name alone (e.g. 'alert if powershell.exe runs') are trivially bypassed.",
        requirements=[
            Requirement("Sysmon", "Process creation (Event 1) with hash/original-filename metadata",
                        lambda c: get(c, "sysmon", "event_id_1_process_creation") is True),
            Requirement("SIEM", "Masquerading (name/hash mismatch) alert",
                        lambda c: "masquerading_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon process creation logging (captures file hash and original internal filename)",
            "Add SIEM rule comparing a binary's process name against its internal/original filename metadata",
        ],
    ),

    Technique(
        technique_id="T1140",
        name="Deobfuscate/Decode Files or Information",
        tactic="Defense Evasion",
        why_relevant="Attacker's payload decodes/decompresses itself at runtime (e.g. certutil -decode, base64) so the malicious content never exists on disk in a scannable form.",
        impact_if_blind="Signature-based scanning of files on disk finds nothing, because the real payload only exists briefly in memory after decoding.",
        requirements=[
            Requirement("EDR", "Behavioral detection of decode-then-execute chains",
                        lambda c: get(c, "edr", "behavioral_detection") is True),
            Requirement("Windows Event Log", "Process command line (certutil -decode, base64, etc.)",
                        lambda c: get(c, "windows_event_logs", "process_command_line") is True),
            Requirement("SIEM", "Deobfuscation utility abuse alert",
                        lambda c: "deobfuscation_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable EDR behavioral detection for decode-then-execute process chains",
            "Enable command-line auditing to catch 'certutil -decode' and similar LOLBin abuse",
            "Add SIEM rule for certutil.exe used with -decode/-urlcache flags (rarely legitimate)",
        ],
    ),

    Technique(
        technique_id="T1553.002",
        name="Subvert Trust Controls: Code Signing",
        tactic="Defense Evasion",
        why_relevant="Attacker signs malware with a stolen or fraudulently-obtained code-signing certificate so it appears trusted to the OS and security tools.",
        impact_if_blind="Malware passes 'is it signed?' checks that many security tools and admins rely on as a trust signal.",
        requirements=[
            Requirement("EDR", "Code integrity / signature validation checking",
                        lambda c: get(c, "edr", "code_integrity_check") is True),
            Requirement("SIEM", "Invalid/revoked signature execution alert",
                        lambda c: "invalid_signature_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable EDR code-integrity checking that validates against known-revoked/suspicious certificates",
            "Add SIEM rule for binaries signed by newly-seen or recently-issued certificates",
        ],
    ),

    # ═══ DISCOVERY (batch 2) ═══
    Technique(
        technique_id="T1069.001",
        name="Permission Groups Discovery: Local Groups",
        tactic="Discovery",
        why_relevant="Attacker enumerates local group membership (especially Administrators) to identify which accounts are worth targeting for privilege escalation.",
        impact_if_blind="Attacker maps out exactly which accounts to go after next, with the reconnaissance itself invisible.",
        requirements=[
            Requirement("Windows Event Log", "Process command line (net localgroup / Get-LocalGroupMember)",
                        lambda c: get(c, "windows_event_logs", "process_command_line") is True),
            Requirement("SIEM", "Discovery tool detection",
                        lambda c: "discovery_tool_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable command-line auditing to catch 'net localgroup'/Get-LocalGroupMember enumeration",
            "Add SIEM rule for group-enumeration commands from non-admin accounts or unusual hosts",
        ],
    ),

    Technique(
        technique_id="T1518.001",
        name="Software Discovery: Security Software Discovery",
        tactic="Discovery",
        why_relevant="Attacker checks which AV/EDR/firewall products are installed before deciding how to proceed, so they can pick matching evasion techniques.",
        impact_if_blind="Attacker tailors their entire attack to specifically evade the security stack you have, with no warning that this reconnaissance happened.",
        requirements=[
            Requirement("EDR", "Behavioral detection of security-tool enumeration",
                        lambda c: get(c, "edr", "behavioral_detection") is True),
            Requirement("Windows Event Log", "Process command line (Get-Service, wmic, reg query on AV keys)",
                        lambda c: get(c, "windows_event_logs", "process_command_line") is True),
            Requirement("SIEM", "Security software discovery alert",
                        lambda c: "security_software_discovery_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable EDR self-tamper/enumeration detection where available",
            "Enable command-line auditing to catch queries against known AV/EDR service names or registry keys",
            "Add SIEM rule for processes querying multiple known security-product identifiers in sequence",
        ],
    ),

    # ═══ LATERAL MOVEMENT (batch 2) ═══
    Technique(
        technique_id="T1021.004",
        name="Remote Services: SSH",
        tactic="Lateral Movement",
        why_relevant="Attacker uses SSH (often on Linux servers or network devices in an otherwise Windows-centric SMB) to move between systems with valid credentials.",
        impact_if_blind="Non-Windows assets become a blind corridor for lateral movement that your primarily Windows-focused telemetry never sees.",
        requirements=[
            Requirement("Firewall", "Outbound/internal connection logging",
                        lambda c: get(c, "firewall", "outbound_logging") is True),
            Requirement("SIEM", "SSH lateral movement alert",
                        lambda c: "ssh_lateral_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable logging on internal segments carrying SSH traffic, not just the perimeter",
            "Add SIEM rule for SSH connections between hosts that don't normally communicate",
            "Centralize Linux/network-device auth logs into the same SIEM as Windows logs",
        ],
    ),

    Technique(
        technique_id="T1550.002",
        name="Use Alternate Authentication Material: Pass the Hash",
        tactic="Lateral Movement",
        why_relevant="Attacker authenticates using a stolen password hash directly, without ever needing to crack it — a very common technique once LSASS credentials are dumped.",
        impact_if_blind="Attacker moves laterally using stolen hashes exactly like a legitimate admin logon — nothing distinguishes it in standard logs.",
        requirements=[
            Requirement("Windows Event Log", "Remote logon auditing (NTLM logon type 3 tracking)",
                        lambda c: get(c, "windows_event_logs", "remote_logon_audit") is True),
            Requirement("SIEM", "Pass-the-hash correlation alert",
                        lambda c: "pass_the_hash_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable remote logon auditing across all hosts (not just servers)",
            "Add SIEM rule for NTLM authentication where Kerberos would normally be expected",
            "Enable Credential Guard / restrict NTLM where possible",
        ],
    ),

    Technique(
        technique_id="T1210",
        name="Exploitation of Remote Services",
        tactic="Lateral Movement",
        why_relevant="Attacker exploits a vulnerability in a remote service (SMB, RDP, RPC) to move to another host without needing valid credentials at all.",
        impact_if_blind="Attacker spreads through the network purely via unpatched vulnerabilities — no credential-based signal exists to catch it.",
        requirements=[
            Requirement("Sysmon", "Process creation (Event 1) on the target service host",
                        lambda c: get(c, "sysmon", "event_id_1_process_creation") is True),
            Requirement("EDR", "Behavioral/exploit detection",
                        lambda c: get(c, "edr", "behavioral_detection") is True),
            Requirement("SIEM", "Remote service exploitation alert",
                        lambda c: "remote_exploit_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon process creation logging on all servers running exposed services",
            "Enable EDR exploit/behavioral protection on internal servers, not just endpoints",
            "Patch internet-facing and internally-exposed services promptly (SMB, RDP, RPC)",
        ],
    ),

    # ═══ COLLECTION (batch 2) ═══
    Technique(
        technique_id="T1005",
        name="Data from Local System",
        tactic="Collection",
        why_relevant="Attacker systematically collects files from the local file system (documents, databases, source code) ahead of exfiltration.",
        impact_if_blind="Sensitive data is gathered and staged for theft with no signal until the exfiltration step itself — if that's caught at all.",
        requirements=[
            Requirement("Sysmon", "File creation/access (Event 11)",
                        lambda c: get(c, "sysmon", "event_id_11_file_create") is True),
            Requirement("Windows Event Log", "File access auditing",
                        lambda c: get(c, "windows_event_logs", "file_audit") is True),
            Requirement("SIEM", "Mass file access alert",
                        lambda c: "mass_file_access_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon file access logging on sensitive data locations",
            "Enable Windows file/object access auditing on shares containing sensitive data",
            "Add SIEM rule for a single process/account accessing an unusually large number of files",
        ],
    ),

    Technique(
        technique_id="T1114.001",
        name="Email Collection: Local Email Collection",
        tactic="Collection",
        why_relevant="Attacker reads a compromised user's local Outlook PST/OST files to harvest sensitive correspondence and further phishing targets.",
        impact_if_blind="Entire mailboxes — including confidential business communications — are read and exfiltrated with no alert.",
        requirements=[
            Requirement("Sysmon", "File creation/access (Event 11) on PST/OST files",
                        lambda c: get(c, "sysmon", "event_id_11_file_create") is True),
            Requirement("SIEM", "Email data collection alert",
                        lambda c: "email_collection_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon file access logging on Outlook data file locations (.pst/.ost)",
            "Add SIEM rule for non-Outlook processes accessing .pst/.ost files",
        ],
    ),

    # ═══ COMMAND AND CONTROL (batch 2) ═══
    Technique(
        technique_id="T1090.002",
        name="Proxy: External Proxy",
        tactic="Command and Control",
        why_relevant="Attacker routes C2 traffic through a third-party external proxy/relay to hide the true C2 server's location and complicate blocking.",
        impact_if_blind="Blocking a single malicious IP does nothing — the attacker just switches proxies while the real infrastructure stays hidden.",
        requirements=[
            Requirement("Firewall", "Outbound connection logging",
                        lambda c: get(c, "firewall", "outbound_logging") is True),
            Requirement("SIEM", "External proxy C2 alert",
                        lambda c: "proxy_c2_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable outbound firewall logging with destination reputation/category data",
            "Add SIEM rule for connections to known open-proxy or anonymization infrastructure",
        ],
    ),

    Technique(
        technique_id="T1102.002",
        name="Web Service: Bidirectional Communication",
        tactic="Command and Control",
        why_relevant="Attacker uses a legitimate web service (Telegram, Discord, GitHub Gists) as a two-way C2 channel, hiding in traffic that looks completely normal.",
        impact_if_blind="C2 traffic to a well-known, trusted domain (github.com, telegram.org) is invisible to detection that only flags 'suspicious' destinations.",
        requirements=[
            Requirement("Firewall", "HTTPS inspection",
                        lambda c: get(c, "firewall", "https_inspection") is True),
            Requirement("SIEM", "Web-service C2 correlation alert",
                        lambda c: "webservice_c2_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable HTTPS inspection to see actual API calls to legitimate-but-abused web services",
            "Add SIEM rule for endpoint processes making periodic beacon-like calls to APIs of chat/collab platforms",
        ],
    ),

    Technique(
        technique_id="T1571",
        name="Non-Standard Port",
        tactic="Command and Control",
        why_relevant="Attacker runs C2 traffic over a port that doesn't match its protocol (e.g. HTTP over port 8443 or 53) to slip past port-based filtering rules.",
        impact_if_blind="Simplistic 'block by port' firewall rules are bypassed entirely, and protocol/port mismatches go unnoticed.",
        requirements=[
            Requirement("Firewall", "Outbound connection logging",
                        lambda c: get(c, "firewall", "outbound_logging") is True),
            Requirement("Sysmon", "Network connection (Event 3)",
                        lambda c: get(c, "sysmon", "event_id_3_network_connection") is True),
            Requirement("SIEM", "Non-standard port usage alert",
                        lambda c: "nonstandard_port_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable outbound firewall logging with protocol/port pair visibility",
            "Enable Sysmon network connection logging on endpoints",
            "Add SIEM rule for traffic where the observed protocol doesn't match the port's expected service",
        ],
    ),

    # ═══ EXFILTRATION (batch 2) ═══
    Technique(
        technique_id="T1029",
        name="Scheduled Transfer",
        tactic="Exfiltration",
        why_relevant="Attacker times data exfiltration to occur at specific intervals (e.g. only at night) to blend in with normal traffic patterns and avoid burst-detection.",
        impact_if_blind="Slow, scheduled data theft over days or weeks looks like routine background traffic instead of one alarming spike.",
        requirements=[
            Requirement("Firewall", "Outbound connection logging",
                        lambda c: get(c, "firewall", "outbound_logging") is True),
            Requirement("SIEM", "Scheduled/periodic exfiltration pattern alert",
                        lambda c: "scheduled_exfil_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable outbound firewall logging with consistent long-term retention for pattern analysis",
            "Add SIEM rule for consistent, low-volume outbound transfers at regular intervals to the same destination",
        ],
    ),

    Technique(
        technique_id="T1020",
        name="Automated Exfiltration",
        tactic="Exfiltration",
        why_relevant="Attacker uses a script/tool to automatically find and exfiltrate data as soon as it's collected, without further manual interaction.",
        impact_if_blind="Data theft happens immediately and continuously post-compromise, faster than a human analyst could ever intervene manually.",
        requirements=[
            Requirement("Sysmon", "Network connection (Event 3)",
                        lambda c: get(c, "sysmon", "event_id_3_network_connection") is True),
            Requirement("SIEM", "Automated exfiltration alert",
                        lambda c: "automated_exfil_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon network connection logging to correlate file access with immediate outbound transfer",
            "Add SIEM rule for file-collection activity followed within minutes by an outbound transfer",
        ],
    ),

    # ═══ IMPACT (batch 2) ═══
    Technique(
        technique_id="T1485",
        name="Data Destruction",
        tactic="Impact",
        why_relevant="Attacker deletes or corrupts files/systems outright — sometimes as a distraction, sometimes as the final destructive act of the attack.",
        impact_if_blind="Business-critical data is destroyed with no early warning, and no record of what was destroyed or when to guide recovery.",
        requirements=[
            Requirement("Sysmon", "File creation (Event 11) — can help identify overwrite patterns",
                        lambda c: get(c, "sysmon", "event_id_11_file_create") is True),
            Requirement("EDR", "Behavioral detection of mass destructive file operations",
                        lambda c: get(c, "edr", "behavioral_detection") is True),
            Requirement("SIEM", "Data destruction correlation alert",
                        lambda c: "data_destruction_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon file monitoring to catch mass file overwrite/corruption patterns",
            "Ensure EDR behavioral detection covers destructive file operations, not just encryption",
            "Add SIEM rule for a single process destructively modifying many files in a short window",
            "Maintain immutable/offline backups as the ultimate mitigation",
        ],
    ),

    Technique(
        technique_id="T1498",
        name="Network Denial of Service",
        tactic="Impact",
        why_relevant="Attacker uses compromised hosts on your network as a launchpad to flood a third-party target (or uses your own connectivity against you).",
        impact_if_blind="Your organization's IP space becomes a source of attack traffic — with legal/reputational fallout — before anyone notices the abuse.",
        requirements=[
            Requirement("Firewall", "Outbound connection logging",
                        lambda c: get(c, "firewall", "outbound_logging") is True),
            Requirement("SIEM", "Outbound DoS / abnormal traffic volume alert",
                        lambda c: "dos_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable outbound firewall logging with volume/rate metadata",
            "Add SIEM rule for a sudden, sustained spike in outbound connections/traffic from a single host",
        ],
    ),

    # ═══ INITIAL ACCESS (batch 2) ═══
    Technique(
        technique_id="T1078.001",
        name="Valid Accounts: Default Accounts",
        tactic="Initial Access",
        why_relevant="Attacker logs in using default/unchanged vendor credentials (admin/admin, default service account passwords) on exposed devices or software.",
        impact_if_blind="An embarrassingly simple entry point — no exploit needed — because default credentials were never rotated.",
        requirements=[
            Requirement("Windows Event Log", "Remote logon auditing",
                        lambda c: get(c, "windows_event_logs", "remote_logon_audit") is True),
            Requirement("SIEM", "Default account logon alert",
                        lambda c: "default_account_logon_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable logon auditing on all internet-facing and internal devices",
            "Add SIEM rule flagging any successful logon from known default account names",
            "Rotate/disable default vendor credentials on all deployed hardware and software",
        ],
    ),

    Technique(
        technique_id="T1133",
        name="External Remote Services",
        tactic="Initial Access",
        why_relevant="Attacker gains access through exposed remote-access services (VPN, RDP, Citrix) using stolen or weak credentials — one of the most common SMB breach vectors.",
        impact_if_blind="A directly internet-exposed door into your network goes unmonitored — the attacker walks in the front door with valid-looking credentials.",
        requirements=[
            Requirement("Windows Event Log", "Remote logon auditing (RDP/VPN logons)",
                        lambda c: get(c, "windows_event_logs", "remote_logon_audit") is True),
            Requirement("SIEM", "External remote access alert",
                        lambda c: "external_remote_access_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable remote logon auditing on all VPN/RDP/remote-access endpoints",
            "Add SIEM rule for remote logons from unusual countries/IPs or outside business hours",
            "Require MFA on all external remote-access services",
        ],
    ),

    # ═══ EXECUTION (batch 2) ═══
    Technique(
        technique_id="T1053.002",
        name="Scheduled Task/Job: At",
        tactic="Execution",
        why_relevant="Attacker uses the legacy 'at' command to schedule execution of a payload, similar to Scheduled Task but via an older, less-monitored mechanism.",
        impact_if_blind="A less commonly monitored scheduling mechanism lets the payload run on a timer with no alert on its creation.",
        requirements=[
            Requirement("Sysmon", "Process creation (Event 1)",
                        lambda c: get(c, "sysmon", "event_id_1_process_creation") is True),
            Requirement("Windows Event Log", "Scheduled task creation auditing",
                        lambda c: get(c, "windows_event_logs", "scheduled_task_creation") is True),
            Requirement("SIEM", "Scheduled task/job creation alert",
                        lambda c: "task_creation_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon and scheduled-task-creation auditing",
            "Add SIEM rule for use of the legacy 'at' command (rare in modern environments — high-confidence signal)",
        ],
    ),

    Technique(
        technique_id="T1569.002",
        name="System Services: Service Execution",
        tactic="Execution",
        why_relevant="Attacker uses tools like PsExec to remotely install and immediately run a Windows service as a one-shot command execution method.",
        impact_if_blind="One of the most common lateral-movement-plus-execution combos (PsExec-style) leaves only a fleeting service artifact if not specifically monitored.",
        requirements=[
            Requirement("Windows Event Log", "Process command line (service install/start commands)",
                        lambda c: get(c, "windows_event_logs", "process_command_line") is True),
            Requirement("SIEM", "New service execution alert",
                        lambda c: "new_service_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable command-line auditing to catch PsExec-style service creation and immediate deletion",
            "Add SIEM rule for a service being created and started within seconds of creation, then quickly removed",
        ],
    ),

    # ═══ INITIAL ACCESS (batch 3) ═══
    Technique(
        technique_id="T1199",
        name="Trusted Relationship",
        tactic="Initial Access",
        why_relevant="Attacker compromises you through a trusted third party (MSP, vendor with remote access) rather than attacking you directly.",
        impact_if_blind="A breach at your IT vendor or MSP becomes a breach at your organization, entering through a connection everyone assumes is safe.",
        requirements=[
            Requirement("Windows Event Log", "Remote logon auditing for third-party/vendor accounts",
                        lambda c: get(c, "windows_event_logs", "remote_logon_audit") is True),
            Requirement("SIEM", "Trusted relationship / vendor access alert",
                        lambda c: "trusted_relationship_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable remote logon auditing specifically flagging vendor/MSP accounts",
            "Add SIEM rule for vendor accounts logging in outside expected maintenance windows",
            "Require MFA and least-privilege scoping for all third-party remote access",
        ],
    ),

    # ═══ EXECUTION (batch 3) ═══
    Technique(
        technique_id="T1059.005",
        name="Command and Scripting Interpreter: Visual Basic",
        tactic="Execution",
        why_relevant="Attacker uses VBA macros or standalone VBScript — still one of the most common initial-execution methods via malicious Office documents.",
        impact_if_blind="A booby-trapped Word/Excel attachment executes its payload the moment the user clicks 'Enable Content', with no alert.",
        requirements=[
            Requirement("Windows Event Log", "Process command line (wscript/cscript)",
                        lambda c: get(c, "windows_event_logs", "process_command_line") is True),
            Requirement("Sysmon", "Process creation (Event 1)",
                        lambda c: get(c, "sysmon", "event_id_1_process_creation") is True),
            Requirement("SIEM", "VBS/macro execution alert",
                        lambda c: "vbs_execution_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable command-line and process-creation logging to catch wscript.exe/cscript.exe launches",
            "Add SIEM rule for Office applications spawning wscript/cscript/mshta",
            "Disable macros by default via Group Policy where feasible",
        ],
    ),

    Technique(
        technique_id="T1059.007",
        name="Command and Scripting Interpreter: JavaScript",
        tactic="Execution",
        why_relevant="Attacker delivers a malicious .js/.jse file (often via email) that executes via wscript with full Windows API access.",
        impact_if_blind="A file extension most users don't recognize as executable (.js) runs code as freely as an .exe would.",
        requirements=[
            Requirement("Windows Event Log", "Process command line (wscript.exe running .js/.jse)",
                        lambda c: get(c, "windows_event_logs", "process_command_line") is True),
            Requirement("Sysmon", "Process creation (Event 1)",
                        lambda c: get(c, "sysmon", "event_id_1_process_creation") is True),
            Requirement("SIEM", "JavaScript execution alert",
                        lambda c: "vbs_execution_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable command-line logging to catch wscript.exe/cscript.exe with .js/.jse arguments",
            "Add SIEM rule for .js/.jse files executed outside expected application directories",
            "Change the default handler for .js files away from wscript.exe",
        ],
    ),

    Technique(
        technique_id="T1129",
        name="Shared Modules",
        tactic="Execution",
        why_relevant="Attacker executes code by loading a malicious DLL directly via LoadLibrary/rundll32, without ever writing a standalone .exe.",
        impact_if_blind="Execution happens through a shared library load — a mechanism most process-centric alerting rules don't examine closely.",
        requirements=[
            Requirement("Sysmon", "Image load event (Event 7)",
                        lambda c: get(c, "sysmon", "image_load_event") is True),
            Requirement("SIEM", "Shared module / unusual DLL load alert",
                        lambda c: "shared_module_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon Event ID 7 (image load) logging",
            "Add SIEM rule for DLLs loaded from user-writable or unusual paths",
        ],
    ),

    Technique(
        technique_id="T1203",
        name="Exploitation for Client Execution",
        tactic="Execution",
        why_relevant="Attacker exploits a vulnerability in a client application (browser, PDF reader, Office) to achieve code execution just by having the user open a file/page.",
        impact_if_blind="Simply viewing a malicious file or webpage triggers code execution — no macro-enable click, no attachment save, required.",
        requirements=[
            Requirement("EDR", "Exploit/behavioral detection",
                        lambda c: get(c, "edr", "behavioral_detection") is True),
            Requirement("EDR", "Malware detection engine active",
                        lambda c: get(c, "edr", "malware_detection") is True),
            Requirement("SIEM", "Client-side exploit alert",
                        lambda c: "client_exploit_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable EDR exploit protection on all client applications (browsers, Office, PDF readers)",
            "Add SIEM rule for client applications spawning unexpected child processes shortly after opening a file",
            "Keep browsers, Office, and PDF readers patched and consider application sandboxing",
        ],
    ),

    # ═══ PERSISTENCE (batch 3) ═══
    Technique(
        technique_id="T1037.001",
        name="Boot or Logon Initialization Scripts: Logon Script (Windows)",
        tactic="Persistence",
        why_relevant="Attacker sets a malicious logon script (via registry or GPO) that runs automatically whenever a user logs in.",
        impact_if_blind="Persistence re-triggers at every logon for every affected user, hidden in a rarely-reviewed registry/GPO setting.",
        requirements=[
            Requirement("Sysmon", "Registry value set (Event 13) on logon script keys",
                        lambda c: get(c, "sysmon", "event_id_13_registry_set_value") is True),
            Requirement("SIEM", "Logon script persistence alert",
                        lambda c: "logon_script_persistence_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon registry monitoring on HKCU/HKLM logon script value locations",
            "Add SIEM rule for any change to logon script registry values or GPO logon script settings",
        ],
    ),

    Technique(
        technique_id="T1176",
        name="Browser Extensions",
        tactic="Persistence",
        why_relevant="Attacker installs a malicious browser extension that persists across restarts and can read/exfiltrate everything the user sees in the browser.",
        impact_if_blind="An extension with broad permissions silently harvests session cookies, form data, and browsing activity indefinitely.",
        requirements=[
            Requirement("EDR", "Behavioral detection of unauthorized extension installs",
                        lambda c: get(c, "edr", "behavioral_detection") is True),
            Requirement("SIEM", "Malicious browser extension alert",
                        lambda c: "malicious_extension_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable EDR/browser-management visibility into installed extensions",
            "Add SIEM rule for new browser extensions installed outside of an approved allowlist",
            "Enforce extension allowlisting via browser management policy",
        ],
    ),

    # ═══ PRIVILEGE ESCALATION (batch 3) ═══
    Technique(
        technique_id="T1484.001",
        name="Domain or Tenant Policy Modification: Group Policy Modification",
        tactic="Privilege Escalation",
        why_relevant="Attacker modifies a Group Policy Object to push malicious settings (scripts, scheduled tasks, security setting changes) to many machines at once.",
        impact_if_blind="A single GPO change can compromise the entire domain simultaneously — one of the highest-impact, lowest-noise attacker moves.",
        requirements=[
            Requirement("Windows Event Log", "AD/GPO change auditing",
                        lambda c: get(c, "windows_event_logs", "ad_replication_audit") is True),
            Requirement("SIEM", "GPO modification alert",
                        lambda c: "gpo_modification_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Group Policy change auditing on domain controllers",
            "Add SIEM rule for any GPO modification, especially to security-relevant or widely-linked GPOs",
            "Restrict GPO edit rights to a small, monitored set of accounts",
        ],
    ),

    # ═══ DEFENSE EVASION (batch 3) ═══
    Technique(
        technique_id="T1497",
        name="Virtualization/Sandbox Evasion",
        tactic="Defense Evasion",
        why_relevant="Malware checks if it's running in a sandbox/VM (used for analysis) and stays dormant or behaves differently to avoid detection during analysis.",
        impact_if_blind="Automated sandbox analysis reports the file as benign, while it behaves maliciously on real end-user machines.",
        requirements=[
            Requirement("EDR", "Behavioral detection beyond sandbox-only analysis",
                        lambda c: get(c, "edr", "behavioral_detection") is True),
            Requirement("SIEM", "Sandbox evasion pattern alert",
                        lambda c: "sandbox_evasion_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Ensure EDR does real-time behavioral monitoring on production endpoints, not just sandbox pre-checks",
            "Add SIEM rule for processes that behave differently based on detected environment characteristics",
        ],
    ),

    Technique(
        technique_id="T1222.001",
        name="File and Directory Permissions Modification: Windows File and Directory Permissions Modification",
        tactic="Defense Evasion",
        why_relevant="Attacker changes file/folder permissions (icacls, takeown) to block security tools from scanning/quarantining their malware, or to grant themselves persistent access.",
        impact_if_blind="EDR/AV may be unable to remove or even read a malicious file because its own permissions have been locked down against them.",
        requirements=[
            Requirement("Windows Event Log", "File/object access auditing",
                        lambda c: get(c, "windows_event_logs", "file_audit") is True),
            Requirement("SIEM", "Permission modification alert",
                        lambda c: "permission_modification_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable file/object access auditing on sensitive directories",
            "Add SIEM rule for icacls/takeown usage, especially against security-tool install directories",
        ],
    ),

    Technique(
        technique_id="T1564.001",
        name="Hide Artifacts: Hidden Files and Directories",
        tactic="Defense Evasion",
        why_relevant="Attacker sets the hidden/system attribute on their files, or uses names/locations designed to blend in and be skipped during casual review.",
        impact_if_blind="Malicious files sit on disk indefinitely, invisible during a manual folder review by IT staff.",
        requirements=[
            Requirement("Sysmon", "File creation (Event 11)",
                        lambda c: get(c, "sysmon", "event_id_11_file_create") is True),
            Requirement("SIEM", "Hidden file creation alert",
                        lambda c: "hidden_file_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon file creation logging (captures attribute changes in event metadata)",
            "Add SIEM rule for executable files created with the hidden/system attribute set",
        ],
    ),

    Technique(
        technique_id="T1620",
        name="Reflective Code Loading",
        tactic="Defense Evasion",
        why_relevant="Attacker loads and executes code directly in memory without it ever touching disk as a normal file or DLL — a favorite technique of modern malware loaders.",
        impact_if_blind="No file-based artifact ever exists for AV/EDR file-scanning to catch — the payload only ever lives in process memory.",
        requirements=[
            Requirement("Sysmon", "Process access (Event 10)",
                        lambda c: get(c, "sysmon", "event_id_10_process_access") is True),
            Requirement("EDR", "Behavioral/memory-based detection",
                        lambda c: get(c, "edr", "behavioral_detection") is True),
            Requirement("SIEM", "Reflective code loading alert",
                        lambda c: "reflective_load_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon Event ID 10 with a filter for memory-region execute permissions",
            "Ensure EDR includes memory-scanning/in-process detection, not file-scan-only",
            "Add SIEM rule for unusual memory allocation + execute permission patterns",
        ],
    ),

    # ═══ CREDENTIAL ACCESS (batch 3) ═══
    Technique(
        technique_id="T1187",
        name="Forced Authentication",
        tactic="Credential Access",
        why_relevant="Attacker tricks a system into authenticating to an attacker-controlled server (e.g. via a UNC path in a document), leaking the NTLM hash.",
        impact_if_blind="A victim's credentials leak just from their system trying to render a file preview or open a document — no malware execution required.",
        requirements=[
            Requirement("Firewall", "Outbound connection logging",
                        lambda c: get(c, "firewall", "outbound_logging") is True),
            Requirement("SIEM", "Forced authentication / outbound SMB alert",
                        lambda c: "forced_auth_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable outbound firewall logging for SMB (445) and WebDAV traffic leaving the network",
            "Add SIEM rule for outbound SMB authentication attempts to external IPs",
            "Block outbound SMB (445) at the perimeter firewall",
        ],
    ),

    Technique(
        technique_id="T1212",
        name="Exploitation for Credential Access",
        tactic="Credential Access",
        why_relevant="Attacker exploits a vulnerability specifically to extract credentials (e.g. a vulnerable service that leaks memory containing passwords).",
        impact_if_blind="Credentials are extracted through a software flaw rather than a 'normal' credential-dumping tool, bypassing tool-signature detection.",
        requirements=[
            Requirement("EDR", "Behavioral/exploit detection",
                        lambda c: get(c, "edr", "behavioral_detection") is True),
            Requirement("SIEM", "Credential-access exploit alert",
                        lambda c: "credential_exploit_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable EDR exploit protection on services known to handle credentials",
            "Add SIEM rule for credential-handling service crashes followed by anomalous process behavior",
            "Patch credential-handling services promptly",
        ],
    ),

    # ═══ DISCOVERY (batch 3) ═══
    Technique(
        technique_id="T1083",
        name="File and Directory Discovery",
        tactic="Discovery",
        why_relevant="Attacker browses the file system to find valuable data or interesting configuration files before deciding what to collect/exfiltrate.",
        impact_if_blind="Attacker maps out exactly where your sensitive data lives, with the reconnaissance step itself invisible.",
        requirements=[
            Requirement("Windows Event Log", "Process command line (dir /s, Get-ChildItem -Recurse)",
                        lambda c: get(c, "windows_event_logs", "process_command_line") is True),
            Requirement("SIEM", "Discovery tool detection",
                        lambda c: "discovery_tool_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable command-line auditing to catch mass directory enumeration commands",
            "Add SIEM rule for recursive directory listing commands across many folders in a short time",
        ],
    ),

    Technique(
        technique_id="T1016",
        name="System Network Configuration Discovery",
        tactic="Discovery",
        why_relevant="Attacker checks network configuration (ipconfig, routing table, DNS servers) to understand the network they've landed in.",
        impact_if_blind="Attacker builds a map of your network topology before moving further, with zero record of this reconnaissance step.",
        requirements=[
            Requirement("Windows Event Log", "Process command line (ipconfig, route print, arp -a)",
                        lambda c: get(c, "windows_event_logs", "process_command_line") is True),
            Requirement("SIEM", "Discovery tool detection",
                        lambda c: "discovery_tool_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable command-line auditing to catch network config enumeration commands",
            "Add SIEM rule correlating network discovery commands with subsequent lateral movement attempts",
        ],
    ),

    Technique(
        technique_id="T1049",
        name="System Network Connections Discovery",
        tactic="Discovery",
        why_relevant="Attacker lists active network connections (netstat) to identify other systems already communicating with the compromised host.",
        impact_if_blind="Attacker identifies live sessions and connected systems to target next, with no signal that this enumeration occurred.",
        requirements=[
            Requirement("Sysmon", "Process creation (Event 1)",
                        lambda c: get(c, "sysmon", "event_id_1_process_creation") is True),
            Requirement("SIEM", "Discovery tool detection",
                        lambda c: "discovery_tool_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon process creation logging to catch netstat/Get-NetTCPConnection usage",
            "Add SIEM rule for connection-enumeration commands followed by new outbound connections",
        ],
    ),

    # ═══ LATERAL MOVEMENT (batch 3) ═══
    Technique(
        technique_id="T1080",
        name="Taint Shared Content",
        tactic="Lateral Movement",
        why_relevant="Attacker plants a malicious file on a shared drive that other users will naturally open, spreading laterally without any active exploitation.",
        impact_if_blind="The infection spreads passively as legitimate users go about normal file-sharing activity — no active attacker action needed per victim.",
        requirements=[
            Requirement("Sysmon", "File creation (Event 11) on shared locations",
                        lambda c: get(c, "sysmon", "event_id_11_file_create") is True),
            Requirement("Windows Event Log", "Share access auditing",
                        lambda c: get(c, "windows_event_logs", "share_access_audit") is True),
            Requirement("SIEM", "Tainted shared content alert",
                        lambda c: "tainted_content_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon file creation logging on network shares",
            "Enable share access auditing to correlate who wrote/modified files on shared drives",
            "Add SIEM rule for executable/script files newly created on general-purpose file shares",
        ],
    ),

    Technique(
        technique_id="T1563.002",
        name="Remote Service Session Hijacking: RDP Hijacking",
        tactic="Lateral Movement",
        why_relevant="Attacker takes over an existing, disconnected RDP session (often as SYSTEM) to move laterally without needing new credentials.",
        impact_if_blind="Attacker rides in on a legitimate user's already-authenticated session — no new logon event to distinguish it from normal activity.",
        requirements=[
            Requirement("Windows Event Log", "Remote logon auditing (session reconnect events)",
                        lambda c: get(c, "windows_event_logs", "remote_logon_audit") is True),
            Requirement("SIEM", "RDP session hijack alert",
                        lambda c: "rdp_hijack_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable remote logon auditing including session reconnect/disconnect events",
            "Add SIEM rule for RDP session reconnects from a source host different from the original logon",
            "Restrict use of tscon.exe / session-switching tools to authorized admins only",
        ],
    ),

    # ═══ COLLECTION (batch 3) ═══
    Technique(
        technique_id="T1119",
        name="Automated Collection",
        tactic="Collection",
        why_relevant="Attacker scripts the collection of files matching certain criteria (extensions, keywords) instead of manually browsing — much faster and stealthier.",
        impact_if_blind="Large volumes of targeted data are gathered in seconds via script, rather than the slower manual browsing that's easier to notice.",
        requirements=[
            Requirement("Sysmon", "Process creation (Event 1)",
                        lambda c: get(c, "sysmon", "event_id_1_process_creation") is True),
            Requirement("SIEM", "Automated collection script alert",
                        lambda c: "automated_collection_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon process creation logging for scripting engines (PowerShell, Python, etc.)",
            "Add SIEM rule for a single script process touching a very high number of files rapidly",
        ],
    ),

    Technique(
        technique_id="T1074.001",
        name="Data Staged: Local Data Staging",
        tactic="Collection",
        why_relevant="Attacker consolidates collected data into a single staging location before compressing/exfiltrating it — a key pre-exfiltration signal.",
        impact_if_blind="A large, unusual collection of files appearing in one folder — a strong precursor to exfiltration — goes completely unnoticed.",
        requirements=[
            Requirement("Sysmon", "File creation (Event 11)",
                        lambda c: get(c, "sysmon", "event_id_11_file_create") is True),
            Requirement("SIEM", "Data staging location alert",
                        lambda c: "data_staging_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon file creation logging, especially in Temp/AppData folders",
            "Add SIEM rule for an unusual number of files newly created in a single folder in a short window",
        ],
    ),

    Technique(
        technique_id="T1115",
        name="Clipboard Data",
        tactic="Collection",
        why_relevant="Attacker monitors the clipboard to capture copied passwords, crypto wallet addresses, or other sensitive data as the user works.",
        impact_if_blind="Sensitive data the user copies (even briefly) — passwords from a password manager, crypto addresses — is silently captured.",
        requirements=[
            Requirement("EDR", "Behavioral detection of clipboard monitoring APIs",
                        lambda c: get(c, "edr", "behavioral_detection") is True),
            Requirement("SIEM", "Clipboard capture alert",
                        lambda c: "clipboard_capture_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable EDR behavioral detection covering clipboard API usage (SetClipboardViewer, GetClipboardData)",
            "Add SIEM rule for unusual processes repeatedly polling clipboard contents",
        ],
    ),

    # ═══ COMMAND AND CONTROL (batch 3) ═══
    Technique(
        technique_id="T1132.001",
        name="Data Encoding: Standard Encoding",
        tactic="Command and Control",
        why_relevant="Attacker encodes C2 traffic (base64, etc.) to obscure it from simple content-inspection while staying technically 'not encrypted'.",
        impact_if_blind="Basic string/keyword matching on network traffic finds nothing because the content is encoded rather than in plaintext.",
        requirements=[
            Requirement("Sysmon", "Network connection (Event 3)",
                        lambda c: get(c, "sysmon", "event_id_3_network_connection") is True),
            Requirement("SIEM", "Encoded C2 traffic alert",
                        lambda c: "encoded_c2_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon network connection logging on endpoints",
            "Add SIEM rule for consistent, periodic connections carrying high-entropy encoded payloads",
        ],
    ),

    Technique(
        technique_id="T1095",
        name="Non-Application Layer Protocol",
        tactic="Command and Control",
        why_relevant="Attacker uses a raw/uncommon protocol (ICMP, raw sockets) for C2 instead of standard HTTP/HTTPS, evading application-layer inspection entirely.",
        impact_if_blind="Traffic that never looks like normal web traffic (e.g. C2-over-ICMP) sails past tools that only inspect HTTP/DNS/HTTPS.",
        requirements=[
            Requirement("Firewall", "Outbound connection logging",
                        lambda c: get(c, "firewall", "outbound_logging") is True),
            Requirement("Sysmon", "Network connection (Event 3)",
                        lambda c: get(c, "sysmon", "event_id_3_network_connection") is True),
            Requirement("SIEM", "Non-standard protocol usage alert",
                        lambda c: "nonstandard_protocol_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable outbound firewall logging that captures protocol, not just port",
            "Enable Sysmon network connection logging on endpoints",
            "Add SIEM rule for ICMP or raw-socket traffic carrying unusually large or frequent payloads",
        ],
    ),

    Technique(
        technique_id="T1573.002",
        name="Encrypted Channel: Asymmetric Cryptography",
        tactic="Command and Control",
        why_relevant="Attacker encrypts C2 traffic with strong asymmetric crypto, making content inspection impossible even with HTTPS interception in some cases.",
        impact_if_blind="Even organizations doing HTTPS inspection can be blind to C2 using additional application-layer encryption on top.",
        requirements=[
            Requirement("Firewall", "HTTPS inspection",
                        lambda c: get(c, "firewall", "https_inspection") is True),
            Requirement("SIEM", "Encrypted C2 pattern alert",
                        lambda c: "encrypted_c2_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable HTTPS inspection where legally/technically feasible",
            "Add SIEM rule based on connection metadata/timing patterns (JA3 fingerprinting, beacon intervals) rather than content alone",
        ],
    ),

    # ═══ EXFILTRATION (batch 3) ═══
    Technique(
        technique_id="T1567.001",
        name="Exfiltration Over Web Service: Exfiltration to Code Repository",
        tactic="Exfiltration",
        why_relevant="Attacker uploads stolen data to a public or private code repository (GitHub Gist, GitLab) — a destination rarely blocked in corporate environments.",
        impact_if_blind="Data leaves via a domain (github.com) that's almost universally allowed and trusted by default.",
        requirements=[
            Requirement("Firewall", "Outbound connection logging",
                        lambda c: get(c, "firewall", "outbound_logging") is True),
            Requirement("Firewall", "HTTPS inspection",
                        lambda c: get(c, "firewall", "https_inspection") is True),
            Requirement("SIEM", "Code repository exfiltration alert",
                        lambda c: "code_repo_exfil_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable outbound firewall logging with destination category visibility",
            "Enable HTTPS inspection to see actual API calls made to code-hosting platforms",
            "Add SIEM rule for large uploads to code repository domains from non-developer accounts",
        ],
    ),

    Technique(
        technique_id="T1030",
        name="Data Transfer Size Limits",
        tactic="Exfiltration",
        why_relevant="Attacker splits stolen data into small chunks below common data-loss-prevention size thresholds, to avoid triggering volume-based alerts.",
        impact_if_blind="Volume-based DLP/SIEM rules are bypassed by design, since no single transfer looks large enough to trigger them.",
        requirements=[
            Requirement("Firewall", "Outbound connection logging",
                        lambda c: get(c, "firewall", "outbound_logging") is True),
            Requirement("SIEM", "Chunked/split exfiltration pattern alert",
                        lambda c: "chunked_exfil_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable outbound firewall logging with per-connection byte counts",
            "Add SIEM rule for aggregate outbound volume to a single destination over time, not just per-connection size",
        ],
    ),

    # ═══ IMPACT (batch 3) ═══
    Technique(
        technique_id="T1499",
        name="Endpoint Denial of Service",
        tactic="Impact",
        why_relevant="Attacker deliberately crashes or overloads a critical endpoint/service (e.g. a resource-exhaustion attack on a business application).",
        impact_if_blind="Business operations halt because a critical service is knocked offline, with the cause looking like a random crash rather than an attack.",
        requirements=[
            Requirement("EDR", "Behavioral detection of resource-exhaustion patterns",
                        lambda c: get(c, "edr", "behavioral_detection") is True),
            Requirement("SIEM", "Endpoint DoS alert",
                        lambda c: "endpoint_dos_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable EDR behavioral monitoring for abnormal resource consumption patterns",
            "Add SIEM rule for sudden critical-service crashes correlated with unusual process activity",
        ],
    ),

    Technique(
        technique_id="T1531",
        name="Account Access Removal",
        tactic="Impact",
        why_relevant="Attacker locks legitimate users/admins out of their own accounts (password changes, disabling accounts) to delay incident response.",
        impact_if_blind="Your own IT/security team gets locked out right when they need access most, buying the attacker critical extra time.",
        requirements=[
            Requirement("Windows Event Log", "Process command line (net user password changes / disable-adaccount)",
                        lambda c: get(c, "windows_event_logs", "process_command_line") is True),
            Requirement("SIEM", "Mass account lockout/disable alert",
                        lambda c: "account_lockout_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable command-line auditing for password reset and account-disable commands",
            "Add SIEM rule for multiple account password changes/disables in a short time window",
            "Maintain an out-of-band emergency access account not dependent on the primary directory",
        ],
    ),

    Technique(
        technique_id="T1561.001",
        name="Disk Wipe: Disk Content Wipe",
        tactic="Impact",
        why_relevant="Attacker wipes disk contents outright (more destructive than ransomware — no recovery is even offered) as a final, deliberately destructive act.",
        impact_if_blind="Complete, unrecoverable data loss occurs with no early-warning signal to trigger an emergency backup restoration before it's too late.",
        requirements=[
            Requirement("Sysmon", "Process creation (Event 1) — disk-wipe utility launched",
                        lambda c: get(c, "sysmon", "event_id_1_process_creation") is True),
            Requirement("EDR", "Behavioral detection of destructive disk operations",
                        lambda c: get(c, "edr", "behavioral_detection") is True),
            Requirement("SIEM", "Disk wipe correlation alert",
                        lambda c: "disk_wipe_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon process creation logging to catch disk-wipe utility execution",
            "Ensure EDR behavioral detection covers low-level disk write operations",
            "Add SIEM rule treating any disk-wipe utility execution as critical severity",
            "Maintain offline, immutable backups isolated from the production network",
        ],
    ),

    # ═══ INITIAL ACCESS (batch 4) ═══
    Technique(
        technique_id="T1091",
        name="Replication Through Removable Media",
        tactic="Initial Access",
        why_relevant="Attacker uses an infected USB drive with an autorun/LNK payload to compromise a system when plugged in — still common in industrial/SMB settings.",
        impact_if_blind="Air-gapped or network-isolated systems can still be compromised, since the infection vector never touches the network.",
        requirements=[
            Requirement("Sysmon", "File creation (Event 11) — autorun.inf / LNK payload drop",
                        lambda c: get(c, "sysmon", "event_id_11_file_create") is True),
            Requirement("SIEM", "Removable media infection alert",
                        lambda c: "removable_media_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon file creation logging on newly-mounted removable drives",
            "Add SIEM rule for autorun.inf or LNK file creation on removable media",
            "Disable AutoRun/AutoPlay via Group Policy",
        ],
    ),

    Technique(
        technique_id="T1078.004",
        name="Valid Accounts: Cloud Accounts",
        tactic="Initial Access",
        why_relevant="Attacker uses stolen or weak cloud-service credentials (Microsoft 365, Google Workspace) to gain access without touching the on-prem network at all.",
        impact_if_blind="A breach can start and progress entirely within cloud services, invisible to on-premises-focused monitoring.",
        requirements=[
            Requirement("Windows Event Log", "Remote logon auditing (hybrid identity correlation)",
                        lambda c: get(c, "windows_event_logs", "remote_logon_audit") is True),
            Requirement("SIEM", "Cloud account anomalous access alert",
                        lambda c: "cloud_account_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Ingest cloud identity provider sign-in logs into the same SIEM as on-prem logs",
            "Add SIEM rule for impossible-travel or unusual-location cloud sign-ins",
            "Enforce MFA and conditional access on all cloud accounts",
        ],
    ),

    # ═══ EXECUTION (batch 4) ═══
    Technique(
        technique_id="T1059.006",
        name="Command and Scripting Interpreter: Python",
        tactic="Execution",
        why_relevant="Attacker uses a Python interpreter or compiled Python payload (PyInstaller) for cross-platform tooling that's often overlooked in Windows-centric monitoring.",
        impact_if_blind="Python-based malware runs freely since most Windows security tooling is tuned around PowerShell/cmd, not python.exe.",
        requirements=[
            Requirement("Windows Event Log", "Process command line (python.exe arguments)",
                        lambda c: get(c, "windows_event_logs", "process_command_line") is True),
            Requirement("Sysmon", "Process creation (Event 1)",
                        lambda c: get(c, "sysmon", "event_id_1_process_creation") is True),
            Requirement("SIEM", "Python script execution alert",
                        lambda c: "python_execution_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable command-line and process-creation logging including non-Microsoft interpreters",
            "Add SIEM rule for python.exe/pyw.exe execution on hosts where Python isn't a standard tool",
        ],
    ),

    Technique(
        technique_id="T1072",
        name="Software Deployment Tools",
        tactic="Execution",
        why_relevant="Attacker abuses legitimate software deployment/patch management tools (SCCM, PDQ Deploy) to push malware to many machines using an already-trusted channel.",
        impact_if_blind="Malware deploys enterprise-wide through infrastructure specifically designed to be trusted and unmonitored by endpoint security.",
        requirements=[
            Requirement("Windows Event Log", "Process command line for deployment tool activity",
                        lambda c: get(c, "windows_event_logs", "process_command_line") is True),
            Requirement("SIEM", "Deployment tool abuse alert",
                        lambda c: "deployment_tool_abuse_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable command-line auditing on deployment tool servers and agents",
            "Add SIEM rule for new/unusual packages pushed outside change-management windows",
            "Restrict deployment tool console access to a small, monitored admin group",
        ],
    ),

    # ═══ PERSISTENCE (batch 4) ═══
    Technique(
        technique_id="T1547.009",
        name="Boot or Logon Autostart Execution: Shortcut Modification",
        tactic="Persistence",
        why_relevant="Attacker modifies a shortcut (.lnk) in the Startup folder or Taskbar to launch malicious code alongside the legitimate target application.",
        impact_if_blind="A shortcut the user clicks every day (e.g. their browser icon) silently launches malware first, looking completely normal to the user.",
        requirements=[
            Requirement("Sysmon", "File creation (Event 11) — .lnk file changes",
                        lambda c: get(c, "sysmon", "event_id_11_file_create") is True),
            Requirement("SIEM", "Shortcut persistence alert",
                        lambda c: "shortcut_persistence_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon file creation/modification logging on Startup folders and common shortcut locations",
            "Add SIEM rule for .lnk file modifications pointing to unexpected target executables",
        ],
    ),

    Technique(
        technique_id="T1136.002",
        name="Create Account: Domain Account",
        tactic="Persistence",
        why_relevant="Attacker creates a new domain account (not just local) as a persistence fallback with organization-wide reach.",
        impact_if_blind="A backdoor domain account can authenticate to any domain-joined resource the attacker chooses, far beyond a single machine.",
        requirements=[
            Requirement("Windows Event Log", "AD change auditing",
                        lambda c: get(c, "windows_event_logs", "ad_replication_audit") is True),
            Requirement("SIEM", "Domain account creation alert",
                        lambda c: "account_creation_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable AD object creation auditing on domain controllers",
            "Add SIEM rule for new domain user accounts, especially those created outside HR/IT onboarding workflows",
        ],
    ),

    # ═══ PRIVILEGE ESCALATION (batch 4) ═══
    Technique(
        technique_id="T1134.005",
        name="Access Token Manipulation: SID-History Injection",
        tactic="Privilege Escalation",
        why_relevant="Attacker injects a privileged SID into an account's history attribute, granting it hidden admin-equivalent rights without visible group membership changes.",
        impact_if_blind="An account with no visible admin group membership silently has admin-equivalent access — invisible to a standard group-membership review.",
        requirements=[
            Requirement("Windows Event Log", "AD replication/attribute change auditing",
                        lambda c: get(c, "windows_event_logs", "ad_replication_audit") is True),
            Requirement("SIEM", "SID-History injection alert",
                        lambda c: "sid_history_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable AD attribute-change auditing, specifically on the sIDHistory attribute",
            "Add SIEM rule for any modification to an account's sIDHistory attribute",
            "Regularly audit for unexpected non-empty sIDHistory values (SDProp/ADRecon)",
        ],
    ),

    # ═══ DEFENSE EVASION (batch 4) ═══
    Technique(
        technique_id="T1218.005",
        name="System Binary Proxy Execution: Mshta",
        tactic="Defense Evasion",
        why_relevant="Attacker uses the trusted mshta.exe to execute malicious HTA/JavaScript/VBScript, another classic 'living off the land' technique.",
        impact_if_blind="Code execution is attributed to a signed Microsoft binary that most allowlisting policies don't restrict by default.",
        requirements=[
            Requirement("Sysmon", "Process creation (Event 1)",
                        lambda c: get(c, "sysmon", "event_id_1_process_creation") is True),
            Requirement("Windows Event Log", "Process command line for mshta arguments",
                        lambda c: get(c, "windows_event_logs", "process_command_line") is True),
            Requirement("SIEM", "LOLBin abuse correlation alert",
                        lambda c: "lolbin_abuse_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon process creation and command-line logging",
            "Add SIEM rule for mshta.exe execution with a remote URL or unusual local path argument",
            "Block mshta.exe via application control policy where it's not needed",
        ],
    ),

    Technique(
        technique_id="T1207",
        name="Rogue Domain Controller",
        tactic="Defense Evasion",
        why_relevant="Attacker registers an unauthorized DC (DCShadow-style) to push malicious AD changes that bypass normal auditing entirely.",
        impact_if_blind="Malicious directory changes replicate as if made by a legitimate domain controller — one of the stealthiest AD attacks that exists.",
        requirements=[
            Requirement("Windows Event Log", "AD replication auditing",
                        lambda c: get(c, "windows_event_logs", "ad_replication_audit") is True),
            Requirement("SIEM", "Rogue DC / DCShadow correlation alert",
                        lambda c: "dcshadow_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable AD replication auditing across all domain controllers",
            "Add SIEM rule for replication requests from computer objects not on the known DC list",
            "Monitor for new DC registrations in AD Sites and Services",
        ],
    ),

    # ═══ CREDENTIAL ACCESS (batch 4) ═══
    Technique(
        technique_id="T1003.004",
        name="OS Credential Dumping: LSA Secrets",
        tactic="Credential Access",
        why_relevant="Attacker extracts LSA Secrets from the registry, which often contain service account and auto-logon passwords in recoverable form.",
        impact_if_blind="Service account credentials — frequently over-privileged — are extracted directly from the registry with no interaction with LSASS memory needed.",
        requirements=[
            Requirement("Sysmon", "Registry value access on LSA Secrets keys",
                        lambda c: get(c, "sysmon", "event_id_13_registry_set_value") is True),
            Requirement("SIEM", "LSA Secrets access alert",
                        lambda c: "lsa_secrets_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon registry monitoring on HKLM\\SECURITY\\Policy\\Secrets",
            "Add SIEM rule for any non-SYSTEM process accessing the LSA Secrets registry hive",
            "Avoid storing service account credentials as auto-logon/LSA secrets where possible",
        ],
    ),

    Technique(
        technique_id="T1003.005",
        name="OS Credential Dumping: Cached Domain Credentials",
        tactic="Credential Access",
        why_relevant="Attacker extracts cached domain logon credentials (used for offline logon) from the registry, useful even without domain controller access.",
        impact_if_blind="Domain credentials for any user who's ever logged into the machine can be extracted, even long after they've left the organization.",
        requirements=[
            Requirement("Sysmon", "Registry value access on cached credential keys",
                        lambda c: get(c, "sysmon", "event_id_13_registry_set_value") is True),
            Requirement("EDR", "LSASS/credential store protection",
                        lambda c: get(c, "edr", "lsass_protection") is True),
            Requirement("SIEM", "Cached credential dumping alert",
                        lambda c: "cached_creds_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon registry monitoring on HKLM\\SECURITY\\Cache",
            "Enable EDR credential-store protection features",
            "Add SIEM rule for tools known to extract cached domain credentials (mimikatz, secretsdump)",
        ],
    ),

    Technique(
        technique_id="T1556.002",
        name="Modify Authentication Process: Password Filter DLL",
        tactic="Credential Access",
        why_relevant="Attacker installs a malicious password-filter DLL that silently captures every plaintext password as users change them — a very quiet, long-term credential harvester.",
        impact_if_blind="Every future password change across the domain is captured in plaintext, indefinitely, with no ongoing attacker activity needed after initial install.",
        requirements=[
            Requirement("Sysmon", "Image load event (Event 7) on LSASS",
                        lambda c: get(c, "sysmon", "image_load_event") is True),
            Requirement("SIEM", "Authentication process modification alert",
                        lambda c: "auth_process_modification_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon image load logging specifically for DLLs loading into lsass.exe",
            "Add SIEM rule for any new DLL registered in the Notification Packages registry value",
            "Regularly audit the list of DLLs loaded by LSASS on domain controllers",
        ],
    ),

    # ═══ DISCOVERY (batch 4) ═══
    Technique(
        technique_id="T1033",
        name="System Owner/User Discovery",
        tactic="Discovery",
        why_relevant="Attacker identifies the currently logged-in user and their privilege level to decide how to proceed (e.g. escalate vs. move on).",
        impact_if_blind="Attacker quickly learns whether they've landed on a high-value target (an admin's machine) with no visibility into this basic reconnaissance step.",
        requirements=[
            Requirement("Windows Event Log", "Process command line (whoami, query user)",
                        lambda c: get(c, "windows_event_logs", "process_command_line") is True),
            Requirement("SIEM", "Discovery tool detection",
                        lambda c: "discovery_tool_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable command-line auditing to catch whoami/query user enumeration",
            "Add SIEM rule correlating user-discovery commands with subsequent privilege-escalation attempts",
        ],
    ),

    Technique(
        technique_id="T1201",
        name="Password Policy Discovery",
        tactic="Discovery",
        why_relevant="Attacker checks the domain password policy (net accounts) to calibrate a brute-force attack that stays just under the lockout threshold.",
        impact_if_blind="Attacker fine-tunes brute-force attempts to avoid triggering lockout-based defenses, using information gathered with zero risk.",
        requirements=[
            Requirement("Windows Event Log", "Process command line (net accounts / Get-ADDefaultDomainPasswordPolicy)",
                        lambda c: get(c, "windows_event_logs", "process_command_line") is True),
            Requirement("SIEM", "Discovery tool detection",
                        lambda c: "discovery_tool_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable command-line auditing to catch password policy enumeration commands",
            "Add SIEM rule correlating password-policy discovery with subsequent authentication attempts",
        ],
    ),

    Technique(
        technique_id="T1615",
        name="Group Policy Discovery",
        tactic="Discovery",
        why_relevant="Attacker enumerates Group Policy Objects to understand security controls in place (and find weaknesses) before attempting evasion or escalation.",
        impact_if_blind="Attacker learns exactly which defensive controls to plan around, with the reconnaissance step itself completely invisible.",
        requirements=[
            Requirement("Windows Event Log", "Process command line (Get-GPO / gpresult)",
                        lambda c: get(c, "windows_event_logs", "process_command_line") is True),
            Requirement("SIEM", "Discovery tool detection",
                        lambda c: "discovery_tool_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable command-line auditing to catch gpresult/Get-GPO enumeration",
            "Add SIEM rule for GPO enumeration from non-administrative accounts",
        ],
    ),

    # ═══ LATERAL MOVEMENT (batch 4) ═══
    Technique(
        technique_id="T1534",
        name="Internal Spearphishing",
        tactic="Lateral Movement",
        why_relevant="Attacker uses an already-compromised mailbox to send phishing emails to coworkers — far more convincing than an external phishing attempt.",
        impact_if_blind="Colleagues trust an email from a real coworker's real account, dramatically increasing the odds the attack spreads further internally.",
        requirements=[
            Requirement("Email Security", "URL/attachment sandboxing (applied to internal mail too)",
                        lambda c: get(c, "email_security", "url_sandboxing") is True),
            Requirement("SIEM", "Internal phishing propagation alert",
                        lambda c: "internal_phishing_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Ensure sandboxing/scanning applies to internal-to-internal mail, not just inbound external mail",
            "Add SIEM rule for a mailbox suddenly sending high volumes of similar messages internally",
        ],
    ),

    # ═══ COLLECTION (batch 4) ═══
    Technique(
        technique_id="T1123",
        name="Audio Capture",
        tactic="Collection",
        why_relevant="Attacker activates the microphone to record ambient audio — conversations, calls — from a compromised device.",
        impact_if_blind="Confidential conversations in earshot of a compromised laptop/phone are recorded with no indication the microphone is active.",
        requirements=[
            Requirement("EDR", "Behavioral detection of microphone API abuse",
                        lambda c: get(c, "edr", "behavioral_detection") is True),
            Requirement("SIEM", "Audio capture correlation alert",
                        lambda c: "audio_capture_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable EDR behavioral detection covering microphone/audio API calls",
            "Add SIEM rule for unusual processes accessing audio capture devices",
        ],
    ),

    Technique(
        technique_id="T1125",
        name="Video Capture",
        tactic="Collection",
        why_relevant="Attacker activates the webcam to capture video/images without the user's knowledge.",
        impact_if_blind="Highly invasive visual surveillance of the user happens with zero indication the camera is active.",
        requirements=[
            Requirement("EDR", "Behavioral detection of webcam API abuse",
                        lambda c: get(c, "edr", "behavioral_detection") is True),
            Requirement("SIEM", "Video capture correlation alert",
                        lambda c: "video_capture_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable EDR behavioral detection covering webcam API calls",
            "Add SIEM rule for unusual processes accessing camera devices",
            "Consider physical camera covers as a low-tech compensating control",
        ],
    ),

    # ═══ COMMAND AND CONTROL (batch 4) ═══
    Technique(
        technique_id="T1219",
        name="Remote Access Software",
        tactic="Command and Control",
        why_relevant="Attacker installs or abuses a legitimate remote-access tool (AnyDesk, TeamViewer, ScreenConnect) as C2 — traffic looks like normal remote support activity.",
        impact_if_blind="Full interactive remote control of the compromised machine happens through a tool your users already trust and use daily.",
        requirements=[
            Requirement("Windows Event Log", "Process command line for remote-access tool installers",
                        lambda c: get(c, "windows_event_logs", "process_command_line") is True),
            Requirement("SIEM", "Unauthorized remote-access tool alert",
                        lambda c: "remote_access_tool_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable command-line auditing to catch installation of remote-access tools",
            "Add SIEM rule for remote-access tool installers not on an approved allowlist",
            "Restrict which remote-access tools are permitted via application control",
        ],
    ),

    Technique(
        technique_id="T1205",
        name="Traffic Signaling",
        tactic="Command and Control",
        why_relevant="Attacker uses a 'magic packet' or port-knock sequence to open a hidden backdoor listener only when needed, staying invisible to routine port scans.",
        impact_if_blind="A backdoor exists on the host that a standard port scan or firewall audit will never detect, since it's dormant until triggered.",
        requirements=[
            Requirement("Firewall", "Outbound/internal connection logging",
                        lambda c: get(c, "firewall", "outbound_logging") is True),
            Requirement("SIEM", "Traffic signaling / port-knock alert",
                        lambda c: "traffic_signaling_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable detailed connection logging, including rejected/filtered packet attempts",
            "Add SIEM rule for sequential connection attempts to closed ports from the same source in a short window",
        ],
    ),

    Technique(
        technique_id="T1568.002",
        name="Dynamic Resolution: Domain Generation Algorithms",
        tactic="Command and Control",
        why_relevant="Malware algorithmically generates many pseudo-random C2 domain names, so blocking a handful of known-bad domains doesn't stop it.",
        impact_if_blind="Domain/IP blocklists become useless against C2 infrastructure that changes hundreds of times a day.",
        requirements=[
            Requirement("Firewall", "DNS query logging",
                        lambda c: get(c, "firewall", "dns_logging") is True),
            Requirement("SIEM", "DNS anomaly / DGA pattern alert",
                        lambda c: "dns_anomaly_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable DNS query logging on internal DNS servers/resolvers",
            "Add SIEM/DNS-analytics rule for high-entropy domain names and high NXDOMAIN rates from a single host",
        ],
    ),

    # ═══ IMPACT (batch 4) ═══
    Technique(
        technique_id="T1565.001",
        name="Data Manipulation: Stored Data Manipulation",
        tactic="Impact",
        why_relevant="Attacker subtly alters stored data (financial records, databases) rather than destroying it outright — harder to detect and can cause lasting business damage.",
        impact_if_blind="Corrupted or falsified data (e.g. altered financial records) can go unnoticed for months, undermining trust in every downstream decision made from it.",
        requirements=[
            Requirement("Sysmon", "File creation/modification (Event 11)",
                        lambda c: get(c, "sysmon", "event_id_11_file_create") is True),
            Requirement("EDR", "Behavioral detection of unusual data-modification patterns",
                        lambda c: get(c, "edr", "behavioral_detection") is True),
            Requirement("SIEM", "Data manipulation correlation alert",
                        lambda c: "data_manipulation_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon file modification logging on business-critical data stores",
            "Add SIEM rule for unusual write patterns to production databases/files outside normal application activity",
            "Maintain versioned/immutable backups to enable point-in-time data integrity verification",
        ],
    ),

    Technique(
        technique_id="T1496",
        name="Resource Hijacking",
        tactic="Impact",
        why_relevant="Attacker uses compromised systems to mine cryptocurrency or run other resource-intensive tasks for their own profit at your expense.",
        impact_if_blind="Systems run degraded, power/cloud costs rise, and hardware wears out faster — often mistaken for a performance problem rather than a compromise.",
        requirements=[
            Requirement("EDR", "Behavioral detection of cryptomining/resource-abuse patterns",
                        lambda c: get(c, "edr", "behavioral_detection") is True),
            Requirement("SIEM", "Resource hijacking / cryptomining alert",
                        lambda c: "resource_hijack_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable EDR behavioral detection tuned for cryptomining process signatures",
            "Add SIEM rule for sustained abnormal CPU/GPU usage correlated with connections to known mining pools",
        ],
    ),

    Technique(
        technique_id="T1529",
        name="System Shutdown/Reboot",
        tactic="Impact",
        why_relevant="Attacker forces shutdowns/reboots across many systems simultaneously — a simple but highly disruptive denial-of-service against business operations.",
        impact_if_blind="Coordinated mass reboots disrupt the entire business at once, and the sudden interruption itself can also mask other attacker activity happening in parallel.",
        requirements=[
            Requirement("Windows Event Log", "Process command line (shutdown.exe / Restart-Computer)",
                        lambda c: get(c, "windows_event_logs", "process_command_line") is True),
            Requirement("SIEM", "Unexpected mass shutdown/reboot alert",
                        lambda c: "unexpected_shutdown_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable command-line auditing to catch remote shutdown/restart commands",
            "Add SIEM rule for shutdown/restart commands issued to multiple hosts within a short window",
        ],
    ),

    # ═══ INITIAL ACCESS (batch 5) ═══
    Technique(
        technique_id="T1195.002",
        name="Supply Chain Compromise: Compromise Software Supply Chain",
        tactic="Initial Access",
        why_relevant="Attacker compromises a legitimate software vendor's update mechanism so victims install malware through a trusted, signed update.",
        impact_if_blind="Malware arrives disguised as a routine, expected software update — the single hardest initial-access vector to distinguish from normal IT operations.",
        requirements=[
            Requirement("EDR", "Malware detection on all installed/updated software",
                        lambda c: get(c, "edr", "malware_detection") is True),
            Requirement("SIEM", "Supply chain compromise alert",
                        lambda c: "supply_chain_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Ensure EDR scans software post-install/update, not just at first download",
            "Add SIEM rule for known-vendor update processes exhibiting unexpected network/file behavior",
            "Track vendor security advisories for supply-chain compromise notices",
        ],
    ),

    Technique(
        technique_id="T1189",
        name="Drive-by Compromise",
        tactic="Initial Access",
        why_relevant="Attacker compromises a legitimate website or serves malicious ads so simply browsing (no click needed) triggers a browser exploit.",
        impact_if_blind="A user visiting an otherwise-trusted news site or industry forum gets compromised with zero interaction beyond normal browsing.",
        requirements=[
            Requirement("Firewall", "HTTPS inspection",
                        lambda c: get(c, "firewall", "https_inspection") is True),
            Requirement("EDR", "Behavioral/exploit detection",
                        lambda c: get(c, "edr", "behavioral_detection") is True),
            Requirement("SIEM", "Drive-by compromise alert",
                        lambda c: "drive_by_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable HTTPS inspection/web filtering with exploit-kit detection",
            "Ensure EDR exploit protection covers browsers and browser plugins",
            "Add SIEM rule for browsers spawning unexpected child processes shortly after page load",
        ],
    ),

    Technique(
        technique_id="T1566.002",
        name="Phishing: Spearphishing Link",
        tactic="Initial Access",
        why_relevant="Attacker sends a malicious link (rather than attachment) that leads to a credential-harvesting page or drive-by exploit — bypasses attachment scanning entirely.",
        impact_if_blind="Attachment-focused email security misses this vector completely, since the email itself contains no file to scan.",
        requirements=[
            Requirement("Email Security", "URL sandboxing",
                        lambda c: get(c, "email_security", "url_sandboxing") is True),
            Requirement("SIEM", "Phishing link click alert",
                        lambda c: "phishing_link_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable URL sandboxing/rewriting on the email gateway for all inbound links",
            "Add SIEM rule correlating a link click with a subsequent credential submission to a lookalike domain",
        ],
    ),

    Technique(
        technique_id="T1078.002",
        name="Valid Accounts: Domain Accounts",
        tactic="Initial Access",
        why_relevant="Attacker uses a stolen legitimate domain account to gain initial access, blending in with normal authenticated activity from the very first step.",
        impact_if_blind="The entire intrusion, from the very first logon, looks like an authorized employee — nothing about it appears anomalous by default.",
        requirements=[
            Requirement("Windows Event Log", "Remote logon auditing",
                        lambda c: get(c, "windows_event_logs", "remote_logon_audit") is True),
            Requirement("SIEM", "Anomalous domain account logon alert",
                        lambda c: "anomalous_logon_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable remote logon auditing across all domain-joined systems",
            "Add SIEM rule for domain account logons from new devices, locations, or at unusual times",
            "Enforce MFA on all domain accounts, not just admin accounts",
        ],
    ),

    # ═══ EXECUTION (batch 5) ═══
    Technique(
        technique_id="T1106",
        name="Native API",
        tactic="Execution",
        why_relevant="Attacker calls Windows API functions directly (bypassing cmd.exe/PowerShell) to execute actions without generating typical process/command-line artifacts.",
        impact_if_blind="Actions happen through direct API calls invisible to logging that only watches for new processes or command lines.",
        requirements=[
            Requirement("EDR", "Behavioral detection of direct API abuse",
                        lambda c: get(c, "edr", "behavioral_detection") is True),
            Requirement("SIEM", "Native API abuse alert",
                        lambda c: "native_api_abuse_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Ensure EDR hooks/monitors native API calls (NtCreateProcess, NtWriteVirtualMemory, etc.), not just process creation",
            "Add SIEM rule for behavioral indicators of direct syscall usage bypassing normal Win32 API wrappers",
        ],
    ),

    # ═══ PERSISTENCE (batch 5) ═══
    Technique(
        technique_id="T1546.008",
        name="Event Triggered Execution: Accessibility Features",
        tactic="Persistence",
        why_relevant="Attacker replaces an accessibility tool (Sticky Keys, Utility Manager) with cmd.exe, giving SYSTEM-level shell access from the Windows logon screen itself.",
        impact_if_blind="Anyone with physical/RDP access to the logon screen can trigger a SYSTEM shell without ever needing to log in.",
        requirements=[
            Requirement("Sysmon", "Registry value set (Event 13) / file replacement on accessibility binaries",
                        lambda c: get(c, "sysmon", "event_id_13_registry_set_value") is True),
            Requirement("SIEM", "Accessibility feature persistence alert",
                        lambda c: "accessibility_persistence_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon registry/file monitoring on accessibility tool binaries and their Image File Execution Options keys",
            "Add SIEM rule for any modification to sethc.exe/utilman.exe or their IFEO debugger registry values",
        ],
    ),

    # ═══ PRIVILEGE ESCALATION (batch 5) ═══
    Technique(
        technique_id="T1055.002",
        name="Process Injection: Portable Executable Injection",
        tactic="Privilege Escalation",
        why_relevant="Attacker injects a full malicious PE (executable) into another process's memory space — a step up in sophistication from simple shellcode injection.",
        impact_if_blind="A complete malicious program runs entirely inside a trusted process's memory, with no separate process ever appearing to investigate.",
        requirements=[
            Requirement("Sysmon", "Process access (Event 10)",
                        lambda c: get(c, "sysmon", "event_id_10_process_access") is True),
            Requirement("EDR", "Behavioral detection of injection APIs",
                        lambda c: get(c, "edr", "behavioral_detection") is True),
            Requirement("SIEM", "Process injection correlation alert",
                        lambda c: "process_injection_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon Event ID 10 with filters for cross-process memory writes",
            "Enable EDR memory-injection detection",
            "Add SIEM rule for processes with injected, unbacked executable memory regions",
        ],
    ),

    # ═══ DEFENSE EVASION (batch 5) ═══
    Technique(
        technique_id="T1553.004",
        name="Subvert Trust Controls: Install Root Certificate",
        tactic="Defense Evasion",
        why_relevant="Attacker installs a rogue root CA certificate so the OS/browser trusts attacker-signed malware and intercepted TLS traffic without warning.",
        impact_if_blind="Every future security warning about untrusted certificates is silently suppressed for this device, including for actively malicious sites/binaries.",
        requirements=[
            Requirement("EDR", "Code integrity / certificate validation checking",
                        lambda c: get(c, "edr", "code_integrity_check") is True),
            Requirement("SIEM", "Rogue root certificate installation alert",
                        lambda c: "rogue_cert_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable EDR monitoring of the Trusted Root Certification Authorities store",
            "Add SIEM rule for any new certificate added to the root store outside of managed deployment (GPO/Intune)",
        ],
    ),

    Technique(
        technique_id="T1036.005",
        name="Masquerading: Match Legitimate Name or Location",
        tactic="Defense Evasion",
        why_relevant="Attacker names their malware to match a legitimate Windows process (e.g. 'svch0st.exe' or placing it in a folder resembling System32) so it's overlooked during review.",
        impact_if_blind="A quick glance at Task Manager or a process list shows what looks like a normal Windows process, and it gets skipped over.",
        requirements=[
            Requirement("Sysmon", "Process creation (Event 1) with full path and hash metadata",
                        lambda c: get(c, "sysmon", "event_id_1_process_creation") is True),
            Requirement("SIEM", "Masquerading (path/name mismatch) alert",
                        lambda c: "masquerading_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon process creation logging (captures full path, not just process name)",
            "Add SIEM rule for known Windows process names running from non-standard file paths",
        ],
    ),

    # ═══ CREDENTIAL ACCESS (batch 5) ═══
    Technique(
        technique_id="T1552.004",
        name="Unsecured Credentials: Private Keys",
        tactic="Credential Access",
        why_relevant="Attacker searches for unprotected SSH/TLS private keys on disk, which grant direct access to servers or the ability to impersonate services.",
        impact_if_blind="Server access or code-signing capability is stolen directly, often granting far broader access than a single user's password would.",
        requirements=[
            Requirement("Sysmon", "File creation/access (Event 11) on key file locations",
                        lambda c: get(c, "sysmon", "event_id_11_file_create") is True),
            Requirement("SIEM", "Private key file access alert",
                        lambda c: "credential_file_access_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon file access logging on .ssh, .pem, .ppk, and certificate-store locations",
            "Add SIEM rule for unusual processes reading private key files",
            "Store private keys in a hardware security module or secrets manager where possible",
        ],
    ),

    Technique(
        technique_id="T1556.001",
        name="Modify Authentication Process: Domain Controller Authentication",
        tactic="Credential Access",
        why_relevant="Attacker installs a 'Skeleton Key' style patch on a domain controller, adding a master password that works for any account without changing anyone's real password.",
        impact_if_blind="Every account in the domain becomes accessible via one attacker-known password, invisibly, while all real passwords keep working normally too.",
        requirements=[
            Requirement("Sysmon", "Image load event (Event 7) on LSASS on domain controllers",
                        lambda c: get(c, "sysmon", "image_load_event") is True),
            Requirement("SIEM", "Skeleton Key / DC authentication tampering alert",
                        lambda c: "skeleton_key_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon image load logging on all domain controllers, focused on lsass.exe",
            "Add SIEM rule for unsigned/unexpected DLLs loading into lsass.exe on a DC",
            "Enable Credential Guard on domain controllers where supported",
        ],
    ),

    Technique(
        technique_id="T1111",
        name="Multi-Factor Authentication Interception",
        tactic="Credential Access",
        why_relevant="Attacker intercepts one-time codes or push approvals (e.g. via a fake login portal or SIM-swap) to bypass MFA entirely.",
        impact_if_blind="MFA — often treated as a silver bullet — is defeated, and the compromise looks identical to a fully legitimate, second-factor-verified logon.",
        requirements=[
            Requirement("EDR", "Behavioral detection of credential/token interception patterns",
                        lambda c: get(c, "edr", "behavioral_detection") is True),
            Requirement("SIEM", "MFA interception correlation alert",
                        lambda c: "mfa_interception_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable EDR behavioral detection covering credential-phishing proxy patterns",
            "Add SIEM rule for MFA approvals immediately following a login from a new/unusual device or location",
            "Move toward phishing-resistant MFA (FIDO2 security keys) for high-value accounts",
        ],
    ),

    # ═══ DISCOVERY (batch 5) ═══
    Technique(
        technique_id="T1482",
        name="Domain Trust Discovery",
        tactic="Discovery",
        why_relevant="Attacker maps trust relationships between domains/forests to find a path into a more valuable target domain via an already-compromised, weaker one.",
        impact_if_blind="Attacker identifies a path from a low-value domain into your crown-jewel domain, with the mapping step itself invisible.",
        requirements=[
            Requirement("Windows Event Log", "Process command line (nltest /domain_trusts)",
                        lambda c: get(c, "windows_event_logs", "process_command_line") is True),
            Requirement("SIEM", "Discovery tool detection",
                        lambda c: "discovery_tool_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable command-line auditing to catch nltest/Get-ADTrust enumeration",
            "Add SIEM rule for domain trust enumeration from non-administrative accounts",
        ],
    ),

    Technique(
        technique_id="T1135",
        name="Network Share Discovery",
        tactic="Discovery",
        why_relevant="Attacker enumerates available network shares to find data repositories worth collecting or additional lateral-movement paths.",
        impact_if_blind="Attacker finds your most valuable file shares to target next, with zero visibility into this reconnaissance step.",
        requirements=[
            Requirement("Windows Event Log", "Share access auditing",
                        lambda c: get(c, "windows_event_logs", "share_access_audit") is True),
            Requirement("SIEM", "Discovery tool detection",
                        lambda c: "discovery_tool_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable share access auditing across file servers",
            "Add SIEM rule for a single host enumerating many shares across the network in a short window",
        ],
    ),

    # ═══ LATERAL MOVEMENT (batch 5) ═══
    Technique(
        technique_id="T1021.003",
        name="Remote Services: Distributed Component Object Model",
        tactic="Lateral Movement",
        why_relevant="Attacker uses DCOM to execute code on a remote system — a lesser-known lateral movement path that many detection rules focused on WMI/PsExec/RDP miss entirely.",
        impact_if_blind="Attacker moves laterally through a mechanism most SOC playbooks don't specifically hunt for, since it's less common than WMI or admin shares.",
        requirements=[
            Requirement("Sysmon", "Process creation (Event 1) — DCOM-spawned processes",
                        lambda c: get(c, "sysmon", "event_id_1_process_creation") is True),
            Requirement("Windows Event Log", "Process command line",
                        lambda c: get(c, "windows_event_logs", "process_command_line") is True),
            Requirement("SIEM", "DCOM lateral movement alert",
                        lambda c: "dcom_lateral_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon and command-line logging to catch unusual parent processes for DCOM-launched applications (e.g. mmc.exe, excel.exe spawning cmd)",
            "Add SIEM rule for known DCOM lateral-movement application chains (MMC20.Application, ShellWindows)",
        ],
    ),

    # ═══ COLLECTION (batch 5) ═══
    Technique(
        technique_id="T1114.002",
        name="Email Collection: Remote Email Collection",
        tactic="Collection",
        why_relevant="Attacker uses stolen credentials to pull mailbox contents directly from the mail server/cloud service (e.g. via IMAP/Graph API), without ever touching the victim's endpoint.",
        impact_if_blind="Entire mailboxes are exfiltrated purely through server-side access, leaving no trace on the compromised endpoint at all.",
        requirements=[
            Requirement("Firewall", "Outbound connection logging",
                        lambda c: get(c, "firewall", "outbound_logging") is True),
            Requirement("SIEM", "Remote email collection alert",
                        lambda c: "email_collection_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable outbound logging for mail-protocol traffic (IMAP/EWS/Graph API)",
            "Add SIEM rule for mailbox access via legacy protocols (IMAP/POP) or from unusual client applications",
            "Disable legacy mail authentication protocols where MFA can't be enforced on them",
        ],
    ),

    Technique(
        technique_id="T1185",
        name="Browser Session Hijacking",
        tactic="Collection",
        why_relevant="Attacker steals active browser session cookies/tokens to access logged-in web services without ever needing the victim's password.",
        impact_if_blind="Attacker accesses SaaS applications the user is currently logged into, completely bypassing MFA (which already happened for that session).",
        requirements=[
            Requirement("EDR", "Behavioral detection of session/cookie theft",
                        lambda c: get(c, "edr", "behavioral_detection") is True),
            Requirement("SIEM", "Session/cookie hijacking alert",
                        lambda c: "session_hijack_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable EDR behavioral detection for browser cookie-store access by non-browser processes",
            "Add SIEM rule for the same session token used from two very different IP addresses/locations in a short time",
        ],
    ),

    # ═══ COMMAND AND CONTROL (batch 5) ═══
    Technique(
        technique_id="T1008",
        name="Fallback Channels",
        tactic="Command and Control",
        why_relevant="Malware keeps a secondary C2 channel ready to switch to automatically if the primary one is blocked, ensuring attacker access survives basic remediation.",
        impact_if_blind="Blocking the primary C2 domain gives a false sense of containment while the malware quietly switches to its backup channel.",
        requirements=[
            Requirement("Firewall", "Outbound connection logging",
                        lambda c: get(c, "firewall", "outbound_logging") is True),
            Requirement("SIEM", "Fallback channel switch alert",
                        lambda c: "fallback_channel_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable outbound firewall logging with enough retention to spot pattern changes after a block",
            "Add SIEM rule for a host immediately establishing a new type of outbound connection right after a previous one was blocked",
        ],
    ),

    # ═══ EXFILTRATION (batch 5) ═══
    Technique(
        technique_id="T1537",
        name="Transfer Data to Cloud Account",
        tactic="Exfiltration",
        why_relevant="Attacker moves stolen data into their own cloud storage/compute account (e.g. their own AWS S3 bucket) rather than downloading it directly — blends in as normal cloud-to-cloud traffic.",
        impact_if_blind="Data leaves via cloud-to-cloud transfer that never touches a traditional network egress point most monitoring is built around.",
        requirements=[
            Requirement("Firewall", "Outbound connection logging",
                        lambda c: get(c, "firewall", "outbound_logging") is True),
            Requirement("Firewall", "HTTPS inspection",
                        lambda c: get(c, "firewall", "https_inspection") is True),
            Requirement("SIEM", "Cloud-to-cloud data transfer alert",
                        lambda c: "cloud_account_transfer_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable outbound logging and HTTPS inspection for cloud storage/compute API traffic",
            "Add SIEM rule for large data transfers to cloud accounts not belonging to the organization's own tenant",
        ],
    ),

    # ═══ IMPACT (batch 5) ═══
    Technique(
        technique_id="T1491.001",
        name="Defacement: Internal Defacement",
        tactic="Impact",
        why_relevant="Attacker alters internal-facing content (intranet pages, internal dashboards) to send a message, cause confusion, or mask other ongoing activity.",
        impact_if_blind="Internal trust in company systems is damaged, and the defacement itself can serve as a distraction from other simultaneous attacker actions.",
        requirements=[
            Requirement("EDR", "Malware detection on internal web/content servers",
                        lambda c: get(c, "edr", "malware_detection") is True),
            Requirement("SIEM", "Internal defacement alert",
                        lambda c: "defacement_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Ensure EDR/file-integrity monitoring covers internal web/content servers",
            "Add SIEM rule for unexpected changes to internal-facing web content files",
        ],
    ),

    Technique(
        technique_id="T1657",
        name="Financial Theft",
        tactic="Impact",
        why_relevant="Attacker directly manipulates financial systems/processes (e.g. BEC-style wire fraud, invoice fraud) for direct monetary gain — a top-line risk for SMBs specifically.",
        impact_if_blind="Direct financial loss occurs through fraudulent transactions that look like normal business activity in accounting systems.",
        requirements=[
            Requirement("Email Security", "URL/attachment sandboxing (BEC-style phishing entry point)",
                        lambda c: get(c, "email_security", "url_sandboxing") is True),
            Requirement("EDR", "Behavioral detection on finance-system endpoints",
                        lambda c: get(c, "edr", "behavioral_detection") is True),
            Requirement("SIEM", "Financial fraud pattern alert",
                        lambda c: "financial_theft_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable email sandboxing specifically for finance-team mailboxes (common BEC target)",
            "Enable EDR behavioral monitoring on systems with access to banking/payment platforms",
            "Add SIEM rule for finance-system access patterns diverging from established norms",
            "Enforce out-of-band verification for any payment detail changes or new wire transfers",
        ],
    ),

    # ═══ PERSISTENCE (batch 6) ═══
    Technique(
        technique_id="T1098.001",
        name="Account Manipulation: Additional Cloud Credentials",
        tactic="Persistence",
        why_relevant="Attacker adds a second set of credentials (an app password, API key, or federated identity) to an already-compromised cloud account as a hidden backup access method.",
        impact_if_blind="Even after the original compromised password is reset, the attacker's hidden second credential keeps working.",
        requirements=[
            Requirement("Windows Event Log", "Process command line (identity/credential management commands)",
                        lambda c: get(c, "windows_event_logs", "process_command_line") is True),
            Requirement("SIEM", "Additional credential/account manipulation alert",
                        lambda c: "account_manipulation_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Ingest cloud identity provider audit logs (credential/app-password additions) into the SIEM",
            "Add SIEM rule for new API keys/app passwords added to an account shortly after a suspicious sign-in",
        ],
    ),

    Technique(
        technique_id="T1547.005",
        name="Boot or Logon Autostart Execution: Security Support Provider",
        tactic="Persistence",
        why_relevant="Attacker registers a malicious Security Support Provider (SSP) DLL that loads into LSASS at every boot — surviving reboots and often capturing credentials as a side effect.",
        impact_if_blind="A persistence mechanism embedded directly in the authentication subsystem re-launches at every boot, often doubling as a credential harvester.",
        requirements=[
            Requirement("Sysmon", "Registry value set (Event 13) on SSP registry keys",
                        lambda c: get(c, "sysmon", "event_id_13_registry_set_value") is True),
            Requirement("Sysmon", "Image load event (Event 7) on LSASS",
                        lambda c: get(c, "sysmon", "image_load_event") is True),
            Requirement("SIEM", "SSP persistence alert",
                        lambda c: "ssp_persistence_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon registry monitoring on the Security Packages / Security Support Provider registry values",
            "Enable Sysmon image load logging for LSASS",
            "Add SIEM rule for any new entry added to the Security Support Provider registry list",
        ],
    ),

    # ═══ DEFENSE EVASION (batch 6) ═══
    Technique(
        technique_id="T1564.003",
        name="Hide Artifacts: Hidden Window",
        tactic="Defense Evasion",
        why_relevant="Attacker launches PowerShell/scripts with a hidden window style so the process runs with no visible UI, even if the user is actively using the machine.",
        impact_if_blind="Malicious scripts execute in plain sight of the logged-in user, who sees nothing on screen to suggest anything is running.",
        requirements=[
            Requirement("Windows Event Log", "Process command line (-WindowStyle Hidden)",
                        lambda c: get(c, "windows_event_logs", "process_command_line") is True),
            Requirement("SIEM", "Hidden window execution alert",
                        lambda c: "hidden_window_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable command-line auditing to catch '-WindowStyle Hidden' / '-w hidden' flags",
            "Add SIEM rule for scripting engines launched with hidden-window arguments",
        ],
    ),

    Technique(
        technique_id="T1564.004",
        name="Hide Artifacts: NTFS File Attributes",
        tactic="Defense Evasion",
        why_relevant="Attacker hides payloads inside NTFS Alternate Data Streams, which don't show up in normal directory listings or most casual file reviews.",
        impact_if_blind="A malicious payload can sit attached to an innocent-looking file with zero visible size increase or separate file entry.",
        requirements=[
            Requirement("Sysmon", "File creation/stream hash event (Event 11/15)",
                        lambda c: get(c, "sysmon", "event_id_11_file_create") is True),
            Requirement("SIEM", "Alternate Data Stream creation alert",
                        lambda c: "ads_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable Sysmon file creation/stream-hash logging",
            "Add SIEM rule for executable content written into a file's alternate data stream",
        ],
    ),

    # ═══ CREDENTIAL ACCESS (batch 6) ═══
    Technique(
        technique_id="T1606.001",
        name="Forge Web Credentials: Web Cookies",
        tactic="Credential Access",
        why_relevant="Attacker forges a valid-looking session cookie (rather than stealing a real one) to impersonate an authenticated user without ever compromising their actual session.",
        impact_if_blind="Access is gained via a cookie that was never legitimately issued, bypassing normal authentication and session-monitoring entirely.",
        requirements=[
            Requirement("EDR", "Behavioral detection of cookie/token forgery patterns",
                        lambda c: get(c, "edr", "behavioral_detection") is True),
            Requirement("SIEM", "Forged web credential alert",
                        lambda c: "cookie_forgery_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable EDR/identity-provider behavioral detection for anomalous token signing patterns",
            "Add SIEM rule for session tokens with signing anomalies or unexpected issuer claims",
            "Rotate token-signing keys regularly and monitor for their compromise",
        ],
    ),

    Technique(
        technique_id="T1552.006",
        name="Unsecured Credentials: Group Policy Preferences",
        tactic="Credential Access",
        why_relevant="Attacker retrieves and decrypts passwords stored in old Group Policy Preferences XML files — a well-known, still-common misconfiguration years after Microsoft patched the underlying flaw.",
        impact_if_blind="A single overlooked legacy GPP file can hand over a plaintext, easily-decrypted password (often for a local admin account used domain-wide).",
        requirements=[
            Requirement("Windows Event Log", "AD/SYSVOL access auditing",
                        lambda c: get(c, "windows_event_logs", "ad_replication_audit") is True),
            Requirement("SIEM", "GPP password retrieval alert",
                        lambda c: "gpp_password_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable auditing on SYSVOL access, particularly for Groups.xml and similar GPP files",
            "Add SIEM rule for access to any Group Policy Preferences file containing a 'cpassword' attribute",
            "Remove all legacy GPP-stored passwords and rotate any accounts they exposed (MS14-025)",
        ],
    ),

    # ═══ LATERAL MOVEMENT (batch 6) ═══
    Technique(
        technique_id="T1021.005",
        name="Remote Services: VNC",
        tactic="Lateral Movement",
        why_relevant="Attacker uses VNC (often left running with a weak or no password on internal systems) to remotely control another machine.",
        impact_if_blind="A frequently-overlooked remote access protocol lets an attacker move between systems with graphical access, unlike more commonly-monitored RDP/SSH.",
        requirements=[
            Requirement("Firewall", "Outbound/internal connection logging",
                        lambda c: get(c, "firewall", "outbound_logging") is True),
            Requirement("SIEM", "VNC lateral movement alert",
                        lambda c: "vnc_lateral_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable logging on internal network segments carrying VNC traffic (typically port 5900+)",
            "Add SIEM rule for VNC connections between hosts that don't normally use it",
            "Remove or properly secure/authenticate any VNC servers found on the internal network",
        ],
    ),

    # ═══ COMMAND AND CONTROL (batch 6) ═══
    Technique(
        technique_id="T1104",
        name="Multi-Stage Channels",
        tactic="Command and Control",
        why_relevant="Malware uses a simple first-stage channel just to fetch a more capable second-stage C2 tool, keeping the initial footprint small and less suspicious.",
        impact_if_blind="A tiny, easy-to-miss first-stage connection quietly upgrades into a full-featured C2 implant, with the escalation itself unmonitored.",
        requirements=[
            Requirement("Firewall", "Outbound connection logging",
                        lambda c: get(c, "firewall", "outbound_logging") is True),
            Requirement("Sysmon", "Network connection (Event 3) + file creation (Event 11)",
                        lambda c: get(c, "sysmon", "event_id_3_network_connection") is True and
                                  get(c, "sysmon", "event_id_11_file_create") is True),
            Requirement("SIEM", "Multi-stage C2 escalation alert",
                        lambda c: "multistage_c2_alert" in (get(c, "siem", "correlation_rules") or [])),
        ],
        remediation=[
            "Enable outbound logging and Sysmon network+file correlation",
            "Add SIEM rule for a small initial connection immediately followed by a new, larger executable being downloaded and run",
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
