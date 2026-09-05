#!/usr/bin/env python3
"""
Configuration Parsers for various security tools

Supports:
- Sysmon XML configuration
- Windows GPO audit policy reports
"""

import xml.etree.ElementTree as ET
import json
from typing import Dict, Any


def parse_sysmon_xml(xml_file) -> Dict[str, Any]:
    """
    Parse Sysmon configuration XML file.
    Extracts which event IDs are enabled.
    
    Args:
        xml_file: File object or path to Sysmon config XML
    
    Returns:
        Dict with sysmon configuration
    """
    try:
        if isinstance(xml_file, str):
            tree = ET.parse(xml_file)
        else:
            # Handle uploaded file
            content = xml_file.read()
            if isinstance(content, bytes):
                content = content.decode('utf-8')
            tree = ET.ElementTree(ET.fromstring(content))

        root = tree.getroot()

        # Parse EventFiltering section
        config = {
            "sysmon": {
                "installed": True,
                "event_id_1_process_creation": False,
                "event_id_3_network_connection": False,
                "event_id_10_process_access": False,
                "event_id_11_file_create": False,
                "event_id_13_registry_set_value": False,
                "image_load_event": False,
                "network_connection_event": False,
                "registry_set_value_event": False,
                "file_create_event": False,
            }
        }

        # Find all Rule elements
        for rule in root.findall(".//Rule"):
            name = rule.get('name', '')
            enabled = rule.get('enabled', 'true').lower() == 'true'

            if not enabled:
                continue

            # Map rule names to event IDs
            if 'ProcessCreate' in name or name == 'Process creation':
                config["sysmon"]["event_id_1_process_creation"] = True
                config["sysmon"]["process_creation_event"] = True

            elif 'NetworkConnect' in name or name == 'Network connection':
                config["sysmon"]["event_id_3_network_connection"] = True
                config["sysmon"]["network_connection_event"] = True

            elif 'ProcessAccess' in name or name == 'Process access':
                config["sysmon"]["event_id_10_process_access"] = True

            elif 'FileCreate' in name or name == 'File created':
                config["sysmon"]["event_id_11_file_create"] = True
                config["sysmon"]["file_create_event"] = True

            elif 'RegistrySet' in name or name == 'Registry object added or deleted':
                config["sysmon"]["event_id_13_registry_set_value"] = True
                config["sysmon"]["registry_set_value_event"] = True

            elif 'ImageLoad' in name or name == 'Image loaded':
                config["sysmon"]["image_load_event"] = True

        return config

    except Exception as e:
        print(f"Error parsing Sysmon XML: {e}")
        return {"sysmon": {"installed": False}}


def parse_windows_gpo_report(report_file) -> Dict[str, Any]:
    """
    Parse Windows GPO audit policy report.
    Looks for enabled audit categories.
    
    Args:
        report_file: GPO report file (text or JSON)
    
    Returns:
        Dict with Windows Event Log configuration
    """
    try:
        config = {
            "windows_event_logs": {
                "powershell_script_block_logging": False,
                "powershell_module_logging": False,
                "registry_audit": False,
                "scheduled_task_creation": False,
                "ad_replication_audit": False,
                "process_command_line": False,
                "remote_logon_audit": False,
                "log_clear_audit": False,
                "file_audit": False,
                "share_access_audit": False,
            }
        }

        if isinstance(report_file, str):
            with open(report_file, 'r') as f:
                content = f.read()
        else:
            content = report_file.read().decode('utf-8')

        # Look for audit policy settings
        if 'Script Block Logging' in content or '4104' in content:
            config["windows_event_logs"]["powershell_script_block_logging"] = True

        if 'Module Logging' in content or '4103' in content:
            config["windows_event_logs"]["powershell_module_logging"] = True

        if 'Registry' in content or 'Object Access' in content or '4663' in content:
            config["windows_event_logs"]["registry_audit"] = True

        if 'Scheduled Task' in content or '4698' in content:
            config["windows_event_logs"]["scheduled_task_creation"] = True

        if 'Directory Services' in content or '4662' in content:
            config["windows_event_logs"]["ad_replication_audit"] = True

        if 'Process Creation' in content or '4688' in content:
            config["windows_event_logs"]["process_command_line"] = True

        if 'Logon' in content or '4624' in content:
            config["windows_event_logs"]["remote_logon_audit"] = True

        if 'Clear Log' in content or '104' in content:
            config["windows_event_logs"]["log_clear_audit"] = True

        if 'File' in content or 'File and Object Access' in content:
            config["windows_event_logs"]["file_audit"] = True

        if 'Network Share' in content or '5140' in content:
            config["windows_event_logs"]["share_access_audit"] = True

        return config

    except Exception as e:
        print(f"Error parsing GPO report: {e}")
        return {
            "windows_event_logs": {
                "powershell_script_block_logging": False,
            }
        }


def parse_defender_config_json(defender_file) -> Dict[str, Any]:
    """Parse Microsoft Defender configuration JSON (Get-MpPreference | ConvertTo-Json)."""
    try:
        if isinstance(defender_file, str):
            with open(defender_file, 'r') as f:
                data = json.load(f)
        else:
            content = defender_file.read()
            if isinstance(content, bytes):
                content = content.decode('utf-8')
            data = json.loads(content)

        config = {
            "edr": {
                "product": "Microsoft Defender for Endpoint",
                "lsass_protection": data.get("MpPreference", {}).get("LsassMrTraceLevel") == 2,
                "tamper_protection": data.get("MpPreference", {}).get("TamperProtectionSource", 0) > 0,
                "real_time_protection": data.get("MpPreference", {}).get("DisableRealtimeMonitoring") is False,
                "network_protection": data.get("MpPreference", {}).get("NetworkProtectionAction", 0) > 0,
                "code_integrity_check": False,
                "behavioral_detection": True,
                "malware_detection": True,
                "keyboard_input_monitoring": False,
            }
        }

        return config

    except Exception as e:
        print(f"Error parsing Defender config: {e}")
        return {"edr": {"product": "Unknown"}}


def parse_windows_firewall_json(firewall_file) -> Dict[str, Any]:
    """
    Parse Windows Defender Firewall profile export.
    Expected input: output of
        Get-NetFirewallProfile -All | ConvertTo-Json
    (as instructed on the Getting Started page).

    Note: DNS query logging and HTTPS/TLS inspection are not exposed by
    Get-NetFirewallProfile — Windows Firewall itself doesn't perform DNS
    or TLS inspection, those live in a separate DNS server or proxy/NGFW
    config. We leave those two fields False here; fill them in manually
    (Option 3: Paste JSON) if your environment has a DNS server query log
    or a proxy doing HTTPS inspection.

    Args:
        firewall_file: JSON file/string — either a single profile object
            or a list of profile objects (Domain/Private/Public)

    Returns:
        Dict with firewall configuration
    """
    try:
        if isinstance(firewall_file, str):
            with open(firewall_file, 'r') as f:
                data = json.load(f)
        else:
            content = firewall_file.read()
            if isinstance(content, bytes):
                content = content.decode('utf-8')
            data = json.loads(content)

        profiles = data if isinstance(data, list) else [data]

        def _is_logging(profile: Dict[str, Any]) -> bool:
            val = profile.get("LogAllowed", profile.get("LogBlocked"))
            return str(val).strip().lower() in ("true", "1", "yes")

        outbound_logging = any(_is_logging(p) for p in profiles)

        config = {
            "firewall": {
                "outbound_logging": outbound_logging,
                "dns_logging": False,       # not visible in this export — check DNS server logs separately
                "https_inspection": False,  # not visible in this export — check proxy/NGFW config separately
            }
        }

        return config

    except Exception as e:
        print(f"Error parsing Windows Firewall config: {e}")
        return {"firewall": {"outbound_logging": False, "dns_logging": False, "https_inspection": False}}


def merge_configs(*configs: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge multiple configuration dictionaries.
    
    Args:
        *configs: Variable number of config dicts
    
    Returns:
        Merged configuration
    """
    merged = {}
    for config in configs:
        for key, value in config.items():
            if key not in merged:
                merged[key] = {}
            merged[key].update(value)
    return merged
