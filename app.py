#!/usr/bin/env python3
"""
Security Visibility Assessment Platform — Web Application
Complete Streamlit app with 5 pages
"""

import streamlit as st
import json
import re
import pandas as pd
from gap_engine import assess, calculate_coverage, KNOWLEDGE_BASE, search_techniques, REFERENCE_CATALOG
from config_parsers import parse_sysmon_xml, parse_windows_gpo_report, parse_defender_config_json, parse_windows_firewall_json
from pdf_export import generate_pdf_report
import io
from datetime import datetime

# Page config
st.set_page_config(
    page_title="xSOC — Visibility Gap Assessment",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 20px;
        border-radius: 10px;
        text-align: center;
        margin: 10px 0;
    }
    .metric-value {
        font-size: 48px;
        font-weight: bold;
    }
    .metric-label {
        font-size: 14px;
        opacity: 0.9;
    }
    .blind-spot {
        background-color: #ffe6e6;
        border-left: 4px solid #e63946;
    }
    .partial {
        background-color: #fff3cd;
        border-left: 4px solid #f4a261;
    }
    .covered {
        background-color: #e8f5e9;
        border-left: 4px solid #2ec4b6;
    }
    .xsoc-brand {
        font-size: 26px;
        font-weight: 800;
        letter-spacing: 0.5px;
        padding: 4px 0 0 0;
    }
    .xsoc-brand .x {
        color: #e63946;
    }
    .xsoc-tagline {
        font-size: 12px;
        opacity: 0.65;
        margin-bottom: 18px;
    }
    .tactic-header-row {
        display: flex;
        align-items: center;
        gap: 10px;
        flex-wrap: wrap;
    }
    .tactic-badge {
        display: inline-flex;
        align-items: center;
        gap: 4px;
        padding: 2px 9px;
        border-radius: 999px;
        font-size: 13px;
        font-weight: 600;
    }
    .badge-covered { background-color: #e8f5e9; color: #1b7a4d; }
    .badge-partial { background-color: #fff3cd; color: #a5690c; }
    .badge-blind   { background-color: #fdeaea; color: #c0392b; }
    .tactic-bar-container {
        background-color: rgba(128,128,128,0.2);
        border-radius: 6px;
        height: 9px;
        margin: 8px 0 18px 0;
        overflow: hidden;
        width: 100%;
    }
    .tactic-bar-fill {
        height: 100%;
        border-radius: 6px;
        width: 0%;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if "current_page" not in st.session_state:
    st.session_state.current_page = "onboarding"
if "config" not in st.session_state:
    st.session_state.config = None
if "results" not in st.session_state:
    st.session_state.results = None


def page_onboarding():
    """Page 1: Onboarding & Export Guides"""
    st.title("🚀 Getting Started")
    st.markdown("Learn how to export security tool configurations")

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("📋 Export Configuration")
        with st.expander("1️⃣ Sysmon", expanded=False):
            st.markdown("""
            **Location:** C:\\Program Files\\Sysmon\\sysmon.xml
            
            **Steps:**
            1. Open Command Prompt as Administrator
            2. Run: `sysmon -c`
            3. Copy the output XML file
            
            **Or use PowerShell:**
            ```powershell
            Get-Content "C:\\Program Files\\Sysmon\\sysmon.xml" | Out-File sysmon_config.xml
            ```
            """)

        with st.expander("2️⃣ Windows Event Log", expanded=False):
            st.markdown("""
            **Steps:**
            1. Open Group Policy Editor (gpedit.msc)
            2. Navigate to: Computer Configuration > Windows Settings > Security Settings > Audit Policy
            3. Export as GPO report
            
            **Or PowerShell:**
            ```powershell
            auditpol /get /category:* > audit_policy.txt
            ```
            """)

        with st.expander("3️⃣ Microsoft Defender", expanded=False):
            st.markdown("""
            **Steps:**
            1. Open Microsoft Defender Security Center
            2. Settings > Device management > Configuration export
            3. Download JSON configuration
            
            **Or PowerShell:**
            ```powershell
            Get-MpPreference | ConvertTo-Json | Out-File defender_config.json
            ```
            """)

        with st.expander("4️⃣ Firewall", expanded=False):
            st.markdown("""
            **Windows Defender Firewall:**
            ```powershell
            Get-NetFirewallProfile | ConvertTo-Json | Out-File firewall_config.json
            ```
            
            **3rd-party Firewalls (Palo Alto, Fortinet):**
            - Export configuration from admin console
            - Usually under: Device > Setup > Export Configuration
            """)

        with st.expander("5️⃣ SIEM Correlation Rules", expanded=False):
            st.markdown("""
            **Steps:**
            1. Open your SIEM console (Splunk, ELK, etc.)
            2. Export list of enabled correlation rules
            3. Save as JSON or CSV
            
            **Minimal Required:**
            - List of enabled alert rules
            - Log retention period
            - Ingested data sources
            """)

    with col2:
        st.subheader("📥 Sample Configuration")
        st.markdown("Download a sample configuration to fill in:")

        sample_config = {
            "windows_event_logs": {
                "powershell_script_block_logging": True,
                "registry_audit": False,
                "scheduled_task_creation": True,
                "ad_replication_audit": False,
                "process_command_line": False,
                "remote_logon_audit": True,
                "log_clear_audit": False,
                "file_audit": False,
            },
            "sysmon": {
                "installed": True,
                "event_id_10_process_access": True,
                "event_id_1_process_creation": True,
                "registry_set_value_event": False,
                "file_create_event": True,
                "image_load_event": False,
                "network_connection_event": True,
            },
            "edr": {
                "product": "Microsoft Defender for Endpoint",
                "lsass_protection": False,
                "tamper_protection": True,
                "real_time_protection": True,
                "network_protection": False,
                "code_integrity_check": False,
                "behavioral_detection": True,
                "malware_detection": True,
                "keyboard_input_monitoring": False,
            },
            "firewall": {
                "outbound_logging": True,
                "dns_logging": False,
                "https_inspection": False,
            },
            "siem": {
                "ingested_sources": ["windows_security", "sysmon"],
                "correlation_rules": [
                    "failed_login_burst",
                    "security_service_stopped",
                ],
                "log_retention_days": 30,
            },
            "email_security": {
                "url_sandboxing": False,
            },
        }

        st.download_button(
            label="📥 Download Sample Config (JSON)",
            data=json.dumps(sample_config, indent=2),
            file_name="sample_config.json",
            mime="application/json"
        )

        st.info("👉 Click 'Next' when you're ready to upload your configuration")

    col1, col2, col3 = st.columns([1, 1, 1])
    with col3:
        if st.button("➡️ Next: Upload Configuration", key="onboarding_next"):
            st.session_state.current_page = "upload"
            st.rerun()


def page_upload():
    """Page 2: Config Upload & Validation"""
    st.title("📤 Upload Security Configuration")

    st.markdown("Upload your exported configuration or paste JSON directly")

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Option 1: Upload JSON File")
        uploaded_file = st.file_uploader("Choose a JSON file", type="json")

        if uploaded_file:
            try:
                st.session_state.config = json.load(uploaded_file)
                st.success("✅ Configuration loaded successfully")
            except json.JSONDecodeError:
                st.error("❌ Invalid JSON file")

    with col2:
        st.subheader("Option 2: Parse Tool Export")
        st.caption("Upload the file exported from each tool (see Getting Started for the export command)")

        tab_sysmon, tab_gpo, tab_defender, tab_fw = st.tabs(["Sysmon", "Windows Event Log", "Defender", "Firewall"])

        def _merge_parsed(parsed_config):
            if st.session_state.config is None:
                st.session_state.config = {}
            st.session_state.config.update(parsed_config)

        with tab_sysmon:
            sysmon_file = st.file_uploader("sysmon_config.xml", type="xml", key="sysmon_uploader")
            if sysmon_file:
                try:
                    _merge_parsed(parse_sysmon_xml(sysmon_file))
                    st.success("✅ Sysmon configuration parsed")
                except Exception as e:
                    st.error(f"❌ Error parsing Sysmon XML: {e}")

        with tab_gpo:
            gpo_file = st.file_uploader("audit_policy.txt", type=["txt", "json"], key="gpo_uploader")
            if gpo_file:
                try:
                    _merge_parsed(parse_windows_gpo_report(gpo_file))
                    st.success("✅ Windows Event Log audit policy parsed")
                except Exception as e:
                    st.error(f"❌ Error parsing audit policy: {e}")

        with tab_defender:
            defender_file = st.file_uploader("defender_config.json", type="json", key="defender_uploader")
            if defender_file:
                try:
                    _merge_parsed(parse_defender_config_json(defender_file))
                    st.success("✅ Defender configuration parsed")
                except Exception as e:
                    st.error(f"❌ Error parsing Defender config: {e}")

        with tab_fw:
            fw_file = st.file_uploader("firewall_config.json", type="json", key="fw_uploader")
            if fw_file:
                try:
                    _merge_parsed(parse_windows_firewall_json(fw_file))
                    st.success("✅ Firewall configuration parsed")
                    st.caption("ℹ️ DNS logging & HTTPS inspection aren't in this export — set them via Option 4 or Option 3 if applicable.")
                except Exception as e:
                    st.error(f"❌ Error parsing firewall config: {e}")

    st.markdown("---")

    # Or paste JSON
    st.subheader("Option 3: Paste JSON Directly")
    json_text = st.text_area("Paste your JSON configuration here:", height=200)

    if json_text:
        try:
            pasted_config = json.loads(json_text)
            if st.button("Load pasted JSON"):
                st.session_state.config = pasted_config
                st.success("✅ Configuration loaded from text")
        except json.JSONDecodeError:
            st.error("❌ Invalid JSON format")

    st.markdown("---")

    # SIEM manual checklist — there's no universal export format across
    # Splunk/ELK/Sentinel/QRadar, so instead of guessing at a parser that
    # will only work for one vendor, we ask directly what's enabled.
    st.subheader("Option 4: SIEM Correlation Rules (checklist)")
    st.caption("No single export format works across SIEM vendors — tick what's actually enabled in yours.")

    SIEM_RULES = [
        "accessibility_persistence_alert", "account_creation_alert", "account_lockout_alert",
        "account_manipulation_alert", "admin_share_alert", "ads_alert",
        "anomalous_logon_alert", "archive_utility_alert", "audio_capture_alert",
        "auth_process_modification_alert", "automated_collection_alert", "automated_exfil_alert",
        "browser_credential_theft_alert", "c2_domain_alert", "cached_creds_alert",
        "chunked_exfil_alert", "client_exploit_alert", "clipboard_capture_alert",
        "cloud_account_alert", "cloud_account_transfer_alert", "cloud_exfil_alert",
        "cmd_suspicious_alert", "code_repo_exfil_alert", "cookie_forgery_alert",
        "credential_exploit_alert", "credential_file_access_alert", "data_destruction_alert",
        "data_manipulation_alert", "data_staging_alert", "dcom_lateral_alert",
        "dcshadow_alert", "dcsync_alert", "defacement_alert",
        "default_account_logon_alert", "deobfuscation_alert", "deployment_tool_abuse_alert",
        "discovery_tool_alert", "disk_wipe_alert", "dll_hijack_alert",
        "dns_anomaly_alert", "dos_alert", "drive_by_alert",
        "email_collection_alert", "encoded_c2_alert", "encrypted_c2_alert",
        "endpoint_dos_alert", "exfil_volume_alert", "exploit_attempt_alert",
        "external_remote_access_alert", "fallback_channel_alert", "financial_theft_alert",
        "forced_auth_alert", "gpo_modification_alert", "gpp_password_alert",
        "hidden_file_alert", "hidden_window_alert", "internal_phishing_alert",
        "invalid_signature_alert", "kerberoast_alert", "lateral_tool_transfer_alert",
        "log_clear_alert", "logon_script_persistence_alert", "lolbin_abuse_alert",
        "lsa_secrets_alert", "lsass_access_alert", "malicious_extension_alert",
        "malicious_file_execution_alert", "masquerading_alert", "mass_file_access_alert",
        "mfa_fatigue_alert", "mfa_interception_alert", "multistage_c2_alert",
        "native_api_abuse_alert", "new_service_alert", "nonstandard_port_alert",
        "nonstandard_protocol_alert", "ntds_dump_alert", "obfuscated_payload_alert",
        "pass_the_hash_alert", "permission_modification_alert", "phishing_link_alert",
        "port_scan_alert", "powershell_suspicious_alert", "process_hollowing_alert",
        "process_injection_alert", "proxy_c2_alert", "python_execution_alert",
        "ransomware_alert", "rdp_alert", "rdp_hijack_alert",
        "reflective_load_alert", "registry_modification_alert", "remote_access_tool_alert",
        "remote_exploit_alert", "removable_media_alert", "resource_hijack_alert",
        "rogue_cert_alert", "sam_access_alert", "sandbox_evasion_alert",
        "scheduled_exfil_alert", "screen_capture_alert", "security_software_discovery_alert",
        "service_stop_alert", "session_hijack_alert", "shadow_copy_deletion_alert",
        "shared_module_alert", "shortcut_persistence_alert", "sid_history_alert",
        "skeleton_key_alert", "ssh_lateral_alert", "ssp_persistence_alert",
        "supply_chain_alert", "tainted_content_alert", "task_creation_alert",
        "token_theft_alert", "tool_transfer_alert", "traffic_signaling_alert",
        "trusted_relationship_alert", "tunneling_alert", "uac_bypass_alert",
        "unexpected_shutdown_alert", "vbs_execution_alert", "video_capture_alert",
        "vnc_lateral_alert", "webservice_c2_alert", "webshell_alert",
        "winlogon_persistence_alert", "wmi_execution_alert", "wmi_persistence_alert",
    ]
    SIEM_SOURCES = ["windows_security", "sysmon", "defender_alerts", "firewall", "dns", "proxy"]

    with st.expander("Fill in SIEM configuration", expanded=False):
        selected_rules = st.multiselect("Enabled correlation rules", SIEM_RULES, key="siem_rules")
        selected_sources = st.multiselect("Ingested log sources", SIEM_SOURCES, key="siem_sources")
        retention_days = st.number_input("Log retention (days)", min_value=0, value=30, key="siem_retention")

        if st.button("Apply SIEM configuration"):
            _merge_parsed({
                "siem": {
                    "ingested_sources": selected_sources,
                    "correlation_rules": selected_rules,
                    "log_retention_days": retention_days,
                }
            })
            st.success("✅ SIEM configuration applied")

    # Config summary
    if st.session_state.config:
        st.markdown("---")
        st.subheader("📊 Configuration Summary")

        col1, col2, col3, col4, col5 = st.columns(5)

        tools = {
            "windows_event_logs": "Windows Event Log",
            "sysmon": "Sysmon",
            "edr": "EDR",
            "firewall": "Firewall",
            "siem": "SIEM",
        }

        for tool_key, tool_name in tools.items():
            with st.columns(5)[list(tools.keys()).index(tool_key)]:
                if tool_key in st.session_state.config:
                    st.metric(tool_name, "✓", "Connected")
                else:
                    st.metric(tool_name, "✗", "Not found")

        st.markdown("---")
        col1, col2, col3 = st.columns([1, 1, 1])

        with col1:
            if st.button("⬅️ Back", key="upload_back"):
                st.session_state.current_page = "onboarding"
                st.rerun()

        with col3:
            if st.session_state.config and st.button("➡️ Analyze", key="upload_next"):
                st.session_state.results = assess(st.session_state.config)
                st.session_state.current_page = "dashboard"
                st.rerun()


def page_dashboard():
    """Page 3: Main Dashboard with Results"""
    st.title("📊 Security Visibility Dashboard")

    if st.session_state.results is None:
        st.error("No assessment results. Please upload a configuration first.")
        return

    results = st.session_state.results
    coverage = calculate_coverage(results)

    # Coverage metric
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Overall Coverage", f"{coverage:.0f}%", 
                  delta=None if coverage == 100 else f"{100 - coverage:.0f}% gap")

    covered = sum(1 for r in results if r["status"] == "COVERED")
    partial = sum(1 for r in results if r["status"] == "PARTIAL VISIBILITY")
    blind = sum(1 for r in results if r["status"] == "BLIND SPOT")

    with col2:
        st.metric("Covered", covered, delta_color="off")
    with col3:
        st.metric("Partial", partial, delta_color="off")
    with col4:
        st.metric("Blind Spots", blind, delta_color="inverse")

    st.markdown("---")

    # Tabs
    tab1, tab2, tab3, tab4 = st.tabs([
        f"📋 All Techniques ({len(results)})",
        f"❌ Blind Spots ({blind})",
        f"⚠️ Partial ({partial})",
        f"✅ Covered ({covered})"
    ])

    with tab1:
        st.subheader("All Techniques Assessed — by Tactic")

        TACTIC_ORDER = [
            "Initial Access", "Execution", "Persistence", "Privilege Escalation",
            "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
            "Collection", "Command and Control", "Exfiltration", "Impact",
        ]

        by_tactic = {}
        for r in results:
            by_tactic.setdefault(r["tactic"], []).append(r)

        ordered_tactics = [t for t in TACTIC_ORDER if t in by_tactic]
        ordered_tactics += sorted(t for t in by_tactic if t not in TACTIC_ORDER)

        status_icon = {
            "COVERED": "✅",
            "PARTIAL VISIBILITY": "⚠️",
            "BLIND SPOT": "❌",
        }

        for tactic in ordered_tactics:
            items = by_tactic[tactic]
            t_covered = sum(1 for r in items if r["status"] == "COVERED")
            t_partial = sum(1 for r in items if r["status"] == "PARTIAL VISIBILITY")
            t_blind = sum(1 for r in items if r["status"] == "BLIND SPOT")
            t_total = len(items)
            t_pct = round((t_covered + 0.5 * t_partial) / t_total * 100) if t_total else 0

            bar_color = "#2ec4b6" if t_pct >= 75 else ("#f4a261" if t_pct >= 40 else "#e63946")
            slug = re.sub(r"[^a-z0-9]+", "_", tactic.lower())

            label = f"{tactic}  ·  {t_total} techniques  —  ✅ {t_covered}  ⚠️ {t_partial}  ❌ {t_blind}"

            with st.expander(label, expanded=False):
                st.markdown(
                    f"""
                    <style>
                    @keyframes grow_{slug} {{ from {{ width: 0%; }} to {{ width: {t_pct}%; }} }}
                    </style>
                    <div class="tactic-bar-container">
                        <div class="tactic-bar-fill" style="width:{t_pct}%; background-color:{bar_color};
                             animation: grow_{slug} 0.9s ease-out;"></div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                for r in items:
                    col1, col2, col3 = st.columns([1, 4, 1])
                    with col1:
                        st.write(status_icon[r["status"]])
                    with col2:
                        if st.button(f"**{r['technique_id']}** — {r['name']}", key=f"all_{r['technique_id']}"):
                            st.session_state.current_page = "detail"
                            st.session_state.selected_technique = r
                            st.rerun()
                    with col3:
                        st.caption(r["status"].title())

    with tab2:
        st.subheader("Blind Spots — Immediate Action Required")
        for r in results:
            if r["status"] == "BLIND SPOT":
                with st.container():
                    st.markdown(f"<div class='blind-spot'>", unsafe_allow_html=True)
                    col1, col2 = st.columns([3, 1])
                    with col1:
                        st.markdown(f"**{r['technique_id']}** — {r['name']}")
                        st.markdown(f"*{r['why'][:100]}...*")
                    with col2:
                        if st.button("Details", key=f"blind_{r['technique_id']}"):
                            st.session_state.current_page = "detail"
                            st.session_state.selected_technique = r
                            st.rerun()
                    st.markdown("</div>", unsafe_allow_html=True)

    with tab3:
        st.subheader("Partial Visibility — Add Alert Rules")
        for r in results:
            if r["status"] == "PARTIAL VISIBILITY":
                with st.container():
                    st.markdown(f"<div class='partial'>", unsafe_allow_html=True)
                    col1, col2 = st.columns([3, 1])
                    with col1:
                        st.markdown(f"**{r['technique_id']}** — {r['name']}")
                        if r["quality_gaps"]:
                            st.markdown(f"*Issue: {r['quality_gaps'][0]}*")
                    with col2:
                        if st.button("Fix", key=f"partial_{r['technique_id']}"):
                            st.session_state.current_page = "detail"
                            st.session_state.selected_technique = r
                            st.rerun()
                    st.markdown("</div>", unsafe_allow_html=True)

    with tab4:
        st.subheader("Covered Techniques ✅")
        for r in results:
            if r["status"] == "COVERED":
                with st.container():
                    st.markdown(f"<div class='covered'>", unsafe_allow_html=True)
                    col1, col2 = st.columns([3, 1])
                    with col1:
                        st.markdown(f"**{r['technique_id']}** — {r['name']}")
                    with col2:
                        st.write("✅ All good")
                    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("---")

    col1, col2, col3 = st.columns([1, 1, 1])

    with col1:
        if st.button("⬅️ Upload Another Config", key="dashboard_back"):
            st.session_state.current_page = "upload"
            st.session_state.config = None
            st.session_state.results = None
            st.rerun()

    with col2:
        if st.button("🔍 Search Technique", key="dashboard_search"):
            st.session_state.current_page = "search"
            st.rerun()

    with col3:
        pdf_bytes = generate_pdf_report(st.session_state.results, coverage)
        st.download_button(
            label="📥 Download PDF Report",
            data=pdf_bytes,
            file_name=f"security_visibility_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
            mime="application/pdf"
        )


def page_search():
    """Page 4: Search and Test Technique"""
    st.title("🔍 Search Technique")
    st.caption(f"Searching {len(KNOWLEDGE_BASE)} fully-assessed + {len(REFERENCE_CATALOG)} reference techniques ({len(KNOWLEDGE_BASE) + len(REFERENCE_CATALOG)} total, MITRE ATT&CK Enterprise)")

    if st.session_state.results is None:
        st.error("No assessment loaded. Please upload a configuration first.")
        return

    # Search box — now searches the FULL catalog (assessed + reference), not just the 20 assessed ones
    search_term = st.text_input("Search by technique ID or name (e.g., 'T1003', 'PowerShell', 'LSASS')")

    if search_term:
        matches = search_techniques(search_term)
        assessed_ids = {m["technique_id"] for m in matches if m["assessed"]}
        matching = [r for r in st.session_state.results if r["technique_id"] in assessed_ids]
        reference_matches = [m for m in matches if not m["assessed"]]

        if matching or reference_matches:
            if matching:
                st.subheader("Matching Techniques — Assessed")
            options = matching + [
                {**next(t for t in REFERENCE_CATALOG if t["technique_id"] == m["technique_id"])}
                for m in reference_matches
            ]
            selected = st.selectbox(
                "Select a technique",
                options=options,
                format_func=lambda x: f"{x['technique_id']} — {x['name']}" + ("" if x.get("status") else "  (reference only — no custom detection logic yet)")
            )

            if selected and "status" not in selected:
                # Reference-only technique: no custom check logic built yet
                st.markdown("---")
                st.subheader(f"{selected['technique_id']} — {selected['name']}")
                st.info("🔎 **Coverage Unknown** — this technique is in the MITRE ATT&CK catalog, but xSOC hasn't built custom detection-mapping logic for it against your tools yet. This is *not* the same as a Blind Spot.")

                col1, col2 = st.columns(2)
                with col1:
                    st.metric("Status", "⚪ Coverage Unknown")
                with col2:
                    st.metric("Tactic", selected["tactic"])

                st.markdown("**Description (MITRE ATT&CK):**")
                st.write(selected["description"])

                if selected.get("detection_summary"):
                    st.markdown("**MITRE detection guidance:**")
                    st.write(selected["detection_summary"])

                if selected.get("log_sources"):
                    st.markdown("**Relevant log sources:**")
                    for ls in selected["log_sources"]:
                        st.write(f"- {ls}")

                if st.button("⬅️ Back to Dashboard", key="search_back_ref"):
                    st.session_state.current_page = "dashboard"
                    st.rerun()
                return

            if selected:
                st.markdown("---")
                st.subheader(f"{selected['technique_id']} — {selected['name']}")

                col1, col2, col3 = st.columns(3)
                with col1:
                    status_color = {
                        "COVERED": "🟢",
                        "PARTIAL VISIBILITY": "🟡",
                        "BLIND SPOT": "🔴"
                    }[selected["status"]]
                    st.metric("Status", status_color + " " + selected["status"])

                with col2:
                    st.metric("Tactic", selected["tactic"])

                with col3:
                    if selected["satisfied_requirements"]:
                        st.metric("Coverage", f"{len(selected['satisfied_requirements'])} tools")
                    else:
                        st.metric("Coverage", "0/0")

                st.markdown("---")

                st.markdown("**Why it matters:**")
                st.write(selected["why"])

                if selected["impact"]:
                    st.markdown("**Impact if blind:**")
                    st.warning(selected["impact"])

                if selected["quality_gaps"]:
                    st.markdown("**Quality gaps:**")
                    for gap in selected["quality_gaps"]:
                        st.warning(f"⚠️ {gap}")

                st.markdown("**Remediation steps:**")
                for i, step in enumerate(selected["remediation"], 1):
                    st.markdown(f"{i}. {step}")

                st.markdown("**Currently satisfied by:**")
                for req in selected["satisfied_requirements"]:
                    st.info(f"✓ {req}")

                col1, col2 = st.columns([1, 1])
                with col1:
                    if st.button("⬅️ Back to Dashboard", key="search_back"):
                        st.session_state.current_page = "dashboard"
                        st.rerun()

                with col2:
                    pdf_bytes = generate_pdf_report(
                        [selected],
                        100 if selected["status"] == "COVERED" else 50 if selected["status"] == "PARTIAL VISIBILITY" else 0
                    )
                    st.download_button(
                        label="📥 Download Technique Report",
                        data=pdf_bytes,
                        file_name=f"{selected['technique_id']}_report.pdf",
                        mime="application/pdf"
                    )

        else:
            st.warning("No matching techniques found")

    else:
        col1, col2 = st.columns([1, 1])
        with col1:
            if st.button("⬅️ Back to Dashboard", key="search_back_empty"):
                st.session_state.current_page = "dashboard"
                st.rerun()


def page_detail():
    """Page 5: Detailed Technique Report"""
    st.title("📋 Technique Detail Report")

    if not hasattr(st.session_state, "selected_technique"):
        st.error("No technique selected")
        return

    r = st.session_state.selected_technique

    # Header
    col1, col2, col3 = st.columns([2, 1, 1])
    with col1:
        st.markdown(f"## {r['technique_id']} — {r['name']}")
    with col2:
        status_badge = {
            "COVERED": "✅ COVERED",
            "PARTIAL VISIBILITY": "⚠️ PARTIAL",
            "BLIND SPOT": "❌ BLIND"
        }[r["status"]]
        st.markdown(f"### {status_badge}")
    with col3:
        st.markdown(f"### {r['tactic']}")

    st.markdown("---")

    # Details
    col1, col2 = st.columns([1, 1])

    with col1:
        st.markdown("**Why it matters:**")
        st.write(r["why"])

    with col2:
        if r["impact"]:
            st.markdown("**Detection impact if blind:**")
            st.warning(r["impact"])

    st.markdown("---")

    # Remediation
    st.markdown("## 🔧 Remediation Steps")
    for i, step in enumerate(r["remediation"], 1):
        st.markdown(f"**{i}. {step}**")

    st.markdown("---")

    # Requirements
    st.markdown("## Requirements")
    if r["satisfied_requirements"]:
        st.success("Currently satisfied by:")
        for req in r["satisfied_requirements"]:
            st.write(f"✓ {req}")
    else:
        st.error("No requirements satisfied — this is a BLIND SPOT")

    if r["quality_gaps"]:
        st.warning("Quality gaps detected:")
        for gap in r["quality_gaps"]:
            st.write(f"⚠️ {gap}")

    st.markdown("---")

    # Navigation
    col1, col2, col3 = st.columns([1, 1, 1])

    with col1:
        if st.button("⬅️ Back", key="detail_back"):
            st.session_state.current_page = "dashboard"
            st.rerun()

    with col3:
        pdf_bytes = generate_pdf_report(
            [r],
            100 if r["status"] == "COVERED" else 50 if r["status"] == "PARTIAL VISIBILITY" else 0
        )
        st.download_button(
            label="📥 Download PDF",
            data=pdf_bytes,
            file_name=f"{r['technique_id']}_report.pdf",
            mime="application/pdf"
        )


def render_sidebar():
    """Persistent sidebar: brand + one-click navigation between pages"""
    with st.sidebar:
        st.markdown(
            '<div class="xsoc-brand">'
            '<span class="x">x</span>SOC</div>'
            '<div class="xsoc-tagline">Security Visibility Gap Assessment</div>',
            unsafe_allow_html=True
        )
        st.markdown("---")

        has_results = st.session_state.results is not None
        nav_items = [
            ("onboarding", "🏠", "Getting Started", True),
            ("upload", "📤", "Upload Config", True),
            ("dashboard", "📊", "Dashboard", has_results),
            ("search", "🔍", "Search Technique", has_results),
        ]

        for page_key, icon, label, enabled in nav_items:
            is_current = st.session_state.current_page == page_key
            if st.button(
                f"{icon}  {label}",
                key=f"nav_{page_key}",
                use_container_width=True,
                disabled=not enabled,
                type="primary" if is_current else "secondary",
            ):
                st.session_state.current_page = page_key
                st.rerun()

        if not has_results:
            st.caption("Upload a configuration to unlock Dashboard & Search.")

        st.markdown("---")
        st.caption(f"MITRE ATT&CK coverage: {len(KNOWLEDGE_BASE)} assessed · {len(REFERENCE_CATALOG)} reference")


# Main app
def main():
    render_sidebar()

    pages = {
        "onboarding": page_onboarding,
        "upload": page_upload,
        "dashboard": page_dashboard,
        "search": page_search,
        "detail": page_detail,
    }

    page_func = pages.get(st.session_state.current_page, page_onboarding)
    page_func()


if __name__ == "__main__":
    main()
