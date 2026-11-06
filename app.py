import streamlit as st
import pandas as pd
import plotly.express as px
import os
import re
import json
import tempfile
import subprocess

from core.database import (
    init_db, save_scan_and_findings, get_all_scans,
    get_findings_by_scan, get_all_findings, update_finding_status,
    get_custom_rules, insert_custom_rule,
    get_rule_states, set_rule_state, clear_all_data
)
from core.engine import SecretDetectionEngine
from core.entropy import calculate_shannon_entropy
from core.scanners import (
    scan_text_buffer, scan_safe_zip, scan_local_directory, scan_git_history
)
from core.reporting import (
    generate_json_report, generate_csv_report, generate_html_report
)

st.set_page_config(
    page_title="LeakShield | Cross-Platform Data Leak Detection",
    page_icon="\U0001f6e1\ufe0f",
    layout="wide",
    initial_sidebar_state="expanded"
)

init_db()

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');

    .stApp {
        background: radial-gradient(circle at top right, #111827 0%, #090d16 65%, #060911 100%);
        color: #f1f5f9;
        font-family: 'Inter', sans-serif;
    }
    [data-testid="stSidebar"] {
        background-color: #070b14;
        border-right: 1px solid #1e293b;
    }
    .hero-banner {
        background: linear-gradient(135deg, rgba(30, 58, 138, 0.35) 0%, rgba(88, 28, 135, 0.25) 100%);
        border: 1px solid rgba(99, 102, 241, 0.3);
        border-radius: 12px;
        padding: 22px 28px;
        margin-bottom: 24px;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    .hero-title {
        font-size: 26px;
        font-weight: 800;
        background: linear-gradient(90deg, #60a5fa, #c084fc);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin: 0;
    }
    .hero-sub {
        color: #94a3b8;
        font-size: 13.5px;
        margin-top: 4px;
    }
    .vector-pill {
        display: inline-block;
        background: rgba(59, 130, 246, 0.12);
        border: 1px solid rgba(59, 130, 246, 0.35);
        color: #93c5fd;
        padding: 4px 10px;
        border-radius: 999px;
        font-size: 11px;
        font-weight: 600;
        margin-right: 6px;
    }
    .kpi-grid {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 14px;
        margin-bottom: 18px;
    }
    .kpi-card {
        background: rgba(17, 24, 39, 0.85);
        border: 1px solid #1e293b;
        border-left: 4px solid #3b82f6;
        border-radius: 10px;
        padding: 16px 18px;
        box-shadow: 0 8px 16px -4px rgba(0, 0, 0, 0.45);
    }
    .kpi-label {
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        color: #94a3b8;
    }
    .kpi-value {
        font-size: 28px;
        font-weight: 800;
        margin-top: 6px;
        font-family: 'JetBrains Mono', monospace;
    }
    .location-box {
        background: rgba(15, 23, 42, 0.9);
        border: 1px solid #334155;
        border-left: 4px solid #38bdf8;
        padding: 12px 16px;
        border-radius: 8px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 13px;
        margin-bottom: 12px;
    }
    .sev-badge {
        padding: 3px 10px;
        border-radius: 6px;
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
        display: inline-block;
    }
    .sev-Critical { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.45); }
    .sev-High { background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.45); }
    .sev-Medium { background: rgba(234, 179, 8, 0.2); color: #facc15; border: 1px solid rgba(234, 179, 8, 0.45); }
    .sev-Low { background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.45); }
    div.stButton > button {
        background: linear-gradient(135deg, #2563eb 0%, #6366f1 100%);
        color: #ffffff;
        border: 1px solid rgba(255,255,255,0.1);
        border-radius: 8px;
        font-weight: 600;
        transition: all 0.2s ease;
    }
    div.stButton > button:hover {
        border-color: #60a5fa;
        box-shadow: 0 0 14px rgba(59, 130, 246, 0.45);
    }
</style>
""", unsafe_allow_html=True)

if "active_page" not in st.session_state:
    st.session_state["active_page"] = "1. Overview"
if "selected_report_scan" not in st.session_state:
    st.session_state["selected_report_scan"] = None
if "max_file_mb" not in st.session_state:
    st.session_state["max_file_mb"] = 5

def run_demo_seed(engine: SecretDetectionEngine):
    if os.path.exists("sample_data/.env.sample"):
        with open("sample_data/.env.sample", "r", encoding="utf-8", errors="ignore") as f:
            f_env = scan_text_buffer(engine, f.read(), "sample_data/.env.sample")
            save_scan_and_findings("Prod-Config-Env-Audit", "Configuration File", 1, f_env)

    if os.path.exists("sample_data/app.log"):
        with open("sample_data/app.log", "r", encoding="utf-8", errors="ignore") as f:
            f_log = scan_text_buffer(engine, f.read(), "sample_data/app.log")
            save_scan_and_findings("AuthGateway-App-Logs", "Application Logs", 1, f_log)

    if os.path.exists("sample_data/cloud_storage.tf"):
        with open("sample_data/cloud_storage.tf", "r", encoding="utf-8", errors="ignore") as f:
            f_cloud = scan_text_buffer(engine, f.read(), "sample_data/cloud_storage.tf")
            save_scan_and_findings("MultiCloud-Storage-IaC", "Cloud Storage & IaC", 1, f_cloud)

    git_mock = """
    commit 8f4a9c21 (Author: dev@corp.io)
    + AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
    + OAUTH_CLIENT_SECRET = "client_secret_998877665544332211aabbcc"
    """
    f_git = scan_text_buffer(engine, git_mock, "src/auth/config.py (commit 8f4a9c21)")
    save_scan_and_findings("PaymentService-Git-History", "Git Commit History", 14, f_git)

rule_states = get_rule_states()
custom_rules = get_custom_rules()
engine = SecretDetectionEngine(custom_rules=custom_rules, rule_states=rule_states)

with st.sidebar:
    st.markdown("""
    <div style="padding: 8px 0 16px 0;">
        <div style="font-size: 22px; font-weight: 800; color: #f8fafc; letter-spacing: -0.02em;">&#128737;&#65039; LEAKSHIELD</div>
        <div style="font-size: 11px; color: #38bdf8; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em;">HACK-DAY 2026 Enterprise Edition</div>
    </div>
    """, unsafe_allow_html=True)

    pages = [
        "1. Overview",
        "2. New Scan",
        "3. Findings",
        "4. Repositories",
        "5. Scan History",
        "6. Reports",
        "7. Detection Rules",
        "8. Settings"
    ]
    selected_nav = st.radio("SECURITY CONSOLE", pages, index=pages.index(st.session_state["active_page"]))
    st.session_state["active_page"] = selected_nav

    st.markdown("---")
    st.markdown("**Protected Exposure Vectors:**")
    st.caption("- Public & Local Git Repos\n- Application & Access Logs\n- Config & IaC Files (.env, .tf)\n- Cloud Storage (S3, Azure, GCP)")
    st.markdown("---")
    if st.button("Load Demo Incident Data", use_container_width=True):
        run_demo_seed(engine)
        st.rerun()

st.markdown("""
<div class="hero-banner">
    <div>
        <h1 class="hero-title">LeakShield &mdash; Cross-Platform Data Leak Detection System</h1>
        <div class="hero-sub">Context-Aware Regex &bull; Shannon Entropy Gating &bull; Exact File &amp; Line Mapping</div>
        <div style="margin-top: 10px;">
            <span class="vector-pill">Public &amp; Local Git Repos</span>
            <span class="vector-pill">Application Logs</span>
            <span class="vector-pill">Configuration Files</span>
            <span class="vector-pill">Cloud Storage &amp; IaC</span>
        </div>
    </div>
    <div style="text-align: right; font-size: 12px; color: #94a3b8;">
        <div><strong>Engine Status:</strong> <span style="color:#10b981;">&#9679; Online (100% Local)</span></div>
        <div><strong>Active Rules:</strong> """ + str(len([r for r in engine.rules if r.get("enabled", True)])) + """ Signatures</div>
    </div>
</div>
""", unsafe_allow_html=True)

# 1. OVERVIEW DASHBOARD
if selected_nav == "1. Overview":
    all_scans = get_all_scans()
    all_findings = get_all_findings()

    if not all_scans:
        st.warning("No scans exist in the database yet. Start your first scan or load the multi-vector demo dataset.")
        c1, c2, _ = st.columns([1.5, 1.5, 4])
        if c1.button("Start Your First Scan", use_container_width=True):
            st.session_state["active_page"] = "2. New Scan"
            st.rerun()
        if c2.button("Seed Multi-Vector Demo Data", use_container_width=True):
            run_demo_seed(engine)
            st.rerun()
        st.stop()

    total_scans = len(all_scans)
    total_findings = len(all_findings)
    crit_c = sum(1 for f in all_findings if f["severity"] == "Critical")
    high_c = sum(1 for f in all_findings if f["severity"] == "High")
    med_c = sum(1 for f in all_findings if f["severity"] == "Medium")
    low_c = sum(1 for f in all_findings if f["severity"] == "Low")
    open_c = sum(1 for f in all_findings if f["status"] == "Open")
    res_c = sum(1 for f in all_findings if f["status"] == "Resolved")

    st.markdown(f"""
    <div class="kpi-grid">
        <div class="kpi-card" style="border-left-color: #38bdf8;">
            <div class="kpi-label">Total Scans</div>
            <div class="kpi-value" style="color: #38bdf8;">{total_scans}</div>
        </div>
        <div class="kpi-card" style="border-left-color: #a855f7;">
            <div class="kpi-label">Total Findings</div>
            <div class="kpi-value" style="color: #c084fc;">{total_findings}</div>
        </div>
        <div class="kpi-card" style="border-left-color: #ef4444;">
            <div class="kpi-label">Critical Findings</div>
            <div class="kpi-value" style="color: #f87171;">{crit_c}</div>
        </div>
        <div class="kpi-card" style="border-left-color: #f97316;">
            <div class="kpi-label">High-Severity Findings</div>
            <div class="kpi-value" style="color: #fb923c;">{high_c}</div>
        </div>
        <div class="kpi-card" style="border-left-color: #eab308;">
            <div class="kpi-label">Medium-Severity Findings</div>
            <div class="kpi-value" style="color: #facc15;">{med_c}</div>
        </div>
        <div class="kpi-card" style="border-left-color: #3b82f6;">
            <div class="kpi-label">Low-Severity Findings</div>
            <div class="kpi-value" style="color: #60a5fa;">{low_c}</div>
        </div>
        <div class="kpi-card" style="border-left-color: #f43f5e;">
            <div class="kpi-label">Open Findings</div>
            <div class="kpi-value" style="color: #fb7185;">{open_c}</div>
        </div>
        <div class="kpi-card" style="border-left-color: #10b981;">
            <div class="kpi-label">Resolved Findings</div>
            <div class="kpi-value" style="color: #34d399;">{res_c}</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    ch1, ch2, ch3 = st.columns(3)

    with ch1:
        st.markdown("##### A. Severity Distribution")
        sev_df = pd.DataFrame([
            {"Severity": "Critical", "Count": crit_c},
            {"Severity": "High", "Count": high_c},
            {"Severity": "Medium", "Count": med_c},
            {"Severity": "Low", "Count": low_c}
        ])
        fig_donut = px.pie(
            sev_df, values="Count", names="Severity", hole=0.62,
            color="Severity",
            color_discrete_map={"Critical": "#ef4444", "High": "#f97316", "Medium": "#eab308", "Low": "#3b82f6"}
        )
        fig_donut.update_layout(
            paper_bgcolor="rgba(17,24,39,0.7)", plot_bgcolor="rgba(0,0,0,0)",
            font_color="#e2e8f0", height=290, margin=dict(t=20, b=20, l=20, r=20),
            legend=dict(orientation="h", yanchor="bottom", y=-0.15)
        )
        st.plotly_chart(fig_donut, use_container_width=True)

    with ch2:
        st.markdown("##### B. Scan Activity Over Time")
        scans_df = pd.DataFrame(all_scans).sort_values("id")
        fig_line = px.line(
            scans_df, x="scan_name", y="findings_count", markers=True,
            labels={"scan_name": "Scan Session", "findings_count": "Leaks Detected"}
        )
        fig_line.update_traces(line_color="#8b5cf6", line_width=3, marker=dict(size=9, color="#38bdf8"))
        fig_line.update_layout(
            paper_bgcolor="rgba(17,24,39,0.7)", plot_bgcolor="rgba(0,0,0,0)",
            font_color="#e2e8f0", height=290, margin=dict(t=20, b=20, l=20, r=20)
        )
        st.plotly_chart(fig_line, use_container_width=True)

    with ch3:
        st.markdown("##### C. Detected Secret Categories")
        if all_findings:
            cat_df = pd.Series([f["category"] for f in all_findings]).value_counts().reset_index()
            cat_df.columns = ["Category", "Count"]
            fig_bar = px.bar(
                cat_df, x="Count", y="Category", orientation="h",
                color="Count", color_continuous_scale=["#3b82f6", "#8b5cf6", "#ec4899"]
            )
            fig_bar.update_layout(
                paper_bgcolor="rgba(17,24,39,0.7)", plot_bgcolor="rgba(0,0,0,0)",
                font_color="#e2e8f0", height=290, margin=dict(t=20, b=20, l=20, r=20),
                coloraxis_showscale=False
            )
            st.plotly_chart(fig_bar, use_container_width=True)

    st.markdown("### D. Recent Security Scans")
    for s in all_scans[:8]:
        sc1, sc2, sc3, sc4, sc5, sc6, sc7 = st.columns([2.2, 1.5, 1.6, 1, 1, 1, 1.4])
        sc1.markdown(f"**{s['scan_name']}**")
        sc2.caption(f"`{s['scan_type']}`")
        sc3.caption(s["started_at"])
        sc4.markdown(f"`{s['files_scanned']}` files")
        badge_col = "#ef4444" if s["findings_count"] > 0 else "#10b981"
        sc5.markdown(f"<span style='color:{badge_col};font-weight:700;'>{s['findings_count']} findings</span>", unsafe_allow_html=True)
        sc6.markdown(f"`{s['status']}`")
        if sc7.button("View Report", key=f"dash_rep_{s['id']}"):
            st.session_state["selected_report_scan"] = s["id"]
            st.session_state["active_page"] = "6. Reports"
            st.rerun()

# 2. NEW SCAN
elif selected_nav == "2. New Scan":
    st.subheader("Multi-Vector Security Scanner")
    st.caption("Inspect Public/Local Git Repositories, Application Logs, Configuration Files, Cloud Storage IaC, and ZIP Archives.")

    t_cfg, t_log, t_cloud, t_zip, t_dir, t_git = st.tabs([
        "Config & Source Files",
        "Application Logs",
        "Cloud Storage & IaC",
        "Safe ZIP Archive",
        "Local Directory",
        "Git Repo & History"
    ])

    with t_cfg:
        st.markdown("#### Configuration & Source Code Upload")
        job_name = st.text_input("Scan Name", value="Config-Source-Audit", key="cfg_name")
        up_files = st.file_uploader("Upload Configuration or Source Files", accept_multiple_files=True, key="up_cfg")
        if st.button("Scan Uploaded Files", key="btn_cfg") and up_files:
            findings = []
            for uf in up_files:
                raw = uf.read().decode("utf-8", errors="ignore")
                findings.extend(scan_text_buffer(engine, raw, uf.name))
            sid = save_scan_and_findings(job_name, "Configuration & Source", len(up_files), findings)
            st.success(f"Completed! Analyzed {len(up_files)} file(s) and detected {len(findings)} exposed secret(s). (Scan #{sid})")

    with t_log:
        st.markdown("#### Application & Access Log Analyzer")
        log_name = st.text_input("Log Scan Name", value="App-Log-Inspection", key="log_name")
        raw_log = st.text_area(
            "Paste Application Log Lines",
            height=160,
            value='2026-11-06 11:20:01 [ERROR] DB error on postgres://admin:SuperSecret99!@db.prod.local:5432/users\n2026-11-06 11:20:04 [DEBUG] Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.signature1234567890'
        )
        if st.button("Scan Pasted Log Stream"):
            findings = scan_text_buffer(engine, raw_log, "pasted_application.log")
            sid = save_scan_and_findings(log_name, "Application Logs", 1, findings)
            st.success(f"Detected {len(findings)} exposed credential(s) in log stream! (Scan #{sid})")

    with t_cloud:
        st.markdown("#### Cloud Storage & Infrastructure-as-Code Inspector")
        cloud_name = st.text_input("Cloud Scan Label", value="Cloud-Storage-Audit")
        cloud_snippet = st.text_area(
            "Paste Cloud Policy / Terraform / S3 Pre-signed URL / Azure SAS Config",
            height=160,
            value='resource "aws_s3_bucket" "data_lake" {\n  bucket = "corp-sensitive-backups"\n  acl    = "public-read"\n}'
        )
        if st.button("Analyze Cloud Storage Config"):
            findings = scan_text_buffer(engine, cloud_snippet, "cloud_storage_config.tf")
            sid = save_scan_and_findings(cloud_name, "Cloud Storage & IaC", 1, findings)
            st.success(f"Cloud Storage inspection complete: {len(findings)} exposure(s) found! (Scan #{sid})")

    with t_zip:
        st.markdown("#### Safe ZIP Archive Scanner")
        z_name = st.text_input("ZIP Scan Name", value="Archive-Security-Audit")
        z_file = st.file_uploader("Upload ZIP Archive (.zip)", type=["zip"])
        if st.button("Scan ZIP Archive Safely") and z_file:
            try:
                findings, f_count = scan_safe_zip(engine, z_file)
                sid = save_scan_and_findings(z_name, "ZIP Archive", f_count, findings)
                st.success(f"Safe in-memory ZIP scan finished! Evaluated {f_count} files, found {len(findings)} leak(s).")
            except Exception as e:
                st.error(f"ZIP Security Guard Blocked Archive: {str(e)}")

    with t_dir:
        st.markdown("#### Authorized Local Directory Scanner")
        d_name = st.text_input("Directory Scan Name", value="Local-Workspace-Scan")
        d_path = st.text_input("Authorized Local Directory Path", value="./sample_data")
        if st.button("Scan Directory Now"):
            try:
                findings, f_count = scan_local_directory(engine, d_path)
                sid = save_scan_and_findings(d_name, "Directory Scan", f_count, findings)
                st.success(f"Scanned {f_count} supported file(s) in '{d_path}' - found {len(findings)} secret(s)!")
            except Exception as e:
                st.error(str(e))

    with t_git:
        st.markdown("#### Git Repository & Commit History Scanner")
        g_name = st.text_input("Git Scan Label", value="Git-Commit-Audit")
        g_path = st.text_input("Local Git Repository Path", value=".")
        g_depth = st.slider("Commit History Depth", 5, 100, 30)
        if st.button("Scan Git Commit History"):
            try:
                findings, c_count = scan_git_history(engine, g_path, g_depth)
                sid = save_scan_and_findings(g_name, "Git History", c_count, findings)
                st.success(f"Inspected {c_count} commits - found {len(findings)} leaked secret(s) in commit history!")
            except Exception as e:
                st.error(f"Git Scan Notice: {str(e)}")

# 3. FINDINGS MANAGEMENT (WITH EXACT FILE & LINE INSPECTOR)
elif selected_nav == "3. Findings":
    st.subheader("Findings Triage, Exact File & Line Inspector")
    all_findings = get_all_findings()

    if not all_findings:
        st.info("No findings in database. Run a scan or click 'Load Demo Incident Data' in the sidebar.")
        st.stop()

    fc1, fc2, fc3, fc4 = st.columns([1.5, 1.5, 1.5, 2])
    sev_filter = fc1.multiselect("Severity", ["Critical", "High", "Medium", "Low"], default=["Critical", "High", "Medium", "Low"])
    status_filter = fc2.multiselect("Status", ["Open", "Resolved", "False Positive"], default=["Open", "Resolved", "False Positive"])
    cats = sorted(list({f["category"] for f in all_findings}))
    cat_filter = fc3.multiselect("Category", cats, default=cats)
    search_q = fc4.text_input("Search file path, rule ID, or category", "")

    filtered = [
        f for f in all_findings
        if f["severity"] in sev_filter
        and f["status"] in status_filter
        and f["category"] in cat_filter
        and (search_q.lower() in f["file_path"].lower() or search_q.lower() in f["rule_id"].lower() or search_q.lower() in f["category"].lower())
    ]

    st.caption(f"Showing **{len(filtered)}** prioritized findings. Each finding pinpoints the exact file path and line number.")

    for f in filtered:
        sev = f["severity"]
        header_label = f"[{sev.upper()}] {f['category']} | {f['file_path']} (Line {f['line_number']}) | Risk: {f['risk_score']}/100"
        with st.expander(header_label):
            # EXPLICIT FILE & LINE LOCATION CARD
            st.markdown(f"""
            <div class="location-box">
                <div><strong>&#128193; Target File Path:</strong> <code>{f['file_path']}</code></div>
                <div style="margin-top: 4px;"><strong>&#128204; Exact Line Number:</strong> Line <code>{f['line_number']}</code></div>
            </div>
            """, unsafe_allow_html=True)

            d1, d2 = st.columns([2.3, 1.2])
            with d1:
                st.markdown(f"""
                - **Finding ID:** `#{f['id']}` | **Scan ID:** `#{f['scan_id']}` | **First Detected:** `{f['created_at']}`
                - **Detection Rule:** `{f['rule_id']}` - **{f.get('rule_name', 'Rule')}**
                - **Confidence:** `{f['confidence']}%` | **Shannon Entropy:** `{f.get('entropy', 0.0)} bits/char`
                - **Redacted Secret Token:** `{f['redacted_secret']}`
                """)
                st.markdown(f"**Code Context at Line {f['line_number']} (Redacted):**")
                st.code(f["redacted_evidence"], language="bash")
                st.markdown(f"**Explanation:** {f['description']}")
                st.info(f"**Remediation:** {f['remediation']}")

            with d2:
                st.markdown("#### Triage Actions")
                st.metric("LeakShield Risk Score", f"{f['risk_score']} / 100")

                b1, b2 = st.columns(2)
                if b1.button("Mark Resolved", key=f"res_{f['id']}", use_container_width=True):
                    update_finding_status(f["id"], "Resolved")
                    st.rerun()
                if b2.button("False Positive", key=f"fp_{f['id']}", use_container_width=True):
                    update_finding_status(f["id"], "False Positive")
                    st.rerun()

                b3, b4 = st.columns(2)
                if b3.button("Reopen", key=f"re_{f['id']}", use_container_width=True):
                    update_finding_status(f["id"], "Open")
                    st.rerun()
                b4.download_button(
                    "Export JSON",
                    data=json.dumps(f, indent=2),
                    file_name=f"finding_{f['id']}.json",
                    mime="application/json",
                    key=f"exp_{f['id']}",
                    use_container_width=True
                )

# 4. REPOSITORIES
elif selected_nav == "4. Repositories":
    st.subheader("Git Repository & Commit History Inspector")
    local_repo = st.text_input("Local Repository Path", value=".")
    max_c = st.number_input("Max Commits to Inspect", min_value=5, max_value=200, value=30)
    if st.button("Scan Local Git Repository & History"):
        try:
            w_findings, w_files = scan_local_directory(engine, local_repo)
            h_findings = []
            if os.path.isdir(os.path.join(local_repo, ".git")):
                h_findings, _ = scan_git_history(engine, local_repo, int(max_c))
            combined = w_findings + h_findings
            sid = save_scan_and_findings(f"Repo-{os.path.basename(os.path.abspath(local_repo))}", "Git Repository", w_files, combined)
            st.success(f"Repository scan complete! Working tree + commit history yielded {len(combined)} finding(s). (Scan #{sid})")
        except Exception as e:
            st.error(str(e))

    st.markdown("---")
    st.markdown("#### Repository & Commit History Findings (With File & Commit Line Numbers)")
    git_findings = [f for f in get_all_findings() if "commit" in f["file_path"].lower() or "git" in f["description"].lower()]
    if git_findings:
        st.dataframe(pd.DataFrame(git_findings)[["id", "severity", "category", "file_path", "line_number", "redacted_secret", "risk_score", "status"]], use_container_width=True)
    else:
        st.caption("No commit-specific findings recorded yet. Click 'Load Demo Incident Data' in the sidebar.")

# 5. SCAN HISTORY
elif selected_nav == "5. Scan History":
    st.subheader("Complete Scan Audit History")
    scans = get_all_scans()
    if not scans:
        st.info("No scan history recorded yet.")
    else:
        st.dataframe(pd.DataFrame(scans), use_container_width=True)

# 6. REPORTS
elif selected_nav == "6. Reports":
    st.subheader("Security Assessment Report Generator")
    scans = get_all_scans()
    if not scans:
        st.info("No scans available for reporting.")
        st.stop()

    scan_map = {f"Scan #{s['id']} - {s['scan_name']} ({s['scan_type']} | {s['findings_count']} findings)": s["id"] for s in scans}
    default_idx = 0
    if st.session_state["selected_report_scan"]:
        for idx, s in enumerate(scans):
            if s["id"] == st.session_state["selected_report_scan"]:
                default_idx = idx
                break

    chosen = st.selectbox("Select Scan Session to Export", list(scan_map.keys()), index=default_idx)
    sid = scan_map[chosen]
    meta = next(s for s in scans if s["id"] == sid)
    findings = get_findings_by_scan(sid)

    json_rep = generate_json_report(meta, findings)
    csv_rep = generate_csv_report(findings)
    html_rep = generate_html_report(meta, findings)

    dl1, dl2, dl3 = st.columns(3)
    dl1.download_button("Download JSON Report", json_rep, file_name=f"LeakShield_Scan_{sid}.json", mime="application/json", use_container_width=True)
    dl2.download_button("Download CSV Report", csv_rep, file_name=f"LeakShield_Scan_{sid}.csv", mime="text/csv", use_container_width=True)
    dl3.download_button("Download Executive HTML Report", html_rep, file_name=f"LeakShield_Scan_{sid}.html", mime="text/html", use_container_width=True)

    st.markdown("#### Live Executive HTML Report Preview")
    st.components.v1.html(html_rep, height=620, scrolling=True)

# 7. DETECTION RULES
elif selected_nav == "7. Detection Rules":
    st.subheader("Detection Rules & Custom Signature Engine")
    for r in engine.rules:
        rc1, rc2, rc3, rc4, rc5 = st.columns([1.2, 2.2, 1.5, 1, 1.2])
        rc1.markdown(f"`{r['id']}`")
        rc2.markdown(f"**{r['name']}**")
        rc3.caption(f"{r['category']}")
        rc4.markdown(f"<span class='sev-badge sev-{r['severity']}'>{r['severity']}</span>", unsafe_allow_html=True)
        enabled_now = r.get("enabled", True)
        if rc5.checkbox("Enabled", value=enabled_now, key=f"tog_{r['id']}") != enabled_now:
            set_rule_state(r["id"], not enabled_now)
            st.rerun()

# 8. SETTINGS
elif selected_nav == "8. Settings":
    st.subheader("Platform Security & Scanner Settings")
    st.slider("Max Individual File Size (MB)", 1, 50, key="max_file_mb")
    st.markdown("- **ZIP Bomb Uncompressed Limit:** `50 MB` (Enforced)")
    st.markdown("- **Zero Raw Secret Storage Policy:** `Enforced`")
    st.markdown("---")
    if st.button("Reset & Purge All Scan History", type="secondary"):
        clear_all_data()
        st.success("Database cleared.")
        st.rerun()
