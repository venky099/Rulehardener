"""
RuleHardener — Next-Gen Cybersecurity Detection Testing & Hardening Dashboard
Modern Glassmorphism Dark UI with Interactive Visual Analytics
"""
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import json
import yaml
from pathlib import Path
import html
from datetime import datetime

# Set Page Config
st.set_page_config(
    page_title="RuleHardener — Sigma Detection Studio",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

from backend.config import settings
from backend.models import SigmaRule, AttackScenario, TelemetryEvent
from backend.database import (
    init_db, save_rule, get_rules, get_rule_by_id, get_rule_versions, rollback_rule_version,
    save_scenarios, get_scenarios,
    save_telemetry_events, get_telemetry_events,
    save_evaluation_run, get_evaluation_runs,
    save_hardening_proposal, get_hardening_proposals,
    save_report, get_reports
)
from backend.utils.pdf_generator import generate_pdf_report
from backend.utils.validators import (
    validate_rule_filename, validate_telemetry_filename, validate_payload_size, is_safe_path
)
from backend.rule_manager.sigma_loader import load_rules_from_directory, parse_sigma_yaml
from backend.rule_manager.sigma_validator import validate_sigma_rule
from backend.rule_manager.rule_analyzer import analyze_rule
from backend.telemetry.synthetic_generator import get_predefined_scenarios, generate_telemetry_for_scenarios
from backend.telemetry.log_loader import parse_uploaded_jsonl
from backend.detection.detection_evaluator import evaluate_rule_on_dataset
from backend.detection.metrics import calculate_detection_metrics
from backend.hardening.rule_comparator import evaluate_and_compare_rules

# ==============================================================================
# ADVANCED MODERN CYBERPUNK / GLASSMORPHISM CSS & ANIMATIONS
# ==============================================================================
st.markdown("""
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=Space+Grotesk:wght@500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">

<style>
    /* Global Typography */
    html, body, [class*="css"] {
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
        letter-spacing: -0.01em;
    }
    
    h1, h2, h3, .hero-title, .card-value {
        font-family: 'Space Grotesk', -apple-system, sans-serif !important;
        letter-spacing: -0.03em;
    }

    code, pre, .stCodeBlock, [data-testid="stCode"] {
        font-family: 'JetBrains Mono', monospace !important;
    }

    /* Keyframe Animations */
    @keyframes fadeInUp {
        from {
            opacity: 0;
            transform: translateY(16px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }

    @keyframes pulseLive {
        0%, 100% {
            box-shadow: 0 0 6px rgba(16, 185, 129, 0.4);
            transform: scale(1);
        }
        50% {
            box-shadow: 0 0 16px rgba(16, 185, 129, 0.95);
            transform: scale(1.15);
        }
    }

    @keyframes subtleGlow {
        0%, 100% { opacity: 0.6; }
        50% { opacity: 0.9; }
    }

    /* Main Container Background */
    .stApp {
        background: radial-gradient(circle at 15% 15%, #0f172a 0%, #06090e 100%);
        color: #e2e8f0;
    }

    /* Top Hero Header */
    .hero-banner {
        background: linear-gradient(135deg, rgba(30, 41, 59, 0.75) 0%, rgba(15, 23, 42, 0.92) 100%);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 18px;
        padding: 26px 30px;
        margin-bottom: 24px;
        box-shadow: 0 16px 36px rgba(0, 0, 0, 0.4), inset 0 1px 0 rgba(255, 255, 255, 0.1);
        backdrop-filter: blur(16px);
        animation: fadeInUp 0.45s cubic-bezier(0.16, 1, 0.3, 1) both;
    }
    .hero-title {
        font-size: 2.05rem;
        font-weight: 800;
        background: linear-gradient(90deg, #38bdf8 0%, #818cf8 50%, #c084fc 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 8px;
    }
    .hero-subtitle {
        color: #94a3b8;
        font-size: 0.98rem;
        line-height: 1.55;
    }

    /* Status Pulse Badge */
    .status-badge-live {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        background: rgba(16, 185, 129, 0.12);
        color: #10b981;
        border: 1px solid rgba(16, 185, 129, 0.35);
        padding: 5px 14px;
        border-radius: 9999px;
        font-size: 0.76rem;
        font-weight: 700;
        letter-spacing: 0.05em;
        text-transform: uppercase;
        backdrop-filter: blur(8px);
    }
    .status-badge-live::before {
        content: "";
        width: 8px;
        height: 8px;
        background: #10b981;
        border-radius: 50%;
        animation: pulseLive 2s infinite ease-in-out;
    }

    /* Glassmorphism Metric Cards */
    .glass-card {
        background: linear-gradient(145deg, rgba(30, 41, 59, 0.65) 0%, rgba(15, 23, 42, 0.8) 100%);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 16px;
        padding: 22px;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.28);
        backdrop-filter: blur(14px);
        transition: all 0.28s cubic-bezier(0.16, 1, 0.3, 1);
        position: relative;
        overflow: hidden;
        animation: fadeInUp 0.5s cubic-bezier(0.16, 1, 0.3, 1) both;
    }
    .glass-card:hover {
        transform: translateY(-5px) scale(1.012);
        border-color: rgba(56, 189, 248, 0.5);
        box-shadow: 0 20px 40px -10px rgba(0, 0, 0, 0.6), 0 0 22px rgba(56, 189, 248, 0.16);
    }
    .glass-card-top-accent-cyan { border-top: 3px solid #38bdf8; }
    .glass-card-top-accent-green { border-top: 3px solid #10b981; }
    .glass-card-top-accent-violet { border-top: 3px solid #a855f7; }
    .glass-card-top-accent-rose { border-top: 3px solid #f43f5e; }

    /* Staggered Card Animation Delays */
    div[data-testid="column"]:nth-child(1) .glass-card { animation-delay: 0.04s; }
    div[data-testid="column"]:nth-child(2) .glass-card { animation-delay: 0.08s; }
    div[data-testid="column"]:nth-child(3) .glass-card { animation-delay: 0.12s; }
    div[data-testid="column"]:nth-child(4) .glass-card { animation-delay: 0.16s; }
    div[data-testid="column"]:nth-child(5) .glass-card { animation-delay: 0.20s; }

    .card-label {
        color: #94a3b8;
        font-size: 0.77rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.07em;
        margin-bottom: 8px;
    }
    .card-value {
        color: #f8fafc;
        font-size: 2.25rem;
        font-weight: 800;
        line-height: 1.1;
    }
    .card-subtext {
        font-size: 0.82rem;
        margin-top: 10px;
        display: flex;
        align-items: center;
        gap: 6px;
    }

    /* Custom Badges */
    .chip-attack {
        background: rgba(239, 68, 68, 0.16);
        color: #f87171;
        border: 1px solid rgba(239, 68, 68, 0.35);
        padding: 4px 10px;
        border-radius: 8px;
        font-size: 0.76rem;
        font-weight: 700;
        display: inline-block;
        transition: transform 0.2s ease;
    }
    .chip-attack:hover { transform: scale(1.05); }

    .chip-benign {
        background: rgba(16, 185, 129, 0.16);
        color: #34d399;
        border: 1px solid rgba(16, 185, 129, 0.35);
        padding: 4px 10px;
        border-radius: 8px;
        font-size: 0.76rem;
        font-weight: 700;
        display: inline-block;
        transition: transform 0.2s ease;
    }
    .chip-benign:hover { transform: scale(1.05); }

    .chip-mitre {
        background: rgba(99, 102, 241, 0.16);
        color: #818cf8;
        border: 1px solid rgba(99, 102, 241, 0.35);
        padding: 4px 10px;
        border-radius: 8px;
        font-size: 0.76rem;
        font-weight: 600;
        display: inline-block;
        transition: transform 0.2s ease;
    }
    .chip-mitre:hover { transform: scale(1.05); }

    /* Workflow Pipeline */
    .pipeline-bar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        background: rgba(15, 23, 42, 0.75);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 14px;
        padding: 16px 24px;
        margin: 18px 0 28px 0;
        box-shadow: 0 6px 20px rgba(0, 0, 0, 0.25);
    }
    .step-item {
        display: flex;
        align-items: center;
        gap: 12px;
        font-size: 0.92rem;
        font-weight: 600;
        color: #cbd5e1;
        transition: all 0.2s ease;
    }
    .step-item:hover {
        color: #38bdf8;
        transform: translateX(3px);
    }
    .step-number {
        width: 28px;
        height: 28px;
        border-radius: 50%;
        background: linear-gradient(135deg, #38bdf8 0%, #2563eb 100%);
        color: #ffffff;
        display: flex;
        align-items: center;
        justify-content: center;
        font-weight: 800;
        font-size: 0.82rem;
        box-shadow: 0 2px 8px rgba(56, 189, 248, 0.4);
    }
    .step-arrow {
        color: #64748b;
        font-size: 1.3rem;
        font-weight: 300;
    }

    /* Buttons Upgrade with Motion */
    div.stButton > button {
        font-family: 'Space Grotesk', sans-serif !important;
        background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%);
        color: #ffffff !important;
        font-weight: 600;
        letter-spacing: -0.01em;
        border: 1px solid rgba(255, 255, 255, 0.16);
        border-radius: 12px;
        padding: 12px 26px;
        transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
        box-shadow: 0 4px 16px rgba(37, 99, 235, 0.35);
    }
    div.stButton > button:hover {
        background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
        border-color: rgba(255, 255, 255, 0.3);
        box-shadow: 0 8px 24px rgba(37, 99, 235, 0.55);
        transform: translateY(-2px);
    }
    div.stButton > button:active {
        transform: translateY(1px);
    }

    /* Sidebar Styling */
    section[data-testid="stSidebar"] {
        background: #080c14;
        border-right: 1px solid rgba(255, 255, 255, 0.06);
    }
    
    /* Expander Styling */
    .streamlit-expanderHeader {
        background: rgba(30, 41, 59, 0.45) !important;
        border-radius: 10px !important;
        border: 1px solid rgba(255, 255, 255, 0.06) !important;
        transition: all 0.2s ease;
    }
    .streamlit-expanderHeader:hover {
        background: rgba(30, 41, 59, 0.7) !important;
        border-color: rgba(56, 189, 248, 0.3) !important;
    }
</style>
""", unsafe_allow_html=True)

# ----------------- App Data Bootstrap -----------------
def bootstrap_application():
    """Initializes tables and fixtures."""
    init_db()
    rules = get_rules()
    if not rules:
        loaded = load_rules_from_directory(settings.RULES_DIR)
        for r in loaded:
            save_rule(r)
    
    attacks, benign = get_predefined_scenarios()
    save_scenarios(attacks + benign)
    
    telemetry = get_telemetry_events()
    if len(telemetry) < 20:
        atk_evts, ben_evts = generate_telemetry_for_scenarios()
        save_telemetry_events(atk_evts + ben_evts)

bootstrap_application()

# ----------------- Sidebar -----------------
with st.sidebar:
    st.markdown("""
    <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
        <span style="font-size: 2.2rem;">🛡️</span>
        <div>
            <div style="font-weight: 800; font-size: 1.25rem; letter-spacing: -0.02em; color: #f8fafc;">RuleHardener</div>
            <div style="font-size: 0.72rem; color: #38bdf8; font-weight: 600; text-transform: uppercase;">Detection Studio 2.0</div>
        </div>
    </div>
    <div class="status-badge-live" style="margin-bottom: 20px;">Deterministic Core Active</div>
    """, unsafe_allow_html=True)

    page = st.radio(
        "NAVIGATION",
        [
            "🏠 Overview Dashboard",
            "📜 Sigma Rule Manager",
            "🎯 Attack Scenarios",
            "🔍 Telemetry Explorer",
            "⚡ Detection Results",
            "🛡️ Rule Hardening Studio",
            "📊 Reports & Exports"
        ],
        label_visibility="collapsed"
    )

    st.markdown("---")
    st.markdown("<div style='font-size: 0.75rem; color: #64748b;'>Engine Specs: In-Memory AST • 100% Offline • Zero LLM Hallucinations • SQLite Local</div>", unsafe_allow_html=True)

# Global Active Rule Resolution
rules = get_rules()
if "selected_rule_id" not in st.session_state and rules:
    st.session_state.selected_rule_id = rules[0].id

selected_rule = get_rule_by_id(st.session_state.get("selected_rule_id", ""))
if not selected_rule and rules:
    selected_rule = rules[0]
    st.session_state.selected_rule_id = selected_rule.id

# ==============================================================================
# PAGE 1: OVERVIEW DASHBOARD
# ==============================================================================
if page == "🏠 Overview Dashboard":
    st.markdown("""
    <div class="hero-banner">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 12px;">
            <div>
                <div class="hero-title">RuleHardener Detection Engine</div>
                <div class="hero-subtitle">Automated, deterministic testing & hardening of Sigma detection rules against attack variations without introducing false positives.</div>
            </div>
            <div class="status-badge-live">Engine: Ready</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    scenarios = get_scenarios()
    telemetry = get_telemetry_events()
    runs = get_evaluation_runs()
    latest_run = runs[0] if runs else None

    # Modern 4-Card Scorecard
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(f"""
        <div class="glass-card glass-card-top-accent-cyan">
            <div class="card-label">Active Sigma Rules</div>
            <div class="card-value">{len(rules)}</div>
            <div class="card-subtext" style="color: #38bdf8;">⚡ Version Controlled</div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        attack_count = sum(1 for s in scenarios if s.category == "attack")
        st.markdown(f"""
        <div class="glass-card glass-card-top-accent-rose">
            <div class="card-label">Attack Scenarios</div>
            <div class="card-value">{attack_count}</div>
            <div class="card-subtext"><span class="chip-attack">MITRE T1059.001</span></div>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        benign_count = sum(1 for e in telemetry if not e.is_attack)
        st.markdown(f"""
        <div class="glass-card glass-card-top-accent-green">
            <div class="card-label">Benign Baseline Events</div>
            <div class="card-value">{benign_count}</div>
            <div class="card-subtext"><span class="chip-benign">FP Guardrail Baseline</span></div>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        dr = f"{latest_run['detection_rate']}%" if latest_run else "Not Run"
        fpr = f"{latest_run['false_positive_rate']}%" if latest_run else "0.0%"
        st.markdown(f"""
        <div class="glass-card glass-card-top-accent-violet">
            <div class="card-label">Latest Detection Rate</div>
            <div class="card-value">{dr}</div>
            <div class="card-subtext" style="color: #94a3b8;">False Positive Rate: <b style="color: #10b981;">{fpr}</b></div>
        </div>
        """, unsafe_allow_html=True)

    # Workflow Visual Stepper
    st.markdown("""
    <div class="pipeline-bar">
        <div class="step-item"><span class="step-number">1</span> Ingest Baseline Rule & Fixtures</div>
        <span class="step-arrow">➔</span>
        <div class="step-item"><span class="step-number">2</span> Run Deterministic AST Evaluation</div>
        <span class="step-arrow">➔</span>
        <div class="step-item"><span class="step-number">3</span> Synthesize Hardening & Verify FP Guardrail</div>
    </div>
    """, unsafe_allow_html=True)

    c_left, c_right = st.columns([1, 1], gap="large")

    with c_left:
        st.subheader("⚡ Quick Rule Evaluation")
        if selected_rule:
            st.info(f"Target: **{selected_rule.title}** (Version `v{selected_rule.version}`) | ID: `{selected_rule.id[:18]}...`")
            if st.button("🚀 Run Immediate Test Suite", key="btn_quick_eval", use_container_width=True):
                events = get_telemetry_events()
                ev_res, sc_res = evaluate_rule_on_dataset(selected_rule, events, scenarios)
                metrics = calculate_detection_metrics(ev_res, sc_res)
                run_id = save_evaluation_run(selected_rule, metrics, ev_res)
                st.session_state.active_metrics = metrics
                st.session_state.active_event_results = ev_res
                st.session_state.active_scenario_results = sc_res
                st.success(f"Evaluation complete! Run `{run_id}`: Detection Rate: **{metrics.detection_rate}%** | False Positives: **{metrics.false_positives}**")
                st.rerun()
        else:
            st.warning("No Sigma rules found.")

    with c_right:
        st.subheader("🕒 Recent Evaluation Activity")
        if runs:
            df_runs = pd.DataFrame(runs[:5])
            df_runs = df_runs[["run_id", "rule_title", "detection_rate", "false_positives", "f1_score", "created_at"]]
            df_runs.columns = ["Run ID", "Rule", "Detection %", "FPs", "F1 Score", "Date / Time"]
            st.dataframe(df_runs, use_container_width=True, hide_index=True)
        else:
            st.write("No evaluation runs recorded yet. Click 'Run Immediate Test Suite' to begin.")

# ==============================================================================
# PAGE 2: SIGMA RULE MANAGER
# ==============================================================================
elif page == "📜 Sigma Rule Manager":
    st.markdown("""
    <div class="hero-banner">
        <div class="hero-title">Sigma Detection Rule Manager</div>
        <div class="hero-subtitle">Manage detection rule assets, inspect parsed AST conditions, validate YAML syntax, and track version lineage.</div>
    </div>
    """, unsafe_allow_html=True)

    tab1, tab2 = st.tabs(["Active Rule Inspector", "Import Custom Sigma YAML"])

    with tab1:
        if rules:
            rule_options = {f"{r.title} (v{r.version})": r.id for r in rules}
            selected_label = st.selectbox(
                "Choose Active Rule to Inspect or Evaluate:",
                list(rule_options.keys()),
                index=0
            )
            current_rule_id = rule_options[selected_label]
            st.session_state.selected_rule_id = current_rule_id
            curr_rule = get_rule_by_id(current_rule_id)

            if curr_rule:
                c1, c2, c3, c4 = st.columns(4)
                c1.markdown(f"""<div class="glass-card"><div class="card-label">Status</div><div style="font-weight:700; color:#38bdf8;">{curr_rule.status.upper()}</div></div>""", unsafe_allow_html=True)
                c2.markdown(f"""<div class="glass-card"><div class="card-label">Severity Level</div><div style="font-weight:700; color:#f59e0b;">{curr_rule.level.upper()}</div></div>""", unsafe_allow_html=True)
                c3.markdown(f"""<div class="glass-card"><div class="card-label">Version</div><div style="font-weight:700; color:#10b981;">v{curr_rule.version}</div></div>""", unsafe_allow_html=True)
                c4.markdown(f"""<div class="glass-card"><div class="card-label">Rule ID</div><div style="font-weight:600; font-size:0.85rem; font-family:'JetBrains Mono';">{curr_rule.id[:14]}...</div></div>""", unsafe_allow_html=True)

                escaped_desc = html.escape(curr_rule.description)
                st.markdown(f"<div style='margin: 16px 0; color: #cbd5e1;'><b>Description:</b> {escaped_desc}</div>", unsafe_allow_html=True)
                
                # Tag Chips with HTML escaping
                st.markdown("**Mapped MITRE ATT&CK Techniques:** " + " ".join([f"<span class='chip-mitre'>{html.escape(t)}</span>" for t in curr_rule.tags]), unsafe_allow_html=True)
                
                # Rule Topology Analysis
                analysis = analyze_rule(curr_rule)
                escaped_fields = html.escape(', '.join(analysis['target_fields']))
                escaped_modifiers = html.escape(', '.join(analysis['modifiers_used']))
                escaped_cond = html.escape(str(curr_rule.condition))
                st.markdown(f"""
                <div style="background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 8px; padding: 12px 16px; margin: 12px 0;">
                    <b>Targeted Fields:</b> <code style="color:#38bdf8;">{escaped_fields}</code> &nbsp;|&nbsp; 
                    <b>Modifiers Used:</b> <code style="color:#a855f7;">{escaped_modifiers}</code> &nbsp;|&nbsp;
                    <b>Condition Expression:</b> <code style="color:#10b981;">{escaped_cond}</code>
                </div>
                """, unsafe_allow_html=True)

                st.subheader("YAML Specification")
                st.code(curr_rule.raw_yaml, language="yaml")

                # Version History & Rollback Controls
                versions = get_rule_versions(curr_rule.id)
                if versions:
                    with st.expander(f"📜 Rule Version Lineage ({len(versions)} snapshots recorded in SQLite)", expanded=True):
                        v_table = []
                        for v in versions:
                            v_table.append({
                                "Version": f"v{v['version']}",
                                "Timestamp": v["created_at"],
                                "Summary of Changes": v["change_summary"]
                            })
                        st.dataframe(pd.DataFrame(v_table), use_container_width=True, hide_index=True)

                        # Active Rollback Controls
                        older_versions = [v for v in versions if v["version"] < curr_rule.version]
                        if older_versions:
                            st.markdown("##### ⏪ Instant Version Rollback")
                            st.caption("Restore any historical rule snapshot into production:")
                            rb_col1, rb_col2 = st.columns([3, 1])
                            with rb_col1:
                                target_v = st.selectbox(
                                    "Select Previous Version to Restore:",
                                    [v["version"] for v in older_versions],
                                    format_func=lambda x: f"v{x} — {next(v['change_summary'] for v in older_versions if v['version'] == x)}"
                                )
                            with rb_col2:
                                st.markdown("<div style='height:28px;'></div>", unsafe_allow_html=True)
                                if st.button(f"Rollback to v{target_v}", use_container_width=True):
                                    restored = rollback_rule_version(curr_rule.id, target_v)
                                    if restored:
                                        st.session_state.selected_rule_id = restored.id
                                        st.session_state.promotion_banner = f"Rule successfully rolled back to v{target_v} (now active as v{restored.version})"
                                        st.rerun()
        else:
            st.warning("No rules in database.")

    with tab2:
        st.subheader("Upload Custom Sigma YAML")
        uploaded_file = st.file_uploader("Upload YAML Rule File", type=["yml", "yaml"])
        raw_text = st.text_area("Or Paste Raw Sigma Rule Definition:", height=200)

        if st.button("Validate & Register Rule", use_container_width=True):
            content_to_parse = ""
            if uploaded_file is not None:
                # Security validations: filename pattern and payload size
                is_valid_fn, fn_err = validate_rule_filename(uploaded_file.name)
                if not is_valid_fn:
                    st.error(f"Rule file rejected: {fn_err}")
                else:
                    raw_bytes = uploaded_file.getvalue()
                    is_valid_sz, sz_err = validate_payload_size(raw_bytes)
                    if not is_valid_sz:
                        st.error(f"Rule file rejected: {sz_err}")
                    else:
                        content_to_parse = raw_bytes.decode("utf-8", errors="replace")
            elif raw_text.strip():
                content_to_parse = raw_text

            if content_to_parse:
                is_valid, errors, warnings = validate_sigma_rule(content_to_parse)
                if not is_valid:
                    st.error(f"Rule Validation Failed: {'; '.join(errors)}")
                else:
                    if warnings:
                        st.warning(f"Warnings: {'; '.join(warnings)}")
                    try:
                        new_rule = parse_sigma_yaml(content_to_parse)
                        save_rule(new_rule)
                        st.session_state.selected_rule_id = new_rule.id
                        st.success(f"Rule '{new_rule.title}' successfully imported and saved!")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Error parsing rule: {str(e)}")
            else:
                st.error("Please provide a file or YAML text.")

# ==============================================================================
# PAGE 3: ATTACK SCENARIOS
# ==============================================================================
elif page == "🎯 Attack Scenarios":
    st.markdown("""
    <div class="hero-banner">
        <div class="hero-title">Attack & Benign Scenario Library</div>
        <div class="hero-subtitle">Deterministic test fixtures covering real-world adversary evasion techniques and benign administrative baselines.</div>
    </div>
    """, unsafe_allow_html=True)

    category_filter = st.radio("Filter Scenarios:", ["All Scenarios (20)", "Attack Scenarios Only (8)", "Benign Baselines Only (12)"], horizontal=True)
    
    scenarios = get_scenarios()
    if "Attack" in category_filter:
        display_scenarios = [s for s in scenarios if s.category == "attack"]
    elif "Benign" in category_filter:
        display_scenarios = [s for s in scenarios if s.category == "benign"]
    else:
        display_scenarios = scenarios

    for sc in display_scenarios:
        is_atk = sc.category == "attack"
        badge = "<span class='chip-attack'>ATTACK FIXTURE</span>" if is_atk else "<span class='chip-benign'>BENIGN BASELINE</span>"
        mitre_badge = f"<span class='chip-mitre'>{sc.mitre_technique_id} • {sc.mitre_tactic}</span>" if sc.mitre_technique_id else f"<span class='chip-mitre'>{sc.mitre_tactic}</span>"

        with st.expander(f"{sc.scenario_id}: {sc.name}"):
            st.markdown(f"{badge} &nbsp; {mitre_badge}", unsafe_allow_html=True)
            st.markdown(f"**Description:** {sc.description}")
            st.markdown(f"**Expected Security Outcome:** {sc.expected_behavior}")
            st.markdown(f"**Expected by Original Baseline Rule:** `{'DETECTED' if sc.expected_detection_original else 'MISSED (True Negative)'}`")
            if sc.process_fields:
                st.markdown("**Process Telemetry Attributes:**")
                st.json(sc.process_fields)

# ==============================================================================
# PAGE 4: TELEMETRY EXPLORER
# ==============================================================================
elif page == "🔍 Telemetry Explorer":
    st.markdown("""
    <div class="hero-banner">
        <div class="hero-title">Telemetry Explorer</div>
        <div class="hero-subtitle">Inspect realistic Windows process creation events (Event 4688 / Sysmon 1) used to benchmark rules.</div>
    </div>
    """, unsafe_allow_html=True)

    telemetry = get_telemetry_events()
    scenarios = get_scenarios()
    
    col1, col2, col3 = st.columns([2, 1, 1])
    with col1:
        search_query = st.text_input("🔍 Search Command Line, Image, or Event ID:", "")
    with col2:
        type_filter = st.selectbox("Telemetry Stream:", ["All Events", "Attack Telemetry", "Benign Telemetry"])
    with col3:
        scenario_filter = st.selectbox("Scenario Filter:", ["All"] + sorted(list(set(e.scenario_id for e in telemetry))))

    filtered_evts = telemetry
    if type_filter == "Attack Telemetry":
        filtered_evts = [e for e in filtered_evts if e.is_attack]
    elif type_filter == "Benign Telemetry":
        filtered_evts = [e for e in filtered_evts if not e.is_attack]

    if scenario_filter != "All":
        filtered_evts = [e for e in filtered_evts if e.scenario_id == scenario_filter]

    if search_query:
        q = search_query.lower()
        filtered_evts = [e for e in filtered_evts if q in e.command_line.lower() or q in e.image.lower() or q in e.event_id.lower()]

    st.markdown(f"Displaying **{len(filtered_evts)}** events:")
    
    table_data = []
    for e in filtered_evts:
        table_data.append({
            "Event ID": e.event_id,
            "Type": "ATTACK" if e.is_attack else "BENIGN",
            "Scenario": e.scenario_id,
            "Process Image": e.image.split("\\")[-1],
            "Command Line": e.command_line,
            "Parent": e.parent_image.split("\\")[-1] if e.parent_image else "",
            "User": e.user
        })

    st.dataframe(pd.DataFrame(table_data), use_container_width=True, hide_index=True)

    st.markdown("---")
    st.subheader("Upload Custom Telemetry (JSON / JSONL)")
    upload_tel = st.file_uploader("Upload custom logs in JSON or JSONL format:", type=["jsonl", "json"])
    tel_label = st.radio("Label uploaded events as:", ["Benign Baseline Telemetry", "Adversary Attack Telemetry"], horizontal=True)

    if st.button("Import & Normalize Telemetry"):
        if upload_tel is not None:
            # Security validations: filename and payload size
            is_valid_fn, fn_err = validate_telemetry_filename(upload_tel.name)
            if not is_valid_fn:
                st.error(f"Telemetry file rejected: {fn_err}")
            else:
                raw_bytes = upload_tel.getvalue()
                is_valid_sz, sz_err = validate_payload_size(raw_bytes)
                if not is_valid_sz:
                    st.error(f"Telemetry file rejected: {sz_err}")
                else:
                    raw_text = raw_bytes.decode("utf-8", errors="replace")
                    is_atk = "Attack" in tel_label
                    events_parsed, parse_errs = parse_uploaded_jsonl(raw_text, default_is_attack=is_atk)
                    if events_parsed:
                        save_telemetry_events(events_parsed)
                        st.success(f"Successfully imported and normalized {len(events_parsed)} events!")
                        st.rerun()
                    else:
                        st.error("No valid telemetry events could be parsed.")

# ==============================================================================
# PAGE 5: DETECTION RESULTS
# ==============================================================================
elif page == "⚡ Detection Results":
    st.markdown("""
    <div class="hero-banner">
        <div class="hero-title">Deterministic Detection Evaluation</div>
        <div class="hero-subtitle">In-memory evaluation of the active Sigma rule against attack & benign telemetry with Confusion Matrix analytics.</div>
    </div>
    """, unsafe_allow_html=True)

    if not selected_rule:
        st.warning("Please select a rule from the Rule Manager.")
    else:
        st.info(f"Targeting Rule: **{selected_rule.title}** (Version `v{selected_rule.version}`) | ID: `{selected_rule.id}`")

        events = get_telemetry_events()
        scenarios = get_scenarios()

        if st.button("▶️ Execute Deterministic Rule Evaluation", use_container_width=True):
            with st.spinner("Executing in-memory AST condition matching..."):
                event_results, scenario_results = evaluate_rule_on_dataset(selected_rule, events, scenarios)
                metrics = calculate_detection_metrics(event_results, scenario_results)
                run_id = save_evaluation_run(selected_rule, metrics, event_results)
                st.session_state.active_metrics = metrics
                st.session_state.active_event_results = event_results
                st.session_state.active_scenario_results = scenario_results
                st.session_state.last_run_id = run_id

        if "active_metrics" in st.session_state:
            metrics = st.session_state.active_metrics
            sc_results = st.session_state.active_scenario_results

            # 5 Key Scorecard Metrics
            c1, c2, c3, c4, c5 = st.columns(5)
            c1.markdown(f"""<div class="glass-card glass-card-top-accent-cyan"><div class="card-label">Detection Rate</div><div class="card-value">{metrics.detection_rate}%</div></div>""", unsafe_allow_html=True)
            c2.markdown(f"""<div class="glass-card glass-card-top-accent-green"><div class="card-label">False Positive Rate</div><div class="card-value">{metrics.false_positive_rate}%</div></div>""", unsafe_allow_html=True)
            c3.markdown(f"""<div class="glass-card"><div class="card-label">Precision</div><div class="card-value">{metrics.precision}</div></div>""", unsafe_allow_html=True)
            c4.markdown(f"""<div class="glass-card"><div class="card-label">Recall</div><div class="card-value">{metrics.recall}</div></div>""", unsafe_allow_html=True)
            c5.markdown(f"""<div class="glass-card glass-card-top-accent-violet"><div class="card-label">F1 Score</div><div class="card-value">{metrics.f1_score}</div></div>""", unsafe_allow_html=True)

            st.markdown("<div style='height: 18px;'></div>", unsafe_allow_html=True)

            col_chart1, col_chart2 = st.columns([1, 1], gap="large")

            with col_chart1:
                st.subheader("Confusion Matrix")
                z_matrix = [
                    [metrics.true_positives, metrics.false_negatives],
                    [metrics.false_positives, metrics.true_negatives]
                ]
                fig = go.Figure(data=go.Heatmap(
                    z=z_matrix,
                    x=["Detected (Positive)", "Missed (Negative)"],
                    y=["Actual Attack", "Actual Benign"],
                    colorscale="Blues",
                    text=[[f"TP: {metrics.true_positives}", f"FN: {metrics.false_negatives}"],
                          [f"FP: {metrics.false_positives}", f"TN: {metrics.true_negatives}"]],
                    texttemplate="%{text}",
                    textfont={"size": 17, "family": "Inter, sans-serif"}
                ))
                fig.update_layout(
                    template="plotly_dark",
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    height=320,
                    margin=dict(l=20, r=20, t=30, b=20)
                )
                st.plotly_chart(fig, use_container_width=True)

            with col_chart2:
                st.subheader("Attack Scenario Coverage Breakdown")
                pie_fig = px.pie(
                    names=["Detected Attacks", "Missed Attacks"],
                    values=[metrics.detected_attack_scenarios, metrics.missed_attack_scenarios],
                    color=["Detected Attacks", "Missed Attacks"],
                    color_discrete_map={"Detected Attacks": "#10b981", "Missed Attacks": "#ef4444"},
                    hole=0.55
                )
                pie_fig.update_layout(
                    template="plotly_dark",
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    height=320,
                    margin=dict(l=20, r=20, t=30, b=20)
                )
                st.plotly_chart(pie_fig, use_container_width=True)

            # Scenario Coverage Table
            st.subheader("Scenario-Level Detection Verdicts")
            sc_table = []
            for sc in sc_results:
                if sc.is_attack:
                    status_str = "✅ DETECTED" if sc.detected else "❌ MISSED"
                else:
                    status_str = "⚠️ FALSE POSITIVE" if sc.detected else "🛡️ TRUE NEGATIVE"
                sc_table.append({
                    "Scenario ID": sc.scenario_id,
                    "Scenario Name": sc.scenario_name,
                    "Category": "ATTACK" if sc.is_attack else "BENIGN",
                    "Detection Verdict": status_str,
                    "MITRE Technique": sc.mitre_technique_id or "N/A"
                })
            st.dataframe(pd.DataFrame(sc_table), use_container_width=True, hide_index=True)

# ==============================================================================
# PAGE 6: RULE HARDENING STUDIO
# ==============================================================================
elif page == "🛡️ Rule Hardening Studio":
    st.markdown("""
    <div class="hero-banner">
        <div class="hero-title">Deterministic Rule Hardening Studio</div>
        <div class="hero-subtitle">Automated blind-spot diagnosis, condition expansion, and False-Positive Guardrail verification.</div>
    </div>
    """, unsafe_allow_html=True)

    # Persistent Banner Notice
    if "promotion_banner" in st.session_state:
        st.success(st.session_state["promotion_banner"])
        if st.button("Dismiss notice", key="dismiss_promo_btn"):
            del st.session_state["promotion_banner"]
            st.rerun()

    if not selected_rule:
        st.warning("Please select a rule from the Rule Manager.")
    else:
        st.info(f"Target Baseline: **{selected_rule.title}** (Version `v{selected_rule.version}`) | ID: `{selected_rule.id}`")

        events = get_telemetry_events()
        scenarios = get_scenarios()

        if st.button("🔬 Trigger Deterministic Rule Hardening", use_container_width=True):
            with st.spinner("Analyzing missed conditions, synthesizing hardened rule, and testing FP guardrail..."):
                proposal = evaluate_and_compare_rules(selected_rule, events, scenarios)
                save_hardening_proposal(proposal)
                st.session_state.active_proposal = proposal

        if "active_proposal" in st.session_state:
            p = st.session_state.active_proposal

            st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
            if p.passed_guardrail:
                st.markdown("""
                <div style="background: rgba(16, 185, 129, 0.15); border: 1px solid rgba(16, 185, 129, 0.4); border-radius: 10px; padding: 14px 18px; margin-bottom: 20px;">
                    <b style="color: #34d399; font-size: 1.05rem;">✅ FP Guardrail Passed:</b>
                    <span style="color: #cbd5e1;"> Proposed modifications significantly expand detection coverage without introducing any false alarms on the benign telemetry baseline.</span>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown("""
                <div style="background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.4); border-radius: 10px; padding: 14px 18px; margin-bottom: 20px;">
                    <b style="color: #f87171; font-size: 1.05rem;">❌ Guardrail Blocked:</b>
                    <span style="color: #cbd5e1;"> Proposed modifications introduced false positives on benign baselines and were rejected.</span>
                </div>
                """, unsafe_allow_html=True)

            # Metric Comparison Deltas
            c1, c2, c3, c4 = st.columns(4)
            c1.markdown(f"""<div class="glass-card"><div class="card-label">Original Detection</div><div class="card-value">{p.original_metrics.detection_rate}%</div></div>""", unsafe_allow_html=True)
            delta_dr = round(p.improved_metrics.detection_rate - p.original_metrics.detection_rate, 2)
            c2.markdown(f"""<div class="glass-card glass-card-top-accent-green"><div class="card-label">Hardened Detection</div><div class="card-value" style="color:#10b981;">{p.improved_metrics.detection_rate}%</div><div class="card-subtext" style="color:#10b981; font-weight:700;">▲ +{delta_dr}% Coverage</div></div>""", unsafe_allow_html=True)
            c3.markdown(f"""<div class="glass-card"><div class="card-label">Original False Positives</div><div class="card-value">{p.original_metrics.false_positives}</div></div>""", unsafe_allow_html=True)
            
            fp_delta_text = f"🛡️ 0 New False Alarms" if p.false_positive_impact == 0 else f"⚠️ +{p.false_positive_impact} New False Alarms"
            fp_color = "#10b981" if p.false_positive_impact <= 0 else "#ef4444"
            fp_card_accent = "glass-card-top-accent-green" if p.false_positive_impact <= 0 else "glass-card-top-accent-cyan"
            c4.markdown(f"""<div class="glass-card {fp_card_accent}"><div class="card-label">Hardened False Positives</div><div class="card-value" style="color:{fp_color};">{p.improved_metrics.false_positives}</div><div class="card-subtext" style="color:{fp_color}; font-weight:700;">{fp_delta_text}</div></div>""", unsafe_allow_html=True)

            # Modifications Applied
            st.subheader("Synthesized Rule Modifications")
            for mod in p.modification_reasons:
                st.markdown(f"- 🔧 **{html.escape(mod)}**")

            # Addressed Scenarios
            st.markdown(f"**Addressed Missed Scenarios:** " + " ".join([f"<span class='chip-mitre'>{html.escape(sc)}</span>" for sc in p.addressed_scenarios]), unsafe_allow_html=True)

            # Side-by-Side YAML Comparison
            st.subheader("Side-by-Side Rule Specification")
            col_orig, col_imp = st.columns(2)
            with col_orig:
                st.markdown("**Original Sigma Rule (v1):**")
                st.code(p.original_yaml, language="yaml")
            with col_imp:
                st.markdown(f"**Hardened Sigma Rule (v{selected_rule.version + 1} Candidate):**")
                st.code(p.improved_yaml, language="yaml")

            # Unified Diff
            st.subheader("Unified YAML Diff")
            st.code(p.diff, language="diff")

            # Action Buttons
            c_btn1, c_btn2 = st.columns([1, 1], gap="medium")
            with c_btn1:
                if st.button("💾 Approve & Promote Hardened Rule to Version History", use_container_width=True):
                    improved_rule = parse_sigma_yaml(p.improved_yaml)
                    improved_rule.version = selected_rule.version + 1
                    improved_rule.parent_rule_id = selected_rule.id
                    save_rule(improved_rule, version=improved_rule.version, change_summary="; ".join(p.modification_reasons))
                    st.session_state.selected_rule_id = improved_rule.id
                    
                    # Clean proposal and stale metrics
                    if "active_proposal" in st.session_state:
                        del st.session_state.active_proposal
                    if "active_metrics" in st.session_state:
                        del st.session_state.active_metrics
                    if "active_event_results" in st.session_state:
                        del st.session_state.active_event_results
                    if "active_scenario_results" in st.session_state:
                        del st.session_state.active_scenario_results

                    st.session_state["promotion_banner"] = f"🎉 Rule successfully hardened and promoted to Version {improved_rule.version}! It is now the active rule across all detection and reporting pages."
                    st.rerun()

            with c_btn2:
                if st.button("❌ Reject Proposed Changes", use_container_width=True):
                    del st.session_state.active_proposal
                    st.info("Proposed hardening changes discarded.")
                    st.rerun()
        else:
            if selected_rule and selected_rule.version > 1:
                st.markdown(f"**Current Status:** Target rule is currently at hardened version **v{selected_rule.version}**.")
                st.info(f"💡 You can evaluate its full 100% detection coverage on the **⚡ Detection Results** page or export audit data under **📊 Reports & Exports**.")

# ==============================================================================
# PAGE 7: REPORTS & EXPORTS
# ==============================================================================
elif page == "📊 Reports & Exports":
    st.markdown("""
    <div class="hero-banner">
        <div class="hero-title">Compliance & Defensive Audit Reports</div>
        <div class="hero-subtitle">Export production-ready audit dossiers in JSON, CSV, and printable HTML/PDF formats.</div>
    </div>
    """, unsafe_allow_html=True)

    runs = get_evaluation_runs()
    proposals = get_hardening_proposals()

    if not runs:
        st.warning("No evaluation runs recorded yet. Please run an evaluation on the Detection Results or Rule Hardening page first.")
    else:
        latest_run = runs[0]
        st.info(f"Active Evaluation Audit: **{latest_run['run_id']}** ({latest_run['rule_title']} | Recorded {latest_run['created_at']})")

        # Compile Full Audit Report Data
        report_data = {
            "application": settings.APP_NAME,
            "version": settings.VERSION,
            "timestamp": datetime.utcnow().isoformat(),
            "rule": {
                "id": latest_run["rule_id"],
                "title": latest_run["rule_title"],
                "version": latest_run["rule_version"]
            },
            "metrics": {
                "total_scenarios": latest_run["total_scenarios"],
                "detected_scenarios": latest_run["detected_scenarios"],
                "missed_scenarios": latest_run["missed_scenarios"],
                "detection_rate": latest_run["detection_rate"],
                "false_positives": latest_run["false_positives"],
                "false_positive_rate": latest_run["false_positive_rate"],
                "precision": latest_run["precision"],
                "recall": latest_run["recall"],
                "f1_score": latest_run["f1_score"]
            },
            "proposals_count": len(proposals)
        }

        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.download_button(
                label="📥 Download JSON Dossier",
                data=json.dumps(report_data, indent=2),
                file_name=f"rulehardener_report_{latest_run['run_id']}.json",
                mime="application/json",
                use_container_width=True
            )

        with col2:
            df_runs = pd.DataFrame(runs)
            csv_data = df_runs.to_csv(index=False)
            st.download_button(
                label="📥 Download CSV Metrics",
                data=csv_data,
                file_name=f"rulehardener_metrics_{latest_run['run_id']}.csv",
                mime="text/csv",
                use_container_width=True
            )

        with col3:
            escaped_title = html.escape(str(latest_run['rule_title']))
            escaped_run_id = html.escape(str(latest_run['run_id']))
            fps = latest_run['false_positives']
            det_rate = latest_run['detection_rate']
            fp_badge = '<span class="badge badge-green">0 New FP (Clean)</span>' if fps == 0 else f'<span class="badge badge-red">{fps} FP Flagged</span>'
            dr_badge = '<span class="badge badge-green">Coverage Verified</span>' if det_rate >= 80 else f'<span class="badge badge-amber">{det_rate}% Partial</span>'

            html_report = f"""<!DOCTYPE html>
<html>
<head>
    <title>RuleHardener Audit Report - {escaped_run_id}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; margin: 40px; background: #fff; color: #1e293b; }}
        h1 {{ color: #0f172a; border-bottom: 2px solid #e2e8f0; padding-bottom: 10px; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }}
        .badge-green {{ background: #dcfce7; color: #166534; }}
        .badge-red {{ background: #fee2e2; color: #991b1b; }}
        .badge-amber {{ background: #fef3c7; color: #92400e; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ border: 1px solid #cbd5e1; padding: 10px; text-align: left; }}
        th {{ background: #f8fafc; }}
    </style>
</head>
<body>
    <h1>RuleHardener Defensive Audit Dossier</h1>
    <p><strong>Evaluation Run:</strong> {escaped_run_id}</p>
    <p><strong>Generated At:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
    <p><strong>Target Rule:</strong> {escaped_title} (v{latest_run['rule_version']})</p>
    
    <h2>Detection Performance Scorecard</h2>
    <table>
        <tr><th>Metric</th><th>Value</th><th>Status</th></tr>
        <tr><td>Detection Rate</td><td>{latest_run['detection_rate']}%</td><td>{dr_badge}</td></tr>
        <tr><td>False Positive Rate</td><td>{latest_run['false_positive_rate']}%</td><td>{fp_badge}</td></tr>
        <tr><td>Precision</td><td>{latest_run['precision']}</td><td>Computed (Event-Level)</td></tr>
        <tr><td>Recall</td><td>{latest_run['recall']}</td><td>Computed (Event-Level)</td></tr>
        <tr><td>F1 Score</td><td>{latest_run['f1_score']}</td><td>Computed</td></tr>
    </table>
</body>
</html>
"""
            st.download_button(
                label="📥 Download HTML Report",
                data=html_report,
                file_name=f"rulehardener_audit_{latest_run['run_id']}.html",
                mime="text/html",
                use_container_width=True
            )

        with col4:
            pdf_bytes = generate_pdf_report(latest_run, len(proposals))
            st.download_button(
                label="📥 Download PDF Dossier",
                data=pdf_bytes,
                file_name=f"rulehardener_audit_{latest_run['run_id']}.pdf",
                mime="application/pdf",
                use_container_width=True
            )

        st.subheader("Dossier JSON Preview")
        st.json(report_data)
