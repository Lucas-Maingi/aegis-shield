"""Streamlit dashboard for Aegis Shield.

Provides real-time visibility into LLM gateway activity: total requests, blocked
requests (threat rate), estimated API costs, threat distribution, and a searchable
audit log of all scanned transits.
"""

from __future__ import annotations

import sqlite3
import pandas as pd
import streamlit as st

# Configure page metadata
st.set_page_config(
    page_title="Aegis Shield Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── Title & Sidebar ──────────────────────────────────────────────────────

st.title("🛡️ Aegis Shield — Security Console")
st.markdown("Real-time LLM Gateway compliance audit and threat intelligence.")

db_path = st.sidebar.text_input("SQLite Database Path", "aegis_shield.db")

# ── Data Fetching helpers ────────────────────────────────────────────────

def get_connection():
    return sqlite3.connect(db_path)

def load_data():
    conn = get_connection()
    df = pd.read_sql_query("SELECT * FROM scan_log ORDER BY timestamp DESC", conn)
    conn.close()
    
    # Ensure timestamp is datetime
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df

# ── Main view ────────────────────────────────────────────────────────────

try:
    df = load_data()
except Exception as e:
    st.error(f"Failed to load database. Ensure the gateway has run and created the DB. Error: {str(e)}")
    st.stop()

if df.empty:
    st.info("No scan logs found in the database. Send some requests to the gateway to see them here!")
    st.stop()

# ── KPI Cards ────────────────────────────────────────────────────────────

total_requests = len(df)
blocked_df = df[df["verdict"] == "block"]
total_blocked = len(blocked_df)
threat_rate = (total_blocked / total_requests) * 100 if total_requests > 0 else 0.0
total_cost = df["estimated_cost_usd"].sum()

col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("Total Requests", f"{total_requests:,}")
with col2:
    st.metric("Blocked Requests", f"{total_blocked:,}", delta=f"{threat_rate:.1f}% Threat Rate", delta_color="inverse")
with col3:
    st.metric("Total API Cost", f"${total_cost:.4f}")
with col4:
    st.metric("Active Gateways", "1 Node")

# ── Threat Distribution & Charts ────────────────────────────────────────

st.subheader("Gateway Activity Analytics")

chart_col1, chart_col2 = st.columns(2)

with chart_col1:
    st.markdown("**Request Volume by Verdict**")
    verdict_counts = df["verdict"].value_counts().reset_index()
    verdict_counts.columns = ["Verdict", "Count"]
    st.bar_chart(verdict_counts.set_index("Verdict"))

with chart_col2:
    st.markdown("**Threat Breakdown**")
    # Parse findings JSON to extract threat categories
    categories = []
    for findings_str in df["findings_json"]:
        if findings_str:
            import json
            try:
                findings = json.loads(findings_str)
                for f in findings:
                    categories.append(f.get("category", "unknown"))
            except Exception:
                pass
                
    if categories:
        cat_counts = pd.Series(categories).value_counts().reset_index()
        cat_counts.columns = ["Threat Category", "Occurrences"]
        st.bar_chart(cat_counts.set_index("Threat Category"))
    else:
        st.info("No security threats detected yet.")

# ── Audit Log ────────────────────────────────────────────────────────────

st.subheader("Audit Log")

# Filter controls
filter_col1, filter_col2 = st.columns(2)
with filter_col1:
    verdict_filter = st.multiselect("Filter by Verdict", options=["allow", "block", "warn"], default=["allow", "block", "warn"])
with filter_col2:
    search_query = st.text_input("Search client IP / Request ID")

filtered_df = df[df["verdict"].isin(verdict_filter)]

if search_query:
    filtered_df = filtered_df[
        filtered_df["request_id"].str.contains(search_query, case=False, na=False) |
        filtered_df["client_ip"].str.contains(search_query, case=False, na=False)
    ]

# Format data frame for presentation
if not filtered_df.empty:
    display_df = filtered_df[[
        "request_id", "timestamp", "client_ip", "model", "verdict", 
        "prompt_tokens", "completion_tokens", "upstream_latency_ms", "estimated_cost_usd"
    ]].copy()
    
    st.dataframe(
        display_df,
        column_config={
            "request_id": "Request ID",
            "timestamp": "Timestamp",
            "client_ip": "Client IP",
            "model": "Model",
            "verdict": "Verdict",
            "prompt_tokens": "Prompt Tokens",
            "completion_tokens": "Completion Tokens",
            "upstream_latency_ms": "Upstream Latency (ms)",
            "estimated_cost_usd": st.column_config.NumberColumn("Estimated Cost (USD)", format="$%.4f")
        },
        hide_index=True,
        use_container_width=True
    )
else:
    st.info("No matching records found in the audit log.")
