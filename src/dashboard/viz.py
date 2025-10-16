"""
============================================================================
GOLD LAYER STREAMLIT DASHBOARD - CVE Analytics (Clean Rev)
============================================================================
Description : Interactive Streamlit dashboard for Gold layer analytics
Author      : Data Engineering Team
Date        : 2025-10-16
Usage       : streamlit run viz.py
============================================================================
"""

from pathlib import Path
import sys
sys.path.append(str(Path(__file__).resolve().parents[2]))

import os
import logging
from datetime import datetime

import pandas as pd
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
from sqlalchemy import create_engine

# ===============================================================
# 🔧 Logging (console)
# ===============================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("cve_dashboard")

# ===============================================================
# 🔌 Database Connection (PostgreSQL)
# ===============================================================
DB_CONFIG = {
    "user": os.getenv("PG_USER", "postgres"),
    "password": os.getenv("PG_PASSWORD", "tip_pwd"),
    "host": os.getenv("PG_HOST", "localhost"),
    "port": os.getenv("PG_PORT", "5432"),
    "database": os.getenv("PG_DB", "tip"),
}

CONN_STR = (
    f"postgresql+psycopg2://{DB_CONFIG['user']}:{DB_CONFIG['password']}"
    f"@{DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['database']}"
)

# Build a single engine and cache it
@st.cache_resource
def get_db_engine():
    engine = create_engine(CONN_STR)
    # Smoke test
    try:
        with engine.connect() as conn:
            version = conn.exec_driver_sql("SELECT version();").scalar()
            logger.info("✅ Connected successfully to PostgreSQL!")
            logger.info("📦 Database: %s", DB_CONFIG["database"])
            logger.info("🖥️  Host: %s", DB_CONFIG["host"])
            logger.info("🧩 Version: %s", version)
    except Exception as e:
        st.error(f"❌ Failed to connect to PostgreSQL: {e}")
        logger.exception("DB connection failed")
    return engine

@st.cache_data(ttl=300)
def query_data(sql: str) -> pd.DataFrame:
    try:
        engine = get_db_engine()
        df = pd.read_sql(sql, engine)
        return df
    except Exception as e:
        st.error(f"Query failed: {e}")
        logger.exception("Query failed")
        return pd.DataFrame()

# ===============================================================
# 🎛️ Page Config & Styles
# ===============================================================
st.set_page_config(
    page_title="CVE Analytics Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 800;
        color: #1f77b4;
        text-align: center;
        padding: .5rem 0 0.2rem 0;
    }
</style>
""", unsafe_allow_html=True)

# ===============================================================
# 📥 Data Loading helpers (Gold schema)
# ===============================================================
def load_summary_stats() -> dict:
    sql = """
    SELECT 
        COUNT(*) AS total_cves,
        COUNT(*) FILTER (WHERE is_critical = true) AS critical_cves,
        COUNT(*) FILTER (WHERE cvss_severity = 'HIGH') AS high_cves,
        COUNT(*) FILTER (WHERE cvss_severity = 'MEDIUM') AS medium_cves,
        COUNT(*) FILTER (WHERE cvss_severity = 'LOW') AS low_cves,
        ROUND(AVG(cvss_score)::numeric, 2) AS avg_cvss_score,
        ROUND(AVG(risk_score)::numeric, 2) AS avg_risk_score,
        COUNT(*) FILTER (WHERE remotely_exploit = true) AS remote_exploitable
    FROM gold.gold_cve_summary;
    """
    df = query_data(sql)
    return df.iloc[0].to_dict() if not df.empty else {}

def load_yearly_trends() -> pd.DataFrame:
    sql = """
    SELECT 
        cve_year,
        COUNT(*) AS total_cves,
        ROUND(AVG(cvss_score)::numeric, 2) AS avg_cvss_score,
        COUNT(*) FILTER (WHERE cvss_severity = 'CRITICAL') AS critical_count,
        COUNT(*) FILTER (WHERE cvss_severity = 'HIGH') AS high_count,
        COUNT(*) FILTER (WHERE cvss_severity = 'MEDIUM') AS medium_count,
        COUNT(*) FILTER (WHERE cvss_severity = 'LOW') AS low_count,
        COUNT(*) FILTER (WHERE remotely_exploit = true) AS remote_exploitable
    FROM gold.gold_cve_summary
    WHERE cve_year IS NOT NULL
    GROUP BY cve_year
    ORDER BY cve_year;
    """
    return query_data(sql)

def load_monthly_trends() -> pd.DataFrame:
    sql = """
    SELECT 
        period,
        total_cves,
        avg_cvss_score,
        median_cvss_score,
        max_cvss_score,
        remote_exploitable_count,
        dominant_category,
        year
    FROM gold.gold_vulnerability_trends
    ORDER BY period;
    """
    df = query_data(sql)
    if not df.empty and "period" in df.columns:
        df["period"] = pd.to_datetime(df["period"])
    return df

def load_top_vendors(limit: int = 15) -> pd.DataFrame:
    sql = f"""
    SELECT 
        vendor,
        total_products,
        total_vulnerabilities,
        avg_cvss_score,
        vendor_risk_score,
        risk_rank,
        vulnerabilities_per_product,
        remote_exploitable_count
    FROM gold.gold_vendor_security_metrics
    ORDER BY total_vulnerabilities DESC
    LIMIT {int(limit)};
    """
    return query_data(sql)

def load_product_risk_distribution() -> pd.DataFrame:
    sql = """
    SELECT 
        risk_category,
        COUNT(*) AS product_count,
        AVG(product_risk_score) AS avg_risk_score,
        SUM(total_vulnerabilities) AS total_vulns
    FROM gold.gold_product_risk_profile
    WHERE risk_category IS NOT NULL
    GROUP BY risk_category
    ORDER BY 
        CASE risk_category
            WHEN 'CRITICAL' THEN 1
            WHEN 'HIGH' THEN 2
            WHEN 'MEDIUM' THEN 3
            WHEN 'LOW' THEN 4
        END;
    """
    return query_data(sql)

def load_cvss_version_stats() -> pd.DataFrame:
    sql = """
    SELECT 
        versions_count,
        COUNT(*) AS cve_count,
        AVG(score_variance) AS avg_variance,
        AVG(score_range) AS avg_range,
        COUNT(*) FILTER (WHERE is_consistent = true) AS consistent_count
    FROM gold.gold_cvss_version_comparison
    GROUP BY versions_count
    ORDER BY versions_count;
    """
    return query_data(sql)

# Backward-compat alias (the UI may call load_cvss_versions)
def load_cvss_versions() -> pd.DataFrame:
    return load_cvss_version_stats()

def load_top_critical_cves(limit: int = 10) -> pd.DataFrame:
    sql = f"""
    SELECT 
        cve_id,
        title,
        cvss_score,
        cvss_severity,
        risk_score,
        published_date,
        affected_products_count
    FROM gold.gold_cve_summary
    WHERE is_critical = true
    ORDER BY risk_score DESC, cvss_score DESC
    LIMIT {int(limit)};
    """
    df = query_data(sql)
    if not df.empty and "published_date" in df.columns:
        df["published_date"] = pd.to_datetime(df["published_date"]).dt.strftime("%Y-%m-%d")
    return df

def load_severity_distribution() -> pd.DataFrame:
    sql = """
    SELECT 
        COALESCE(cvss_severity, 'UNKNOWN') AS severity,
        COUNT(*) AS count
    FROM gold.gold_cve_summary
    GROUP BY cvss_severity
    ORDER BY 
        CASE cvss_severity
            WHEN 'CRITICAL' THEN 1
            WHEN 'HIGH' THEN 2
            WHEN 'MEDIUM' THEN 3
            WHEN 'LOW' THEN 4
            ELSE 5
        END;
    """
    return query_data(sql)

def load_category_distribution() -> pd.DataFrame:
    sql = """
    SELECT 
        COALESCE(category, 'Unknown') AS category,
        COUNT(*) AS count,
        AVG(cvss_score) AS avg_score
    FROM gold.gold_cve_summary
    GROUP BY category
    ORDER BY count DESC
    LIMIT 10;
    """
    return query_data(sql)

# ===============================================================
# 📊 Chart Builders
# ===============================================================
def plot_yearly_trends(df: pd.DataFrame):
    fig = go.Figure()
    fig.add_bar(name="Critical", x=df["cve_year"], y=df["critical_count"], marker_color="#d62728")
    fig.add_bar(name="High",     x=df["cve_year"], y=df["high_count"],     marker_color="#ff7f0e")
    fig.add_bar(name="Medium",   x=df["cve_year"], y=df["medium_count"],   marker_color="#ffbb78")
    fig.add_bar(name="Low",      x=df["cve_year"], y=df["low_count"],      marker_color="#2ca02c")
    fig.update_layout(
        title="CVE Trends by Year and Severity",
        xaxis_title="Year",
        yaxis_title="Number of CVEs",
        barmode="stack",
        height=400,
        hovermode="x unified",
        legend=dict(orientation="h")
    )
    return fig

def plot_monthly_trends(df: pd.DataFrame):
    fig = make_subplots(specs=[[{"secondary_y": True}]])
    fig.add_scatter(
        x=df["period"], y=df["total_cves"], name="Total CVEs",
        mode="lines+markers", line=dict(color="#1f77b4", width=2),
        secondary_y=False
    )
    fig.add_scatter(
        x=df["period"], y=df["avg_cvss_score"], name="Avg CVSS Score",
        mode="lines+markers", line=dict(color="#d62728", width=2),
        secondary_y=True
    )
    fig.update_xaxes(title_text="Period")
    fig.update_yaxes(title_text="Number of CVEs", secondary_y=False)
    fig.update_yaxes(title_text="Average CVSS Score", secondary_y=True)
    fig.update_layout(title="Monthly Vulnerability Trends", height=400, hovermode="x unified")
    return fig

def plot_vendor_risk(df: pd.DataFrame):
    fig = go.Figure()
    fig.add_bar(
        y=df["vendor"],
        x=df["total_vulnerabilities"],
        orientation="h",
        marker=dict(
            color=df["vendor_risk_score"],
            colorscale="Reds",
            showscale=True,
            colorbar=dict(title="Risk Score"),
        ),
        text=df["total_vulnerabilities"],
        textposition="auto",
        hovertemplate="<b>%{y}</b><br>Vulnerabilities: %{x}<br>Risk Score: %{marker.color:.2f}<extra></extra>",
    )
    fig.update_layout(
        title="Top Vendors by Vulnerability Count",
        xaxis_title="Total Vulnerabilities",
        yaxis_title="Vendor",
        height=500,
        yaxis=dict(autorange="reversed")
    )
    return fig

def plot_severity_pie(df: pd.DataFrame):
    colors = {
        "CRITICAL": "#d62728", "HIGH": "#ff7f0e",
        "MEDIUM": "#ffbb78", "LOW": "#2ca02c", "UNKNOWN": "#7f7f7f"
    }
    fig = go.Figure(data=[go.Pie(
        labels=df["severity"],
        values=df["count"],
        hole=0.4,
        marker=dict(colors=[colors.get(s, "#7f7f7f") for s in df["severity"]]),
        textinfo="label+percent",
        textposition="outside"
    )])
    fig.update_layout(title="CVE Distribution by Severity", height=400)
    return fig

def plot_product_risk(df: pd.DataFrame):
    palette = {"CRITICAL": "#d62728", "HIGH": "#ff7f0e", "MEDIUM": "#ffbb78", "LOW": "#2ca02c"}
    fig = go.Figure()
    fig.add_bar(
        x=df["risk_category"],
        y=df["product_count"],
        marker_color=[palette.get(cat, "#7f7f7f") for cat in df["risk_category"]],
        text=df["product_count"],
        textposition="auto"
    )
    fig.update_layout(
        title="Products by Risk Category",
        xaxis_title="Risk Category",
        yaxis_title="Number of Products",
        height=400
    )
    return fig

def plot_category_distribution(df: pd.DataFrame):
    fig = go.Figure()
    fig.add_bar(
        x=df["category"], y=df["count"],
        marker_color="#1f77b4", text=df["count"], textposition="auto"
    )
    fig.update_layout(
        title="Top CVE Categories",
        xaxis_title="Category", yaxis_title="Count",
        height=400, xaxis={"tickangle": -45}
    )
    return fig

def plot_cvss_versions(df: pd.DataFrame):
    fig = go.Figure()
    fig.add_bar(
        x=df["versions_count"], y=df["cve_count"],
        marker_color="#17becf", text=df["cve_count"], textposition="auto"
    )
    fig.update_layout(
        title="CVEs by Number of CVSS Versions",
        xaxis_title="Number of CVSS Versions", yaxis_title="CVE Count",
        height=400
    )
    return fig

# ===============================================================
# 🧭 UI
# ===============================================================
def sidebar():
    with st.sidebar:
        st.title("Navigation")
        page = st.radio(
            "Select View:",
            ["📊 Overview", "📈 Trends", "🏢 Vendors & Products", "🔍 Detailed Analysis"]
        )

        st.markdown("---")
        st.subheader("Actions")
        if st.button("🔄 Refresh Data"):
            st.cache_data.clear()
            st.rerun()

        st.markdown("---")
        st.caption(f"**Last Updated:** {datetime.now():%Y-%m-%d %H:%M:%S}")
    return page

# ===============================================================
# 🚀 Pages
# ===============================================================
def page_overview():
    st.subheader("📊 Executive Overview")

    stats = load_summary_stats()
    if not stats:
        st.warning("No data available. Please run the ETL pipeline first.")
        return

    total = max(1, stats.get("total_cves", 0))

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total CVEs", f"{stats.get('total_cves', 0):,}")
    c2.metric(
        "Critical CVEs",
        f"{stats.get('critical_cves', 0):,}",
        f"{(stats.get('critical_cves', 0)/total*100):.1f}%"
    )
    c3.metric("Avg CVSS Score", f"{stats.get('avg_cvss_score', 0):.2f}")
    c4.metric(
        "Remote Exploitable",
        f"{stats.get('remote_exploitable', 0):,}",
        f"{(stats.get('remote_exploitable', 0)/total*100):.1f}%"
    )

    st.markdown("---")

    # Severity + Product Risk
    col1, col2 = st.columns(2)
    severity_df = load_severity_distribution()
    if not severity_df.empty:
        col1.subheader("Severity Breakdown")
        col1.plotly_chart(plot_severity_pie(severity_df), width="stretch")

    risk_df = load_product_risk_distribution()
    if not risk_df.empty:
        col2.subheader("Product Risk Distribution")
        col2.plotly_chart(plot_product_risk(risk_df), width="stretch")

    st.markdown("---")
    st.subheader("🚨 Top 10 Critical CVEs")
    top_cves = load_top_critical_cves(10)
    if not top_cves.empty:
        st.dataframe(
            top_cves,
            width="stretch",
            hide_index=True,
            column_config={
                "cve_id": "CVE ID",
                "title": "Title",
                "cvss_score": st.column_config.NumberColumn("CVSS Score", format="%.2f"),
                "risk_score": st.column_config.NumberColumn("Risk Score", format="%.2f"),
                "cvss_severity": "Severity",
                "published_date": "Published",
                "affected_products_count": "Affected Products",
            },
        )

def page_trends():
    st.subheader("📈 Vulnerability Trends")

    st.markdown("#### Yearly Trends")
    yearly_df = load_yearly_trends()
    if not yearly_df.empty:
        st.plotly_chart(plot_yearly_trends(yearly_df), width="stretch")

        c1, c2, c3 = st.columns(3)
        if len(yearly_df) >= 1:
            try:
                total_growth = (
                    (yearly_df.iloc[-1]["total_cves"] / max(1, yearly_df.iloc[0]["total_cves"]) - 1) * 100
                    if len(yearly_df) > 1 else 0
                )
            except Exception:
                total_growth = 0
            c1.metric("Total Growth", f"{total_growth:.1f}%")
            c2.metric("Latest Year", int(yearly_df.iloc[-1]["cve_year"]))
            c3.metric("Peak Year", int(yearly_df.loc[yearly_df["total_cves"].idxmax(), "cve_year"]))

    st.markdown("---")

    st.markdown("#### Monthly Trends")
    monthly_df = load_monthly_trends()
    if not monthly_df.empty:
        st.plotly_chart(plot_monthly_trends(monthly_df), width="stretch")
        with st.expander("📋 View Monthly Data"):
            st.dataframe(monthly_df, width="stretch", hide_index=True)
    else:
        st.info("No monthly trend data available.")

    st.markdown("---")

    st.markdown("#### CVE Categories")
    cat_df = load_category_distribution()
    if not cat_df.empty:
        st.plotly_chart(plot_category_distribution(cat_df), width="stretch")

def page_vendors_products():
    st.subheader("🏢 Vendors & Products Analysis")

    c1, c2 = st.columns([3, 1])
    with c2:
        vendor_limit = st.selectbox("Show top:", [10, 15, 20, 25], index=1)

    st.markdown("#### Top Vendors by Vulnerability Count")
    vendor_df = load_top_vendors(vendor_limit)
    if not vendor_df.empty:
        st.plotly_chart(plot_vendor_risk(vendor_df), width="stretch")
        with st.expander("📋 View Detailed Vendor Metrics"):
            st.dataframe(
                vendor_df,
                width="stretch",
                hide_index=True,
                column_config={
                    "vendor": "Vendor",
                    "total_products": "Products",
                    "total_vulnerabilities": "Vulnerabilities",
                    "avg_cvss_score": st.column_config.NumberColumn("Avg CVSS", format="%.2f"),
                    "vendor_risk_score": st.column_config.NumberColumn("Risk Score", format="%.2f"),
                    "risk_rank": "Risk Rank",
                    "vulnerabilities_per_product": st.column_config.NumberColumn("Vulns/Product", format="%.2f"),
                    "remote_exploitable_count": "Remote Exploitable",
                },
            )

    st.markdown("---")

    col1, col2 = st.columns(2)
    risk_df = load_product_risk_distribution()
    if not risk_df.empty:
        col1.subheader("Product Risk Distribution")
        col1.plotly_chart(plot_product_risk(risk_df), width="stretch")

        col2.subheader("Risk Statistics")
        for _, row in risk_df.iterrows():
            col2.metric(
                label=f"{row['risk_category']} Risk",
                value=f"{int(row['product_count'])} products",
                delta=f"Avg Score: {float(row['avg_risk_score']):.2f}",
            )

def page_detailed():
    st.subheader("🔍 Detailed Analysis")

    st.markdown("#### CVSS Version Coverage")
    cvss_df = load_cvss_versions()
    if not cvss_df.empty:
        st.plotly_chart(plot_cvss_versions(cvss_df), width="stretch")

        c1, c2, c3 = st.columns(3)
        total_cves = int(cvss_df["cve_count"].sum())
        c1.metric("Total CVEs Analyzed", f"{total_cves:,}")

        avg_versions = (
            (cvss_df["versions_count"] * cvss_df["cve_count"]).sum() / max(1, total_cves)
            if total_cves else 0
        )
        c2.metric("Avg Versions per CVE", f"{avg_versions:.2f}")

        if "consistent_count" in cvss_df.columns and total_cves:
            consistency_rate = cvss_df["consistent_count"].sum() / total_cves * 100
            c3.metric("Consistency Rate", f"{consistency_rate:.1f}%")

    st.markdown("---")

    st.markdown("#### 💻 Custom Query")
    with st.expander("Run Custom SQL Query"):
        query = st.text_area(
            "Enter SQL Query:",
            value="SELECT * FROM gold.gold_cve_summary LIMIT 10;",
            height=120
        )
        if st.button("Execute Query"):
            result = query_data(query)
            st.success(f"Query returned {len(result)} rows")
            if not result.empty:
                st.dataframe(result, width="stretch")

    st.markdown("---")

    st.markdown("#### 📊 Data Quality Metrics")
    quality_sql = """
    SELECT 
        'CVE Summary' AS table_name,
        COUNT(*) AS total_records,
        COUNT(*) FILTER (WHERE cvss_score IS NULL) AS missing_cvss,
        COUNT(*) FILTER (WHERE cvss_severity IS NULL) AS missing_severity,
        COUNT(*) FILTER (WHERE description IS NULL) AS missing_description
    FROM gold.gold_cve_summary
    UNION ALL
    SELECT 
        'Product Risk Profile',
        COUNT(*),
        COUNT(*) FILTER (WHERE avg_cvss_score IS NULL),
        COUNT(*) FILTER (WHERE risk_category IS NULL),
        COUNT(*) FILTER (WHERE product_name IS NULL)
    FROM gold.gold_product_risk_profile;
    """
    quality_df = query_data(quality_sql)
    if not quality_df.empty:
        st.dataframe(quality_df, width="stretch", hide_index=True)

# ===============================================================
# 🧠 Main
# ===============================================================
def main():
    st.markdown('<h1 class="main-header">🛡️ CVE Analytics Dashboard — Gold Layer</h1>', unsafe_allow_html=True)
    st.markdown("---")

    page = sidebar()

    if page == "📊 Overview":
        page_overview()
    elif page == "📈 Trends":
        page_trends()
    elif page == "🏢 Vendors & Products":
        page_vendors_products()
    elif page == "🔍 Detailed Analysis":
        page_detailed()
    else:
        st.info("Select a page in the sidebar.")

if __name__ == "__main__":
    main()
