"""
CVE Analytics Dashboard - Data Warehouse Visualization
Full-featured Streamlit dashboard for Gold Layer CVE data
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import psycopg2
from psycopg2.extras import RealDictCursor
import os
from datetime import datetime, timedelta
import numpy as np

# ================================================================
# CONFIGURATION
# ================================================================

st.set_page_config(
    page_title="CVE Analytics Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Database Configuration
DB_CONFIG = {
    "user": os.getenv("PG_USER", "postgres"),
    "password": os.getenv("PG_PASSWORD", "tip_pwd"),
    "host": os.getenv("PG_HOST", "localhost"),
    "port": os.getenv("PG_PORT", "5432"),
    "database": os.getenv("PG_DB", "tip"),
}

# ================================================================
# DATABASE CONNECTION
# ================================================================

@st.cache_resource
def get_db_engine():
    """Créer un moteur SQLAlchemy pour éviter les warnings"""
    from sqlalchemy import create_engine
    try:
        db_url = f"postgresql://{DB_CONFIG['user']}:{DB_CONFIG['password']}@{DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['database']}"
        engine = create_engine(db_url, pool_pre_ping=True)
        return engine
    except Exception as e:
        st.error(f"❌ Erreur de création du moteur: {e}")
        return None

@st.cache_data(ttl=300)
def execute_query(query, params=None):
    """Exécuter une requête et retourner DataFrame"""
    engine = get_db_engine()
    if engine is None:
        return pd.DataFrame()
    
    try:
        df = pd.read_sql_query(query, engine, params=params)
        return df
    except Exception as e:
        st.error(f"❌ Erreur d'exécution de la requête: {e}")
        return pd.DataFrame()

# ================================================================
# QUERIES
# ================================================================

def get_kpi_stats():
    """Récupérer statistiques KPI principales"""
    query = """
    SELECT 
        COUNT(DISTINCT cve_id) as total_cves,
        COUNT(DISTINCT CASE WHEN cve_year >= EXTRACT(YEAR FROM CURRENT_DATE) THEN cve_id END) as cves_this_year,
        COUNT(DISTINCT source_identifier) as total_sources,
        MAX(published_date) as latest_cve_date
    FROM gold.dim_cve;
    """
    return execute_query(query)

def get_cvss_distribution():
    """Distribution des scores CVSS"""
    query = """
    SELECT 
        cvss_version,
        cvss_severity,
        COUNT(*) as count,
        ROUND(AVG(cvss_score), 2) as avg_score,
        MIN(cvss_score) as min_score,
        MAX(cvss_score) as max_score
    FROM gold.mv_cve_all_cvss
    WHERE cvss_score IS NOT NULL
    GROUP BY cvss_version, cvss_severity
    ORDER BY cvss_version, 
        CASE cvss_severity 
            WHEN 'CRITICAL' THEN 1 
            WHEN 'HIGH' THEN 2 
            WHEN 'MEDIUM' THEN 3 
            WHEN 'LOW' THEN 4 
            ELSE 5 
        END;
    """
    return execute_query(query)

def get_cve_timeline():
    """Timeline des CVE par année"""
    query = """
    SELECT 
        cve_year,
        COUNT(DISTINCT cve_id) as total_cves,
        COUNT(DISTINCT CASE WHEN category = 'critical' THEN cve_id END) as critical_cves,
        COUNT(DISTINCT source_identifier) as sources
    FROM gold.dim_cve
    WHERE cve_year >= 2000
    GROUP BY cve_year
    ORDER BY cve_year;
    """
    return execute_query(query)

def get_top_vendors():
    """Top vendors par nombre de CVE"""
    query = """
    SELECT 
        p.vendor,
        p.total_cves,
        COUNT(DISTINCT bcp.cve_id) as verified_cves,
        p.first_cve_date,
        p.last_cve_date,
        p.product_lifespan_days
    FROM gold.dim_products p
    LEFT JOIN gold.bridge_cve_products bcp ON p.product_id = bcp.product_id
    GROUP BY p.product_id, p.vendor, p.total_cves, p.first_cve_date, 
             p.last_cve_date, p.product_lifespan_days
    ORDER BY p.total_cves DESC
    LIMIT 20;
    """
    return execute_query(query)

def get_top_products():
    """Top produits par nombre de CVE"""
    query = """
    SELECT 
        p.product_name,
        p.vendor,
        p.total_cves,
        p.first_cve_date,
        p.last_cve_date
    FROM gold.dim_products p
    ORDER BY p.total_cves DESC
    LIMIT 20;
    """
    return execute_query(query)

def get_cvss_metrics_analysis():
    """Analyse des métriques CVSS"""
    query = """
    SELECT 
        cvss_version,
        av as attack_vector,
        ac as attack_complexity,
        COUNT(*) as count,
        ROUND(AVG(cvss_score), 2) as avg_score
    FROM gold.mv_cve_all_cvss
    WHERE av IS NOT NULL AND ac IS NOT NULL
    GROUP BY cvss_version, av, ac
    ORDER BY cvss_version, count DESC;
    """
    return execute_query(query)

def get_monthly_trends():
    """Tendances mensuelles des CVE"""
    query = """
    SELECT 
        DATE_TRUNC('month', published_date) as month,
        COUNT(DISTINCT cve_id) as cve_count,
        COUNT(DISTINCT CASE WHEN remotely_exploit = true THEN cve_id END) as remote_exploitable
    FROM gold.dim_cve
    WHERE published_date >= CURRENT_DATE - INTERVAL '24 months'
    GROUP BY DATE_TRUNC('month', published_date)
    ORDER BY month;
    """
    return execute_query(query)

def get_source_statistics():
    """Statistiques par source CVSS"""
    query = """
    SELECT 
        s.source_name,
        COUNT(DISTINCT v2.cve_id) as cvss_v2_count,
        COUNT(DISTINCT v3.cve_id) as cvss_v3_count,
        COUNT(DISTINCT v4.cve_id) as cvss_v4_count,
        COUNT(DISTINCT v2.cve_id) + COUNT(DISTINCT v3.cve_id) + COUNT(DISTINCT v4.cve_id) as total_scores
    FROM gold.dim_cvss_source s
    LEFT JOIN gold.cvss_v2 v2 ON s.source_id = v2.source_id
    LEFT JOIN gold.cvss_v3 v3 ON s.source_id = v3.source_id
    LEFT JOIN gold.cvss_v4 v4 ON s.source_id = v4.source_id
    GROUP BY s.source_name
    ORDER BY total_scores DESC;
    """
    return execute_query(query)

def search_cves(search_term):
    """Rechercher des CVE"""
    query = """
    SELECT 
        c.cve_id,
        c.title,
        c.category,
        c.published_date,
        c.source_identifier,
        COALESCE(MAX(v3.cvss_score), MAX(v2.cvss_score), MAX(v4.cvss_score)) as max_cvss_score,
        COALESCE(MAX(v3.cvss_severity), MAX(v2.cvss_severity), MAX(v4.cvss_severity)) as severity
    FROM gold.dim_cve c
    LEFT JOIN gold.cvss_v3 v3 ON c.cve_id = v3.cve_id
    LEFT JOIN gold.cvss_v2 v2 ON c.cve_id = v2.cve_id
    LEFT JOIN gold.cvss_v4 v4 ON c.cve_id = v4.cve_id
    WHERE c.cve_id ILIKE %s OR c.title ILIKE %s OR c.description ILIKE %s
    GROUP BY c.cve_id, c.title, c.category, c.published_date, c.source_identifier
    ORDER BY c.published_date DESC
    LIMIT 50;
    """
    search_pattern = f"%{search_term}%"
    return execute_query(query, (search_pattern, search_pattern, search_pattern))

# ================================================================
# STYLING
# ================================================================

def apply_custom_css():
    """Appliquer CSS personnalisé"""
    st.markdown("""
    <style>
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 20px;
        border-radius: 10px;
        color: white;
        text-align: center;
    }
    .stMetric {
        background-color: #f0f2f6;
        padding: 15px;
        border-radius: 8px;
        border-left: 4px solid #667eea;
    }
    h1 {
        color: #667eea;
        font-weight: 700;
    }
    .sidebar .sidebar-content {
        background: linear-gradient(180deg, #667eea 0%, #764ba2 100%);
    }
    </style>
    """, unsafe_allow_html=True)

# ================================================================
# VISUALIZATION FUNCTIONS
# ================================================================

def plot_severity_distribution(df):
    """Graphique distribution des sévérités"""
    fig = px.bar(
        df, 
        x='cvss_severity', 
        y='count',
        color='cvss_version',
        title='Distribution des Sévérités CVSS par Version',
        labels={'count': 'Nombre de CVE', 'cvss_severity': 'Sévérité'},
        color_discrete_sequence=px.colors.qualitative.Set2,
        barmode='group'
    )
    fig.update_layout(height=400)
    return fig

def plot_timeline(df):
    """Graphique timeline des CVE"""
    fig = go.Figure()
    
    fig.add_trace(go.Scatter(
        x=df['cve_year'],
        y=df['total_cves'],
        mode='lines+markers',
        name='Total CVE',
        line=dict(color='#667eea', width=3),
        marker=dict(size=8)
    ))
    
    fig.add_trace(go.Scatter(
        x=df['cve_year'],
        y=df['critical_cves'],
        mode='lines+markers',
        name='CVE Critiques',
        line=dict(color='#ff6b6b', width=2, dash='dash'),
        marker=dict(size=6)
    ))
    
    fig.update_layout(
        title='Évolution Temporelle des CVE (2000-Present)',
        xaxis_title='Année',
        yaxis_title='Nombre de CVE',
        hovermode='x unified',
        height=450
    )
    
    return fig

def plot_top_vendors(df):
    """Graphique top vendors"""
    fig = px.bar(
        df.head(15),
        x='total_cves',
        y='vendor',
        orientation='h',
        title='Top 15 Vendors par Nombre de CVE',
        labels={'total_cves': 'Nombre de CVE', 'vendor': 'Vendor'},
        color='total_cves',
        color_continuous_scale='Viridis'
    )
    fig.update_layout(height=500, showlegend=False)
    return fig

def plot_cvss_scores_histogram(df):
    """Histogramme des scores CVSS"""
    fig = px.histogram(
        df,
        x='cvss_score',
        color='cvss_version',
        nbins=30,
        title='Distribution des Scores CVSS',
        labels={'cvss_score': 'Score CVSS', 'count': 'Fréquence'},
        marginal='box',
        color_discrete_sequence=px.colors.qualitative.Pastel
    )
    fig.update_layout(height=400)
    return fig

def plot_monthly_trends(df):
    """Graphique tendances mensuelles"""
    fig = make_subplots(specs=[[{"secondary_y": True}]])
    
    fig.add_trace(
        go.Bar(
            x=df['month'],
            y=df['cve_count'],
            name='Total CVE',
            marker_color='lightblue'
        ),
        secondary_y=False
    )
    
    fig.add_trace(
        go.Scatter(
            x=df['month'],
            y=df['remote_exploitable'],
            name='Exploitables à Distance',
            mode='lines+markers',
            line=dict(color='red', width=2)
        ),
        secondary_y=True
    )
    
    fig.update_layout(
        title='Tendances Mensuelles des CVE (24 derniers mois)',
        hovermode='x unified',
        height=400
    )
    
    fig.update_xaxes(title_text='Mois')
    fig.update_yaxes(title_text='Nombre de CVE', secondary_y=False)
    fig.update_yaxes(title_text='CVE Exploitables', secondary_y=True)
    
    return fig

def plot_attack_vectors(df):
    """Graphique vecteurs d'attaque"""
    av_map = {
        'N': 'Network',
        'A': 'Adjacent',
        'L': 'Local',
        'P': 'Physical'
    }
    df['attack_vector_label'] = df['attack_vector'].map(av_map)
    
    fig = px.sunburst(
        df,
        path=['cvss_version', 'attack_vector_label'],
        values='count',
        title='Vecteurs d\'Attaque par Version CVSS',
        color='avg_score',
        color_continuous_scale='RdYlGn_r'
    )
    fig.update_layout(height=500)
    return fig

# ================================================================
# MAIN APP
# ================================================================

def main():
    apply_custom_css()
    
    # Header
    st.markdown("# 🛡️ CVE Analytics Dashboard")
    st.markdown("### Data Warehouse - Gold Layer Visualization")
    st.markdown("---")
    
    # Sidebar
    with st.sidebar:
        st.image("https://img.icons8.com/clouds/200/security-shield-green.png", width=150)
        st.markdown("## 📊 Navigation")
        
        page = st.radio(
            "Choisir une section:",
            ["🏠 Vue d'ensemble", "📈 Analyses CVSS", "🏢 Vendors & Produits", 
             "🔍 Recherche CVE", "📊 Statistiques Avancées"]
        )
        
        st.markdown("---")
        st.markdown("### ⚙️ Options")
        
        if st.button("🔄 Rafraîchir les données"):
            st.cache_data.clear()
            st.success("Cache actualisé!")
        
        st.markdown("---")
        st.markdown("#### 📍 Connexion DB")
        st.info(f"Host: {DB_CONFIG['host']}\nDB: {DB_CONFIG['database']}")
    
    # ================================================================
    # PAGE: VUE D'ENSEMBLE
    # ================================================================
    
    if page == "🏠 Vue d'ensemble":
        # KPI Section
        st.markdown("## 📊 Indicateurs Clés")
        
        kpi_data = get_kpi_stats()
        
        if not kpi_data.empty:
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric(
                    label="Total CVE",
                    value=f"{kpi_data['total_cves'].iloc[0]:,}",
                    delta="Base complète"
                )
            
            with col2:
                st.metric(
                    label="CVE Cette Année",
                    value=f"{kpi_data['cves_this_year'].iloc[0]:,}",
                    delta=f"+{kpi_data['cves_this_year'].iloc[0]}"
                )
            
            with col3:
                st.metric(
                    label="Sources Uniques",
                    value=f"{kpi_data['total_sources'].iloc[0]:,}",
                    delta="Actives"
                )
            
            with col4:
                latest_date = pd.to_datetime(kpi_data['latest_cve_date'].iloc[0])
                st.metric(
                    label="Dernière CVE",
                    value=latest_date.strftime("%Y-%m-%d"),
                    delta="À jour"
                )
        
        st.markdown("---")
        
        # Timeline et Distribution
        col1, col2 = st.columns([2, 1])
        
        with col1:
            timeline_data = get_cve_timeline()
            if not timeline_data.empty:
                st.plotly_chart(plot_timeline(timeline_data), use_container_width=True)
        
        with col2:
            cvss_dist = get_cvss_distribution()
            if not cvss_dist.empty:
                severity_summary = cvss_dist.groupby('cvss_severity')['count'].sum().reset_index()
                
                fig = px.pie(
                    severity_summary,
                    values='count',
                    names='cvss_severity',
                    title='Répartition par Sévérité',
                    color='cvss_severity',
                    color_discrete_map={
                        'CRITICAL': '#ff0000',
                        'HIGH': '#ff6600',
                        'MEDIUM': '#ffcc00',
                        'LOW': '#99cc00'
                    }
                )
                fig.update_layout(height=400)
                st.plotly_chart(fig, use_container_width=True)
        
        # Tendances mensuelles
        st.markdown("## 📅 Tendances Récentes")
        monthly_data = get_monthly_trends()
        if not monthly_data.empty:
            st.plotly_chart(plot_monthly_trends(monthly_data), use_container_width=True)
    
    # ================================================================
    # PAGE: ANALYSES CVSS
    # ================================================================
    
    elif page == "📈 Analyses CVSS":
        st.markdown("## 📈 Analyses des Scores CVSS")
        
        # Distribution des scores
        st.markdown("### Distribution des Scores")
        cvss_data = execute_query("SELECT cvss_score, cvss_version FROM gold.mv_cve_all_cvss WHERE cvss_score IS NOT NULL")
        
        if not cvss_data.empty:
            col1, col2 = st.columns(2)
            
            with col1:
                st.plotly_chart(plot_cvss_scores_histogram(cvss_data), use_container_width=True)
            
            with col2:
                cvss_dist = get_cvss_distribution()
                st.plotly_chart(plot_severity_distribution(cvss_dist), use_container_width=True)
        
        # Analyse des métriques
        st.markdown("### 🎯 Analyse des Vecteurs d'Attaque")
        metrics_data = get_cvss_metrics_analysis()
        
        if not metrics_data.empty:
            col1, col2 = st.columns(2)
            
            with col1:
                st.plotly_chart(plot_attack_vectors(metrics_data), use_container_width=True)
            
            with col2:
                st.markdown("#### 📋 Statistiques par Version")
                version_stats = cvss_dist.groupby('cvss_version').agg({
                    'count': 'sum',
                    'avg_score': 'mean'
                }).reset_index()
                
                fig = px.bar(
                    version_stats,
                    x='cvss_version',
                    y='count',
                    text='count',
                    title='Nombre de Scores par Version CVSS',
                    color='avg_score',
                    color_continuous_scale='Reds'
                )
                fig.update_traces(texttemplate='%{text:,}', textposition='outside')
                fig.update_layout(height=400)
                st.plotly_chart(fig, use_container_width=True)
        
        # Tableau détaillé
        st.markdown("### 📊 Tableau Détaillé")
        if not cvss_dist.empty:
            st.dataframe(
                cvss_dist.style.background_gradient(subset=['avg_score'], cmap='RdYlGn_r'),
                use_container_width=True
            )
    
    # ================================================================
    # PAGE: VENDORS & PRODUITS
    # ================================================================
    
    elif page == "🏢 Vendors & Produits":
        st.markdown("## 🏢 Analyse Vendors et Produits")
        
        tab1, tab2 = st.tabs(["Top Vendors", "Top Produits"])
        
        with tab1:
            vendors_data = get_top_vendors()
            
            if not vendors_data.empty:
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    st.plotly_chart(plot_top_vendors(vendors_data), use_container_width=True)
                
                with col2:
                    st.markdown("#### 📊 Statistiques")
                    st.metric("Total Vendors", len(vendors_data))
                    st.metric("CVE Moyen par Vendor", f"{vendors_data['total_cves'].mean():.0f}")
                    st.metric("Max CVE (Vendor)", f"{vendors_data['total_cves'].max():,}")
                
                st.markdown("#### 📋 Tableau Détaillé")
                st.dataframe(
                    vendors_data.style.background_gradient(subset=['total_cves'], cmap='Blues'),
                    use_container_width=True
                )
        
        with tab2:
            products_data = get_top_products()
            
            if not products_data.empty:
                st.markdown("#### Top 20 Produits")
                
                fig = px.treemap(
                    products_data.head(20),
                    path=['vendor', 'product_name'],
                    values='total_cves',
                    title='Carte Arborescente des Produits par Vendor',
                    color='total_cves',
                    color_continuous_scale='RdYlBu_r'
                )
                fig.update_layout(height=600)
                st.plotly_chart(fig, use_container_width=True)
                
                st.dataframe(products_data, use_container_width=True)
    
    # ================================================================
    # PAGE: RECHERCHE CVE
    # ================================================================
    
    elif page == "🔍 Recherche CVE":
        st.markdown("## 🔍 Recherche de CVE")
        
        col1, col2 = st.columns([3, 1])
        
        with col1:
            search_term = st.text_input(
                "Rechercher par CVE ID, titre ou description:",
                placeholder="Ex: CVE-2024, apache, buffer overflow..."
            )
        
        with col2:
            st.markdown("####")
            search_btn = st.button("🔎 Rechercher", type="primary", use_container_width=True)
        
        if search_term and search_btn:
            with st.spinner("Recherche en cours..."):
                results = search_cves(search_term)
                
                if not results.empty:
                    st.success(f"✅ {len(results)} résultat(s) trouvé(s)")
                    
                    for idx, row in results.iterrows():
                        with st.expander(f"🔐 {row['cve_id']} - {row['title'][:100]}..."):
                            col1, col2, col3 = st.columns(3)
                            
                            with col1:
                                st.markdown(f"**Catégorie:** {row['category']}")
                                st.markdown(f"**Date:** {row['published_date']}")
                            
                            with col2:
                                severity = row['severity'] if pd.notna(row['severity']) else 'N/A'
                                score = row['max_cvss_score'] if pd.notna(row['max_cvss_score']) else 'N/A'
                                
                                color = {
                                    'CRITICAL': '🔴',
                                    'HIGH': '🟠',
                                    'MEDIUM': '🟡',
                                    'LOW': '🟢'
                                }.get(severity, '⚪')
                                
                                st.markdown(f"**Sévérité:** {color} {severity}")
                                st.markdown(f"**Score CVSS:** {score}")
                            
                            with col3:
                                st.markdown(f"**Source:** {row['source_identifier']}")
                else:
                    st.warning("Aucun résultat trouvé")
    
    # ================================================================
    # PAGE: STATISTIQUES AVANCÉES
    # ================================================================
    
    elif page == "📊 Statistiques Avancées":
        st.markdown("## 📊 Statistiques Avancées")
        
        # Sources CVSS
        st.markdown("### 📡 Statistiques par Source")
        source_stats = get_source_statistics()
        
        if not source_stats.empty:
            col1, col2 = st.columns(2)
            
            with col1:
                fig = px.bar(
                    source_stats,
                    x='source_name',
                    y=['cvss_v2_count', 'cvss_v3_count', 'cvss_v4_count'],
                    title='Scores CVSS par Source et Version',
                    labels={'value': 'Nombre de Scores', 'variable': 'Version'},
                    barmode='stack'
                )
                fig.update_layout(height=400)
                st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                fig = px.pie(
                    source_stats,
                    values='total_scores',
                    names='source_name',
                    title='Répartition des Scores par Source'
                )
                fig.update_layout(height=400)
                st.plotly_chart(fig, use_container_width=True)
            
            st.dataframe(source_stats, use_container_width=True)
        
        # Statistiques générales
        st.markdown("### 📈 Métriques Globales")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            total_products = execute_query("SELECT COUNT(*) as count FROM gold.dim_products")
            if not total_products.empty:
                st.metric("Total Produits", f"{total_products['count'].iloc[0]:,}")
        
        with col2:
            total_bridges = execute_query("SELECT COUNT(*) as count FROM gold.bridge_cve_products")
            if not total_bridges.empty:
                st.metric("Relations CVE-Produits", f"{total_bridges['count'].iloc[0]:,}")
        
        with col3:
            avg_cve_per_product = execute_query("SELECT ROUND(AVG(total_cves), 2) as avg FROM gold.dim_products")
            if not avg_cve_per_product.empty:
                st.metric("CVE Moyen/Produit", f"{avg_cve_per_product['avg'].iloc[0]}")
    
    # Footer
    st.markdown("---")
    st.markdown(
        "<div style='text-align: center; color: gray;'>"
        "CVE Analytics Dashboard | Data Warehouse Gold Layer | "
        f"Dernière mise à jour: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        "</div>",
        unsafe_allow_html=True
    )

if __name__ == "__main__":
    main()