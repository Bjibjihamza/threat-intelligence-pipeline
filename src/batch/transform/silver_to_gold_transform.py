"""
============================================================================
SILVER TO GOLD TRANSFORMATION - CVE Analytics Layer
============================================================================
Description: Transform normalized Silver data into business-ready Gold layer
            with aggregations, KPIs, and analytical tables
Author: Data Engineering Team
Date: 2025-10-16
============================================================================
"""

from pathlib import Path
import sys
sys.path.append(str(Path(__file__).resolve().parents[2]))

import logging
from datetime import datetime
from typing import Dict, Any, Optional, List
import numpy as np
import pandas as pd
from sqlalchemy import text
from sqlalchemy.engine import Engine

from database.connection import create_db_engine

# ============================================================================
# LOGGING SETUP
# ============================================================================
PROJECT_ROOT = Path(__file__).resolve().parents[3]
LOGS_DIR = PROJECT_ROOT / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOGS_DIR / "silver_to_gold.log"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ============================================================================
# Small helpers (coercion, dtype hygiene, safe ops)
# ============================================================================
def coerce_numeric(df: pd.DataFrame, cols: List[str]) -> None:
    """Coerce listed columns to numeric (NaN on bad), in-place if column exists."""
    for c in cols:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors='coerce')

def coerce_datetime(df: pd.DataFrame, cols: List[str]) -> None:
    for c in cols:
        if c in df.columns:
            df[c] = pd.to_datetime(df[c], errors='coerce')

def coerce_bool(series: pd.Series) -> pd.Series:
    if series is None:
        return pd.Series([], dtype='boolean')
    mapping = {
        True: True, False: False,
        'true': True, 'false': False,
        'True': True, 'False': False,
        1: True, 0: False, '1': True, '0': False,
        't': True, 'f': False, 'T': True, 'F': False
    }
    return series.map(mapping).fillna(False).astype('boolean')

def safe_round(series: pd.Series, ndigits=2) -> pd.Series:
    """Round only if numeric; otherwise coerce to numeric then round."""
    if series.dtype.kind in "biufc":
        return series.round(ndigits)
    s = pd.to_numeric(series, errors='coerce')
    return s.round(ndigits)

def ensure_columns(df: pd.DataFrame, columns: Dict[str, str]) -> pd.DataFrame:
    """Ensure df has the given columns with specified pandas dtypes."""
    for col, dtype in columns.items():
        if col not in df.columns:
            df[col] = pd.Series([], dtype=dtype)
        else:
            try:
                if dtype.startswith('datetime64'):
                    df[col] = pd.to_datetime(df[col], errors='coerce')
                elif dtype == 'boolean':
                    df[col] = coerce_bool(df[col])
                elif dtype in ('float64', 'float32'):
                    df[col] = pd.to_numeric(df[col], errors='coerce')
                elif dtype in ('Int64', 'Int32'):
                    df[col] = pd.to_numeric(df[col], errors='coerce').astype(dtype)
                elif dtype == 'string':
                    df[col] = df[col].astype('string')
                else:
                    df[col] = df[col].astype(dtype)
            except Exception:
                # fallback: best effort without crashing
                pass
    # Preserve column order as given
    return df[list(columns.keys())]

# ============================================================================
# SCHEMA VALIDATION
# ============================================================================
def verify_gold_schema(engine: Engine) -> bool:
    """Verify Gold schema exists, create if not."""
    logger.info("🔍 Verifying Gold schema...")
    with engine.connect() as conn:
        exists = conn.execute(text("""
            SELECT 1 FROM information_schema.schemata WHERE schema_name='gold'
        """)).fetchone()
        if not exists:
            logger.warning("⚠️  Gold schema doesn't exist, creating...")
            conn.execute(text("CREATE SCHEMA gold"))
            conn.commit()
            logger.info("✅ Gold schema created")
        else:
            logger.info("✅ Gold schema exists")
    return True

# ============================================================================
# DATA LOADING FROM SILVER
# ============================================================================
def load_silver_data(engine: Engine) -> Dict[str, pd.DataFrame]:
    """Load all necessary data from Silver layer."""
    logger.info("=" * 70)
    logger.info("📥 LOADING DATA FROM SILVER LAYER")
    logger.info("=" * 70)

    silver_data: Dict[str, pd.DataFrame] = {}

    def read_sql_df(sql: str) -> pd.DataFrame:
        try:
            return pd.read_sql(sql, engine)
        except Exception as e:
            logger.warning(f"ℹ️ Query returned no rows or failed: {e}")
            return pd.DataFrame()

    # dim_cve
    logger.info("📊 Loading dim_cve...")
    df_cve = read_sql_df("SELECT * FROM silver.dim_cve")
    logger.info(f"   ✓ Loaded {len(df_cve):,} CVEs")
    coerce_datetime(df_cve, ['published_date', 'last_modified', 'updated_at', 'created_at'])
    if 'remotely_exploit' in df_cve.columns:
        df_cve['remotely_exploit'] = coerce_bool(df_cve['remotely_exploit'])

    # fact_cvss_scores + source
    logger.info("📊 Loading fact_cvss_scores...")
    df_cvss = read_sql_df("""
        SELECT f.*, s.source_name
        FROM silver.fact_cvss_scores f
        LEFT JOIN silver.dim_cvss_source s ON f.source_id = s.source_id
    """)
    logger.info(f"   ✓ Loaded {len(df_cvss):,} CVSS scores")
    coerce_numeric(df_cvss, ['cvss_score', 'cvss_exploitability_score', 'cvss_impact_score'])
    if 'cvss_version' in df_cvss.columns:
        df_cvss['cvss_version'] = df_cvss['cvss_version'].astype('string')

    # dim_products
    logger.info("📊 Loading dim_products...")
    df_products = read_sql_df("SELECT * FROM silver.dim_products")
    logger.info(f"   ✓ Loaded {len(df_products):,} products")
    # Optional numeric fields if they exist
    coerce_numeric(df_products, ['product_lifespan_days'])

    # bridge
    logger.info("📊 Loading bridge_cve_products...")
    df_bridge = read_sql_df("SELECT * FROM silver.bridge_cve_products")
    logger.info(f"   ✓ Loaded {len(df_bridge):,} relationships")

    logger.info("=" * 70)
    logger.info("✅ All Silver data loaded successfully")
    logger.info("=" * 70)

    silver_data['dim_cve'] = df_cve
    silver_data['fact_cvss'] = df_cvss
    silver_data['dim_products'] = df_products
    silver_data['bridge'] = df_bridge
    return silver_data

# ============================================================================
# GOLD: CVE SUMMARY
# ============================================================================
def create_gold_cve_summary(silver_data: Dict[str, pd.DataFrame]) -> pd.DataFrame:
    """
    Create aggregated CVE summary with key metrics (empty-safe + numeric coercion)
    """
    logger.info("🔨 Creating gold_cve_summary...")

    df_cve = silver_data.get('dim_cve', pd.DataFrame()).copy()
    df_cvss = silver_data.get('fact_cvss', pd.DataFrame()).copy()
    df_bridge = silver_data.get('bridge', pd.DataFrame()).copy()

    final_cols_types = {
        'cve_id': 'string',
        'title': 'string',
        'description': 'string',
        'category': 'string',
        'published_date': 'datetime64[ns]',
        'last_modified': 'datetime64[ns]',
        'cve_year': 'Int64',
        'remotely_exploit': 'boolean',
        'source_identifier': 'string',
        'cvss_version': 'string',
        'cvss_score': 'float64',
        'cvss_severity': 'string',
        'cvss_exploitability_score': 'float64',
        'cvss_impact_score': 'float64',
        'affected_products_count': 'Int64',
        'cvss_sources_count': 'Int64',
        'risk_score': 'float64',
        'is_critical': 'boolean'
    }

    if df_cve.empty:
        logger.info("ℹ️ dim_cve is empty → returning empty gold_cve_summary")
        return ensure_columns(pd.DataFrame(), final_cols_types)

    # Prepare CVSS latest per CVE (prefer higher version, then higher score)
    if not df_cvss.empty:
        df_cvss['version_priority'] = df_cvss.get('cvss_version', pd.Series(dtype='string')).map({
            'CVSS 4.0': 4, 'CVSS 3.1': 3, 'CVSS 3.0': 2, 'CVSS 2.0': 1
        }).fillna(0)

        coerce_numeric(df_cvss, ['cvss_score', 'cvss_exploitability_score', 'cvss_impact_score'])
        df_cvss_sorted = df_cvss.sort_values(
            ['cve_id', 'version_priority', 'cvss_score'],
            ascending=[True, False, False]
        )
        df_latest_cvss = df_cvss_sorted.groupby('cve_id', as_index=False).first()
    else:
        df_latest_cvss = pd.DataFrame(columns=['cve_id','cvss_version','cvss_score','cvss_severity',
                                               'cvss_exploitability_score','cvss_impact_score'])

    # Products and sources counts
    if not df_bridge.empty:
        product_counts = df_bridge.groupby('cve_id').size().reset_index(name='affected_products_count')
    else:
        product_counts = pd.DataFrame(columns=['cve_id', 'affected_products_count'])

    if not df_cvss.empty:
        source_counts = df_cvss.groupby('cve_id')['source_name'].nunique().reset_index(name='cvss_sources_count')
    else:
        source_counts = pd.DataFrame(columns=['cve_id', 'cvss_sources_count'])

    # Merge
    gold_cve = df_cve.merge(
        df_latest_cvss[['cve_id','cvss_version','cvss_score','cvss_severity',
                        'cvss_exploitability_score','cvss_impact_score']],
        on='cve_id', how='left'
    ).merge(product_counts, on='cve_id', how='left') \
     .merge(source_counts, on='cve_id', how='left')

    # Coerce types needed for math
    coerce_numeric(gold_cve, ['cvss_score','cvss_exploitability_score','cvss_impact_score'])
    coerce_datetime(gold_cve, ['published_date','last_modified'])
    if 'remotely_exploit' in gold_cve.columns:
        gold_cve['remotely_exploit'] = coerce_bool(gold_cve['remotely_exploit'])
    else:
        gold_cve['remotely_exploit'] = pd.Series(False, index=gold_cve.index, dtype='boolean')

    gold_cve['affected_products_count'] = pd.to_numeric(gold_cve.get('affected_products_count', 0), errors='coerce').fillna(0).astype('Int64')
    gold_cve['cvss_sources_count']     = pd.to_numeric(gold_cve.get('cvss_sources_count', 0), errors='coerce').fillna(0).astype('Int64')

    # Risk score
    cvss_part = gold_cve['cvss_score'].fillna(0) * 0.6
    explo_part = gold_cve['cvss_exploitability_score'].fillna(0) * 0.3
    remote_part = gold_cve['remotely_exploit'].astype(int) * (10 * 0.1)
    gold_cve['risk_score'] = (cvss_part + explo_part + remote_part).astype(float)
    gold_cve['risk_score'] = safe_round(gold_cve['risk_score'], 2)

    # Critical flag
    gold_cve['is_critical'] = (
        gold_cve['cvss_severity'].isin(['CRITICAL', 'HIGH']).fillna(False) |
        (gold_cve['cvss_score'].fillna(0) >= 7.0) |
        (gold_cve['remotely_exploit'] == True)
    ).astype('boolean')

    # Year
    if 'cve_year' not in gold_cve.columns or gold_cve['cve_year'].isna().all():
        if 'published_date' in gold_cve.columns:
            gold_cve['cve_year'] = gold_cve['published_date'].dt.year.astype('Int64')
        else:
            gold_cve['cve_year'] = pd.Series(pd.array([None]*len(gold_cve), dtype='Int64'))

    # Final select + enforce dtypes
    gold_cve = ensure_columns(gold_cve, final_cols_types)

    logger.info(f"✅ gold_cve_summary: {len(gold_cve):,} rows")
    logger.info(f"   • Critical CVEs: {int(gold_cve['is_critical'].sum()) if not gold_cve.empty else 0:,}")
    logger.info(f"   • Avg Risk Score: {gold_cve['risk_score'].mean():.2f}" if not gold_cve['risk_score'].empty else "   • Avg Risk Score: n/a")
    return gold_cve

# ============================================================================
# GOLD: VULNERABILITY TRENDS (TEMPORAL)
# ============================================================================
def create_gold_vulnerability_trends(silver_data: Dict[str, pd.DataFrame]) -> pd.DataFrame:
    """
    Aggregate CVE data by month; empty-safe and dtype-safe
    """
    logger.info("🔨 Creating gold_vulnerability_trends...")

    df_cve = silver_data.get('dim_cve', pd.DataFrame()).copy()
    df_cvss = silver_data.get('fact_cvss', pd.DataFrame()).copy()

    cols_types = {
        'period': 'string',
        'total_cves': 'Int64',
        'avg_cvss_score': 'float64',
        'median_cvss_score': 'float64',
        'max_cvss_score': 'float64',
        'remote_exploitable_count': 'Int64',
        'dominant_category': 'string',
        'period_type': 'string',
        'year': 'Int64'
    }

    if df_cve.empty:
        logger.info("ℹ️ dim_cve is empty → returning empty trends")
        return ensure_columns(pd.DataFrame(), cols_types)

    coerce_datetime(df_cve, ['published_date'])
    if 'remotely_exploit' in df_cve.columns:
        df_cve['remotely_exploit'] = coerce_bool(df_cve['remotely_exploit'])
    coerce_numeric(df_cvss, ['cvss_score'])

    # Latest cvss per cve (if available)
    if not df_cvss.empty:
        df_cvss_sorted = df_cvss.sort_values(['cve_id', 'cvss_score'], ascending=[True, False])
        df_latest = df_cvss_sorted.groupby('cve_id', as_index=False).first()
        df = df_cve.merge(df_latest[['cve_id','cvss_score','cvss_severity']], on='cve_id', how='left')
    else:
        df = df_cve.copy()
        df['cvss_score'] = np.nan
        df['cvss_severity'] = pd.NA

    df['year_month'] = df['published_date'].dt.to_period('M').astype(str)

    # Aggregate monthly
    def remote_sum(x: pd.Series) -> int:
        try:
            return int(coerce_bool(x).sum())
        except Exception:
            return 0

    def first_mode(x: pd.Series):
        m = x.mode(dropna=True)
        return m.iloc[0] if len(m) else pd.NA

    grouped = df.groupby('year_month', dropna=True).agg(
        total_cves=('cve_id','count'),
        avg_cvss_score=('cvss_score', 'mean'),
        median_cvss_score=('cvss_score', 'median'),
        max_cvss_score=('cvss_score', 'max'),
        remote_exploitable_count=('remotely_exploit', remote_sum),
        dominant_category=('category', first_mode)
    ).reset_index().rename(columns={'year_month':'period'})

    if grouped.empty:
        return ensure_columns(pd.DataFrame(), cols_types)

    # Additional fields
    grouped['period_type'] = 'monthly'
    grouped['year'] = grouped['period'].str[:4].astype('Int64')

    # Rounding numerics
    for col in ['avg_cvss_score','median_cvss_score','max_cvss_score']:
        grouped[col] = safe_round(grouped[col], 2)

    # Enforce dtypes
    grouped = ensure_columns(grouped, cols_types)

    logger.info(f"✅ gold_vulnerability_trends: {len(grouped):,} periods")
    if not grouped.empty:
        logger.info(f"   • Date range: {grouped['period'].min()} → {grouped['period'].max()}")
    return grouped

# ============================================================================
# GOLD: PRODUCT RISK PROFILE
# ============================================================================
def create_gold_product_risk(silver_data: Dict[str, pd.DataFrame]) -> pd.DataFrame:
    """
    Aggregate product-level metrics and risk profiles (empty-safe)
    """
    logger.info("🔨 Creating gold_product_risk_profile...")

    df_products = silver_data.get('dim_products', pd.DataFrame()).copy()
    df_bridge   = silver_data.get('bridge', pd.DataFrame()).copy()
    df_cvss     = silver_data.get('fact_cvss', pd.DataFrame()).copy()
    df_cve      = silver_data.get('dim_cve', pd.DataFrame()).copy()

    cols_types = {
        'product_id': 'Int64',
        'vendor': 'string',
        'product_name': 'string',
        'total_vulnerabilities': 'Int64',
        'avg_cvss_score': 'float64',
        'median_cvss_score': 'float64',
        'max_cvss_score': 'float64',
        'min_cvss_score': 'float64',
        'avg_exploitability': 'float64',
        'avg_impact': 'float64',
        'remote_exploitable_count': 'Int64',
        'first_vulnerability_date': 'datetime64[ns]',
        'last_vulnerability_date': 'datetime64[ns]',
        'product_lifespan_days': 'float64',
        'vulnerability_density': 'float64',
        'critical_vulnerability_ratio': 'float64',
        'product_risk_score': 'float64',
        'risk_category': 'string'
    }

    if df_products.empty:
        logger.info("ℹ️ dim_products is empty → returning empty profile")
        return ensure_columns(pd.DataFrame(), cols_types)

    # Joins (safe)
    coerce_numeric(df_cvss, ['cvss_score','cvss_exploitability_score','cvss_impact_score'])
    coerce_datetime(df_cve, ['published_date'])
    if 'remotely_exploit' in df_cve.columns:
        df_cve['remotely_exploit'] = coerce_bool(df_cve['remotely_exploit'])
    coerce_numeric(df_products, ['product_lifespan_days'])

    df = df_bridge.merge(df_cvss, on='cve_id', how='left') \
                  .merge(df_cve[['cve_id','published_date','remotely_exploit']], on='cve_id', how='left')

    # Aggregations per product
    if df.empty:
        base = df_products[['product_id','vendor','product_name']].copy()
        result = ensure_columns(base, cols_types)
        return result

    def remote_sum(x: pd.Series) -> int:
        return int(coerce_bool(x).sum())

    product_metrics = df.groupby('product_id', dropna=False).agg(
        total_vulnerabilities=('cve_id','count'),
        avg_cvss_score=('cvss_score','mean'),
        median_cvss_score=('cvss_score','median'),
        max_cvss_score=('cvss_score','max'),
        min_cvss_score=('cvss_score','min'),
        avg_exploitability=('cvss_exploitability_score','mean'),
        avg_impact=('cvss_impact_score','mean'),
        remote_exploitable_count=('remotely_exploit', remote_sum),
        first_vulnerability_date=('published_date','min'),
        last_vulnerability_date=('published_date','max')
    ).reset_index()

    gold_products = df_products.merge(product_metrics, on='product_id', how='left')

    # Derived metrics
    gold_products['product_lifespan_days'] = pd.to_numeric(
        gold_products.get('product_lifespan_days', np.nan), errors='coerce'
    )

    denom_years = (gold_products['product_lifespan_days'].fillna(0) / 365.0).replace(0, np.nan)
    gold_products['vulnerability_density'] = (gold_products['total_vulnerabilities'] / denom_years).fillna(0.0)
    gold_products['vulnerability_density'] = safe_round(gold_products['vulnerability_density'], 2)

    # Critical/high ratio (guard against divide-by-zero)
    if not df.empty:
        highcrit_counts = df[df['cvss_severity'].isin(['CRITICAL','HIGH'])].groupby('product_id')['cve_id'].count()
        total_counts = product_metrics.set_index('product_id')['total_vulnerabilities']
        ratio = (highcrit_counts / total_counts).reindex(total_counts.index).fillna(0.0)
        gold_products = gold_products.merge(ratio.rename('critical_vulnerability_ratio'), on='product_id', how='left')
    else:
        gold_products['critical_vulnerability_ratio'] = 0.0

    # Risk score
    gold_products['product_risk_score'] = (
        gold_products['avg_cvss_score'].fillna(0)*0.4 +
        gold_products['avg_exploitability'].fillna(0)*0.3 +
        gold_products['vulnerability_density'].fillna(0)*0.2 +
        (gold_products['remote_exploitable_count'].fillna(0) /
         gold_products['total_vulnerabilities'].replace(0, np.nan)).fillna(0) * 10 * 0.1
    ).astype(float)
    gold_products['product_risk_score'] = safe_round(gold_products['product_risk_score'], 2)

    # Risk category
    bins = [0, 3, 5, 7, 10]
    labels = ['LOW','MEDIUM','HIGH','CRITICAL']
    try:
        gold_products['risk_category'] = pd.cut(
            gold_products['product_risk_score'].fillna(0),
            bins=bins, labels=labels, include_lowest=True
        ).astype('string')
    except Exception:
        gold_products['risk_category'] = 'LOW'

    # Round some columns
    for col in ['avg_cvss_score','median_cvss_score','avg_exploitability','avg_impact','critical_vulnerability_ratio']:
        if col in gold_products.columns:
            gold_products[col] = safe_round(gold_products[col], 2 if col != 'critical_vulnerability_ratio' else 3)

    gold_products = ensure_columns(gold_products, cols_types)
    logger.info(f"✅ gold_product_risk_profile: {len(gold_products):,} products")
    if 'risk_category' in gold_products.columns and not gold_products.empty:
        logger.info(f"   • High/Critical: {(gold_products['risk_category'].isin(['HIGH','CRITICAL'])).sum():,}")
    return gold_products

# ============================================================================
# GOLD: CVSS VERSION COMPARISON
# ============================================================================
def create_gold_cvss_comparison(silver_data: Dict[str, pd.DataFrame]) -> pd.DataFrame:
    """
    Compare CVSS scores across versions and sources for each CVE (empty-safe)
    """
    logger.info("🔨 Creating gold_cvss_version_comparison...")

    df_cvss = silver_data.get('fact_cvss', pd.DataFrame()).copy()
    cols_types = {
        'cve_id': 'string',
        'score_cvss_2_0': 'float64',
        'score_cvss_3_0': 'float64',
        'score_cvss_3_1': 'float64',
        'score_cvss_4_0': 'float64',
        'score_variance': 'float64',
        'score_range': 'float64',
        'versions_count': 'Int64',
        'source_diversity': 'Int64',
        'dominant_severity': 'string',
        'is_consistent': 'boolean'
    }

    if df_cvss.empty:
        logger.info("ℹ️ fact_cvss_scores empty → returning empty comparison")
        return ensure_columns(pd.DataFrame(), cols_types)

    coerce_numeric(df_cvss, ['cvss_score'])
    # Pivot: max per version
    pivot = df_cvss.pivot_table(
        index='cve_id', columns='cvss_version', values='cvss_score', aggfunc='max'
    ).reset_index()
    pivot.columns.name = None

    rename_map = {
        'CVSS 2.0': 'score_cvss_2_0',
        'CVSS 3.0': 'score_cvss_3_0',
        'CVSS 3.1': 'score_cvss_3_1',
        'CVSS 4.0': 'score_cvss_4_0'
    }
    pivot = pivot.rename(columns=rename_map)

    score_cols = [c for c in pivot.columns if c.startswith('score_')]
    pivot['score_variance'] = pivot[score_cols].var(axis=1, skipna=True)
    pivot['score_range'] = pivot[score_cols].max(axis=1, skipna=True) - pivot[score_cols].min(axis=1, skipna=True)
    pivot['versions_count'] = pivot[score_cols].notna().sum(axis=1).astype('Int64')

    # Source diversity + dominant severity
    src = df_cvss.groupby('cve_id').agg(
        source_diversity=('source_name','nunique'),
        dominant_severity=('cvss_severity', lambda x: x.mode().iloc[0] if len(x.mode()) else pd.NA)
    ).reset_index()

    out = pivot.merge(src, on='cve_id', how='left')
    out['is_consistent'] = (
        (out['score_variance'] < 1.0) | (out['score_range'] < 2.0)
    ).fillna(False).astype('boolean')

    # Round floats
    for c in ['score_variance','score_range'] + score_cols:
        if c in out.columns:
            out[c] = safe_round(out[c], 2)

    out = ensure_columns(out, cols_types)
    logger.info(f"✅ gold_cvss_version_comparison: {len(out):,} CVEs")
    return out

# ============================================================================
# GOLD: VENDOR SECURITY METRICS
# ============================================================================
def create_gold_vendor_metrics(silver_data: Dict[str, pd.DataFrame]) -> pd.DataFrame:
    """
    Aggregate security metrics by vendor (empty-safe)
    """
    logger.info("🔨 Creating gold_vendor_security_metrics...")

    df_products = silver_data.get('dim_products', pd.DataFrame()).copy()
    df_bridge   = silver_data.get('bridge', pd.DataFrame()).copy()
    df_cvss     = silver_data.get('fact_cvss', pd.DataFrame()).copy()
    df_cve      = silver_data.get('dim_cve', pd.DataFrame()).copy()

    cols_types = {
        'vendor': 'string',
        'total_products': 'Int64',
        'total_vulnerabilities': 'Int64',
        'avg_cvss_score': 'float64',
        'max_cvss_score': 'float64',
        'avg_exploitability': 'float64',
        'remote_exploitable_count': 'Int64',
        'vulnerability_span_years': 'Int64',
        'vulnerabilities_per_product': 'float64',
        'vendor_risk_score': 'float64',
        'risk_rank': 'Int64'
    }

    if df_products.empty or df_bridge.empty:
        logger.info("ℹ️ products/bridge empty → returning empty vendor metrics")
        return ensure_columns(pd.DataFrame(), cols_types)

    # Join data
    coerce_numeric(df_cvss, ['cvss_score','cvss_exploitability_score'])
    if 'remotely_exploit' in df_cve.columns:
        df_cve['remotely_exploit'] = coerce_bool(df_cve['remotely_exploit'])

    df = df_products.merge(df_bridge, on='product_id', how='inner') \
                    .merge(df_cvss, on='cve_id', how='left') \
                    .merge(df_cve[['cve_id','cve_year','remotely_exploit']], on='cve_id', how='left')

    if df.empty:
        return ensure_columns(pd.DataFrame(), cols_types)

    def remote_sum(x: pd.Series) -> int:
        return int(coerce_bool(x).sum())

    vendor_metrics = df.groupby('vendor', dropna=False).agg(
        total_products=('product_id','nunique'),
        total_vulnerabilities=('cve_id','count'),
        avg_cvss_score=('cvss_score','mean'),
        max_cvss_score=('cvss_score','max'),
        avg_exploitability=('cvss_exploitability_score','mean'),
        remote_exploitable_count=('remotely_exploit', remote_sum),
        vulnerability_span_years=('cve_year', lambda x: (x.max() - x.min()) if x.notna().any() else 0)
    ).reset_index()

    vendor_metrics['vulnerabilities_per_product'] = (
        vendor_metrics['total_vulnerabilities'] / vendor_metrics['total_products'].replace(0, np.nan)
    ).fillna(0.0)

    vendor_metrics['vendor_risk_score'] = (
        vendor_metrics['avg_cvss_score'].fillna(0)*0.5 +
        vendor_metrics['vulnerabilities_per_product']*0.3 +
        (vendor_metrics['remote_exploitable_count'] /
         vendor_metrics['total_vulnerabilities'].replace(0, np.nan)).fillna(0) * 10 * 0.2
    ).astype(float)
    vendor_metrics['vendor_risk_score'] = safe_round(vendor_metrics['vendor_risk_score'], 2)

    # Rank vendors (dense)
    if not vendor_metrics.empty:
        vendor_metrics['risk_rank'] = vendor_metrics['vendor_risk_score'].rank(ascending=False, method='dense').astype('Int64')
    else:
        vendor_metrics['risk_rank'] = pd.Series([], dtype='Int64')

    # Rounds
    for col in ['avg_cvss_score','max_cvss_score','avg_exploitability','vulnerabilities_per_product']:
        if col in vendor_metrics.columns:
            vendor_metrics[col] = safe_round(vendor_metrics[col], 2)

    vendor_metrics = vendor_metrics.sort_values('total_vulnerabilities', ascending=False)
    vendor_metrics = ensure_columns(vendor_metrics, cols_types)

    logger.info(f"✅ gold_vendor_security_metrics: {len(vendor_metrics):,} vendors")
    if not vendor_metrics.empty:
        logger.info(f"   • Avg vulns/vendor: {vendor_metrics['total_vulnerabilities'].mean():.0f}")
    return vendor_metrics


def drop_dependent_views(engine: Engine, schema: str = 'gold') -> None:
    """
    Drop all materialized views in the Gold schema before dropping tables
    """
    logger.info("🔍 Checking for dependent materialized views...")
    
    with engine.begin() as conn:
        # Find all materialized views in the schema
        result = conn.execute(text(f"""
            SELECT matviewname 
            FROM pg_matviews 
            WHERE schemaname = '{schema}'
        """))
        
        mat_views = [row[0] for row in result.fetchall()]
        
        if mat_views:
            logger.info(f"   Found {len(mat_views)} materialized views: {', '.join(mat_views)}")
            for mv in mat_views:
                logger.info(f"   Dropping {mv}...")
                conn.execute(text(f"DROP MATERIALIZED VIEW IF EXISTS {schema}.{mv} CASCADE"))
            logger.info(f"✅ Dropped {len(mat_views)} materialized views")
        else:
            logger.info("   No materialized views found")


def recreate_materialized_views(engine: Engine) -> None:
    """
    Recreate common materialized views after loading data
    """
    logger.info("\n🔨 Recreating materialized views...")
    
    mat_views = [
        # Top 100 critical CVEs
        """
        CREATE MATERIALIZED VIEW gold.mv_top_critical_cves AS
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
        LIMIT 100
        """,
        
        # Yearly statistics
        """
        CREATE MATERIALIZED VIEW gold.mv_yearly_statistics AS
        SELECT 
            cve_year,
            COUNT(*) as total_cves,
            AVG(cvss_score) as avg_cvss_score,
            MAX(cvss_score) as max_cvss_score,
            SUM(CASE WHEN is_critical THEN 1 ELSE 0 END) as critical_count,
            AVG(risk_score) as avg_risk_score
        FROM gold.gold_cve_summary
        WHERE cve_year IS NOT NULL
        GROUP BY cve_year
        ORDER BY cve_year DESC
        """
    ]
    
    with engine.begin() as conn:
        for i, view_sql in enumerate(mat_views, 1):
            try:
                conn.execute(text(view_sql))
                # Extract view name from SQL for logging
                view_name = view_sql.split("VIEW")[1].split("AS")[0].strip()
                logger.info(f"   ✓ Created {view_name}")
            except Exception as e:
                logger.warning(f"   ⚠️  Failed to create materialized view {i}: {e}")
    
    logger.info("✅ Materialized views recreated")


# ============================================================================
# LOAD TO GOLD LAYER
# ============================================================================
def load_to_gold(gold_tables: Dict[str, pd.DataFrame], engine: Engine, if_exists: str = 'replace') -> bool:
    """
    Load all Gold tables to PostgreSQL (handles empty frames and dependent views cleanly)
    """
    logger.info("=" * 70)
    logger.info("💾 LOADING TO GOLD LAYER")
    logger.info("=" * 70)

    try:
        # ✅ Drop dependent materialized views FIRST
        drop_dependent_views(engine)
        
        with engine.begin() as conn:
            for table_name, df in gold_tables.items():
                logger.info(f"📥 Loading {table_name}...")

                # Clean NaT/inf
                for col in df.select_dtypes(include=['datetime64[ns]', 'datetime64[ns, UTC]']).columns:
                    df[col] = df[col].where(df[col].notna(), None)
                for col in df.select_dtypes(include=['number']).columns:
                    df[col] = df[col].replace([np.inf, -np.inf], None)

                # Load data
                df.to_sql(
                    name=table_name,
                    con=conn,
                    schema='gold',
                    if_exists=if_exists,
                    index=False,
                    method='multi',
                    chunksize=1000
                )
                logger.info(f"   ✓ Loaded {len(df):,} rows to gold.{table_name}")

        # Create indexes
        logger.info("\n🔍 Creating indexes...")
        create_gold_indexes(engine)
        
        # ✅ Recreate materialized views AFTER loading data
        recreate_materialized_views(engine)

        # Summary
        logger.info("\n" + "=" * 70)
        logger.info("📊 GOLD LAYER SUMMARY")
        logger.info("=" * 70)
        with engine.connect() as conn:
            for table_name in gold_tables.keys():
                result = conn.execute(text(f"""
                    SELECT 
                        COUNT(*) as row_count,
                        pg_size_pretty(pg_total_relation_size('gold.{table_name}')) as size
                    FROM gold.{table_name}
                """)).fetchone()
                logger.info(f"\n🔹 {table_name.upper()}")
                logger.info(f"   Rows: {result[0]:,}")
                logger.info(f"   Size: {result[1]}")

        logger.info("\n" + "=" * 70)
        logger.info("✅ GOLD LAYER LOADED SUCCESSFULLY")
        logger.info("=" * 70)
        return True

    except Exception as e:
        logger.error(f"❌ Failed to load Gold layer: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False
    
# ============================================================================
# CREATE INDEXES
# ============================================================================
def create_gold_indexes(engine: Engine):
    """Create indexes on Gold tables for better query performance"""
    indexes = [
        # gold_cve_summary
        "CREATE INDEX IF NOT EXISTS idx_gold_cve_year ON gold.gold_cve_summary(cve_year)",
        "CREATE INDEX IF NOT EXISTS idx_gold_cve_severity ON gold.gold_cve_summary(cvss_severity)",
        "CREATE INDEX IF NOT EXISTS idx_gold_cve_risk_score ON gold.gold_cve_summary(risk_score DESC)",
        "CREATE INDEX IF NOT EXISTS idx_gold_cve_critical ON gold.gold_cve_summary(is_critical)",

        # gold_vulnerability_trends
        "CREATE INDEX IF NOT EXISTS idx_gold_trends_period ON gold.gold_vulnerability_trends(period)",
        "CREATE INDEX IF NOT EXISTS idx_gold_trends_year ON gold.gold_vulnerability_trends(year)",

        # gold_product_risk_profile
        "CREATE INDEX IF NOT EXISTS idx_gold_product_vendor ON gold.gold_product_risk_profile(vendor)",
        "CREATE INDEX IF NOT EXISTS idx_gold_product_risk_score ON gold.gold_product_risk_profile(product_risk_score DESC)",
        "CREATE INDEX IF NOT EXISTS idx_gold_product_risk_cat ON gold.gold_product_risk_profile(risk_category)",

        # gold_vendor_security_metrics
        "CREATE INDEX IF NOT EXISTS idx_gold_vendor_name ON gold.gold_vendor_security_metrics(vendor)",
        "CREATE INDEX IF NOT EXISTS idx_gold_vendor_risk ON gold.gold_vendor_security_metrics(vendor_risk_score DESC)",
    ]
    with engine.begin() as conn:
        for idx_sql in indexes:
            try:
                conn.execute(text(idx_sql))
            except Exception as e:
                logger.warning(f"⚠️  Index creation warning: {e}")
    logger.info("✅ Indexes created")

# ============================================================================
# MAIN ORCHESTRATOR
# ============================================================================
def main():
    """
    Main ETL pipeline: Silver → Gold transformation
    """
    logger.info("=" * 70)
    logger.info("🚀 SILVER → GOLD TRANSFORMATION PIPELINE")
    logger.info("=" * 70)

    start_time = datetime.now()

    try:
        # Connect to database
        logger.info("🔌 Connecting to database...")
        engine = create_db_engine()
        logger.info("✅ Connected to PostgreSQL at %s", engine.url)

        # Verify schemas
        if not verify_gold_schema(engine):
            logger.error("❌ Gold schema validation failed")
            return False

        # Load Silver data
        silver_data = load_silver_data(engine)

        # Transform to Gold tables
        logger.info("\n" + "=" * 70)
        logger.info("🔄 TRANSFORMING TO GOLD LAYER")
        logger.info("=" * 70)

        gold_tables = {
            'gold_cve_summary': create_gold_cve_summary(silver_data),
            'gold_vulnerability_trends': create_gold_vulnerability_trends(silver_data),
            'gold_product_risk_profile': create_gold_product_risk(silver_data),
            'gold_cvss_version_comparison': create_gold_cvss_comparison(silver_data),
            'gold_vendor_security_metrics': create_gold_vendor_metrics(silver_data),
        }

        # Load to database
        success = load_to_gold(gold_tables, engine, if_exists='replace')

        duration = (datetime.now() - start_time).total_seconds()
        if success:
            logger.info("\n" + "=" * 70)
            logger.info("🎉 PIPELINE COMPLETED SUCCESSFULLY!")
            logger.info(f"⏱️  Total duration: {duration:.2f}s")
            logger.info("=" * 70)
        else:
            logger.error("\n❌ Pipeline failed")
            return False

        return True

    except Exception as e:
        logger.error(f"\n❌ Pipeline failed with error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False

# ============================================================================
# ENTRY POINT
# ============================================================================
if __name__ == "__main__":
    print(f"▶ Running {Path(__file__).name}")
    success = main()
    sys.exit(0 if success else 1)
