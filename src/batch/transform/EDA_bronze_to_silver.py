# ============================================================================
# BRONZE TO SILVER TRANSFORMATION + LOADING
# ============================================================================
# Description: Transform raw CVE data and load to Silver schema
# Author: Data Engineering Team
# Date: 2025-10-14
# ============================================================================

from pathlib import Path
import sys

# If you run this file directly from its folder, keep this.
# If you run with:  python -m batch.transform.bronze_to_silver  (from src/)
# you can remove the sys.path.append line.
sys.path.append(str(Path(__file__).resolve().parents[2]))  # -> <repo>/src

import logging
from datetime import datetime
import re, json
import numpy as np
import pandas as pd
from dateutil import parser

# ✅ Use central connection manager (single DB, multi-schemas)
from database.connection import create_db_engine, get_schema_name

# ✅ Import silver loader from your package (not tip.*)
from batch.load.load_silver_layer import (
    load_silver_layer,
    refresh_materialized_views,
)

# ----------------------------------------------------------------------------
# Logging (console + file)
# ----------------------------------------------------------------------------
LOGS_DIR = Path(__file__).resolve().parents[3] / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOGS_DIR / "bronze_to_silver.log"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

pd.set_option('display.max_columns', None)
pd.set_option('display.float_format', '{:.2f}'.format)

# ----------------------------------------------------------------------------
# DATA LOADING (from bronze schema)
# ----------------------------------------------------------------------------
def load_raw_data(engine, limit=None):
    """Load raw CVE data from PostgreSQL (bronze layer)"""
    logger.info("📥 Loading raw data from bronze layer...")
    bronze_schema = get_schema_name("bronze")  # typically 'raw'

    if limit:
        df = pd.read_sql(f"""
            SELECT * 
            FROM {bronze_schema}.cve_details
            ORDER BY published_date DESC NULLS LAST
            LIMIT {int(limit)}
        """, engine)
        logger.info(f"✅ Loaded (limited): {len(df):,} rows")
        return df

    # original path (full table)
    query_dims = f"""
    WITH
    rows_count AS (
      SELECT COUNT(*)::bigint AS rows FROM {bronze_schema}.cve_details
    ),
    cols_count AS (
      SELECT COUNT(*)::int AS cols
      FROM information_schema.columns
      WHERE table_schema = '{bronze_schema}' AND table_name = 'cve_details'
    )
    SELECT rows_count.rows, cols_count.cols
    FROM rows_count, cols_count;
    """
    dims = pd.read_sql(query_dims, engine).iloc[0]
    df = pd.read_sql(f"SELECT * FROM {bronze_schema}.cve_details;", engine)
    logger.info(f"✅ Loaded: {int(dims['rows']):,} rows × {int(dims['cols'])} columns")
    return df

# ----------------------------------------------------------------------------
# DATE PROCESSING
# ----------------------------------------------------------------------------
def parse_date_safe(date_str):
    """Parse various date formats to datetime"""
    if pd.isna(date_str):
        return pd.NaT
    try:
        return parser.parse(str(date_str), fuzzy=False)
    except Exception:
        try:
            return parser.parse(str(date_str), fuzzy=True)
        except Exception:
            return pd.NaT

def process_dates(df):
    """Process and normalize all date columns"""
    logger.info("📅 Processing dates...")

    # Parse published_date and last_modified
    for col in ['published_date', 'last_modified']:
        df[col] = df[col].apply(parse_date_safe)
        df[col] = pd.to_datetime(df[col], errors='coerce')

    # Normalize loaded_at
    df['loaded_at'] = (
        pd.to_datetime(df.get('loaded_at'), utc=True, errors='coerce')
        .dt.tz_localize(None)
        .dt.floor('s')
    )

    # Drop rows with invalid dates
    initial_rows = len(df)
    df.dropna(subset=['published_date', 'last_modified'], inplace=True)
    dropped = initial_rows - len(df)
    if dropped > 0:
        logger.info(f"  ⚠  Dropped {dropped} rows with invalid dates")

    logger.info(f"✅ Dates processed: {len(df):,} valid rows")
    return df

# ----------------------------------------------------------------------------
# DATA CLEANING
# ----------------------------------------------------------------------------
def clean_data(df):
    """Clean and normalize data"""
    logger.info("🧹 Cleaning data...")

    # Drop URL column
    df.drop(columns=['url'], inplace=True, errors='ignore')

    # Normalize remotely_exploit
    df['remotely_exploit'] = df.get('remotely_exploit').map({
        'Yes !': True,
        'No': False,
        True: True,
        False: False
    })

    # Normalize category
    df['category'] = df.get('category', '').replace('', 'undefined')

    # Drop source column (no longer needed)
    df.drop(columns=['source'], inplace=True, errors='ignore')

    # Remove rows without CVSS scores
    mask = df['cvss_scores'].isna() | (df['cvss_scores'].astype(str).str.strip() == '[]')
    dropped = mask.sum()
    df = df[~mask].copy()
    if dropped > 0:
        logger.info(f"  ⚠  Dropped {dropped} rows without CVSS scores")

    logger.info(f"✅ Data cleaned: {len(df):,} rows")
    return df

# ----------------------------------------------------------------------------
# CVSS mappings and parsing (unchanged)
# ----------------------------------------------------------------------------
CVSS_MAPS = {
    'v2': {
        'metrics': ['AV', 'AC', 'Au', 'C', 'I', 'A'],
        'mappings': {
            'AV': {'N': 'Network', 'A': 'Adjacent', 'L': 'Local'},
            'AC': {'L': 'Low', 'M': 'Medium', 'H': 'High'},
            'Au': {'N': 'None', 'S': 'Single', 'M': 'Multiple'},
            'C': {'N': 'None', 'P': 'Partial', 'C': 'Complete'},
            'I': {'N': 'None', 'P': 'Partial', 'C': 'Complete'},
            'A': {'N': 'None', 'P': 'Partial', 'C': 'Complete'}
        }
    },
    'v3': {
        'metrics': ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'],
        'mappings': {
            'AV': {'N': 'Network', 'A': 'Adjacent', 'L': 'Local', 'P': 'Physical'},
            'AC': {'L': 'Low', 'H': 'High'},
            'PR': {'N': 'None', 'L': 'Low', 'H': 'High'},
            'UI': {'N': 'None', 'R': 'Required'},
            'S': {'U': 'Unchanged', 'C': 'Changed'},
            'C': {'N': 'None', 'L': 'Low', 'H': 'High'},
            'I': {'N': 'None', 'L': 'Low', 'H': 'High'},
            'A': {'N': 'None', 'L': 'Low', 'H': 'High'}
        }
    },
    'v4': {
        'metrics': ['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA'],
        'mappings': {
            'AV': {'N': 'Network', 'A': 'Adjacent', 'L': 'Local', 'P': 'Physical'},
            'AC': {'L': 'Low', 'H': 'High'},
            'AT': {'N': 'None', 'P': 'Present'},
            'PR': {'N': 'None', 'L': 'Low', 'H': 'High'},
            'UI': {'N': 'None', 'P': 'Passive', 'A': 'Active'},
            'VC': {'N': 'None', 'L': 'Low', 'H': 'High'},
            'VI': {'N': 'None', 'L': 'Low', 'H': 'High'},
            'VA': {'N': 'None', 'L': 'Low', 'H': 'High'},
            'SC': {'N': 'None', 'L': 'Low', 'H': 'High'},
            'SI': {'N': 'None', 'L': 'Low', 'H': 'High'},
            'SA': {'N': 'None', 'L': 'Low', 'H': 'High'}
        }
    }
}

def get_version_key(version_str):
    if version_str == 'CVSS 2.0':
        return 'v2'
    elif version_str in ['CVSS 3.0', 'CVSS 3.1']:
        return 'v3'
    elif version_str == 'CVSS 4.0':
        return 'v4'
    return None

def parse_cvss_vector(vector_str, version_str):
    """Parse CVSS vector string into metrics dictionary"""
    if pd.isna(vector_str) or not isinstance(vector_str, str):
        return {}

    version_key = get_version_key(version_str)
    if not version_key:
        return {}

    mappings = CVSS_MAPS[version_key]['mappings']

    # Clean vector string
    vector_str = re.sub(r'^CVSS:\d+\.\d+/', '', vector_str)

    metrics = {}
    for pair in vector_str.split('/'):
        if ':' not in pair:
            continue
        metric, value = pair.split(':', 1)
        metric = metric.strip()
        value = value.strip()
        if metric in mappings and value in mappings[metric]:
            metrics[metric] = mappings[metric][value]
    return metrics

# ----------------------------------------------------------------------------
# TABLES
# ----------------------------------------------------------------------------
def create_dim_cve(df):
    """Create CVE dimension table - 1 row per unique CVE"""
    logger.info("🔨 Creating dim_cve...")
    dim_cve = df.groupby('cve_id').agg({
        'title': 'first',
        'description': 'first',
        'published_date': 'first',
        'last_modified': 'max',
        'remotely_exploit': 'first',
        'category': 'first',
        'loaded_at': 'max'
    }).reset_index()
    logger.info(f"✅ dim_cve: {len(dim_cve):,} unique CVEs")
    return dim_cve

def create_fact_cvss_scores(df):
    """Create CVSS scores fact table"""
    logger.info("🔨 Creating fact_cvss_scores...")
    records = []

    for _, row in df.iterrows():
        cve_id = row['cve_id']
        cvss_scores = row['cvss_scores']
        if pd.isna(cvss_scores) or cvss_scores == '[]':
            continue

        try:
            scores = json.loads(cvss_scores) if isinstance(cvss_scores, str) else cvss_scores
        except (json.JSONDecodeError, TypeError):
            continue

        for score_entry in scores:
            version_str = score_entry.get('version')
            version_key = get_version_key(version_str)
            if not version_key:
                continue

            vector = score_entry.get('vector', '')
            metrics = parse_cvss_vector(vector, version_str)

            record = {
                'cve_id': cve_id,
                'cvss_version': version_str,
                'cvss_score': score_entry.get('score'),
                'cvss_severity': score_entry.get('severity'),
                'cvss_vector': vector,
                'cvss_exploitability_score': score_entry.get('exploitability_score'),
                'cvss_impact_score': score_entry.get('impact_score')
            }
            for metric, value in metrics.items():
                record[f'cvss_{metric.lower()}'] = value

            records.append(record)

    fact_cvss = pd.DataFrame(records)

    for col in ['cvss_score', 'cvss_exploitability_score', 'cvss_impact_score']:
        if col in fact_cvss.columns:
            fact_cvss[col] = pd.to_numeric(fact_cvss[col], errors='coerce')

    logger.info(f"✅ fact_cvss_scores: {len(fact_cvss):,} score entries")
    return fact_cvss

def create_dim_products(df):
    """Create products dimension table"""
    logger.info("🔨 Creating dim_products...")

    products_dict = {}
    cve_products = []

    for _, row in df.iterrows():
        cve_id = row['cve_id']
        published_date = row['published_date']
        affected_products = row.get('affected_products')

        if pd.isna(affected_products) or affected_products == '[]':
            continue

        try:
            products = json.loads(affected_products) if isinstance(affected_products, str) else affected_products
        except (json.JSONDecodeError, TypeError):
            continue

        for product in products:
            vendor = product.get('vendor', '').strip()
            product_name = product.get('product', '').strip()
            if not vendor or not product_name:
                continue

            key = (vendor.lower(), product_name.lower())
            if key not in products_dict:
                products_dict[key] = {
                    'vendor': vendor,
                    'product_name': product_name,
                    'cve_count': 0
                }
            products_dict[key]['cve_count'] += 1
            cve_products.append({
                'vendor_key': vendor.lower(),
                'product_key': product_name.lower(),
                'cve_id': cve_id,
                'published_date': published_date
            })

    dim_products = pd.DataFrame([
        {
            'product_id': idx,
            'vendor': data['vendor'],
            'product_name': data['product_name'],
            'total_cves': data['cve_count']
        }
        for idx, (key, data) in enumerate(products_dict.items(), start=1)
    ])

    cve_products_df = pd.DataFrame(cve_products)
    product_lookup = {
        (row['vendor'].lower(), row['product_name'].lower()): row['product_id']
        for _, row in dim_products.iterrows()
    }
    cve_products_df['product_id'] = cve_products_df.apply(
        lambda x: product_lookup.get((x['vendor_key'], x['product_key'])),
        axis=1
    )

    date_stats = cve_products_df.groupby('product_id')['published_date'].agg(['min', 'max']).reset_index()
    date_stats.columns = ['product_id', 'first_cve_date', 'last_cve_date']
    dim_products = dim_products.merge(date_stats, on='product_id', how='left')

    logger.info(f"✅ dim_products: {len(dim_products):,} unique products")
    return dim_products, cve_products_df[['cve_id', 'product_id']].drop_duplicates()

def create_bridge_cve_products(cve_products_df):
    """Create bridge table"""
    logger.info("🔨 Creating bridge_cve_products...")
    bridge = cve_products_df[['cve_id', 'product_id']].drop_duplicates().reset_index(drop=True)
    logger.info(f"✅ bridge_cve_products: {len(bridge):,} relationships")
    return bridge

# ----------------------------------------------------------------------------
# MAIN PIPELINE
# ----------------------------------------------------------------------------
def create_silver_layer(df_raw):
    """Transform raw data into Silver layer"""
    logger.info("="*70)
    logger.info("🚀 BRONZE → SILVER TRANSFORMATION")
    logger.info("="*70)

    df = df_raw.copy()
    df = process_dates(df)
    df = clean_data(df)

    dim_cve = create_dim_cve(df)
    fact_cvss_scores = create_fact_cvss_scores(df)
    dim_products, cve_products_temp = create_dim_products(df)
    bridge_cve_products = create_bridge_cve_products(cve_products_temp)

    silver_tables = {
        'dim_cve': dim_cve,
        'fact_cvss_scores': fact_cvss_scores,
        'dim_products': dim_products,
        'bridge_cve_products': bridge_cve_products
    }

    # Summary
    logger.info("="*70)
    logger.info("📊 SILVER LAYER SUMMARY")
    logger.info("="*70)
    for table_name, df_table in silver_tables.items():
        memory_mb = df_table.memory_usage(deep=True).sum() / 1024**2
        logger.info(f"\n🔹 {table_name.upper()}")
        logger.info(f"   Rows    : {len(df_table):,}")
        logger.info(f"   Columns : {len(df_table.columns)}")
        logger.info(f"   Memory  : {memory_mb:.2f} MB")

    logger.info("\n" + "="*70)
    logger.info("✅ TRANSFORMATION COMPLETED")
    logger.info("="*70)

    return silver_tables

# ----------------------------------------------------------------------------
# MAIN EXECUTION
# ----------------------------------------------------------------------------
def main():
    """Main execution function"""
    try:
        logger.info("🔌 Connecting to database...")
        engine = create_db_engine()  # from database.connection

        # Load raw data from bronze layer
        df_raw = load_raw_data(engine)

        # Transform to silver layer
        silver_tables = create_silver_layer(df_raw)

        # Load to database
        logger.info("\n" + "="*70)
        logger.info("💾 LOADING TO DATABASE")
        logger.info("="*70)

        ok = load_silver_layer(silver_tables, engine, if_exists='replace')
        if ok:
            refresh_materialized_views(engine)
            logger.info("\n" + "="*70)
            logger.info("🎉 PIPELINE COMPLETED SUCCESSFULLY!")
            logger.info("="*70)
            logger.info("\n💡 Silver layer is ready for analytics!")
        else:
            logger.error("\n❌ Pipeline failed during loading phase")
            return None

        return silver_tables

    except Exception as e:
        logger.error(f"\n❌ Pipeline failed with error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return None

if __name__ == "__main__":
    print(f"▶ Running {Path(__file__).name} (name={__name__})")
    main()
