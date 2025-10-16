"""
Bronze to Silver Transformation (V3.1)
- KEEP top-level CVE source as `source_identifier` (do NOT drop)
- Extract CVSS source from JSON rows (cvss_scores[].source_identifier)
"""

from pathlib import Path
import sys
sys.path.append(str(Path(__file__).resolve().parents[2]))

import logging
from datetime import datetime
import re
import json
import numpy as np
import pandas as pd
from dateutil import parser

from database.connection import create_db_engine, get_schema_name
from batch.load.load_silver_layer import load_silver_layer, refresh_materialized_views

# ============================================================================
# LOGGING SETUP
# ============================================================================
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

# ============================================================================
# HELPERS
# ============================================================================
def _is_nan_float(x) -> bool:
    return isinstance(x, float) and np.isnan(x)

def _is_empty_json_like(x) -> bool:
    if x is None: return True
    if _is_nan_float(x): return True
    if isinstance(x, str):
        s = x.strip().lower()
        return s in ("", "[]", "null", "none")
    if isinstance(x, (list, tuple, np.ndarray, dict)):
        return len(x) == 0
    return False

def _safe_json_load(x):
    try:
        if isinstance(x, str):
            return json.loads(x)
        return x
    except (json.JSONDecodeError, TypeError, ValueError):
        return None

# ============================================================================
# DATA LOADING
# ============================================================================
def load_raw_data(engine, limit=None):
    logger.info("📥 Loading raw data from bronze layer...")
    bronze_schema = get_schema_name("bronze")
    if limit:
        df = pd.read_sql(
            f"""
            SELECT * 
            FROM {bronze_schema}.cve_details
            ORDER BY published_date DESC NULLS LAST
            LIMIT {int(limit)}
            """,
            engine,
        )
        logger.info(f"✅ Loaded (limited): {len(df):,} rows")
        return df

    dims = pd.read_sql(f"""
        WITH rows_count AS (SELECT COUNT(*)::bigint AS rows FROM {bronze_schema}.cve_details),
             cols_count AS (
               SELECT COUNT(*)::int AS cols
               FROM information_schema.columns
               WHERE table_schema = '{bronze_schema}' AND table_name = 'cve_details'
             )
        SELECT rows_count.rows, cols_count.cols FROM rows_count, cols_count;
    """, engine).iloc[0]
    df = pd.read_sql(f"SELECT * FROM {bronze_schema}.cve_details;", engine)
    logger.info(f"✅ Loaded: {int(dims['rows']):,} rows × {int(dims['cols'])} columns")
    return df

# ============================================================================
# DATE PROCESSING
# ============================================================================
def parse_date_safe(date_str):
    if pd.isna(date_str): return pd.NaT
    try:
        return parser.parse(str(date_str), fuzzy=False)
    except Exception:
        try:
            return parser.parse(str(date_str), fuzzy=True)
        except Exception:
            return pd.NaT

def process_dates(df):
    logger.info("📅 Processing dates...")
    for col in ['published_date', 'last_modified']:
        df[col] = pd.to_datetime(df[col].apply(parse_date_safe), errors='coerce')

    df['loaded_at'] = (
        pd.to_datetime(df.get('loaded_at'), utc=True, errors='coerce')
          .dt.tz_localize(None)
          .dt.floor('s')
    )

    initial = len(df)
    df.dropna(subset=['published_date', 'last_modified'], inplace=True)
    dropped = initial - len(df)
    if dropped > 0:
        logger.info(f"  ⚠  Dropped {dropped} rows with invalid dates")

    logger.info(f"✅ Dates processed: {len(df):,} valid rows")
    return df

# ============================================================================
# DATA CLEANING (KEEP source_identifier)
# ============================================================================
def clean_data(df):
    """
    Clean and normalize data.
    - KEEP `source_identifier` (top-level CVE origin).
    - Remove url only.
    """
    logger.info("🧹 Cleaning data...")
    df = df.copy()

    # drop only URL noise; keep source_identifier
    df.drop(columns=['url'], inplace=True, errors='ignore')

    # Normalize booleans
    if 'remotely_exploit' in df.columns:
        df['remotely_exploit'] = df.get('remotely_exploit').map({
            'Yes !': True, 'Yes': True, 'True': True, True: True,
            'No': False, 'False': False, False: False
        })

    # Category fallback
    if 'category' not in df.columns:
        df['category'] = 'undefined'
    else:
        df['category'] = df['category'].replace('', 'undefined')

    # Remove rows without CVSS scores
    if 'cvss_scores' not in df.columns:
        logger.info("  ⚠  Column 'cvss_scores' missing")
        mask_empty = pd.Series([True] * len(df), index=df.index)
    else:
        mask_empty = df['cvss_scores'].apply(_is_empty_json_like)

    dropped = int(mask_empty.sum())
    df = df[~mask_empty].copy()
    if dropped > 0:
        logger.info(f"  ⚠  Dropped {dropped} rows without CVSS scores")

    # Back-compat: if legacy 'source' exists, map → source_identifier
    if 'source_identifier' not in df.columns and 'source' in df.columns:
        df['source_identifier'] = df['source']

    logger.info(f"✅ Data cleaned: {len(df):,} rows")
    return df

# ============================================================================
# CVSS PARSING
# ============================================================================
CVSS_MAPS = {
    'v2': {'metrics': ['AV','AC','Au','C','I','A'],
           'mappings': {
               'AV': {'N':'Network','A':'Adjacent','L':'Local'},
               'AC': {'L':'Low','M':'Medium','H':'High'},
               'Au': {'N':'None','S':'Single','M':'Multiple'},
               'C': {'N':'None','P':'Partial','C':'Complete'},
               'I': {'N':'None','P':'Partial','C':'Complete'},
               'A': {'N':'None','P':'Partial','C':'Complete'}
           }},
    'v3': {'metrics': ['AV','AC','PR','UI','S','C','I','A'],
           'mappings': {
               'AV': {'N':'Network','A':'Adjacent','L':'Local','P':'Physical'},
               'AC': {'L':'Low','H':'High'},
               'PR': {'N':'None','L':'Low','H':'High'},
               'UI': {'N':'None','R':'Required'},
               'S':  {'U':'Unchanged','C':'Changed'},
               'C': {'N':'None','L':'Low','H':'High'},
               'I': {'N':'None','L':'Low','H':'High'},
               'A': {'N':'None','L':'Low','H':'High'}
           }},
    'v4': {'metrics': ['AV','AC','AT','PR','UI','VC','VI','VA','SC','SI','SA'],
           'mappings': {
               'AV': {'N':'Network','A':'Adjacent','L':'Local','P':'Physical'},
               'AC': {'L':'Low','H':'High'},
               'AT': {'N':'None','P':'Present'},
               'PR': {'N':'None','L':'Low','H':'High'},
               'UI': {'N':'None','P':'Passive','A':'Active'},
               'VC': {'N':'None','L':'Low','H':'High'},
               'VI': {'N':'None','L':'Low','H':'High'},
               'VA': {'N':'None','L':'Low','H':'High'},
               'SC': {'N':'None','L':'Low','H':'High'},
               'SI': {'N':'None','L':'Low','H':'High'},
               'SA': {'N':'None','L':'Low','H':'High'}
           }},
}

def get_version_key(version_str):
    if version_str == 'CVSS 2.0': return 'v2'
    if version_str in ['CVSS 3.0','CVSS 3.1']: return 'v3'
    if version_str == 'CVSS 4.0': return 'v4'
    return None

def parse_cvss_vector(vector_str, version_str):
    if pd.isna(vector_str) or not isinstance(vector_str, str): return {}
    version_key = get_version_key(version_str)
    if not version_key: return {}
    mappings = CVSS_MAPS[version_key]['mappings']
    vector_str = re.sub(r'^CVSS:\d+\.\d+/', '', vector_str)
    metrics = {}
    for pair in vector_str.split('/'):
        if ':' not in pair: continue
        metric, value = pair.split(':', 1)
        metric, value = metric.strip(), value.strip()
        if metric in mappings and value in mappings[metric]:
            metrics[metric] = mappings[metric][value]
    return metrics

# ============================================================================
# TABLE CREATION
# ============================================================================
def create_dim_cve(df):
    """Create CVE dimension table (keeps source_identifier)."""
    logger.info("🔨 Creating dim_cve...")
    cols = ['title','description','published_date','last_modified',
            'remotely_exploit','category','loaded_at','source_identifier']
    for c in cols:
        if c not in df.columns:
            df[c] = None
    dim_cve = df.groupby('cve_id', as_index=False).agg({
        'title':'first','description':'first',
        'published_date':'first','last_modified':'max',
        'remotely_exploit':'first','category':'first',
        'loaded_at':'max','source_identifier':'first'
    })
    logger.info(f"✅ dim_cve: {len(dim_cve):,} unique CVEs")
    return dim_cve

def create_fact_cvss_scores(df):
    """
    Create CVSS scores fact table.
    - Extract cvss_source from JSON: score_entry['source_identifier'] (fallback 'source')
    """
    logger.info("🔨 Creating fact_cvss_scores (source from JSON)...")
    records = []

    for _, row in df.iterrows():
        cve_id = row['cve_id']
        cvss_scores_cell = row.get('cvss_scores')
        if _is_empty_json_like(cvss_scores_cell): continue

        scores = _safe_json_load(cvss_scores_cell)
        if scores is None: continue
        if isinstance(scores, dict): scores = [scores]
        if not isinstance(scores, (list, tuple, np.ndarray)): continue

        for score_entry in scores:
            if not isinstance(score_entry, dict): continue
            version_str = score_entry.get('version')
            version_key = get_version_key(version_str)
            if not version_key: continue

            cvss_source = (
                score_entry.get('source_identifier')
                or score_entry.get('source')
                or 'unknown'
            )

            vector = score_entry.get('vector', '')
            metrics = parse_cvss_vector(vector, version_str)

            record = {
                'cve_id': cve_id,
                'cvss_source': cvss_source,
                'cvss_version': version_str,
                'cvss_score': score_entry.get('score'),
                'cvss_severity': score_entry.get('severity'),
                'cvss_vector': vector,
                'cvss_exploitability_score': score_entry.get('exploitability_score'),
                'cvss_impact_score': score_entry.get('impact_score'),
            }
            for m, v in metrics.items():
                record[f'cvss_{m.lower()}'] = v
            records.append(record)

    base_cols = [
        'cve_id','cvss_source','cvss_version','cvss_score','cvss_severity',
        'cvss_vector','cvss_exploitability_score','cvss_impact_score'
    ]
    fact_cvss = pd.DataFrame(records)
    if fact_cvss.empty:
        fact_cvss = pd.DataFrame(columns=base_cols)

    for col in ['cvss_score','cvss_exploitability_score','cvss_impact_score']:
        if col in fact_cvss.columns:
            fact_cvss[col] = pd.to_numeric(fact_cvss[col], errors='coerce')

    logger.info(f"✅ fact_cvss_scores: {len(fact_cvss):,} entries")
    if not fact_cvss.empty and 'cvss_source' in fact_cvss.columns:
        source_counts = fact_cvss['cvss_source'].value_counts()
        logger.info("   Source distribution (top 5):")
        for src, cnt in source_counts.head(5).items():
            logger.info(f"     • {src}: {cnt:,}")
    return fact_cvss

def create_dim_products(df):
    """Create products dimension table"""
    logger.info("🔨 Creating dim_products...")
    products_dict = {}
    cve_products = []

    for _, row in df.iterrows():
        cve_id = row['cve_id']
        published_date = row['published_date']
        affected_products_cell = row.get('affected_products')
        if _is_empty_json_like(affected_products_cell): continue

        products = _safe_json_load(affected_products_cell)
        if products is None: continue
        if isinstance(products, dict): products = [products]
        if not isinstance(products, (list, tuple, np.ndarray)): continue

        for product in products:
            if not isinstance(product, dict): continue
            vendor = (product.get('vendor') or '').strip()
            product_name = (product.get('product') or '').strip()
            if not vendor or not product_name: continue
            key = (vendor.lower(), product_name.lower())
            if key not in products_dict:
                products_dict[key] = {'vendor': vendor, 'product_name': product_name, 'cve_count': 0}
            products_dict[key]['cve_count'] += 1
            cve_products.append({'vendor_key': vendor.lower(), 'product_key': product_name.lower(),
                                 'cve_id': cve_id, 'published_date': published_date})

    if not products_dict:
        dim_products = pd.DataFrame(columns=[
            'product_id','vendor','product_name','total_cves','first_cve_date','last_cve_date'
        ])
        cve_products_df = pd.DataFrame(columns=['cve_id','product_id'])
        logger.info("✅ dim_products: 0 unique products")
        return dim_products, cve_products_df

    dim_products = pd.DataFrame([
        {'product_id': idx,'vendor': d['vendor'],'product_name': d['product_name'],'total_cves': d['cve_count']}
        for idx, (_, d) in enumerate(products_dict.items(), start=1)
    ])
    cve_products_df = pd.DataFrame(cve_products)
    lookup = {(r['vendor'].lower(), r['product_name'].lower()): r['product_id'] for _, r in dim_products.iterrows()}

    if not cve_products_df.empty:
        cve_products_df['product_id'] = cve_products_df.apply(
            lambda x: lookup.get((x['vendor_key'], x['product_key'])), axis=1
        )
        date_stats = cve_products_df.groupby('product_id', dropna=True)['published_date'].agg(['min','max']).reset_index()
        date_stats.columns = ['product_id','first_cve_date','last_cve_date']
        dim_products = dim_products.merge(date_stats, on='product_id', how='left')
    else:
        dim_products['first_cve_date'] = pd.NaT
        dim_products['last_cve_date'] = pd.NaT

    logger.info(f"✅ dim_products: {len(dim_products):,} unique products")
    return dim_products, cve_products_df[['cve_id','product_id']].dropna().drop_duplicates()

def create_bridge_cve_products(cve_products_df):
    logger.info("🔨 Creating bridge_cve_products...")
    if cve_products_df is None or cve_products_df.empty:
        bridge = pd.DataFrame(columns=['cve_id','product_id'])
        logger.info("✅ bridge_cve_products: 0 relationships")
        return bridge
    bridge = cve_products_df[['cve_id','product_id']].dropna().drop_duplicates().reset_index(drop=True)
    logger.info(f"✅ bridge_cve_products: {len(bridge):,} relationships")
    return bridge

# ============================================================================
# MAIN PIPELINE
# ============================================================================
def create_silver_layer(df_raw):
    logger.info("="*70)
    logger.info("🚀 BRONZE → SILVER TRANSFORMATION (keep source_identifier)")
    logger.info("="*70)

    df = process_dates(df_raw.copy())
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

    logger.info("="*70)
    logger.info("📊 SILVER LAYER SUMMARY")
    logger.info("="*70)
    for table_name, df_table in silver_tables.items():
        memory_mb = df_table.memory_usage(deep=True).sum() / 1024**2 if not df_table.empty else 0.0
        logger.info(f"\n🔹 {table_name.upper()}")
        logger.info(f"   Rows    : {len(df_table):,}")
        logger.info(f"   Columns : {len(df_table.columns)}")
        logger.info(f"   Memory  : {memory_mb:.2f} MB")

    logger.info("\n" + "="*70)
    logger.info("✅ TRANSFORMATION COMPLETED")
    logger.info("="*70)
    return silver_tables

# ============================================================================
# MAIN EXECUTION
# ============================================================================
def main():
    try:
        logger.info("🔌 Connecting to database...")
        engine = create_db_engine()
        df_raw = load_raw_data(engine)
        silver_tables = create_silver_layer(df_raw)

        logger.info("\n" + "="*70)
        logger.info("💾 LOADING TO DATABASE")
        logger.info("="*70)

        ok = load_silver_layer(silver_tables, engine, if_exists='replace')
        if ok:
            refresh_materialized_views(engine)
            logger.info("\n" + "="*70)
            logger.info("🎉 PIPELINE COMPLETED SUCCESSFULLY!")
            logger.info("="*70)
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
    print(f"Running {Path(__file__).name}")
    main()
