#!/usr/bin/env python3
"""
SILVER ➜ GOLD TRANSFORMATION (VERSION 3 - FIXED APPEND-ONLY)
⭐ CHANGEMENT CRITIQUE: if_exists='append' par défaut
- Modélisation en étoile (Star Schema)
- Extraction des métriques CVSS depuis les vecteurs
- Mode APPEND-ONLY (pas de TRUNCATE)
- Compatible avec le scraper incrémental
"""

from pathlib import Path
import sys
sys.path.append(str(Path(__file__).resolve().parents[2]))

import argparse
import logging
from typing import Optional, Dict, Any, Tuple, List
import json
import pandas as pd
from sqlalchemy.engine import Engine

from database.connection import create_db_engine, get_schema_name
from stream.load.load_gold_layer_m import load_gold_layer
from utils.cvss_parser import CVSSVectorParser

# -------------------------------------------------------------------
# Logging
# -------------------------------------------------------------------
LOGS_DIR = Path(__file__).resolve().parents[3] / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOGS_DIR / "transformation_to_gold.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("transformation_to_gold")

pd.set_option("display.max_columns", None)
pd.set_option("display.float_format", "{:.2f}".format)

# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------
def _safe_json_load(x):
    """Charge du JSON de manière sécurisée"""
    try:
        if isinstance(x, str):
            s = x.strip()
            if s and s.lower() not in ('null', 'none', 'nan'):
                return json.loads(s)
        elif isinstance(x, (list, dict)):
            return x
    except Exception:
        pass
    return None

def _is_empty_json_like(x) -> bool:
    """True si valeur vide/None/[]"""
    try:
        if x is None:
            return True
        import numpy as np
        if isinstance(x, float) and pd.isna(x):
            return True
        if isinstance(x, str):
            s = x.strip().lower()
            return s in ("", "[]", "null", "none", "nan")
        if isinstance(x, (list, tuple, dict)):
            return len(x) == 0
        return False
    except Exception:
        return True

def _norm_text(s: Any, maxlen: Optional[int] = None) -> str:
    val = "" if pd.isna(s) else str(s).replace("\xa0", " ").strip()
    if maxlen:
        return val[:maxlen]
    return val

# -------------------------------------------------------------------
# Load Silver Data
# -------------------------------------------------------------------
def load_silver_data(engine: Engine, limit: Optional[int] = None) -> pd.DataFrame:
    logger.info("=" * 72)
    logger.info("📥 LOADING SILVER DATA")
    logger.info("=" * 72)

    silver_schema = get_schema_name("silver")

    if limit:
        query = f"""
            SELECT *
            FROM {silver_schema}.cve_cleaned
            ORDER BY published_date DESC
            LIMIT {int(limit)}
        """
    else:
        query = f"SELECT * FROM {silver_schema}.cve_cleaned;"

    df = pd.read_sql(query, engine)
    logger.info(f"✅ Loaded {len(df):,} rows from silver layer")
    return df

# -------------------------------------------------------------------
# DIMENSION: dim_cve (inclut predicted_category)
# -------------------------------------------------------------------
def create_dim_cve(df: pd.DataFrame) -> pd.DataFrame:
    logger.info("🔨 Building dimension: dim_cve...")

    needed = [
        'cve_id','title','description','category','predicted_category',
        'published_date','last_modified','loaded_at','remotely_exploit','source_identifier'
    ]
    for col in needed:
        if col not in df.columns:
            df[col] = None

    dim_cve = df.groupby('cve_id', as_index=False).agg({
        'title': 'first',
        'description': 'first',
        'category': 'first',
        'predicted_category': 'first',
        'published_date': 'first',
        'last_modified': 'max',
        'loaded_at': 'max',
        'remotely_exploit': 'first',
        'source_identifier': 'first'
    })

    # null safety & types to match DB constraints
    dim_cve['cve_id'] = dim_cve['cve_id'].astype(str).str.slice(0, 20)
    dim_cve['title'] = dim_cve['title'].fillna('Unknown')
    for col in ['published_date','last_modified','loaded_at']:
        dim_cve[col] = pd.to_datetime(dim_cve[col], errors='coerce')
    now = pd.Timestamp.utcnow().tz_localize(None)
    dim_cve['published_date'] = dim_cve['published_date'].fillna(now)
    dim_cve['last_modified']  = dim_cve['last_modified'].fillna(dim_cve['published_date'])
    dim_cve['loaded_at']      = dim_cve['loaded_at'].fillna(now)
    dim_cve['source_identifier'] = dim_cve['source_identifier'].map(lambda x: _norm_text(x) or None)

    logger.info(f"✅ dim_cve: {len(dim_cve):,} unique CVEs")
    return dim_cve

# -------------------------------------------------------------------
# CVSS Version Info
# -------------------------------------------------------------------
def get_version_info(version_str: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    if version_str == "CVSS 2.0": return "v2", "CVSS 2.0"
    if version_str == "CVSS 3.0": return "v3", "CVSS 3.0"
    if version_str == "CVSS 3.1": return "v3", "CVSS 3.1"
    if version_str == "CVSS 4.0": return "v4", "CVSS 4.0"
    return None, None

# -------------------------------------------------------------------
# FACTS: cvss_v2, cvss_v3, cvss_v4
# -------------------------------------------------------------------
def create_cvss_facts(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    logger.info("🔨 Building CVSS facts with vector extraction...")

    rec_v2: List[Dict[str, Any]] = []
    rec_v3: List[Dict[str, Any]] = []
    rec_v4: List[Dict[str, Any]] = []

    for _, row in df.iterrows():
        cve_id = row.get('cve_id')
        if not cve_id:
            continue

        scores = _safe_json_load(row.get('cvss_scores'))
        if _is_empty_json_like(scores):
            continue
        if isinstance(scores, dict):
            scores = [scores]

        for score_entry in scores:
            if not isinstance(score_entry, dict):
                continue

            version = score_entry.get('version')
            vkey, vlabel = get_version_info(version)
            if not vkey:
                continue

            source = _norm_text(score_entry.get('source_identifier') or score_entry.get('source'), 100) or 'unknown'
            vector = _norm_text(score_entry.get('vector'))
            if not vector:
                continue  # NOT NULL in schema

            score = score_entry.get('score')
            severity = score_entry.get('severity')
            exploitability = score_entry.get('exploitability_score')
            impact = score_entry.get('impact_score')

            if vkey == 'v2':
                metrics = CVSSVectorParser.parse_vector(vector, 'v2') or {}
                rec_v2.append({
                    'cve_id': cve_id[:20],
                    'cvss_source': source,
                    'cvss_score': score,
                    'cvss_severity': severity,
                    'cvss_vector': vector,
                    'cvss_v2_av': metrics.get('cvss_v2_av'),
                    'cvss_v2_ac': metrics.get('cvss_v2_ac'),
                    'cvss_v2_au': metrics.get('cvss_v2_au'),
                    'cvss_v2_c': metrics.get('cvss_v2_c'),
                    'cvss_v2_i': metrics.get('cvss_v2_i'),
                    'cvss_v2_a': metrics.get('cvss_v2_a'),
                    'cvss_exploitability_score': exploitability,
                    'cvss_impact_score': impact,
                })
            elif vkey == 'v3':
                metrics = CVSSVectorParser.parse_vector(vector, 'v3') or {}
                rec_v3.append({
                    'cve_id': cve_id[:20],
                    'cvss_source': source,
                    'cvss_version': vlabel,
                    'cvss_score': score,
                    'cvss_severity': severity,
                    'cvss_vector': vector,
                    'cvss_v3_base_av': metrics.get('cvss_v3_base_av'),
                    'cvss_v3_base_ac': metrics.get('cvss_v3_base_ac'),
                    'cvss_v3_base_pr': metrics.get('cvss_v3_base_pr'),
                    'cvss_v3_base_ui': metrics.get('cvss_v3_base_ui'),
                    'cvss_v3_base_s': metrics.get('cvss_v3_base_s'),
                    'cvss_v3_base_c': metrics.get('cvss_v3_base_c'),
                    'cvss_v3_base_i': metrics.get('cvss_v3_base_i'),
                    'cvss_v3_base_a': metrics.get('cvss_v3_base_a'),
                    'cvss_exploitability_score': exploitability,
                    'cvss_impact_score': impact,
                })
            elif vkey == 'v4':
                metrics = CVSSVectorParser.parse_vector(vector, 'v4') or {}
                rec_v4.append({
                    'cve_id': cve_id[:20],
                    'cvss_source': source,
                    'cvss_score': score,
                    'cvss_severity': severity,
                    'cvss_vector': vector,
                    'cvss_v4_av': metrics.get('cvss_v4_av'),
                    'cvss_v4_at': metrics.get('cvss_v4_at'),
                    'cvss_v4_ac': metrics.get('cvss_v4_ac'),
                    'cvss_v4_vc': metrics.get('cvss_v4_vc'),
                    'cvss_v4_vi': metrics.get('cvss_v4_vi'),
                    'cvss_v4_va': metrics.get('cvss_v4_va'),
                    'cvss_v4_sc': metrics.get('cvss_v4_sc'),
                    'cvss_v4_si': metrics.get('cvss_v4_si'),
                    'cvss_v4_sa': metrics.get('cvss_v4_sa'),
                })

    cvss_v2 = pd.DataFrame(rec_v2)
    cvss_v3 = pd.DataFrame(rec_v3)
    cvss_v4 = pd.DataFrame(rec_v4)

    for d in (cvss_v2, cvss_v3, cvss_v4):
        if not d.empty and 'cvss_score' in d:
            d['cvss_score'] = pd.to_numeric(d['cvss_score'], errors='coerce')
            for col in ['cvss_exploitability_score','cvss_impact_score']:
                if col in d.columns:
                    d[col] = pd.to_numeric(d[col], errors='coerce')

    logger.info("✅ CVSS Facts:")
    logger.info(f"   - cvss_v2: {len(cvss_v2):,} records")
    logger.info(f"   - cvss_v3: {len(cvss_v3):,} records")
    logger.info(f"   - cvss_v4: {len(cvss_v4):,} records")
    return cvss_v2, cvss_v3, cvss_v4

# -------------------------------------------------------------------
# DIMENSIONS: dim_vendor + dim_products + BRIDGE: bridge_cve_products
# -------------------------------------------------------------------
def create_vendors_products_and_bridge(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    logger.info("🔨 Building dim_vendor + dim_products + bridge_cve_products...")

    vendors_dict: Dict[str, Dict[str, Any]] = {}
    products_dict: Dict[Tuple[str, str], Dict[str, Any]] = {}
    bridge_records: List[Dict[str, Any]] = []

    for _, row in df.iterrows():
        cve_id = row.get('cve_id')
        if not cve_id:
            continue
        published_date = pd.to_datetime(row.get('published_date'), errors='coerce')

        products = _safe_json_load(row.get('affected_products'))
        if _is_empty_json_like(products):
            continue
        if isinstance(products, dict):
            products = [products]

        for prod in products:
            if not isinstance(prod, dict):
                continue

            vendor = _norm_text(prod.get('vendor'))
            product = _norm_text(prod.get('product'))
            if not vendor or not product:
                continue

            vkey = vendor.lower()
            pkey = product.lower()

            # vendors
            v = vendors_dict.get(vkey)
            if v is None:
                vendors_dict[vkey] = v = {
                    'vendor_name': vendor,
                    'total_products': set([pkey]),
                    'total_cves': 1,
                    'first_cve_date': published_date,
                    'last_cve_date': published_date
                }
            else:
                v['total_cves'] += 1
                v['total_products'].add(pkey)
                if pd.notna(published_date):
                    if v['first_cve_date'] is None or published_date < v['first_cve_date']:
                        v['first_cve_date'] = published_date
                    if v['last_cve_date'] is None or published_date > v['last_cve_date']:
                        v['last_cve_date'] = published_date

            # products
            key = (vkey, pkey)
            p = products_dict.get(key)
            if p is None:
                products_dict[key] = p = {
                    'vendor_lower': vkey,
                    'product_name': product,
                    'total_cves': 1,
                    'first_cve_date': published_date,
                    'last_cve_date': published_date
                }
            else:
                p['total_cves'] += 1
                if pd.notna(published_date):
                    if p['first_cve_date'] is None or published_date < p['first_cve_date']:
                        p['first_cve_date'] = published_date
                    if p['last_cve_date'] is None or published_date > p['last_cve_date']:
                        p['last_cve_date'] = published_date

            # bridge staging
            bridge_records.append({
                'cve_id': cve_id[:20],
                'vendor_lower': vkey,
                'product_lower': pkey
            })

    if not vendors_dict:
        dim_vendor = pd.DataFrame(columns=['vendor_id','vendor_name','total_products','total_cves','first_cve_date','last_cve_date'])
        dim_products = pd.DataFrame(columns=['product_id','vendor_id','product_name','total_cves','first_cve_date','last_cve_date'])
        bridge = pd.DataFrame(columns=['cve_id','product_id'])
        logger.info("✅ dim_vendor: 0 vendors")
        logger.info("✅ dim_products: 0 products")
        logger.info("✅ bridge_cve_products: 0 records")
        return dim_vendor, dim_products, bridge

    # finalize vendors
    for v in vendors_dict.values():
        v['total_products'] = len(v['total_products'])

    dim_vendor = pd.DataFrame([
        {
            'vendor_id': i,
            'vendor_name': d['vendor_name'],
            'total_products': d['total_products'],
            'total_cves': d['total_cves'],
            'first_cve_date': d['first_cve_date'],
            'last_cve_date': d['last_cve_date']
        }
        for i, (_, d) in enumerate(vendors_dict.items(), start=1)
    ])

    # vendor lookup lower -> id
    vendor_lookup = {row['vendor_name'].lower(): int(row['vendor_id']) for _, row in dim_vendor.iterrows()}

    # products with vendor_id
    dim_products = pd.DataFrame([
        {
            'product_id': i,
            'vendor_id': vendor_lookup.get(d['vendor_lower']),
            'product_name': d['product_name'],
            'total_cves': d['total_cves'],
            'first_cve_date': d['first_cve_date'],
            'last_cve_date': d['last_cve_date']
        }
        for i, (_, d) in enumerate(products_dict.items(), start=1)
    ])

    # product lookup: (vendor_lower, product_lower) -> product_id
    product_lookup = {
        (r['vendor_id'], r['product_name'].lower()): int(r['product_id'])
        for _, r in dim_products.iterrows()
        if pd.notna(r['vendor_id'])
    }

    # build bridge with product_id
    bridge_df = pd.DataFrame(bridge_records)
    bridge_df['vendor_id'] = bridge_df['vendor_lower'].map(lambda v: vendor_lookup.get(v))
    bridge_df['product_id'] = bridge_df.apply(
        lambda x: product_lookup.get((x['vendor_id'], x['product_lower'])), axis=1
    )
    bridge = bridge_df[['cve_id','product_id']].dropna().drop_duplicates().reset_index(drop=True)

    logger.info(f"✅ dim_vendor: {len(dim_vendor):,} unique vendors")
    logger.info(f"✅ dim_products: {len(dim_products):,} unique products")
    logger.info(f"✅ bridge_cve_products: {len(bridge):,} CVE-Product relationships")
    return dim_vendor, dim_products, bridge

# -------------------------------------------------------------------
# Main Transformation Pipeline
# -------------------------------------------------------------------
def transform_silver_to_gold(df_silver: pd.DataFrame) -> Dict[str, pd.DataFrame]:
    logger.info("=" * 72)
    logger.info("🚀 SILVER ➜ GOLD TRANSFORMATION (STAR SCHEMA V3)")
    logger.info("=" * 72)

    # 1. Dimensions
    dim_cve = create_dim_cve(df_silver)
    dim_vendor, dim_products, bridge_cve_products = create_vendors_products_and_bridge(df_silver)

    # 2. Facts (CVSS)
    cvss_v2, cvss_v3, cvss_v4 = create_cvss_facts(df_silver)

    # 3. Tables package
    gold_tables = {
        'dim_cve': dim_cve,
        'dim_vendor': dim_vendor,
        'dim_products': dim_products,
        'cvss_v2': cvss_v2,
        'cvss_v3': cvss_v3,
        'cvss_v4': cvss_v4,
        'bridge_cve_products': bridge_cve_products,
    }

    # 4. Stats
    logger.info("\n" + "=" * 72)
    logger.info("📊 GOLD LAYER STATISTICS")
    logger.info("=" * 72)
    for name, d in gold_tables.items():
        if d.empty:
            logger.info(f"🔹 {name}: 0 rows")
        else:
            mem = d.memory_usage(deep=True).sum() / 1024**2
            logger.info(f"🔹 {name}: {len(d):,} rows | {len(d.columns)} cols | {mem:.2f} MB")

    logger.info("=" * 72)
    logger.info("✅ Transformation complete")
    return gold_tables

# -------------------------------------------------------------------
# ⭐ FIXED: Runner (APPEND-ONLY par défaut)
# -------------------------------------------------------------------
def run_silver_to_gold(limit: Optional[int] = None, if_exists: str = 'append') -> bool:
    """
    ⭐ FIXED VERSION: APPEND-ONLY par défaut
    - if_exists='append' est maintenant le défaut
    - 'replace' est déprécié et génère un warning
    """
    logger.info("=" * 72)
    logger.info("🚀 SILVER ➜ GOLD PIPELINE (VERSION 3 - APPEND-ONLY)")
    logger.info("=" * 72)

    # ⭐ AVERTISSEMENT si replace
    if if_exists == 'replace':
        logger.warning("⚠️  WARNING: if_exists='replace' is DEPRECATED!")
        logger.warning("⚠️  Using 'append' mode instead (skip duplicates)")
        logger.warning("⚠️  To reset Gold: TRUNCATE gold.* CASCADE;")
        if_exists = 'append'

    try:
        engine = create_db_engine()
        df_silver = load_silver_data(engine, limit=limit)
        if df_silver.empty:
            logger.warning("⚠️  No data in silver layer!")
            return False

        gold_tables = transform_silver_to_gold(df_silver)

        logger.info("\n💾 Loading to Gold layer (append mode)...")
        success = load_gold_layer(gold_tables, engine, if_exists='append')

        if success:
            logger.info("\n" + "=" * 72)
            logger.info("🎉 PIPELINE COMPLETED SUCCESSFULLY")
            logger.info("=" * 72)
        else:
            logger.error("\n❌ Pipeline failed during load")

        return success

    except Exception as e:
        logger.error(f"❌ Pipeline failed with error: {e}", exc_info=True)
        return False

# -------------------------------------------------------------------
# CLI
# -------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="Silver ➜ Gold: Star Schema Transformation Pipeline (V3 - APPEND-ONLY)"
    )
    parser.add_argument('--limit', type=int, default=None, help='Limit number of rows to process (for testing)')
    parser.add_argument(
        '--if-exists', 
        choices=['append', 'replace'], 
        default='append',  # ⭐ CHANGÉ de 'replace' à 'append'
        help='Gold load mode (replace is deprecated)'
    )
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    print(f"\n🚀 Running {Path(__file__).name}")
    print(f"   Limit: {args.limit or 'None (all data)'}")
    print(f"   Mode: {args.if_exists}")
    
    if args.if_exists == 'replace':
        print("\n⚠️  WARNING: 'replace' mode is deprecated!")
        print("   Using 'append' instead (skips duplicates)")
        print("   To reset Gold: TRUNCATE gold.* CASCADE;\n")
    
    ok = run_silver_to_gold(limit=args.limit, if_exists=args.if_exists)
    sys.exit(0 if ok else 1)