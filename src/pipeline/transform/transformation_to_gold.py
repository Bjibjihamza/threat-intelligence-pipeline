#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
# src/pipeline/transform/transformation_to_gold.py
# UNIFIED SILVER ➜ GOLD TRANSFORMATION
# =============================================================================
# Used by both:
#   - batch/transform/transformation_to_gold.py
#   - stream/transform/transformation_to_gold.py
#
# Creates star schema outputs:
# - dim_cve (with vulnarbilit)
# - dim_vendor, dim_products, bridge_cve_products
# - cvss_v2, cvss_v3, cvss_v4 (with parsed vectors)
# =============================================================================

from pathlib import Path
import sys
import logging
from typing import Optional, Dict, Any, Tuple, List

import json
import pandas as pd
import numpy as np
from sqlalchemy.engine import Engine

# Determine project root dynamically
THIS_FILE = Path(__file__).resolve()
PROJECT_ROOT = THIS_FILE.parents[3]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

from src.database.connection import create_db_engine, get_schema_name
from src.utils.cvss_parser import CVSSVectorParser

# -------------------------------------------------------------------
# Logging
# -------------------------------------------------------------------
LOGS_DIR = PROJECT_ROOT / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOGS_DIR / "transformation_to_gold_unified.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("unified_gold_transform")

pd.set_option("display.max_columns", None)
pd.set_option("display.float_format", "{:.2f}".format)

# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------
def _safe_json_load(x):
    """Safely load JSON from various formats."""
    try:
        if isinstance(x, str):
            s = x.strip()
            if s and s.lower() not in ('null', 'none', 'nan', ''):
                return json.loads(s)
        elif isinstance(x, (list, dict)):
            return x
    except Exception:
        pass
    return None

def _is_empty_json_like(x) -> bool:
    """Check if value is empty/null JSON-like."""
    try:
        if x is None:
            return True
        if isinstance(x, float) and (pd.isna(x) or np.isnan(x)):
            return True
        if isinstance(x, str):
            s = x.strip().lower()
            return s in ("", "[]", "{}", "null", "none", "nan")
        if isinstance(x, (list, tuple, dict)):
            return len(x) == 0
        return False
    except Exception:
        return True

def _norm_text(s: Any, maxlen: Optional[int] = None) -> str:
    """Normalize text: trim, remove non-breaking spaces, optionally truncate."""
    val = "" if pd.isna(s) else str(s).replace("\xa0", " ").strip()
    return val[:maxlen] if maxlen else val

def _first_key(d: dict, *candidates):
    """Get first non-empty value from dict by trying multiple keys."""
    for k in candidates:
        if isinstance(d, dict) and k in d and d[k] not in (None, "", [], {}):
            return d[k]
    return None

# -------------------------------------------------------------------
# Load Silver Data
# -------------------------------------------------------------------
def load_silver_data(engine: Engine, limit: Optional[int] = None) -> pd.DataFrame:
    """Load data from Silver layer."""
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
# DIMENSION: dim_cve
# -------------------------------------------------------------------
def create_dim_cve(df: pd.DataFrame) -> pd.DataFrame:
    """
    Build gold.dim_cve aligned to schema:
      cve_id, vulnarbilit, published_date, last_modified, loaded_at,
      cve_year (generated in DB), remotely_exploit, source_identifier
    """
    logger.info("🔨 Building dimension: dim_cve...")

    needed = [
        'cve_id', 'vulnarbilit', 'published_date', 'last_modified',
        'loaded_at', 'remotely_exploit', 'source_identifier'
    ]
    
    base = df.copy()
    for col in needed:
        if col not in base.columns:
            base[col] = None

    # Group by CVE (take first/max as appropriate)
    dim_cve = base.groupby('cve_id', as_index=False).agg({
        'vulnarbilit': 'first',
        'published_date': 'first',
        'last_modified': 'max',
        'loaded_at': 'max',
        'remotely_exploit': 'first',
        'source_identifier': 'first'
    })

    # Normalize
    dim_cve['cve_id'] = dim_cve['cve_id'].astype(str).str.slice(0, 20)
    dim_cve['vulnarbilit'] = (
        dim_cve['vulnarbilit']
        .fillna('uncategorized')
        .astype(str)
        .str.slice(0, 50)
    )

    # Dates
    for col in ['published_date', 'last_modified', 'loaded_at']:
        dim_cve[col] = pd.to_datetime(dim_cve[col], errors='coerce')
    
    now = pd.Timestamp.utcnow().tz_localize(None)
    dim_cve['published_date'] = dim_cve['published_date'].fillna(now)
    dim_cve['last_modified'] = dim_cve['last_modified'].fillna(dim_cve['published_date'])
    dim_cve['loaded_at'] = dim_cve['loaded_at'].fillna(now)

    # Boolean
    if 'remotely_exploit' in dim_cve.columns:
        dim_cve['remotely_exploit'] = dim_cve['remotely_exploit'].astype('boolean')

    # Source
    if 'source_identifier' in dim_cve.columns:
        dim_cve['source_identifier'] = dim_cve['source_identifier'].map(
            lambda x: _norm_text(x) or None
        )

    # Ensure unique by cve_id
    dim_cve = (
        dim_cve.sort_values(['cve_id', 'last_modified', 'loaded_at'])
        .drop_duplicates(subset=['cve_id'], keep='last')
        .reset_index(drop=True)
    )

    logger.info(f"✅ dim_cve: {len(dim_cve):,} unique CVEs")
    return dim_cve

# -------------------------------------------------------------------
# CVSS Helpers
# -------------------------------------------------------------------
def _unwrap_cvss_entry(entry: dict) -> Optional[Dict[str, Any]]:
    """
    Normalize any CVSS entry to a flat dict with:
    version, vector, score, severity, exploitability_score, impact_score, source
    
    Handles both nested (cvssData) and flat formats.
    """
    if not isinstance(entry, dict):
        return None

    # Try nested format first
    core = entry.get('cvssData') if isinstance(entry.get('cvssData'), dict) else entry

    # Extract version
    version = _first_key(core, 'version', 'cvss_version', 'cvssVersion')
    # Normalize version labels
    if version in ('3.1', '3.0'):
        version = f"CVSS {version}"
    elif version == '2.0':
        version = 'CVSS 2.0'
    elif version == '4.0':
        version = 'CVSS 4.0'

    # Extract other fields
    vector = _first_key(core, 'vector', 'vectorString', 'vector_string', 'cvss_vector')
    score = _first_key(core, 'score', 'baseScore', 'base_score')
    severity = _first_key(core, 'severity', 'baseSeverity', 'base_severity')

    # Exploitability and Impact (usually at entry level, not core)
    exploitability = _first_key(entry, 'exploitability_score', 'exploitabilityScore', 'exploitability')
    impact = _first_key(entry, 'impact_score', 'impactScore', 'impact')

    # Source
    source = (
        _first_key(entry, 'source_identifier', 'source', 'sourceRef') or
        _first_key(core, 'source_identifier', 'source') or
        'unknown'
    )

    return {
        'version': version,
        'vector': vector,
        'score': score,
        'severity': severity,
        'exploitability_score': exploitability,
        'impact_score': impact,
        'source': source
    }

def _cvss_version_key(version_label: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """
    Map version label to (version_key, standard_label).
    version_key: 'v2', 'v3', 'v4'
    standard_label: 'CVSS 2.0', 'CVSS 3.0', 'CVSS 3.1', 'CVSS 4.0'
    """
    if not version_label:
        return None, None
    
    v = version_label.strip().upper()
    
    if v in ('CVSS 2.0', '2.0', 'V2'):
        return 'v2', 'CVSS 2.0'
    if v in ('CVSS 3.0', '3.0'):
        return 'v3', 'CVSS 3.0'
    if v in ('CVSS 3.1', '3.1'):
        return 'v3', 'CVSS 3.1'
    if v in ('CVSS 4.0', '4.0', 'V4'):
        return 'v4', 'CVSS 4.0'
    
    return None, None

# -------------------------------------------------------------------
# FACTS: cvss_v2, cvss_v3, cvss_v4
# -------------------------------------------------------------------
def create_cvss_facts(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Build CVSS fact tables with parsed vector metrics.
    Returns: (cvss_v2, cvss_v3, cvss_v4)
    """
    logger.info("🔨 Building CVSS facts with vector extraction...")

    rec_v2: List[Dict[str, Any]] = []
    rec_v3: List[Dict[str, Any]] = []
    rec_v4: List[Dict[str, Any]] = []

    skipped_no_scores = 0
    skipped_no_version = 0
    skipped_no_vector = 0

    for _, row in df.iterrows():
        cve_id = row.get('cve_id')
        if not cve_id:
            continue

        scores = _safe_json_load(row.get('cvss_scores'))
        if _is_empty_json_like(scores):
            skipped_no_scores += 1
            continue
        
        # Handle single dict as list
        if isinstance(scores, dict):
            scores = [scores]

        for score_entry in scores:
            if not isinstance(score_entry, dict):
                continue

            # Unwrap and normalize
            norm = _unwrap_cvss_entry(score_entry)
            if not norm:
                continue

            vkey, vlabel = _cvss_version_key(norm.get('version'))
            if not vkey:
                skipped_no_version += 1
                continue

            vector = norm.get('vector')
            if not vector:
                skipped_no_vector += 1
                continue

            # Common fields
            source = (_norm_text(norm.get('source')) or 'unknown')[:100]
            score = norm.get('score')
            severity = norm.get('severity')
            exploit = norm.get('exploitability_score')
            impact = norm.get('impact_score')

            # Parse vector and build version-specific record
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
                    'cvss_exploitability_score': exploit,
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
                    'cvss_exploitability_score': exploit,
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

    # Convert to DataFrames
    cvss_v2 = pd.DataFrame(rec_v2)
    cvss_v3 = pd.DataFrame(rec_v3)
    cvss_v4 = pd.DataFrame(rec_v4)

    # Convert numeric columns
    for d in (cvss_v2, cvss_v3, cvss_v4):
        if not d.empty and 'cvss_score' in d:
            d['cvss_score'] = pd.to_numeric(d['cvss_score'], errors='coerce')
            for col in ['cvss_exploitability_score', 'cvss_impact_score']:
                if col in d.columns:
                    d[col] = pd.to_numeric(d[col], errors='coerce')

    logger.info(f"✅ CVSS Facts:")
    logger.info(f"   - cvss_v2: {len(cvss_v2):,} records")
    logger.info(f"   - cvss_v3: {len(cvss_v3):,} records")
    logger.info(f"   - cvss_v4: {len(cvss_v4):,} records")
    logger.info(f"   - Skipped: no_scores={skipped_no_scores:,}, no_version={skipped_no_version:,}, no_vector={skipped_no_vector:,}")
    
    return cvss_v2, cvss_v3, cvss_v4

# -------------------------------------------------------------------
# DIMENSIONS: dim_vendor + dim_products + bridge
# -------------------------------------------------------------------
def create_vendors_products_and_bridge(
    df: pd.DataFrame
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Build vendor and product dimensions with bridge table.
    Returns: (dim_vendor, dim_products, bridge_cve_products)
    """
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
        
        # Handle single dict as list
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

            # Update vendors dict
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

            # Update products dict
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

            # Add to bridge staging
            bridge_records.append({
                'cve_id': cve_id[:20],
                'vendor_lower': vkey,
                'product_lower': pkey
            })

    # Handle empty case
    if not vendors_dict:
        dim_vendor = pd.DataFrame(columns=[
            'vendor_id', 'vendor_name', 'total_products',
            'total_cves', 'first_cve_date', 'last_cve_date'
        ])
        dim_products = pd.DataFrame(columns=[
            'product_id', 'vendor_id', 'product_name',
            'total_cves', 'first_cve_date', 'last_cve_date'
        ])
        bridge = pd.DataFrame(columns=['cve_id', 'product_id'])
        logger.info("✅ dim_vendor: 0 vendors | dim_products: 0 products | bridge: 0")
        return dim_vendor, dim_products, bridge

    # Finalize vendors (convert set to count)
    for v in vendors_dict.values():
        v['total_products'] = len(v['total_products'])

    # Build dim_vendor
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

    # Create vendor lookup (lower name -> id)
    vendor_lookup = {
        row['vendor_name'].lower(): int(row['vendor_id'])
        for _, row in dim_vendor.iterrows()
    }

    # Build dim_products with vendor_id
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

    # Create product lookup: (vendor_id, product_lower) -> product_id
    product_lookup = {
        (int(r['vendor_id']), r['product_name'].lower()): int(r['product_id'])
        for _, r in dim_products.iterrows()
        if pd.notna(r['vendor_id'])
    }

    # Build bridge with product_id
    bridge_df = pd.DataFrame(bridge_records)
    bridge_df['vendor_id'] = bridge_df['vendor_lower'].map(
        lambda v: vendor_lookup.get(v)
    )
    bridge_df['product_id'] = bridge_df.apply(
        lambda x: product_lookup.get((x['vendor_id'], x['product_lower'])),
        axis=1
    )
    bridge = (
        bridge_df[['cve_id', 'product_id']]
        .dropna()
        .drop_duplicates()
        .reset_index(drop=True)
    )

    logger.info(
        f"✅ dim_vendor: {len(dim_vendor):,} | "
        f"dim_products: {len(dim_products):,} | "
        f"bridge: {len(bridge):,}"
    )
    return dim_vendor, dim_products, bridge

# -------------------------------------------------------------------
# Main Transformation Orchestrator
# -------------------------------------------------------------------
def transform_silver_to_gold(df_silver: pd.DataFrame) -> Dict[str, pd.DataFrame]:
    """
    UNIFIED transformation: Silver → Gold star schema.
    
    Returns dictionary with all Gold tables:
    - dim_cve, dim_vendor, dim_products
    - cvss_v2, cvss_v3, cvss_v4
    - bridge_cve_products
    """
    logger.info("=" * 72)
    logger.info("🚀 UNIFIED SILVER ➜ GOLD TRANSFORMATION")
    logger.info("=" * 72)

    # Build dimensions
    dim_cve = create_dim_cve(df_silver)
    dim_vendor, dim_products, bridge_cve_products = create_vendors_products_and_bridge(df_silver)

    # Build facts
    cvss_v2, cvss_v3, cvss_v4 = create_cvss_facts(df_silver)

    # Package results
    gold_tables = {
        'dim_cve': dim_cve,
        'dim_vendor': dim_vendor,
        'dim_products': dim_products,
        'cvss_v2': cvss_v2,
        'cvss_v3': cvss_v3,
        'cvss_v4': cvss_v4,
        'bridge_cve_products': bridge_cve_products,
    }

    # Log statistics
    logger.info("\n" + "=" * 72)
    logger.info("📊 GOLD LAYER STATISTICS")
    logger.info("=" * 72)
    for name, df_table in gold_tables.items():
        if df_table.empty:
            logger.info(f"🔹 {name}: 0 rows")
        else:
            mem = df_table.memory_usage(deep=True).sum() / 1024**2
            logger.info(
                f"🔹 {name}: {len(df_table):,} rows | "
                f"{len(df_table.columns)} cols | {mem:.2f} MB"
            )

    logger.info("=" * 72)
    logger.info("✅ Transformation complete")
    return gold_tables

# -------------------------------------------------------------------
# CLI Entry Point (for standalone testing)
# -------------------------------------------------------------------
def run_silver_to_gold(
    limit: Optional[int] = None,
    if_exists: str = 'replace'
) -> bool:
    """
    Standalone runner for CLI usage (testing).
    Note: This is meant to be called from batch/stream transform scripts.
    """
    logger.info("=" * 72)
    logger.info("🚀 UNIFIED SILVER ➜ GOLD PIPELINE")
    logger.info("=" * 72)

    try:
        engine = create_db_engine()
        
        # Load Silver
        df_silver = load_silver_data(engine, limit=limit)
        if df_silver.empty:
            logger.warning("⚠️  No data in silver layer!")
            return False

        # Transform
        gold_tables = transform_silver_to_gold(df_silver)

        # Import unified Gold loader
        from src.pipeline.load.load_gold_layer import load_gold_layer
        
        # Load to Gold
        logger.info("\n💾 Loading to Gold layer...")
        success = load_gold_layer(gold_tables, engine, if_exists=if_exists)

        if success:
            logger.info("\n🎉 GOLD pipeline completed successfully!")
        else:
            logger.error("\n❌ Pipeline failed during Gold load")

        return success

    except Exception as e:
        logger.error(f"❌ Pipeline failed: {e}", exc_info=True)
        return False

# -------------------------------------------------------------------
# CLI Arguments
# -------------------------------------------------------------------
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Unified Silver ➜ Gold Transformation (for testing)"
    )
    parser.add_argument(
        '--limit',
        type=int,
        default=None,
        help='Limit number of rows to process (testing)'
    )
    parser.add_argument(
        '--if-exists',
        choices=['append', 'replace'],
        default='replace',
        help='Gold load mode'
    )
    args = parser.parse_args()
    
    print(f"\n🚀 Running {Path(__file__).name}")
    print(f"   Limit: {args.limit or 'None (all data)'}")
    print(f"   Mode: {args.if_exists}\n")
    
    success = run_silver_to_gold(limit=args.limit, if_exists=args.if_exists)
    sys.exit(0 if success else 1)