#!/usr/bin/env python3
# =============================================================================
# src/stream/transform/EDA_bronze_to_silver.py
# BRONZE ➜ SILVER: EDA & DATA CLEANING (Stream Processing)
# =============================================================================
# UPDATED: Uses unified Silver loader from src/pipeline/load/load_silver_layer.py
#
# ⚙️ Silver columns only:
# - cve_id, vulnarbilit, published_date, last_modified, loaded_at,
#   remotely_exploit, source_identifier, affected_products (TEXT JSON), 
#   cvss_scores (TEXT JSON)
#
# 🧠 Note:
# We keep the same processing steps, only uses unified loader now.
# If your upstream still provides a Bronze 'category' (CWE id), you can map it to
# 'vulnarbilit' earlier in the pipeline; here we only default if missing.
# =============================================================================

from pathlib import Path
import sys
sys.path.append(str(Path(__file__).resolve().parents[2]))

import argparse
import logging
from typing import Optional

import json
import numpy as np
import pandas as pd
from dateutil import parser as dtparser
from sqlalchemy.engine import Engine

from database.connection import create_db_engine, get_schema_name

# 🔥 UNIFIED SILVER LOADER
from src.pipeline.load.load_silver_layer import load_silver_layer

# -------------------------------------------------------------------
# Logging
# -------------------------------------------------------------------
LOGS_DIR = Path(__file__).resolve().parents[3] / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOGS_DIR / "eda_bronze_to_silver_stream.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("eda_bronze_to_silver_stream")

pd.set_option("display.max_columns", None)
pd.set_option("display.float_format", "{:.2f}".format)

# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------
def _is_nan_float(x) -> bool:
    return isinstance(x, float) and np.isnan(x)

def _is_empty_json_like(x) -> bool:
    if x is None:
        return True
    if _is_nan_float(x):
        return True
    if isinstance(x, str):
        s = x.strip().lower()
        return s in ("", "[]", "{}", "null", "none")
    if isinstance(x, (list, tuple, np.ndarray, dict)):
        return len(x) == 0
    return False

def _parse_date_safe(v):
    """Parse date with fallback to fuzzy parsing"""
    if pd.isna(v):
        return pd.NaT
    s = str(v).strip()
    if not s:
        return pd.NaT
    for fuzzy in (False, True):
        try:
            return dtparser.parse(s, fuzzy=fuzzy)
        except Exception:
            pass
    return pd.NaT

# -------------------------------------------------------------------
# EDA: Data Quality Assessment
# -------------------------------------------------------------------
def perform_eda(df: pd.DataFrame) -> pd.DataFrame:
    """
    Exploratory data analysis (logging only).
    """
    logger.info("=" * 72)
    logger.info("🔍 EXPLORATORY DATA ANALYSIS (STREAM)")
    logger.info("=" * 72)
    
    logger.info(f"\n📊 OVERVIEW:")
    logger.info(f"   Total rows: {len(df):,}")
    logger.info(f"   Total columns: {len(df.columns)}")
    logger.info(f"   Memory usage: {df.memory_usage(deep=True).sum() / 1024**2:.2f} MB")
    
    # Missing values
    logger.info(f"\n🔎 MISSING VALUES ANALYSIS:")
    missing = df.isnull().sum()
    missing_pct = (missing / len(df) * 100).round(2)
    missing_df = pd.DataFrame({
        'Missing': missing,
        'Percentage': missing_pct
    }).sort_values('Missing', ascending=False)
    
    for col, row in missing_df.iterrows():
        if row['Missing'] > 0:
            logger.info(f"   {col}: {row['Missing']:,} ({row['Percentage']:.2f}%)")
    
    # Duplicates
    logger.info(f"\n🔄 DUPLICATES ANALYSIS:")
    if 'cve_id' in df.columns:
        duplicates = df.duplicated(subset=['cve_id']).sum()
        logger.info(f"   Duplicate CVE IDs: {duplicates:,}")
    
    # Dates
    logger.info(f"\n📅 DATE ANALYSIS:")
    if 'published_date' in df.columns:
        parsed = pd.to_datetime(
            df['published_date'].apply(_parse_date_safe),
            errors='coerce'
        )
        valid_dates = parsed.notna().sum()
        logger.info(f"   Valid published dates: {valid_dates:,} / {len(df):,}")
        if valid_dates > 0:
            logger.info(f"   Date range: {parsed.min()} to {parsed.max()}")
    
    # CVSS presence
    logger.info(f"\n🎯 CVSS SCORES ANALYSIS:")
    if 'cvss_scores' in df.columns:
        has_cvss = ~df['cvss_scores'].apply(_is_empty_json_like)
        logger.info(
            f"   CVEs with CVSS: {has_cvss.sum():,} "
            f"({has_cvss.sum()/len(df)*100:.2f}%)"
        )
    
    # Class column
    if 'vulnarbilit' in df.columns:
        vc = df['vulnarbilit'].fillna('uncategorized').replace('', 'uncategorized').value_counts()
        logger.info(f"\n📑 CLASS (vulnarbilit) ANALYSIS: {len(vc)} classes")
        for cls, count in vc.head(5).items():
            logger.info(f"      - {cls}: {count:,}")
    
    logger.info("\n" + "=" * 72)
    return df

# -------------------------------------------------------------------
# Data Cleaning
# -------------------------------------------------------------------
def clean_silver_data(df: pd.DataFrame) -> pd.DataFrame:
    """
    Clean data for Silver layer (unified process).
    """
    logger.info("=" * 72)
    logger.info("🧹 DATA CLEANING (STREAM)")
    logger.info("=" * 72)
    
    d = df.copy()
    initial_rows = len(d)
    
    # 1) Duplicates
    if 'cve_id' in d.columns:
        d = d.drop_duplicates(subset=['cve_id'], keep='first')
    dup_removed = initial_rows - len(d)
    if dup_removed > 0:
        logger.info(f"   ⚠️  Removed {dup_removed:,} duplicate CVE IDs")
    
    # 2) Dates
    for col in ['published_date', 'last_modified']:
        if col in d.columns:
            d[col] = pd.to_datetime(d[col].apply(_parse_date_safe), errors='coerce')
    
    if 'loaded_at' in d.columns:
        d['loaded_at'] = pd.to_datetime(d['loaded_at'], errors='coerce')
    else:
        d['loaded_at'] = pd.Timestamp.utcnow().tz_localize(None)
    
    # 3) Remove rows without critical dates
    before_dates = len(d)
    d = d.dropna(subset=['published_date', 'last_modified'])
    date_removed = before_dates - len(d)
    if date_removed > 0:
        logger.info(f"   ⚠️  Removed {date_removed:,} rows with invalid dates")
    
    # 4) Normalize vulnarbilit (default only; mapping is outside this file)
    if 'vulnarbilit' not in d.columns:
        d['vulnarbilit'] = 'uncategorized'
    d['vulnarbilit'] = (
        d['vulnarbilit']
        .fillna('uncategorized')
        .replace('', 'uncategorized')
    )
    
    # 5) Standardize remotely_exploit (optional, unchanged)
    if 'remotely_exploit' in d.columns:
        d['remotely_exploit'] = d['remotely_exploit'].map({
            'Yes !': True, 'Yes': True, 'True': True, True: True,
            'No': False, 'False': False, False: False
        }).astype('boolean')
    
    # 6) Keep source_identifier if present
    if 'source_identifier' not in d.columns and 'source' in d.columns:
        d['source_identifier'] = d['source']
    
    # 7) Filter CVEs without CVSS (unchanged)
    if 'cvss_scores' in d.columns:
        has_cvss = ~d['cvss_scores'].apply(_is_empty_json_like)
        before_cvss = len(d)
        d = d[has_cvss].copy()
        cvss_removed = before_cvss - len(d)
        if cvss_removed > 0:
            logger.info(f"   ⚠️  Removed {cvss_removed:,} rows without CVSS")
    
    # Summary
    logger.info(f"\n✅ CLEANING SUMMARY:")
    logger.info(f"   Initial rows: {initial_rows:,}")
    logger.info(f"   Final rows: {len(d):,}")
    logger.info(f"   Removed: {initial_rows - len(d):,}")
    logger.info(f"   Quality: {len(d)/initial_rows*100:.2f}%")
    logger.info("\n" + "=" * 72)
    
    return d

# -------------------------------------------------------------------
# Silver Layer Creation
# -------------------------------------------------------------------
def create_silver_layer(df: pd.DataFrame) -> pd.DataFrame:
    """Create Silver format with standardized columns."""
    logger.info("=" * 72)
    logger.info("🏗️  CREATING SILVER LAYER (STREAM)")
    logger.info("=" * 72)
    
    silver_columns = [
        'cve_id', 'vulnarbilit',
        'published_date', 'last_modified', 'loaded_at',
        'remotely_exploit', 'source_identifier',
        'affected_products', 'cvss_scores'
    ]
    
    out = df.copy()
    for col in silver_columns:
        if col not in out.columns:
            out[col] = None
    
    silver_df = out[silver_columns].copy()
    
    logger.info(f"✅ Silver layer: {len(silver_df):,} rows")
    logger.info(f"📊 Columns: {list(silver_df.columns)}")
    return silver_df

# -------------------------------------------------------------------
# Main Pipeline Functions
# -------------------------------------------------------------------
def load_bronze_data(engine: Engine, limit: Optional[int] = None) -> pd.DataFrame:
    """Load data from Bronze (entire DB or limited)."""
    logger.info("=" * 72)
    logger.info("📥 LOADING BRONZE DATA (STREAM)")
    logger.info("=" * 72)
    
    bronze_schema = get_schema_name("bronze")
    if limit:
        query = f"""
            SELECT *
            FROM {bronze_schema}.cve_details
            ORDER BY published_date DESC NULLS LAST
            LIMIT {int(limit)}
        """
    else:
        query = f"SELECT * FROM {bronze_schema}.cve_details;"
    
    df = pd.read_sql(query, engine)
    logger.info(f"✅ Loaded {len(df):,} rows from bronze")
    return df

def run_eda_to_silver(
    limit: Optional[int] = None,
    if_exists: str = 'append'
) -> bool:
    """
    Complete pipeline for CLI: Bronze → EDA → Silver (append-only).
    Uses UNIFIED Silver loader.
    """
    logger.info("=" * 72)
    logger.info("🚀 FULL DATABASE: BRONZE ➜ SILVER PIPELINE (STREAM, UNIFIED LOADER)")
    logger.info("=" * 72)
    
    try:
        engine = create_db_engine()
        
        # Load Bronze
        df_bronze = load_bronze_data(engine, limit=limit)
        if df_bronze.empty:
            logger.warning("⚠️  No data in bronze!")
            return False
        
        # EDA
        df_with_eda = perform_eda(df_bronze)
        
        # Clean
        df_cleaned = clean_silver_data(df_with_eda)
        if df_cleaned.empty:
            logger.error("❌ No data after cleaning!")
            return False
        
        # Create Silver layer
        silver_df = create_silver_layer(df_cleaned)
        
        # Load to Silver (UNIFIED LOADER - always append)
        logger.info("\n💾 Loading to Silver (unified loader, append mode)...")
        tables = {"cve_cleaned": silver_df}
        success = load_silver_layer(tables, engine, if_exists='append')
        
        if success:
            logger.info("\n" + "=" * 72)
            logger.info("🎉 FULL DATABASE PIPELINE COMPLETED (STREAM)")
            logger.info("=" * 72)
        
        return success
        
    except Exception as e:
        logger.error(f"❌ Pipeline failed: {e}", exc_info=True)
        return False

# -------------------------------------------------------------------
# CLI
# -------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="Bronze ➜ Silver: EDA & Cleaning Pipeline (Stream, unified loader)"
    )
    parser.add_argument(
        '--limit',
        type=int,
        default=None,
        help='Limit rows (for testing)'
    )
    parser.add_argument(
        '--if-exists',
        choices=['append', 'replace'],
        default='append',
        help='(always append internally)'
    )
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    print(f"\n🚀 Running {Path(__file__).name}")
    print(f"   Limit: {args.limit or 'None (full DB)'}")
    print(f"   Mode: append (unified loader)")
    
    success = run_eda_to_silver(limit=args.limit, if_exists=args.if_exists)
    sys.exit(0 if success else 1)