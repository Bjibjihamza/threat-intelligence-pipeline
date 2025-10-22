#!/usr/bin/env python3
# =============================================================================
# src/pipeline/load/load_silver_layer.py
# UNIFIED SILVER LAYER LOADER
# =============================================================================
# Used by both:
#   - batch/transform/EDA_bronze_to_silver.py (batch processing)
#   - stream/transform/EDA_bronze_to_silver.py (real-time streaming)
#
# Table: silver.cve_cleaned
#   cve_id (PK), vulnarbilit, published_date, last_modified, loaded_at,
#   remotely_exploit, source_identifier, affected_products (TEXT JSON),
#   cvss_scores (TEXT JSON)
#
# Mode: INSERT ONLY (skip duplicates) - NEVER TRUNCATE/REPLACE
# =============================================================================

from __future__ import annotations

from pathlib import Path
import sys
import logging
from typing import Dict, Optional
from datetime import datetime
import json

import numpy as np
import pandas as pd
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError

# Determine project root dynamically
THIS_FILE = Path(__file__).resolve()
PROJECT_ROOT = THIS_FILE.parents[3]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

from src.database.connection import create_db_engine, get_schema_name

# ----------------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------------
LOGS_DIR = PROJECT_ROOT / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOGS_DIR / "load_silver_unified.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("unified_silver_loader")

# ----------------------------------------------------------------------------
# Schema Validation
# ----------------------------------------------------------------------------
def verify_silver_schema(engine: Engine) -> bool:
    """
    Verify that silver schema and cve_cleaned table exist with required columns.
    """
    schema = get_schema_name("silver")
    table = "cve_cleaned"
    
    required_columns = {
        "cve_id", "vulnarbilit", "published_date", "last_modified", "loaded_at",
        "remotely_exploit", "source_identifier", "affected_products", "cvss_scores"
    }
    
    logger.info(f"🔎 Verifying silver schema '{schema}' and table '{table}'...")
    
    try:
        with engine.connect() as conn:
            # Check schema exists
            if not conn.execute(
                text("SELECT 1 FROM information_schema.schemata WHERE schema_name = :s"),
                {"s": schema}
            ).fetchone():
                logger.error(f"❌ Schema '{schema}' does not exist! Run silver.sql first.")
                return False
            
            # Check table exists
            if not conn.execute(
                text("SELECT 1 FROM information_schema.tables WHERE table_schema = :s AND table_name = :t"),
                {"s": schema, "t": table}
            ).fetchone():
                logger.error(f"❌ Table {schema}.{table} does not exist! Run silver.sql first.")
                return False
            
            # Check required columns
            result = conn.execute(
                text("""
                    SELECT column_name
                    FROM information_schema.columns
                    WHERE table_schema = :s AND table_name = :t
                """),
                {"s": schema, "t": table}
            )
            existing_columns = {row[0] for row in result.fetchall()}
            
            missing_columns = required_columns - existing_columns
            if missing_columns:
                logger.error(f"❌ Missing columns in {schema}.{table}: {sorted(missing_columns)}")
                return False
        
        logger.info("✅ Silver schema validated")
        return True
        
    except Exception as e:
        logger.error(f"❌ Error validating schema: {e}")
        return False

# ----------------------------------------------------------------------------
# Data Normalization Helpers
# ----------------------------------------------------------------------------
def _is_nan_float(x) -> bool:
    """Check if value is NaN float."""
    return isinstance(x, float) and np.isnan(x)

def safe_json_text(x):
    """
    Convert to JSON TEXT (compact) or None if empty/invalid.
    Handles various input types: dict, list, str, None.
    """
    try:
        if x is None or _is_nan_float(x):
            return None
        
        # Already list/dict
        if isinstance(x, (list, dict)):
            if len(x) == 0:
                return None
            return json.dumps(x, ensure_ascii=False, separators=(",", ":"))
        
        # String that needs parsing
        if isinstance(x, str):
            s = x.strip()
            if s == "" or s.lower() in ("null", "none", "nan", "[]", "{}"):
                return None
            try:
                parsed = json.loads(s)
                if isinstance(parsed, (list, dict)) and len(parsed) == 0:
                    return None
                return json.dumps(parsed, ensure_ascii=False, separators=(",", ":"))
            except Exception:
                return None
        
        return None
    except Exception:
        return None

def _coerce_bool(v):
    """
    Normalize various boolean representations for remotely_exploit field.
    """
    if v is None or _is_nan_float(v):
        return None
    s = str(v).strip().lower()
    if s in {'true', 'yes', 'y', '1', 'remote', 'remotely exploitable', 'available'}:
        return True
    if s in {'false', 'no', 'n', '0', 'local', 'not remotely exploitable', 'unavailable'}:
        return False
    return None

# ----------------------------------------------------------------------------
# DataFrame Preparation
# ----------------------------------------------------------------------------
def prepare_silver_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Prepare DataFrame for insertion into silver.cve_cleaned.
    - Ensures all required columns exist
    - Converts dates to timezone-naive timestamps
    - Converts JSON columns to TEXT
    - Normalizes boolean values
    - Removes invalid rows
    """
    logger.info("🛠️ Preparing dataframe for silver layer...")
    
    required_columns = [
        'cve_id', 'vulnarbilit',
        'published_date', 'last_modified', 'loaded_at',
        'remotely_exploit', 'source_identifier',
        'affected_products', 'cvss_scores'
    ]
    
    df_clean = df.copy()
    
    # Add missing columns with None
    for col in required_columns:
        if col not in df_clean.columns:
            logger.warning(f"⚠️  Adding missing column: {col}")
            df_clean[col] = None
    
    # Keep only required columns
    df_clean = df_clean[required_columns].copy()
    
    # Convert dates to timezone-naive timestamps
    for date_col in ['published_date', 'last_modified', 'loaded_at']:
        df_clean[date_col] = pd.to_datetime(df_clean[date_col], errors='coerce')
        # Remove timezone if present
        if pd.api.types.is_datetime64tz_dtype(df_clean[date_col]):
            df_clean[date_col] = df_clean[date_col].dt.tz_localize(None)
    
    # Convert JSON columns to TEXT
    for json_col in ['affected_products', 'cvss_scores']:
        df_clean[json_col] = df_clean[json_col].apply(safe_json_text)
    
    # Normalize vulnarbilit (default to 'uncategorized')
    df_clean['vulnarbilit'] = (
        df_clean['vulnarbilit']
        .fillna('uncategorized')
        .replace('', 'uncategorized')
        .replace('None', 'uncategorized')
    )
    
    # Normalize remotely_exploit to boolean
    if 'remotely_exploit' in df_clean.columns:
        df_clean['remotely_exploit'] = df_clean['remotely_exploit'].apply(_coerce_bool)
    
    # Remove rows with invalid cve_id
    before = len(df_clean)
    df_clean = df_clean[
        df_clean['cve_id'].notna() & 
        (df_clean['cve_id'].astype(str).str.strip() != '')
    ]
    after = len(df_clean)
    if before > after:
        logger.warning(f"⚠️  Removed {before - after} rows with invalid cve_id")
    
    # Remove duplicate cve_ids (keep first)
    before = len(df_clean)
    df_clean = df_clean.drop_duplicates(subset=['cve_id'], keep='first')
    after = len(df_clean)
    if before > after:
        logger.warning(f"⚠️  Removed {before - after} duplicate cve_ids in DataFrame")
    
    logger.info(f"✅ Prepared {len(df_clean):,} rows for silver layer")
    return df_clean

# ----------------------------------------------------------------------------
# Load to Silver - INSERT ONLY (Skip Duplicates)
# ----------------------------------------------------------------------------
def load_to_silver_table(
    df: pd.DataFrame,
    engine: Engine
) -> Dict[str, int]:
    """
    Insert-only loader for silver.cve_cleaned.
    Skips CVEs that already exist in the table.
    NEVER truncates or replaces existing data.
    
    Args:
        df: DataFrame with silver layer data
        engine: SQLAlchemy engine
    
    Returns:
        Dictionary with 'inserted', 'skipped', 'failed' counts
    """
    schema = get_schema_name("silver")
    table = "cve_cleaned"
    full_table = f"{schema}.{table}"
    
    logger.info("=" * 72)
    logger.info(f"🚀 LOADING TO SILVER: {full_table}")
    logger.info("Mode: INSERT ONLY (skip existing) - NO TRUNCATE EVER")
    logger.info("=" * 72)
    
    if df.empty:
        logger.warning("⚠️  No data to load.")
        return {"inserted": 0, "skipped": 0, "failed": 0}
    
    stats = {"inserted": 0, "skipped": 0, "failed": 0}
    start_time = datetime.now()
    
    try:
        # Prepare data
        df_prepared = prepare_silver_dataframe(df)
        if df_prepared.empty:
            logger.warning("⚠️  No valid data after preparation.")
            return stats
        
        logger.info(f"📊 DataFrame shape: {df_prepared.shape}")
        logger.info("🔍 Checking for existing CVEs in Silver...")
        
        # Get CVE IDs from DataFrame
        cve_ids = df_prepared["cve_id"].tolist()
        if not cve_ids:
            logger.warning("⚠️  No CVE IDs to check.")
            return stats
        
        # Build safe IN clause
        escaped_ids = ["'" + str(c).replace("'", "''") + "'" for c in cve_ids]
        placeholders = ",".join(escaped_ids)
        
        # Query existing CVEs
        with engine.connect() as conn:
            result = conn.execute(
                text(f"SELECT cve_id FROM {full_table} WHERE cve_id IN ({placeholders})")
            )
            existing_cves = {row[0] for row in result.fetchall()}
        
        logger.info(f"📋 Already in Silver: {len(existing_cves):,} CVE(s)")
        
        # Filter to only new rows
        df_to_insert = df_prepared[~df_prepared["cve_id"].isin(existing_cves)].copy()
        stats["skipped"] = len(existing_cves)
        
        if df_to_insert.empty:
            logger.info("✅ All CVEs already exist in Silver - nothing to insert.")
            logger.info(f"⭕ Skipped: {stats['skipped']:,} CVE(s)")
            return stats
        
        logger.info(f"📥 New CVEs to insert: {len(df_to_insert):,}")
        
        # Insert new rows
        logger.info("💾 Inserting rows (append mode)...")
        df_to_insert.to_sql(
            name=table,
            con=engine,
            schema=schema,
            if_exists="append",
            index=False,
            method="multi",
            chunksize=500,
        )
        
        stats["inserted"] = len(df_to_insert)
        
        # Get final count
        with engine.connect() as conn:
            final_count = conn.execute(
                text(f"SELECT COUNT(*) FROM {full_table}")
            ).scalar()
        
        duration = (datetime.now() - start_time).total_seconds()
        
        logger.info("=" * 72)
        logger.info("📊 LOAD STATISTICS")
        logger.info("=" * 72)
        logger.info(f"✅ Inserted (new):      {stats['inserted']:,}")
        logger.info(f"⭕ Skipped (existing):  {stats['skipped']:,}")
        logger.info(f"🧮 Total in Silver:     {final_count:,}")
        logger.info(f"⏱️ Duration:            {duration:.2f}s")
        logger.info("=" * 72)
        
        return stats
        
    except SQLAlchemyError as e:
        logger.error(f"❌ Database error: {e}", exc_info=True)
        stats["failed"] = len(df)
        raise
    except Exception as e:
        logger.error(f"❌ Unexpected error: {e}", exc_info=True)
        stats["failed"] = len(df)
        raise

# ----------------------------------------------------------------------------
# Main Orchestrator
# ----------------------------------------------------------------------------
def load_silver_layer(
    tables: Dict[str, pd.DataFrame],
    engine: Optional[Engine] = None,
    if_exists: str = 'append',  # Parameter kept for compatibility but always append
    convert_jsonb: bool = False  # Optional JSONB conversion (usually not needed)
) -> bool:
    """
    UNIFIED entry point: Load data to Silver layer (append-only, skip duplicates).
    
    Args:
        tables: Dictionary with 'cve_cleaned' key containing DataFrame
        engine: SQLAlchemy engine (creates new if None)
        if_exists: Mode ('append' or 'replace') - always uses append internally
        convert_jsonb: Whether to convert TEXT JSON to JSONB (optional)
    
    Returns:
        Boolean indicating success
    """
    logger.info("=" * 72)
    logger.info("🎯 UNIFIED SILVER LAYER LOAD PIPELINE")
    logger.info("=" * 72)
    
    if 'cve_cleaned' not in tables:
        logger.error("❌ Missing 'cve_cleaned' in tables dict!")
        return False
    
    try:
        if engine is None:
            engine = create_db_engine()
        
        if not verify_silver_schema(engine):
            return False
        
        df_cleaned = tables['cve_cleaned']
        
        # Always use INSERT ONLY mode
        _ = load_to_silver_table(df_cleaned, engine)
        
        # Optional: Convert JSON TEXT to JSONB (if stored procedure exists)
        if convert_jsonb:
            try:
                logger.info("🔄 Converting TEXT JSON columns to JSONB...")
                with engine.begin() as conn:
                    conn.execute(text("SELECT silver.convert_json_columns();"))
                logger.info("✅ JSON conversion completed")
            except Exception as e:
                logger.warning(f"⚠️  JSON conversion failed (optional): {e}")
        
        # Refresh statistics
        schema = get_schema_name("silver")
        with engine.begin() as conn:
            conn.execute(text(f"ANALYZE {schema}.cve_cleaned;"))
        
        logger.info("\n" + "=" * 72)
        logger.info("🎉 SILVER LAYER LOAD COMPLETED SUCCESSFULLY")
        logger.info("=" * 72)
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Silver layer load failed: {e}", exc_info=True)
        return False

# ----------------------------------------------------------------------------
# CLI Helper (for testing)
# ----------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Load data to Silver layer (unified loader, append-only)"
    )
    parser.add_argument(
        '--test',
        action='store_true',
        help='Run test mode with sample data'
    )
    args = parser.parse_args()
    
    if args.test:
        logger.info("🧪 Running test mode...")
        
        # Create test data
        test_data = pd.DataFrame([
            {
                'cve_id': f'CVE-2024-TEST-{i:03d}',
                'vulnarbilit': ['xss', 'sql_injection', 'memory_corruption'][i % 3],
                'published_date': pd.Timestamp.now(),
                'last_modified': pd.Timestamp.now(),
                'loaded_at': pd.Timestamp.now(),
                'remotely_exploit': bool(i % 2),
                'source_identifier': 'test@example.com',
                'affected_products': json.dumps([{"vendor": "test", "product": f"app{i}"}]),
                'cvss_scores': json.dumps([{"score": f"{7 + i % 3}.5", "version": "3.1"}])
            }
            for i in range(3)
        ])
        
        tables = {'cve_cleaned': test_data}
        success = load_silver_layer(tables)
        
        sys.exit(0 if success else 1)
    else:
        logger.info("💡 Usage: python load_silver_layer.py --test")
        logger.info("💡 Or import and use: load_silver_layer(tables, engine)")