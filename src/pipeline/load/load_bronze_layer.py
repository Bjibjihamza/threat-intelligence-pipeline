#!/usr/bin/env python3
# =============================================================================
# src/pipeline/load/load_bronze_layer.py
# UNIFIED BRONZE LAYER LOADER
# =============================================================================
# Used by both:
#   - batch/extract/nvd_json_to_bronze.py (NVD JSON files)
#   - stream/scrape_live_cvefeed_bronze.py (Telegram → cvefeed.io scraping)
#
# Table: raw.cve_details
#   cve_id (PK), published_date (TEXT), last_modified (TEXT),
#   remotely_exploit (BOOLEAN), source_identifier (TEXT), category (TEXT),
#   affected_products (JSONB), cvss_scores (JSONB), loaded_at (DEFAULT NOW())
# =============================================================================

from __future__ import annotations

from pathlib import Path
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
import json

import numpy as np
import pandas as pd
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.engine import Engine
from psycopg2.extras import execute_values, Json

# Determine project root dynamically
THIS_FILE = Path(__file__).resolve()
PROJECT_ROOT = THIS_FILE.parents[3]  # Assuming src/pipeline/load/load_bronze_layer.py

import sys
if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

from src.database.connection import create_db_engine, get_schema_name

# ----------------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------------
LOGS_DIR = PROJECT_ROOT / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOGS_DIR / "load_bronze_unified.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("unified_bronze_loader")

# ----------------------------------------------------------------------------
# Schema Validation
# ----------------------------------------------------------------------------
def verify_bronze_schema(engine: Engine) -> bool:
    """
    Verify that bronze schema ('raw') and cve_details table exist.
    """
    schema = get_schema_name("bronze")  # Expected: "raw"
    table = "cve_details"
    logger.info(f"🔎 Verifying bronze schema '{schema}' and table '{schema}.{table}'...")

    with engine.connect() as conn:
        # Check schema exists
        if not conn.execute(
            text("SELECT 1 FROM information_schema.schemata WHERE schema_name = :s"),
            {"s": schema}
        ).fetchone():
            logger.error(f"❌ Schema '{schema}' does not exist! Run your schema SQL first.")
            return False

        # Check table exists
        if not conn.execute(
            text("SELECT 1 FROM information_schema.tables WHERE table_schema = :s AND table_name = :t"),
            {"s": schema, "t": table}
        ).fetchone():
            logger.error(f"❌ Table {schema}.{table} does not exist!")
            return False

    logger.info("✅ Bronze schema validated")
    return True

# ----------------------------------------------------------------------------
# Data Normalization Helpers
# ----------------------------------------------------------------------------
def _coerce_bool(v: Optional[Any]) -> Optional[bool]:
    """
    Normalize various boolean representations for remotely_exploit field.
    """
    if v is None or (isinstance(v, float) and np.isnan(v)):
        return None
    s = str(v).strip().lower()
    truthy = {'true', 'yes', 'y', '1', 'remote', 'remotely exploitable', 'available'}
    falsy = {'false', 'no', 'n', '0', 'local', 'not remotely exploitable',
             'unavailable', 'na', 'n/a', '-', ''}
    if s in truthy:
        return True
    if s in falsy:
        return False
    return None

def _norm_text(v: Any) -> Optional[str]:
    """
    Keep None or trimmed string; avoid literals like 'nan'/'None'.
    """
    if v is None or (isinstance(v, float) and np.isnan(v)):
        return None
    s = str(v).strip()
    return s if s and s.lower() not in {'nan', 'none', ''} else None

def _norm_json(v: Any) -> Optional[Any]:
    """
    Ensure list/dict/None for JSONB; parse if string.
    """
    if v is None or (isinstance(v, float) and np.isnan(v)):
        return None
    if isinstance(v, (list, dict)):
        return v
    try:
        return json.loads(v)
    except Exception:
        return []

def _as_text(v: Any) -> Optional[str]:
    """
    Bronze keeps published_date/last_modified as TEXT.
    If datetime given, convert to ISO string; else stringify.
    """
    if v is None or (isinstance(v, float) and np.isnan(v)):
        return None
    if isinstance(v, datetime):
        return v.isoformat()
    s = str(v).strip()
    return s if s and s.lower() not in {'nan', 'none', ''} else None

# ----------------------------------------------------------------------------
# DataFrame Preparation
# ----------------------------------------------------------------------------
def prepare_dataframe(cve_data_list: List[Dict[str, Any]]) -> pd.DataFrame:
    """
    Transform list of CVE dicts to DataFrame conforming to raw.cve_details schema.
    Drops legacy fields (title/description/url).
    Normalizes 'source' → 'source_identifier' for backward compatibility.
    """
    logger.info("🛠️ Preparing data for Bronze insertion...")

    if not cve_data_list:
        logger.warning("⚠️  No data to prepare!")
        return pd.DataFrame()

    # Normalize keys for backward compatibility
    normalized: List[Dict[str, Any]] = []
    for row in cve_data_list:
        r = dict(row)

        # Map legacy top-level 'source' → 'source_identifier'
        if 'source_identifier' not in r and 'source' in r:
            r['source_identifier'] = r.pop('source')

        # Normalize inner cvss_scores keys
        if isinstance(r.get('cvss_scores'), list):
            for s in r['cvss_scores']:
                if isinstance(s, dict):
                    if 'source_identifier' not in s and 'source' in s:
                        s['source_identifier'] = s.pop('source')

        normalized.append(r)

    df = pd.DataFrame(normalized).copy()

    # Required columns for raw.cve_details
    required = [
        'cve_id',
        'published_date',
        'last_modified',
        'remotely_exploit',
        'source_identifier',
        'category',
        'affected_products',
        'cvss_scores',
    ]

    # Add missing columns as None
    for col in required:
        if col not in df.columns:
            df[col] = None

    # Apply normalizations
    df['published_date'] = df['published_date'].apply(_as_text)
    df['last_modified'] = df['last_modified'].apply(_as_text)
    df['remotely_exploit'] = df['remotely_exploit'].map(_coerce_bool)

    for col in ['affected_products', 'cvss_scores']:
        df[col] = df[col].apply(_norm_json)

    for col in ['cve_id', 'source_identifier', 'category']:
        df[col] = df[col].apply(_norm_text)

    # Drop legacy columns that are no longer in schema
    drop_legacy = [c for c in ['title', 'description', 'url', 'loaded_at'] 
                   if c in df.columns]
    if drop_legacy:
        df = df.drop(columns=drop_legacy)

    # Keep only required columns in order
    df = df[required]

    # Remove rows with missing cve_id
    df = df[df['cve_id'].notna() & (df['cve_id'].astype(str).str.strip() != '')]

    logger.info(f"✅ Prepared {len(df):,} rows for insertion")
    return df

# ----------------------------------------------------------------------------
# Direct Loader
# ----------------------------------------------------------------------------
def load_to_bronze(df: pd.DataFrame, engine: Engine, batch_size: int = 1000) -> Dict[str, int]:
    """
    Load prepared DataFrame to raw.cve_details using batch insert.
    Uses ON CONFLICT DO NOTHING to skip duplicates.
    """
    schema = get_schema_name("bronze")  # Expected: "raw"
    table = "cve_details"

    logger.info("=" * 70)
    logger.info(f"🚀 LOADING TO BRONZE LAYER ({schema}.{table})")
    logger.info("=" * 70)

    if df.empty:
        logger.warning("⚠️  No data to load!")
        return {'inserted': 0, 'skipped': 0, 'failed': 0}

    stats = {'inserted': 0, 'skipped': 0, 'failed': 0}
    start_time = datetime.now()

    def row_iter(frame: pd.DataFrame):
        """Generator for batch insert values."""
        for _, r in frame.iterrows():
            yield (
                r['cve_id'],
                r['published_date'],
                r['last_modified'],
                r['remotely_exploit'],
                r['source_identifier'],
                r['category'],
                Json(r['affected_products']) if r['affected_products'] is not None else None,
                Json(r['cvss_scores']) if r['cvss_scores'] is not None else None,
            )

    insert_sql = f"""
        INSERT INTO {schema}.{table} (
            cve_id, published_date, last_modified,
            remotely_exploit, source_identifier, category,
            affected_products, cvss_scores
        ) VALUES %s
        ON CONFLICT (cve_id) DO NOTHING
    """

    try:
        total_rows = len(df)
        inserted_total = 0

        raw_conn = engine.raw_connection()
        try:
            with raw_conn.cursor() as cur:
                execute_values(cur, insert_sql, row_iter(df), page_size=batch_size)
                inserted_total = cur.rowcount
            raw_conn.commit()
        finally:
            raw_conn.close()

        stats['inserted'] = inserted_total
        stats['skipped'] = total_rows - inserted_total

        # Get total count after insert
        with engine.connect() as conn:
            count_after = conn.execute(
                text(f"SELECT COUNT(*) FROM {schema}.{table}")
            ).scalar()

        duration = (datetime.now() - start_time).total_seconds()

        logger.info("=" * 70)
        logger.info("📊 LOAD STATISTICS")
        logger.info("=" * 70)
        logger.info(f"✅ Inserted:  {stats['inserted']:,} new CVEs")
        logger.info(f"⭕ Skipped:   {stats['skipped']:,} duplicates")
        logger.info(f"⏱️ Duration:  {duration:.2f}s")
        logger.info(f"🧮 Total CVEs in database: {count_after:,}")
        logger.info("=" * 70)

        return stats

    except SQLAlchemyError as e:
        logger.error(f"❌ Database error during load: {e}")
        stats['failed'] = len(df)
        raise
    except Exception as e:
        logger.error(f"❌ Unexpected error during load: {e}")
        stats['failed'] = len(df)
        raise

# ----------------------------------------------------------------------------
# Main Orchestrator
# ----------------------------------------------------------------------------
def load_bronze_layer(
    cve_data_list: List[Dict[str, Any]], 
    engine: Optional[Engine] = None
) -> Dict[str, int]:
    """
    UNIFIED entry point: Load list of CVE dicts to Bronze layer.
    
    Args:
        cve_data_list: List of CVE dictionaries
        engine: SQLAlchemy engine (creates new if None)
    
    Returns:
        Dictionary with 'inserted', 'skipped', 'failed' counts
    """
    logger.info("=" * 70)
    logger.info("🎯 UNIFIED BRONZE LAYER LOAD PIPELINE")
    logger.info("=" * 70)

    if engine is None:
        engine = create_db_engine()

    if not verify_bronze_schema(engine):
        logger.error("❌ Schema validation failed!")
        return {'inserted': 0, 'skipped': 0, 'failed': 0}

    df = prepare_dataframe(cve_data_list)
    if df.empty:
        logger.warning("⚠️  No valid data to load")
        return {'inserted': 0, 'skipped': 0, 'failed': 0}

    stats = load_to_bronze(df, engine)

    logger.info("\n" + "=" * 70)
    logger.info("🎉 BRONZE LAYER LOAD COMPLETED")
    logger.info("=" * 70)

    return stats

# ----------------------------------------------------------------------------
# CLI Helper (for testing with CSV)
# ----------------------------------------------------------------------------
def load_from_csv(csv_path: str, engine: Optional[Engine] = None) -> Dict[str, int]:
    """
    Load CVE data from CSV file (for testing purposes).
    """
    logger.info(f"📂 Loading data from CSV: {csv_path}")

    df = pd.read_csv(
        csv_path,
        dtype=str,
        keep_default_na=False,
        on_bad_lines='skip',
        quotechar='"',
        escapechar='\\',
        engine='python',
    )

    def parse_json(s):
        try:
            return json.loads(s) if s else []
        except Exception:
            return []

    # Build list of dicts
    cve_data_list: List[Dict[str, Any]] = []
    for _, row in df.iterrows():
        obj = row.to_dict()

        # Normalize JSON columns
        for col in ['affected_products', 'cvss_scores']:
            obj[col] = parse_json(obj.get(col, ''))

        cve_data_list.append(obj)

    return load_bronze_layer(cve_data_list, engine)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        csv_file = sys.argv[1]
        stats = load_from_csv(csv_file)
        logger.info(
            f"✅ Done. Inserted={stats['inserted']}, "
            f"Skipped={stats['skipped']}, Failed={stats['failed']}"
        )
    else:
        logger.info("💡 Usage: python load_bronze_layer.py <csv_file>")
        logger.info("💡 Or import and use: load_bronze_layer(cve_data_list, engine)")