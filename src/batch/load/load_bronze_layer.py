# ============================================================================
# LOAD BRONZE LAYER - Direct Scraper to PostgreSQL (no staging)
# ============================================================================
# Description : Load raw CVE data directly into raw.cve_details
# Schema      : raw.cve_details with
#               - remotely_exploit  BOOLEAN
#               - source_identifier TEXT
#               - affected_products JSONB
#               - cvss_scores       JSONB
#               - loaded_at         TIMESTAMPTZ DEFAULT NOW()
# Author      : Data Engineering Team
# Date        : 2025-10-16
# ============================================================================

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

# 👇 Central connection manager
from database.connection import create_db_engine, get_schema_name

# ----------------------------------------------------------------------------
# Logging Configuration
# ----------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[3]
LOGS_DIR = PROJECT_ROOT / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOGS_DIR / "load_bronze.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------------
# Schema Validation
# ----------------------------------------------------------------------------
def verify_bronze_schema(engine: Engine) -> bool:
    """
    Verify that bronze schema and cve_details table exist.
    get_schema_name("bronze") should resolve to "raw" in your setup.
    """
    schema = get_schema_name("bronze")  # expected "raw"
    table = "cve_details"
    logger.info(f"🔎 Verifying bronze schema '{schema}' and table '{schema}.{table}'...")

    with engine.connect() as conn:
        # Check schema
        result = conn.execute(
            text("""
                SELECT schema_name
                FROM information_schema.schemata
                WHERE schema_name = :schema
            """),
            {"schema": schema},
        )
        if not result.fetchone():
            logger.error(f"❌ Schema '{schema}' does not exist! Run your schema SQL first.")
            return False

        # Check table
        result = conn.execute(
            text("""
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = :schema AND table_name = :table
            """),
            {"schema": schema, "table": table},
        )
        if not result.fetchone():
            logger.error(f"❌ Table {schema}.{table} does not exist!")
            return False

    logger.info("✅ Bronze schema validated")
    return True

# ----------------------------------------------------------------------------
# Data Preparation
# ----------------------------------------------------------------------------
def _coerce_bool(v: Optional[Any]) -> Optional[bool]:
    """Map various truthy/falsy inputs to bool/None for remotely_exploit."""
    if v is None or (isinstance(v, float) and np.isnan(v)):
        return None
    s = str(v).strip().lower()
    truthy = {'true', 'yes', 'y', '1', 'remote', 'remotely exploitable', 'available'}
    falsy  = {'false', 'no', 'n', '0', 'local', 'not remotely exploitable',
              'unavailable', 'na', 'n/a', '-', ''}
    if s in truthy:
        return True
    if s in falsy:
        return False
    return None

def _norm_text(v: Any) -> Optional[str]:
    """Normalize text columns: keep None or trimmed string; avoid 'nan' literals."""
    if v is None or (isinstance(v, float) and np.isnan(v)):
        return None
    s = str(v).strip()
    return s if s not in {'nan', 'None'} else None

def _norm_json(v: Any) -> Optional[Any]:
    """Ensure JSONB columns are Python list/dict/None. Parse strings if needed."""
    if v is None or (isinstance(v, float) and np.isnan(v)):
        return None
    if isinstance(v, (list, dict)):
        return v
    try:
        return json.loads(v)
    except Exception:
        return []

def prepare_dataframe(cve_data_list: List[Dict[str, Any]]) -> pd.DataFrame:
    """
    Convert list of CVE dictionaries to DataFrame ready for PostgreSQL
    - Keep JSON columns as Python list/dict (no json.dumps)
    - Coerce remotely_exploit to boolean
    - Let Postgres set loaded_at with DEFAULT NOW()
    - Map legacy 'source' → 'source_identifier'
    """
    logger.info("🛠️ Preparing data for database insertion...")

    if not cve_data_list:
        logger.warning("⚠️  No data to prepare!")
        return pd.DataFrame()

    # Backward-compat: fix top-level + inner CVSS keys if old 'source' present
    normalized: List[Dict[str, Any]] = []
    for row in cve_data_list:
        r = dict(row)
        if 'source_identifier' not in r and 'source' in r:
            r['source_identifier'] = r.pop('source')

        if isinstance(r.get('cvss_scores'), list):
            for s in r['cvss_scores']:
                if isinstance(s, dict) and 'source_identifier' not in s and 'source' in s:
                    s['source_identifier'] = s.pop('source')

        normalized.append(r)

    df = pd.DataFrame(normalized).copy()

    required = [
        'cve_id', 'title', 'description', 'published_date', 'last_modified',
        'remotely_exploit', 'source_identifier', 'category', 'affected_products', 'cvss_scores', 'url'
    ]
    for col in required:
        if col not in df.columns:
            df[col] = None

    df['remotely_exploit'] = df['remotely_exploit'].map(_coerce_bool)

    for col in ['affected_products', 'cvss_scores']:
        df[col] = df[col].apply(_norm_json)

    for col in ['cve_id', 'title', 'description', 'published_date',
                'last_modified', 'source_identifier', 'category', 'url']:
        df[col] = df[col].apply(_norm_text)

    if 'loaded_at' in df.columns:
        df = df.drop(columns=['loaded_at'])

    logger.info(f"✅ Prepared {len(df):,} rows for insertion")
    return df

# ----------------------------------------------------------------------------
# Direct Loader (no staging)
# ----------------------------------------------------------------------------
def load_to_bronze(df: pd.DataFrame, engine: Engine, batch_size: int = 1000) -> Dict[str, int]:
    schema = get_schema_name("bronze")  # expected "raw"
    table = "cve_details"

    logger.info("=" * 70)
    logger.info(f"🚀 LOADING TO BRONZE LAYER ({schema}.{table})")
    logger.info("=" * 70)

    if df.empty:
        logger.warning("⚠️  No data to load!")
        return {'inserted': 0, 'skipped': 0, 'failed': 0}

    df = df[df['cve_id'].notna() & (df['cve_id'].astype(str).str.strip() != '')]

    stats = {'inserted': 0, 'skipped': 0, 'failed': 0}
    start_time = datetime.now()

    def row_iter(frame: pd.DataFrame):
        for _, r in frame.iterrows():
            yield (
                r['cve_id'],
                r['title'],
                r['description'],
                r['published_date'],
                r['last_modified'],
                r['remotely_exploit'],
                r['source_identifier'],   # ← renamed
                r['category'],
                Json(r['affected_products']) if r['affected_products'] is not None else None,
                Json(r['cvss_scores']) if r['cvss_scores'] is not None else None,
                r['url'],
            )

    insert_sql = f"""
        INSERT INTO {schema}.{table} (
            cve_id, title, description, published_date, last_modified,
            remotely_exploit, source_identifier, category, affected_products, cvss_scores, url
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
        stats['skipped']  = total_rows - inserted_total

        with engine.connect() as conn:
            count_after = conn.execute(text(f"SELECT COUNT(*) FROM {schema}.{table}")).scalar()

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
def load_bronze_layer(cve_data_list: List[Dict[str, Any]], engine: Optional[Engine] = None) -> Dict[str, int]:
    """
    Main function to load scraped CVE data to bronze layer.
    """
    logger.info("=" * 70)
    logger.info("🎯 BRONZE LAYER LOAD PIPELINE")
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
# CLI Helper: Load from CSV backup (optional)
# ----------------------------------------------------------------------------
def load_from_csv(csv_path: str, engine: Optional[Engine] = None) -> Dict[str, int]:
    """
    Load CVE rows from a CSV backup file produced by your scraper.
    The CSV must include columns for affected_products/cvss_scores as JSON strings.
    """
    logger.info(f"📂 Loading data from CSV: {csv_path}")

    df = pd.read_csv(
        csv_path,
        dtype=str,
        keep_default_na=False,
        on_bad_lines='skip',
        quotechar='"',
        escapechar='\\',
        engine='python'
    )

    cve_data_list: List[Dict[str, Any]] = []
    for _, row in df.iterrows():
        obj = row.to_dict()

        # Map legacy key if necessary
        if 'source_identifier' not in obj and 'source' in obj:
            obj['source_identifier'] = obj.pop('source')

        # Normalize JSON columns
        for col in ['affected_products', 'cvss_scores']:
            try:
                obj[col] = json.loads(obj.get(col) or '[]')
            except Exception:
                obj[col] = []

        # Ensure inner CVSS rows use source_identifier
        if isinstance(obj.get('cvss_scores'), list):
            for s in obj['cvss_scores']:
                if isinstance(s, dict) and 'source_identifier' not in s and 'source' in s:
                    s['source_identifier'] = s.pop('source')

        cve_data_list.append(obj)

    return load_bronze_layer(cve_data_list, engine)

# ----------------------------------------------------------------------------
# Main Entry Point
# ----------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        csv_file = sys.argv[1]
        logger.info(f"📥 Loading from CSV: {csv_file}")
        stats = load_from_csv(csv_file)
        logger.info(f"✅ Done. Inserted={stats['inserted']}, Skipped={stats['skipped']}, Failed={stats['failed']}")
    else:
        logger.info("💡 Usage:")
        logger.info("   python load_bronze_layer.py <csv_file>")
        logger.info("")
        logger.info("   Or import programmatically:")
        logger.info("     from batch.load.load_bronze_layer import load_bronze_layer")
        logger.info("     stats = load_bronze_layer(cve_data_list)")
