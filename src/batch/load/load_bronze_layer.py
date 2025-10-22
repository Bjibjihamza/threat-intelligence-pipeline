# batch/load/load_bronze_layer.py
# ============================================================================
# LOAD BRONZE LAYER - Direct → raw.cve_details (NO title/description/url)
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

# Connexion centralisée
from database.connection import create_db_engine, get_schema_name

# ----------------------------------------------------------------------------
# Logging
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
    Vérifie que le schéma bronze (raw) et la table existent.
    """
    schema = get_schema_name("bronze")  # attendu: "raw"
    table = "cve_details"
    logger.info(f"🔎 Verifying bronze schema '{schema}' and table '{schema}.{table}'...")

    with engine.connect() as conn:
        # Schéma
        if not conn.execute(
            text("SELECT 1 FROM information_schema.schemata WHERE schema_name=:s"),
            {"s": schema}
        ).fetchone():
            logger.error(f"❌ Schema '{schema}' does not exist! Run your schema SQL first.")
            return False

        # Table
        if not conn.execute(
            text("SELECT 1 FROM information_schema.tables WHERE table_schema=:s AND table_name=:t"),
            {"s": schema, "t": table}
        ).fetchone():
            logger.error(f"❌ Table {schema}.{table} does not exist!")
            return False

    logger.info("✅ Bronze schema validated")
    return True

# ----------------------------------------------------------------------------
# Data Preparation
# ----------------------------------------------------------------------------
def _coerce_bool(v: Optional[Any]) -> Optional[bool]:
    """Normalise diverses représentations booléennes pour remotely_exploit."""
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
    """Conserve None ou une chaîne trim; évite les littéraux 'nan'/'None'."""
    if v is None or (isinstance(v, float) and np.isnan(v)):
        return None
    s = str(v).strip()
    return s if s not in {'nan', 'None'} else None

def _norm_json(v: Any) -> Optional[Any]:
    """Assure list/dict/None pour JSONB; parse si string."""
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
    Transforme une liste de dict CVE en DataFrame conforme au schéma bronze
    (sans title/description/url; dates en TEXT).
    """
    logger.info("🛠️ Preparing data for database insertion...")

    if not cve_data_list:
        logger.warning("⚠️  No data to prepare!")
        return pd.DataFrame()

    # Normalisation légère des clés internes de CVSS (source → source_identifier si besoin)
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

    # Colonnes requises (conformes à raw.cve_details sans title/description/url)
    required = [
        'cve_id',
        'published_date',     # TEXT (brut NVD)
        'last_modified',      # TEXT (brut NVD)
        'remotely_exploit',   # BOOLEAN (peut rester NULL)
        'source_identifier',  # TEXT
        'category',           # TEXT (ex: 'CWE-89')
        'affected_products',  # JSONB
        'cvss_scores',        # JSONB
    ]
    for col in required:
        if col not in df.columns:
            df[col] = None

    # Types/normalisation
    df['remotely_exploit'] = df['remotely_exploit'].map(_coerce_bool)

    for col in ['affected_products', 'cvss_scores']:
        df[col] = df[col].apply(_norm_json)

    for col in ['cve_id', 'published_date', 'last_modified',
                'source_identifier', 'category']:
        df[col] = df[col].apply(_norm_text)

    # On ne gère pas loaded_at (DEFAULT NOW() côté DB)
    if 'loaded_at' in df.columns:
        df = df.drop(columns=['loaded_at'])

    logger.info(f"✅ Prepared {len(df):,} rows for insertion")
    return df

# ----------------------------------------------------------------------------
# Direct Loader (no staging)
# ----------------------------------------------------------------------------
def load_to_bronze(df: pd.DataFrame, engine: Engine, batch_size: int = 1000) -> Dict[str, int]:
    schema = get_schema_name("bronze")  # "raw"
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
# Orchestrateur
# ----------------------------------------------------------------------------
def load_bronze_layer(cve_data_list: List[Dict[str, Any]], engine: Optional[Engine] = None) -> Dict[str, int]:
    """
    Point d'entrée: charge une liste de dicts CVE vers la bronze layer.
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
