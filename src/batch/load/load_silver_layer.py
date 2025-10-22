#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LOAD SILVER LAYER (clean, 1 colonne de classe: vulnarbilit)
Colonnes requises en entrée:
  cve_id, vulnarbilit, published_date, last_modified, loaded_at,
  remotely_exploit, source_identifier, affected_products, cvss_scores
"""

from pathlib import Path
import sys
sys.path.append(str(Path(__file__).resolve().parents[2]))

import logging
from typing import Dict, Optional
import json
import numpy as np
import pandas as pd
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.engine import Engine
from database.connection import create_db_engine, get_schema_name

LOGS_DIR = Path(__file__).resolve().parents[3] / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOGS_DIR / "load_silver_layer.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(LOG_FILE, encoding="utf-8"), logging.StreamHandler()]
)
logger = logging.getLogger("load_silver_layer")

def verify_silver_schema(engine: Engine) -> bool:
    schema = get_schema_name("silver")
    table = "cve_cleaned"
    need = {
        "cve_id","vulnarbilit","published_date","last_modified","loaded_at",
        "remotely_exploit","source_identifier","affected_products","cvss_scores"
    }
    try:
        with engine.connect() as conn:
            if not conn.execute(
                text("SELECT 1 FROM information_schema.schemata WHERE schema_name=:s"), {"s": schema}
            ).fetchone():
                logger.error(f"❌ Schema '{schema}' does not exist! Run silver.sql first.")
                return False
            if not conn.execute(
                text("SELECT 1 FROM information_schema.tables WHERE table_schema=:s AND table_name=:t"),
                {"s": schema, "t": table}
            ).fetchone():
                logger.error(f"❌ Table {schema}.{table} does not exist! Run silver.sql first.")
                return False
            cols = {r[0] for r in conn.execute(
                text("""SELECT column_name FROM information_schema.columns
                        WHERE table_schema=:s AND table_name=:t"""),
                {"s": schema, "t": table}
            )}
            miss = need - cols
            if miss:
                logger.error(f"❌ Missing columns in {schema}.{table}: {sorted(miss)}")
                return False
        logger.info("✅ Silver schema validated")
        return True
    except Exception as e:
        logger.error(f"❌ Error validating schema: {e}")
        return False

REQUIRED_COLS = [
    'cve_id','vulnarbilit','published_date','last_modified','loaded_at',
    'remotely_exploit','source_identifier','affected_products','cvss_scores'
]

def _safe_json_dumps(x):
    try:
        if x is None: return None
        if isinstance(x, float) and np.isnan(x): return None
        if isinstance(x, np.ndarray):
            if x.size == 0: return None
            x = x.tolist()
        if isinstance(x, str):
            s = x.strip()
            if s == '' or s.lower() in ('null','none','nan'):
                return None
            try:
                parsed = json.loads(s)
                return json.dumps(parsed, ensure_ascii=False)
            except Exception:
                return None
        if isinstance(x, (list, dict)):
            if len(x) == 0: return None
            return json.dumps(x, ensure_ascii=False)
        return None
    except Exception:
        return None

def prepare_silver_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    clean = df.copy()
    for c in REQUIRED_COLS:
        if c not in clean.columns:
            clean[c] = None
    clean = clean[REQUIRED_COLS].copy()

    # Dates
    for d in ['published_date','last_modified','loaded_at']:
        clean[d] = pd.to_datetime(clean[d], errors='coerce')
        if str(clean[d].dtype).startswith('datetime64[ns,'):
            clean[d] = clean[d].dt.tz_localize(None)

    # JSON -> TEXT
    for j in ['affected_products','cvss_scores']:
        clean[j] = clean[j].apply(_safe_json_dumps)

    # cve_id ok + unique
    before = len(clean)
    clean = clean[clean['cve_id'].notna() & (clean['cve_id'].astype(str).str.strip() != '')]
    clean = clean.drop_duplicates(subset=['cve_id'], keep='first')

    logger.info(f"✅ Prepared {len(clean):,} rows for silver layer")
    return clean

def load_to_silver_table(
    df: pd.DataFrame, engine: Engine, if_exists: str = 'replace', convert_jsonb: bool = False
) -> Dict[str, int]:
    schema = get_schema_name("silver")
    table = "cve_cleaned"
    full = f"{schema}.{table}"
    stats = {'inserted': 0, 'skipped': 0, 'failed': 0}

    if df.empty:
        logger.warning("⚠️  No data to load!")
        return stats

    try:
        dfp = prepare_silver_dataframe(df)
        if dfp.empty:
            logger.warning("⚠️  No valid data after preparation!")
            return stats

        if if_exists == 'replace':
            logger.info(f"🗑️  Truncating {full} ...")
            with engine.begin() as conn:
                conn.execute(text(f"TRUNCATE TABLE {full} CASCADE;"))

        logger.info(f"📤 Inserting {len(dfp):,} rows into {full} ...")
        rows = dfp.to_sql(
            name=table, con=engine, schema=schema,
            if_exists='append', index=False, method='multi', chunksize=1000
        )

        if convert_jsonb:
            logger.info("🔄 Converting TEXT JSON columns to JSONB...")
            with engine.begin() as conn:
                conn.execute(text("SELECT silver.convert_json_columns();"))

        with engine.connect() as conn:
            final_count = conn.execute(text(f"SELECT COUNT(*) FROM {full}")).scalar()

        stats['inserted'] = final_count if if_exists == 'replace' else rows
        logger.info(f"✅ Rows inserted: {stats['inserted']:,}  |  Total in table: {final_count:,}")
        return stats

    except SQLAlchemyError as e:
        logger.error(f"❌ Database error: {e}", exc_info=True)
        stats['failed'] = len(df)
        raise
    except Exception as e:
        logger.error(f"❌ Unexpected error: {e}", exc_info=True)
        stats['failed'] = len(df)
        raise

def load_silver_layer(
    tables: Dict[str, pd.DataFrame],
    engine: Optional[Engine] = None,
    if_exists: str = 'replace',
    convert_jsonb: bool = False
) -> bool:
    logger.info("=" * 72)
    logger.info("🚀 SILVER LAYER LOAD PIPELINE")
    logger.info("=" * 72)

    if 'cve_cleaned' not in tables:
        logger.error("❌ Missing 'cve_cleaned' in tables dict!")
        return False

    try:
        if engine is None:
            engine = create_db_engine()
        if not verify_silver_schema(engine):
            return False

        _ = load_to_silver_table(tables['cve_cleaned'], engine, if_exists=if_exists, convert_jsonb=convert_jsonb)

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
