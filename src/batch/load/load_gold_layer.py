#!/usr/bin/env python3
# LOAD GOLD LAYER (V3, aligned with vulnarbilit)

from pathlib import Path
import sys
sys.path.append(str(Path(__file__).resolve().parents[2]))

import logging
from typing import Dict, Optional
from datetime import datetime
import pandas as pd
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.engine import Engine

from database.connection import create_db_engine, get_schema_name

LOGS_DIR = Path(__file__).resolve().parents[3] / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOGS_DIR / "load_gold_layer.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(LOG_FILE, encoding="utf-8"), logging.StreamHandler()],
)
logger = logging.getLogger("load_gold_layer")

def verify_gold_schema(engine: Engine) -> bool:
    schema = get_schema_name("gold")
    required_tables = [
        'dim_cve','dim_cvss_source','dim_vendor','dim_products',
        'cvss_v2','cvss_v3','cvss_v4','bridge_cve_products'
    ]
    try:
        with engine.connect() as conn:
            if not conn.execute(text(
                "SELECT 1 FROM information_schema.schemata WHERE schema_name=:s"
            ), {"s": schema}).fetchone():
                logger.error(f"❌ Schema '{schema}' missing (run gold.sql).")
                return False
            for t in required_tables:
                if not conn.execute(text(
                    "SELECT 1 FROM information_schema.tables WHERE table_schema=:s AND table_name=:t"
                ), {"s": schema, "t": t}).fetchone():
                    logger.error(f"❌ Table {schema}.{t} missing (run gold.sql).")
                    return False
        logger.info(f"✅ Gold schema validated ({len(required_tables)} tables).")
        return True
    except Exception as e:
        logger.error(f"❌ Schema validation error: {e}")
        return False

# ------- dim_cvss_source -------
def load_dim_cvss_source(cvss_v2: pd.DataFrame, cvss_v3: pd.DataFrame,
                         cvss_v4: pd.DataFrame, engine: Engine, if_exists: str) -> Dict[str,int]:
    schema = get_schema_name("gold")
    logger.info("📥 Loading dim_cvss_source...")
    sources = set()
    for df in (cvss_v2, cvss_v3, cvss_v4):
        if not df.empty and 'cvss_source' in df.columns:
            vals = (df['cvss_source'].dropna().astype(str).str.replace('\xa0',' ',regex=False).str.strip().str[:100])
            sources.update(vals.unique())
    if not sources:
        logger.info("ℹ️ No sources found."); return {}

    with engine.begin() as conn:
        if if_exists == 'replace':
            conn.execute(text(f"TRUNCATE TABLE {schema}.dim_cvss_source RESTART IDENTITY CASCADE;"))
        existing = set()
        if if_exists == 'append':
            existing = {r[0] for r in conn.execute(text(f"SELECT source_name FROM {schema}.dim_cvss_source")).fetchall()}
    to_add = sorted(s for s in sources if s and s not in existing)
    if to_add:
        pd.DataFrame({'source_name': to_add}).to_sql(
            'dim_cvss_source', engine, schema=schema, if_exists='append', index=False, method='multi', chunksize=1000
        )
    with engine.connect() as conn:
        mapping = {row[1]: row[0] for row in conn.execute(
            text(f"SELECT source_id, source_name FROM {schema}.dim_cvss_source")
        )}
    logger.info(f"✅ dim_cvss_source mapped: {len(mapping)}")
    return mapping

# ------- dimension loaders -------
def _reindex_for_table(df: pd.DataFrame, table: str) -> pd.DataFrame:
    spec = {
        'dim_cve': [
            'cve_id','vulnarbilit','published_date','last_modified','loaded_at',
            'remotely_exploit','source_identifier'
        ],
        'dim_vendor': ['vendor_id','vendor_name','total_products','total_cves','first_cve_date','last_cve_date'],
        'dim_products': ['product_id','vendor_id','product_name','total_cves','first_cve_date','last_cve_date'],
    }
    cols = spec.get(table)
    return df.reindex(columns=cols) if cols else df

def _prepare_dim_cve(df: pd.DataFrame) -> pd.DataFrame:
    d = df.copy()
    d['cve_id'] = d['cve_id'].astype(str).str.slice(0, 20)
    for c in ['published_date','last_modified','loaded_at']:
        d[c] = pd.to_datetime(d[c], errors='coerce')
    now = pd.Timestamp.utcnow().tz_localize(None)
    d['published_date'] = d['published_date'].fillna(now)
    d['last_modified']  = d['last_modified'].fillna(d['published_date'])
    d['loaded_at']      = d['loaded_at'].fillna(now)
    if 'remotely_exploit' in d.columns:
        d['remotely_exploit'] = d['remotely_exploit'].astype('boolean')
    if 'source_identifier' in d.columns:
        d['source_identifier'] = d['source_identifier'].astype(str).str.replace('\xa0',' ',regex=False).str.strip()
    return d

def load_dimension(df: pd.DataFrame, table: str, engine: Engine, if_exists: str) -> int:
    schema = get_schema_name("gold")
    full = f"{schema}.{table}"
    if df.empty:
        logger.info(f"ℹ️ {table}: no rows."); return 0
    if table == 'dim_cve':
        df = _prepare_dim_cve(df)
    df = _reindex_for_table(df, table)
    if if_exists == 'replace':
        with engine.begin() as conn:
            conn.execute(text(f"TRUNCATE TABLE {full} CASCADE;"))
    try:
        df.to_sql(table, engine, schema=schema, if_exists='append', index=False, method='multi', chunksize=1000)
        logger.info(f"✅ {table}: {len(df):,} rows.")
        return len(df)
    except (IntegrityError, SQLAlchemyError) as e:
        logger.error(f"❌ load {table}: {e}", exc_info=True)
        return 0

# ------- facts -------
def load_fact_cvss(df: pd.DataFrame, table: str, source_map: Dict[str,int],
                   engine: Engine, if_exists: str) -> int:
    schema = get_schema_name("gold")
    full = f"{schema}.{table}"
    if df.empty:
        logger.info(f"ℹ️ {table}: no rows."); return 0
    d = df.copy()
    if 'cve_id' in d: d['cve_id'] = d['cve_id'].astype(str).str.slice(0, 20)
    if 'cvss_vector' in d: d = d[d['cvss_vector'].astype(str).str.len() > 0]
    if 'cvss_source' in d.columns:
        d['cvss_source'] = d['cvss_source'].astype(str).str.replace('\xa0',' ',regex=False).str.strip().str[:100]
        d['source_id'] = d['cvss_source'].map(source_map)
        d = d.drop(columns=['cvss_source'])
        d = d[d['source_id'].notna()]
    if if_exists == 'replace':
        with engine.begin() as conn:
            conn.execute(text(f"TRUNCATE TABLE {full} CASCADE;"))
    try:
        d.to_sql(table, engine, schema=schema, if_exists='append', index=False, method='multi', chunksize=1000)
        logger.info(f"✅ {table}: {len(d):,} rows.")
        return len(d)
    except (IntegrityError, SQLAlchemyError) as e:
        logger.error(f"❌ load {table}: {e}", exc_info=True)
        return 0

# ------- bridge -------
def load_bridge(df: pd.DataFrame, engine: Engine, if_exists: str) -> int:
    schema = get_schema_name("gold"); table='bridge_cve_products'; full=f"{schema}.{table}"
    if df.empty:
        logger.info("ℹ️ bridge_cve_products: no rows."); return 0
    d = df.copy()
    d['cve_id'] = d['cve_id'].astype(str).str.slice(0, 20)
    d = d[['cve_id','product_id']].dropna().drop_duplicates()
    if if_exists == 'replace':
        with engine.begin() as conn:
            conn.execute(text(f"TRUNCATE TABLE {full} CASCADE;"))
    try:
        d.to_sql(table, engine, schema=schema, if_exists='append', index=False, method='multi', chunksize=1000)
        logger.info(f"✅ {table}: {len(d):,} rows.")
        return len(d)
    except (IntegrityError, SQLAlchemyError) as e:
        logger.error(f"❌ load {table}: {e}", exc_info=True)
        return 0

# ------- no-op MV -------
def refresh_materialized_views(engine: Engine) -> bool:
    logger.info("ℹ️ No materialized views to refresh in this version.")
    return True

# ------- entrypoint -------
def load_gold_layer(tables: Dict[str,pd.DataFrame], engine: Optional[Engine]=None, if_exists: str='replace') -> bool:
    logger.info("🚀 GOLD LAYER LOAD (V3)")
    for req in ['dim_cve','dim_vendor','dim_products','cvss_v2','cvss_v3','cvss_v4','bridge_cve_products']:
        if req not in tables:
            logger.error(f"❌ Missing table in package: {req}")
            return False
    try:
        engine = engine or create_db_engine()
        if not verify_gold_schema(engine): return False

        src_map = load_dim_cvss_source(tables['cvss_v2'], tables['cvss_v3'], tables['cvss_v4'], engine, if_exists)
        stats = {}
        stats['dim_cve']     = load_dimension(tables['dim_cve'],     'dim_cve',     engine, if_exists)
        stats['dim_vendor']  = load_dimension(tables['dim_vendor'],  'dim_vendor',  engine, if_exists)
        stats['dim_products']= load_dimension(tables['dim_products'],'dim_products',engine, if_exists)
        stats['cvss_v2']     = load_fact_cvss(tables['cvss_v2'], 'cvss_v2', src_map, engine, if_exists)
        stats['cvss_v3']     = load_fact_cvss(tables['cvss_v3'], 'cvss_v3', src_map, engine, if_exists)
        stats['cvss_v4']     = load_fact_cvss(tables['cvss_v4'], 'cvss_v4', src_map, engine, if_exists)
        stats['bridge']      = load_bridge(tables['bridge_cve_products'], engine, if_exists)

        # analyze
        schema = get_schema_name("gold")
        with engine.begin() as conn:
            for t in ['dim_cve','dim_cvss_source','dim_vendor','dim_products','cvss_v2','cvss_v3','cvss_v4','bridge_cve_products']:
                conn.execute(text(f"ANALYZE {schema}.{t};"))

        dur = (datetime.now() - datetime.now()).total_seconds()
        logger.info("🎉 GOLD load done.")
        logger.info(f"Stats: { {k:int(v) for k,v in stats.items()} }")
        return True
    except Exception as e:
        logger.error(f"❌ Gold load failed: {e}", exc_info=True)
        return False
