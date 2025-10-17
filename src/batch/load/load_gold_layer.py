#!/usr/bin/env python3
"""
LOAD GOLD LAYER (VERSION 2)
Charge les données transformées dans le modèle en étoile (Star Schema)
- Dimensions: dim_cve, dim_cvss_source, dim_vendor, dim_products
- Facts: cvss_v2, cvss_v3, cvss_v4
- Bridge: bridge_cve_products
"""

from pathlib import Path
import sys
sys.path.append(str(Path(__file__).resolve().parents[2]))

import logging
from typing import Dict, Optional, Set
from datetime import datetime

import pandas as pd
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.engine import Engine

from database.connection import create_db_engine, get_schema_name

# -------------------------------------------------------------------
# Logging
# -------------------------------------------------------------------
LOGS_DIR = Path(__file__).resolve().parents[3] / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOGS_DIR / "load_gold_layer.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("load_gold_layer")

# -------------------------------------------------------------------
# Schema Validation
# -------------------------------------------------------------------
def verify_gold_schema(engine: Engine) -> bool:
    """Vérifie que le schéma Gold et toutes les tables existent"""
    schema = get_schema_name("gold")

    required_tables = [
        'dim_cve', 'dim_cvss_source', 'dim_vendor', 'dim_products',
        'cvss_v2', 'cvss_v3', 'cvss_v4',
        'bridge_cve_products'
    ]

    logger.info(f"🔎 Verifying gold schema '{schema}'...")

    try:
        with engine.connect() as conn:
            # Vérifier le schéma
            result = conn.execute(
                text("""
                    SELECT schema_name
                    FROM information_schema.schemata
                    WHERE schema_name = :schema
                """),
                {"schema": schema}
            )
            if not result.fetchone():
                logger.error(f"❌ Schema '{schema}' does not exist! Run gold_schema_updated.sql first.")
                return False

            # Vérifier toutes les tables
            for table in required_tables:
                result = conn.execute(
                    text("""
                        SELECT table_name
                        FROM information_schema.tables
                        WHERE table_schema = :schema AND table_name = :table
                    """),
                    {"schema": schema, "table": table}
                )
                if not result.fetchone():
                    logger.error(f"❌ Table {schema}.{table} does not exist! Run gold_schema_updated.sql first.")
                    return False

        logger.info(f"✅ Gold schema validated ({len(required_tables)} tables)")
        return True

    except Exception as e:
        logger.error(f"❌ Error validating schema: {e}")
        return False

# -------------------------------------------------------------------
# Load dim_cvss_source (dimension de référence)
# -------------------------------------------------------------------
def load_dim_cvss_source(cvss_v2: pd.DataFrame, cvss_v3: pd.DataFrame,
                         cvss_v4: pd.DataFrame, engine: Engine,
                         if_exists: str = 'replace') -> Dict[str, int]:
    schema = get_schema_name("gold")
    logger.info("📥 Loading dim_cvss_source...")

    # collect unique sources from all fact dfs
    sources: Set[str] = set()
    for df in [cvss_v2, cvss_v3, cvss_v4]:
        if not df.empty and 'cvss_source' in df.columns:
            vals = (df['cvss_source']
                    .dropna()
                    .astype(str)
                    .str.replace('\xa0', ' ', regex=False)
                    .str.strip()
                    .str[:100])  # VARCHAR(100)
            sources.update(vals.unique())

    if not sources:
        logger.warning("⚠️  No CVSS sources found")
        return {}

    with engine.begin() as conn:
        if if_exists == 'replace':
            conn.execute(text(f"TRUNCATE TABLE {schema}.dim_cvss_source RESTART IDENTITY CASCADE;"))

        # when appending, avoid duplicates already in table
        existing = set()
        if if_exists == 'append':
            res = conn.execute(text(f"SELECT source_name FROM {schema}.dim_cvss_source"))
            existing = {r[0] for r in res.fetchall()}

    new_sources = sorted(s for s in sources if s and s not in existing)
    if new_sources:
        pd.DataFrame({'source_name': new_sources}).to_sql(
            name='dim_cvss_source', con=engine, schema=schema,
            if_exists='append', index=False, method='multi', chunksize=1000
        )
    else:
        logger.info("ℹ️ No new sources to insert")

    # build mapping
    with engine.connect() as conn:
        result = conn.execute(text(f"SELECT source_id, source_name FROM {schema}.dim_cvss_source"))
        mapping = {row[1]: row[0] for row in result}
    logger.info(f"✅ Loaded/mapped {len(mapping)} CVSS sources")
    return mapping

# -------------------------------------------------------------------
# Load Dimensions
# -------------------------------------------------------------------
def _reindex_for_table(df: pd.DataFrame, table_name: str) -> pd.DataFrame:
    """Select only schema columns in the expected order."""
    schemas: Dict[str, list] = {
        'dim_cve': [
            'cve_id', 'title', 'description', 'category', 'predicted_category',
            'published_date', 'last_modified', 'loaded_at',
            'remotely_exploit', 'source_identifier'
        ],
        'dim_vendor': [
            'vendor_id', 'vendor_name', 'total_products', 'total_cves',
            'first_cve_date', 'last_cve_date'
        ],
        'dim_products': [
            'product_id', 'vendor_id', 'product_name',
            'total_cves', 'first_cve_date', 'last_cve_date'
        ]
    }
    cols = schemas.get(table_name)
    return df.reindex(columns=cols) if cols else df

def _prepare_dim_cve(df: pd.DataFrame) -> pd.DataFrame:
    """Fill NOT NULLs and coerce types to match schema."""
    df = df.copy()
    df['cve_id'] = df['cve_id'].astype(str).str.slice(0, 20)
    df['title'] = df['title'].fillna('Unknown')

    for col in ['published_date', 'last_modified', 'loaded_at']:
        df[col] = pd.to_datetime(df[col], errors='coerce')
    now = pd.Timestamp.utcnow().tz_localize(None)
    df['published_date'] = df['published_date'].fillna(now)
    df['last_modified']  = df['last_modified'].fillna(df['published_date'])
    df['loaded_at']      = df['loaded_at'].fillna(now)

    if 'remotely_exploit' in df.columns:
        df['remotely_exploit'] = df['remotely_exploit'].astype('boolean')

    if 'source_identifier' in df.columns:
        df['source_identifier'] = (df['source_identifier']
                                   .astype(str)
                                   .str.replace('\xa0', ' ', regex=False)
                                   .str.strip())
    return df

def load_dimension(
    df: pd.DataFrame,
    table_name: str,
    engine: Engine,
    if_exists: str = 'replace'
) -> int:
    """Charge une table de dimension"""
    schema = get_schema_name("gold")
    full_table = f"{schema}.{table_name}"

    logger.info(f"📥 Loading {table_name}...")

    if df.empty:
        logger.warning(f"⚠️  No data for {table_name}")
        return 0

    # Special prep
    if table_name == 'dim_cve':
        df = _prepare_dim_cve(df)

    df = _reindex_for_table(df, table_name)

    # Truncate si replace
    if if_exists == 'replace':
        with engine.begin() as conn:
            conn.execute(text(f"TRUNCATE TABLE {full_table} CASCADE;"))

    try:
        df.to_sql(
            name=table_name,
            con=engine,
            schema=schema,
            if_exists='append',
            index=False,
            method='multi',
            chunksize=1000
        )
    except IntegrityError as ie:
        logger.error(f"🧱 IntegrityError while loading {table_name}: {ie.orig}", exc_info=True)
        return 0
    except SQLAlchemyError as se:
        logger.error(f"💥 SQLAlchemyError while loading {table_name}: {se}", exc_info=True)
        return 0

    logger.info(f"✅ {table_name}: {len(df):,} rows loaded")
    return len(df)

# -------------------------------------------------------------------
# Load Facts (avec mapping des sources)
# -------------------------------------------------------------------
def load_fact_cvss(
    df: pd.DataFrame,
    table_name: str,
    source_mapping: Dict[str, int],
    engine: Engine,
    if_exists: str = 'replace'
) -> int:
    """Charge une table de faits CVSS avec mapping des sources"""
    schema = get_schema_name("gold")
    full_table = f"{schema}.{table_name}"

    logger.info(f"📥 Loading {table_name}...")

    if df.empty:
        logger.warning(f"⚠️  No data for {table_name}")
        return 0

    # Basic guards for NOT NULLs in facts
    df = df.copy()
    if 'cve_id' in df:
        df = df[df['cve_id'].notna()]
        df['cve_id'] = df['cve_id'].astype(str).str.slice(0, 20)
    if 'cvss_vector' in df:
        df = df[df['cvss_vector'].astype(str).str.len() > 0]

    # Mapper cvss_source -> source_id
    if 'cvss_source' in df.columns:
        df['cvss_source'] = (df['cvss_source']
                             .astype(str)
                             .str.replace('\xa0', ' ', regex=False)
                             .str.strip()
                             .str[:100])
        df['source_id'] = df['cvss_source'].map(source_mapping)

        # Vérifier les sources non mappées
        unmapped = int(df['source_id'].isna().sum())
        if unmapped > 0:
            examples = (df.loc[df['source_id'].isna(), 'cvss_source']
                        .dropna().unique()[:5])
            logger.warning(f"⚠️  {unmapped} rows dropped in {table_name} (unmapped source). Examples: {list(examples)}")
            df = df[df['source_id'].notna()]

        df = df.drop(columns=['cvss_source'])

    # Truncate si replace
    if if_exists == 'replace':
        with engine.begin() as conn:
            conn.execute(text(f"TRUNCATE TABLE {full_table} CASCADE;"))

    try:
        df.to_sql(
            name=table_name,
            con=engine,
            schema=schema,
            if_exists='append',
            index=False,
            method='multi',
            chunksize=1000
        )
    except IntegrityError as ie:
        logger.error(f"🧱 IntegrityError while loading {table_name}: {ie.orig}", exc_info=True)
        return 0
    except SQLAlchemyError as se:
        logger.error(f"💥 SQLAlchemyError while loading {table_name}: {se}", exc_info=True)
        return 0

    logger.info(f"✅ {table_name}: {len(df):,} rows loaded")
    return len(df)

# -------------------------------------------------------------------
# Load Bridge Table
# -------------------------------------------------------------------
def load_bridge(
    df: pd.DataFrame,
    engine: Engine,
    if_exists: str = 'replace'
) -> int:
    """Charge la table bridge_cve_products"""
    schema = get_schema_name("gold")
    table_name = 'bridge_cve_products'
    full_table = f"{schema}.{table_name}"

    logger.info(f"📥 Loading {table_name}...")

    if df.empty:
        logger.warning(f"⚠️  No data for {table_name}")
        return 0

    # Basic sanity
    df = df.copy()
    if 'cve_id' in df:
        df['cve_id'] = df['cve_id'].astype(str).str.slice(0, 20)
    df = df[['cve_id', 'product_id']].dropna().drop_duplicates()

    # Truncate si replace
    if if_exists == 'replace':
        with engine.begin() as conn:
            conn.execute(text(f"TRUNCATE TABLE {full_table} CASCADE;"))

    try:
        df.to_sql(
            name=table_name,
            con=engine,
            schema=schema,
            if_exists='append',
            index=False,
            method='multi',
            chunksize=1000
        )
    except IntegrityError as ie:
        logger.error(f"🧱 IntegrityError while loading {table_name}: {ie.orig}", exc_info=True)
        return 0
    except SQLAlchemyError as se:
        logger.error(f"💥 SQLAlchemyError while loading {table_name}: {se}", exc_info=True)
        return 0

    logger.info(f"✅ {table_name}: {len(df):,} relationships loaded")
    return len(df)

# -------------------------------------------------------------------
# Refresh Materialized Views
# -------------------------------------------------------------------
def refresh_materialized_views(engine: Engine) -> bool:
    """Rafraîchit les vues matérialisées"""
    schema = get_schema_name("gold")

    logger.info("🔄 Refreshing materialized views...")

    try:
        with engine.begin() as conn:
            conn.execute(text(f"REFRESH MATERIALIZED VIEW CONCURRENTLY {schema}.mv_cve_all_cvss;"))

        logger.info("✅ Materialized views refreshed")
        return True

    except Exception as e:
        logger.error(f"❌ Error refreshing views: {e}")
        return False

# -------------------------------------------------------------------
# Main Load Function
# -------------------------------------------------------------------
def load_gold_layer(
    tables: Dict[str, pd.DataFrame],
    engine: Optional[Engine] = None,
    if_exists: str = 'replace'
) -> bool:
    """
    Fonction principale pour charger la couche Gold (Star Schema V2)
    """
    logger.info("=" * 72)
    logger.info("🚀 GOLD LAYER LOAD PIPELINE (STAR SCHEMA V2)")
    logger.info("=" * 72)

    # Validation
    assert if_exists in {'append', 'replace'}, "if_exists must be 'append' or 'replace'"

    required_tables = ['dim_cve', 'dim_vendor', 'dim_products', 'cvss_v2',
                       'cvss_v3', 'cvss_v4', 'bridge_cve_products']
    missing = [t for t in required_tables if t not in tables]
    if missing:
        logger.error(f"❌ Missing tables: {missing}")
        return False

    try:
        # Créer engine si nécessaire
        if engine is None:
            engine = create_db_engine()

        # Vérifier le schéma
        if not verify_gold_schema(engine):
            return False

        start_time = datetime.now()
        stats = {}

        # ÉTAPE 1: Charger dim_cvss_source (dimension de référence)
        source_mapping = load_dim_cvss_source(
            tables['cvss_v2'],
            tables['cvss_v3'],
            tables['cvss_v4'],
            engine,
            if_exists
        )

        # ÉTAPE 2: Charger dim_cve
        stats['dim_cve'] = load_dimension(
            tables['dim_cve'],
            'dim_cve',
            engine,
            if_exists
        )

        # ÉTAPE 3: Charger dim_vendor
        stats['dim_vendor'] = load_dimension(
            tables['dim_vendor'],
            'dim_vendor',
            engine,
            if_exists
        )

        # ÉTAPE 4: Charger dim_products
        stats['dim_products'] = load_dimension(
            tables['dim_products'],
            'dim_products',
            engine,
            if_exists
        )

        # ÉTAPE 5: Charger les faits CVSS
        stats['cvss_v2'] = load_fact_cvss(
            tables['cvss_v2'],
            'cvss_v2',
            source_mapping,
            engine,
            if_exists
        )

        stats['cvss_v3'] = load_fact_cvss(
            tables['cvss_v3'],
            'cvss_v3',
            source_mapping,
            engine,
            if_exists
        )

        stats['cvss_v4'] = load_fact_cvss(
            tables['cvss_v4'],
            'cvss_v4',
            source_mapping,
            engine,
            if_exists
        )

        # ÉTAPE 6: Charger bridge_cve_products
        stats['bridge'] = load_bridge(
            tables['bridge_cve_products'],
            engine,
            if_exists
        )

        # ÉTAPE 7: Rafraîchir les vues matérialisées
        refresh_materialized_views(engine)

        # ÉTAPE 8: Analyser les tables
        schema = get_schema_name("gold")
        with engine.begin() as conn:
            for table in ['dim_cve', 'dim_cvss_source', 'dim_vendor', 'dim_products',
                          'cvss_v2', 'cvss_v3', 'cvss_v4', 'bridge_cve_products']:
                conn.execute(text(f"ANALYZE {schema}.{table};"))

        duration = (datetime.now() - start_time).total_seconds()

        # Rapport final
        logger.info("\n" + "=" * 72)
        logger.info("📊 GOLD LAYER LOAD STATISTICS")
        logger.info("=" * 72)
        logger.info("DIMENSIONS:")
        logger.info(f"  - dim_cve: {stats['dim_cve']:,} rows")
        logger.info(f"  - dim_cvss_source: {len(source_mapping)} rows")
        logger.info(f"  - dim_vendor: {stats['dim_vendor']:,} rows")
        logger.info(f"  - dim_products: {stats['dim_products']:,} rows")
        logger.info("\nFACTS:")
        logger.info(f"  - cvss_v2: {stats['cvss_v2']:,} rows")
        logger.info(f"  - cvss_v3: {stats['cvss_v3']:,} rows")
        logger.info(f"  - cvss_v4: {stats['cvss_v4']:,} rows")
        logger.info("\nBRIDGE:")
        logger.info(f"  - bridge_cve_products: {stats['bridge']:,} relationships")
        logger.info("\nPERFORMANCE:")
        logger.info(f"  - Duration: {duration:.2f}s")
        logger.info(f"  - Total rows: {sum(stats.values()):,}")
        logger.info("=" * 72)
        logger.info("🎉 GOLD LAYER LOAD COMPLETED SUCCESSFULLY")
        logger.info("=" * 72)

        return True

    except Exception as e:
        logger.error(f"❌ Gold layer load failed: {e}", exc_info=True)
        return False

# -------------------------------------------------------------------
# CLI Entry Point (optional)
# -------------------------------------------------------------------
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Load data to Gold layer (Star Schema V2)")
    parser.add_argument(
        '--test',
        action='true',
        help='(unused—invoke load from transformation_to_gold instead)'
    )
    args = parser.parse_args()
    logger.info("ℹ️ This module is intended to be imported by the transformer runner.")
