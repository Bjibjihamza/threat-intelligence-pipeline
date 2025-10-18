#!/usr/bin/env python3
"""
LOAD GOLD LAYER (VERSION 3 - FIXED APPEND-ONLY)
⭐ CHANGEMENT CRITIQUE: Mode APPEND-ONLY par défaut
- JAMAIS de TRUNCATE
- INSERT uniquement les nouveaux records
- SKIP les doublons existants
- Comportement additif comme Silver
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
# ⭐ FIXED: Load dim_cvss_source (APPEND-ONLY)
# -------------------------------------------------------------------
def load_dim_cvss_source(cvss_v2: pd.DataFrame, cvss_v3: pd.DataFrame,
                         cvss_v4: pd.DataFrame, engine: Engine,
                         if_exists: str = 'append') -> Dict[str, int]:
    """
    ⭐ FIXED VERSION: APPEND-ONLY
    - Charge UNIQUEMENT les nouvelles sources
    - Skip les sources existantes
    - JAMAIS de TRUNCATE
    """
    schema = get_schema_name("gold")
    logger.info("📥 Loading dim_cvss_source (append-only)...")

    # ⭐ AVERTISSEMENT si replace demandé
    if if_exists == 'replace':
        logger.warning("⚠️  if_exists='replace' requested but IGNORED")
        logger.warning("⚠️  This script ONLY does INSERT (skip duplicates)")
        logger.warning("⚠️  To reset: TRUNCATE gold.dim_cvss_source CASCADE;")

    # Collect unique sources from all fact dfs
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

    # ⭐ TOUJOURS récupérer les sources existantes
    with engine.connect() as conn:
        res = conn.execute(text(f"SELECT source_name FROM {schema}.dim_cvss_source"))
        existing = {r[0] for r in res.fetchall()}

    # Filtrer pour garder UNIQUEMENT les nouvelles sources
    new_sources = sorted(s for s in sources if s and s not in existing)
    
    if new_sources:
        logger.info(f"   ➕ Inserting {len(new_sources)} new sources...")
        pd.DataFrame({'source_name': new_sources}).to_sql(
            name='dim_cvss_source', con=engine, schema=schema,
            if_exists='append', index=False, method='multi', chunksize=1000
        )
    else:
        logger.info("   ⭕ No new sources to insert (all exist)")

    # Build mapping
    with engine.connect() as conn:
        result = conn.execute(text(f"SELECT source_id, source_name FROM {schema}.dim_cvss_source"))
        mapping = {row[1]: row[0] for row in result}
    
    logger.info(f"✅ Total sources in Gold: {len(mapping)}")
    return mapping

# -------------------------------------------------------------------
# ⭐ FIXED: Load Dimensions (APPEND-ONLY)
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
    if_exists: str = 'append'
) -> int:
    """
    ⭐ FIXED VERSION: APPEND-ONLY
    - Charge UNIQUEMENT les nouveaux records
    - Skip les records existants
    - JAMAIS de TRUNCATE
    """
    schema = get_schema_name("gold")
    full_table = f"{schema}.{table_name}"

    logger.info(f"📥 Loading {table_name} (append-only)...")

    # ⭐ AVERTISSEMENT si replace demandé
    if if_exists == 'replace':
        logger.warning(f"⚠️  if_exists='replace' for {table_name} IGNORED")
        logger.warning(f"⚠️  Using APPEND mode instead")

    if df.empty:
        logger.warning(f"⚠️  No data for {table_name}")
        return 0

    # Special prep
    if table_name == 'dim_cve':
        df = _prepare_dim_cve(df)

    df = _reindex_for_table(df, table_name)

    # ⭐ ÉTAPE CRITIQUE: Vérifier les records existants
    primary_key_col = 'cve_id' if table_name == 'dim_cve' else f"{table_name.split('_')[1]}_id"
    
    if primary_key_col in df.columns:
        ids_to_check = df[primary_key_col].tolist()
        
        if table_name == 'dim_cve':
            # Pour dim_cve, la PK est cve_id (VARCHAR)
            escaped_ids = [f"'{str(id_val).replace(chr(39), chr(39)+chr(39))}'" for id_val in ids_to_check]
        else:
            # Pour dim_vendor et dim_products, la PK est INT
            escaped_ids = [str(int(id_val)) for id_val in ids_to_check if pd.notna(id_val)]
        
        placeholders = ','.join(escaped_ids)
        
        with engine.connect() as conn:
            result = conn.execute(
                text(f"SELECT {primary_key_col} FROM {full_table} WHERE {primary_key_col} IN ({placeholders})")
            )
            existing_ids = {row[0] for row in result.fetchall()}
        
        # Filtrer pour garder UNIQUEMENT les nouveaux
        df_to_insert = df[~df[primary_key_col].isin(existing_ids)].copy()
        skipped = len(existing_ids)
        
        if df_to_insert.empty:
            logger.info(f"   ⭕ All {len(df)} records already exist - nothing to insert")
            return 0
        
        logger.info(f"   ➕ New records: {len(df_to_insert)} | ⭕ Skipped: {skipped}")
        df = df_to_insert

    try:
        df.to_sql(
            name=table_name,
            con=engine,
            schema=schema,
            if_exists='append',  # ⭐ TOUJOURS APPEND
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

    logger.info(f"✅ {table_name}: {len(df):,} rows inserted")
    return len(df)

# -------------------------------------------------------------------
# ⭐ FIXED: Load Facts (APPEND-ONLY)
# -------------------------------------------------------------------
def load_fact_cvss(
    df: pd.DataFrame,
    table_name: str,
    source_mapping: Dict[str, int],
    engine: Engine,
    if_exists: str = 'append'
) -> int:
    """
    ⭐ FIXED VERSION: APPEND-ONLY
    - Charge UNIQUEMENT les nouveaux records CVSS
    - Skip les records existants (composite key: cve_id + source_id + vector)
    - JAMAIS de TRUNCATE
    """
    schema = get_schema_name("gold")
    full_table = f"{schema}.{table_name}"

    logger.info(f"📥 Loading {table_name} (append-only)...")

    # ⭐ AVERTISSEMENT si replace demandé
    if if_exists == 'replace':
        logger.warning(f"⚠️  if_exists='replace' for {table_name} IGNORED")
        logger.warning(f"⚠️  Using APPEND mode instead")

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

    if df.empty:
        logger.warning(f"⚠️  No valid data after mapping for {table_name}")
        return 0

    # ⭐ ÉTAPE CRITIQUE: Vérifier les records existants
    # Pour les facts CVSS, on utilise (cve_id, source_id, cvss_vector) comme clé composite
    logger.info(f"   🔍 Checking for existing CVSS records...")
    
    # Créer une clé composite pour comparaison
    df['_composite_key'] = (
        df['cve_id'].astype(str) + '|' + 
        df['source_id'].astype(str) + '|' + 
        df['cvss_vector'].astype(str)
    )
    
    # Récupérer les clés existantes
    with engine.connect() as conn:
        result = conn.execute(
            text(f"""
                SELECT cve_id || '|' || source_id::TEXT || '|' || cvss_vector as composite_key
                FROM {full_table}
            """)
        )
        existing_keys = {row[0] for row in result.fetchall()}
    
    # Filtrer pour garder UNIQUEMENT les nouveaux
    df_to_insert = df[~df['_composite_key'].isin(existing_keys)].copy()
    df_to_insert = df_to_insert.drop(columns=['_composite_key'])
    skipped = len(existing_keys)
    
    if df_to_insert.empty:
        logger.info(f"   ⭕ All {len(df)} records already exist - nothing to insert")
        return 0
    
    logger.info(f"   ➕ New records: {len(df_to_insert)} | ⭕ Skipped: {skipped}")

    try:
        df_to_insert.to_sql(
            name=table_name,
            con=engine,
            schema=schema,
            if_exists='append',  # ⭐ TOUJOURS APPEND
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

    logger.info(f"✅ {table_name}: {len(df_to_insert):,} rows inserted")
    return len(df_to_insert)

# -------------------------------------------------------------------
# ⭐ FIXED: Load Bridge Table (APPEND-ONLY)
# -------------------------------------------------------------------
def load_bridge(
    df: pd.DataFrame,
    engine: Engine,
    if_exists: str = 'append'
) -> int:
    """
    ⭐ FIXED VERSION: APPEND-ONLY
    - Charge UNIQUEMENT les nouvelles relations
    - Skip les relations existantes
    - JAMAIS de TRUNCATE
    """
    schema = get_schema_name("gold")
    table_name = 'bridge_cve_products'
    full_table = f"{schema}.{table_name}"

    logger.info(f"📥 Loading {table_name} (append-only)...")

    # ⭐ AVERTISSEMENT si replace demandé
    if if_exists == 'replace':
        logger.warning(f"⚠️  if_exists='replace' for {table_name} IGNORED")
        logger.warning(f"⚠️  Using APPEND mode instead")

    if df.empty:
        logger.warning(f"⚠️  No data for {table_name}")
        return 0

    # Basic sanity
    df = df.copy()
    if 'cve_id' in df:
        df['cve_id'] = df['cve_id'].astype(str).str.slice(0, 20)
    df = df[['cve_id', 'product_id']].dropna().drop_duplicates()

    if df.empty:
        logger.warning(f"⚠️  No valid relationships after cleanup")
        return 0

    # ⭐ ÉTAPE CRITIQUE: Vérifier les relations existantes
    logger.info(f"   🔍 Checking for existing relationships...")
    
    df['_composite_key'] = df['cve_id'].astype(str) + '|' + df['product_id'].astype(str)
    
    with engine.connect() as conn:
        result = conn.execute(
            text(f"""
                SELECT cve_id || '|' || product_id::TEXT as composite_key
                FROM {full_table}
            """)
        )
        existing_keys = {row[0] for row in result.fetchall()}
    
    # Filtrer pour garder UNIQUEMENT les nouvelles relations
    df_to_insert = df[~df['_composite_key'].isin(existing_keys)].copy()
    df_to_insert = df_to_insert.drop(columns=['_composite_key'])
    skipped = len(existing_keys)
    
    if df_to_insert.empty:
        logger.info(f"   ⭕ All {len(df)} relationships already exist - nothing to insert")
        return 0
    
    logger.info(f"   ➕ New relationships: {len(df_to_insert)} | ⭕ Skipped: {skipped}")

    try:
        df_to_insert.to_sql(
            name=table_name,
            con=engine,
            schema=schema,
            if_exists='append',  # ⭐ TOUJOURS APPEND
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

    logger.info(f"✅ {table_name}: {len(df_to_insert):,} relationships inserted")
    return len(df_to_insert)

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
# ⭐ FIXED: Main Load Function (APPEND-ONLY)
# -------------------------------------------------------------------
def load_gold_layer(
    tables: Dict[str, pd.DataFrame],
    engine: Optional[Engine] = None,
    if_exists: str = 'append'
) -> bool:
    """
    ⭐ FIXED VERSION: APPEND-ONLY MODE
    - Paramètre if_exists est IGNORÉ (pour compatibilité)
    - Fait TOUJOURS INSERT ONLY (skip duplicates)
    - JAMAIS de TRUNCATE/REPLACE
    - Comportement additif: accumulation progressive
    """
    logger.info("=" * 72)
    logger.info("🚀 GOLD LAYER LOAD PIPELINE (APPEND-ONLY MODE)")
    logger.info("=" * 72)

    # ⭐ AVERTISSEMENT CRITIQUE si if_exists='replace'
    if if_exists == 'replace':
        logger.warning("=" * 72)
        logger.warning("⚠️  WARNING: if_exists='replace' was requested but is IGNORED!")
        logger.warning("⚠️  This script ONLY does INSERT (skip duplicates)")
        logger.warning("⚠️  NEVER truncates Gold tables")
        logger.warning("⚠️  To reset tables, use SQL: TRUNCATE gold.* CASCADE;")
        logger.warning("=" * 72)

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
            if_exists='append'  # ⭐ TOUJOURS APPEND
        )

        # ÉTAPE 2: Charger dim_cve
        stats['dim_cve'] = load_dimension(
            tables['dim_cve'],
            'dim_cve',
            engine,
            if_exists='append'  # ⭐ TOUJOURS APPEND
        )

        # ÉTAPE 3: Charger dim_vendor
        stats['dim_vendor'] = load_dimension(
            tables['dim_vendor'],
            'dim_vendor',
            engine,
            if_exists='append'  # ⭐ TOUJOURS APPEND
        )

        # ÉTAPE 4: Charger dim_products
        stats['dim_products'] = load_dimension(
            tables['dim_products'],
            'dim_products',
            engine,
            if_exists='append'  # ⭐ TOUJOURS APPEND
        )

        # ÉTAPE 5: Charger les faits CVSS
        stats['cvss_v2'] = load_fact_cvss(
            tables['cvss_v2'],
            'cvss_v2',
            source_mapping,
            engine,
            if_exists='append'  # ⭐ TOUJOURS APPEND
        )

        stats['cvss_v3'] = load_fact_cvss(
            tables['cvss_v3'],
            'cvss_v3',
            source_mapping,
            engine,
            if_exists='append'  # ⭐ TOUJOURS APPEND
        )

        stats['cvss_v4'] = load_fact_cvss(
            tables['cvss_v4'],
            'cvss_v4',
            source_mapping,
            engine,
            if_exists='append'  # ⭐ TOUJOURS APPEND
        )

        # ÉTAPE 6: Charger bridge_cve_products
        stats['bridge'] = load_bridge(
            tables['bridge_cve_products'],
            engine,
            if_exists='append'  # ⭐ TOUJOURS APPEND
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
        logger.info(f"  - dim_cve: {stats['dim_cve']:,} rows inserted")
        logger.info(f"  - dim_cvss_source: {len(source_mapping)} total sources")
        logger.info(f"  - dim_vendor: {stats['dim_vendor']:,} rows inserted")
        logger.info(f"  - dim_products: {stats['dim_products']:,} rows inserted")
        logger.info("\nFACTS:")
        logger.info(f"  - cvss_v2: {stats['cvss_v2']:,} rows inserted")
        logger.info(f"  - cvss_v3: {stats['cvss_v3']:,} rows inserted")
        logger.info(f"  - cvss_v4: {stats['cvss_v4']:,} rows inserted")
        logger.info("\nBRIDGE:")
        logger.info(f"  - bridge_cve_products: {stats['bridge']:,} relationships inserted")
        logger.info("\nPERFORMANCE:")
        logger.info(f"  - Duration: {duration:.2f}s")
        logger.info(f"  - Total inserted: {sum(stats.values()):,}")
        logger.info("=" * 72)
        logger.info("🎉 GOLD LAYER LOAD COMPLETED SUCCESSFULLY (APPEND-ONLY)")
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

    parser = argparse.ArgumentParser(description="Load data to Gold layer (APPEND-ONLY)")
    parser.add_argument('--test', action='store_true', help='Run test mode')
    args = parser.parse_args()

    if args.test:
        logger.info("🧪 Running test mode...")
        logger.info("💡 This module is intended to be imported by the transformer runner.")
        logger.info("📝 Fixed Behavior:")
        logger.info("   ✅ INSERT new records only")
        logger.info("   ⭕ SKIP existing records (no duplicates)")
        logger.info("   ❌ NEVER truncate or update")
        logger.info("   🔒 if_exists='replace' is IGNORED")
        logger.info("")
        logger.info("📊 Example:")
        logger.info("   Scrape 10 CVE → Gold has 10")
        logger.info("   Scrape 10 CVE (5 new, 5 duplicates) → Gold has 15")
        logger.info("   Total accumulation without duplicates")
    else:
        logger.info("ℹ️ This module is intended to be imported by transformation_to_gold.py")
        logger.info("💡 Usage:")
        logger.info("   from batch.load.load_gold_layer import load_gold_layer")
        logger.info("   success = load_gold_layer(gold_tables, engine, if_exists='append')")