#!/usr/bin/env python3
"""
LOAD GOLD LAYER
Charge les données transformées dans le modèle en étoile (Star Schema)
- Dimensions: dim_cve, dim_cvss_source, dim_products
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
from sqlalchemy.exc import SQLAlchemyError
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
        'dim_cve', 'dim_cvss_source', 'dim_products',
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
                logger.error(f"❌ Schema '{schema}' does not exist! Run gold.sql first.")
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
                    logger.error(f"❌ Table {schema}.{table} does not exist! Run gold.sql first.")
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
                         cvss_v4: pd.DataFrame, engine: Engine) -> Dict[str, int]:
    """
    Charge dim_cvss_source et retourne un mapping source_name -> source_id
    """
    schema = get_schema_name("gold")
    logger.info("📥 Loading dim_cvss_source...")
    
    # Collecter toutes les sources uniques
    sources: Set[str] = set()
    
    for df in [cvss_v2, cvss_v3, cvss_v4]:
        if not df.empty and 'cvss_source' in df.columns:
            sources.update(df['cvss_source'].dropna().unique())
    
    if not sources:
        logger.warning("⚠️  No CVSS sources found")
        return {}
    
    # Créer DataFrame des sources
    df_sources = pd.DataFrame([{'source_name': s} for s in sorted(sources)])
    
    # Charger dans la table
    df_sources.to_sql(
        name='dim_cvss_source',
        con=engine,
        schema=schema,
        if_exists='append',
        index=False,
        method='multi'
    )
    
    # Récupérer le mapping source_name -> source_id
    with engine.connect() as conn:
        result = conn.execute(
            text(f"SELECT source_id, source_name FROM {schema}.dim_cvss_source")
        )
        source_mapping = {row[1]: row[0] for row in result}
    
    logger.info(f"✅ Loaded {len(source_mapping)} CVSS sources")
    
    return source_mapping

# -------------------------------------------------------------------
# Load Dimensions
# -------------------------------------------------------------------
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
    
    # Truncate si replace
    if if_exists == 'replace':
        with engine.begin() as conn:
            conn.execute(text(f"TRUNCATE TABLE {full_table} CASCADE;"))
    
    # Charger les données
    rows = df.to_sql(
        name=table_name,
        con=engine,
        schema=schema,
        if_exists='append',
        index=False,
        method='multi',
        chunksize=1000
    )
    
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
    
    # Mapper cvss_source -> source_id
    if 'cvss_source' in df.columns:
        df = df.copy()
        df['source_id'] = df['cvss_source'].map(source_mapping)
        
        # Vérifier les sources non mappées
        unmapped = df['source_id'].isna().sum()
        if unmapped > 0:
            logger.warning(f"⚠️  {unmapped} rows with unmapped sources in {table_name}")
            df = df[df['source_id'].notna()]
        
        # Supprimer cvss_source (on garde source_id)
        df = df.drop(columns=['cvss_source'])
    
    # Truncate si replace
    if if_exists == 'replace':
        with engine.begin() as conn:
            conn.execute(text(f"TRUNCATE TABLE {full_table} CASCADE;"))
    
    # Charger les données
    rows = df.to_sql(
        name=table_name,
        con=engine,
        schema=schema,
        if_exists='append',
        index=False,
        method='multi',
        chunksize=1000
    )
    
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
    
    # Truncate si replace
    if if_exists == 'replace':
        with engine.begin() as conn:
            conn.execute(text(f"TRUNCATE TABLE {full_table} CASCADE;"))
    
    # Charger les données
    rows = df.to_sql(
        name=table_name,
        con=engine,
        schema=schema,
        if_exists='append',
        index=False,
        method='multi',
        chunksize=1000
    )
    
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
            # Rafraîchir la vue unifiée CVSS
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
    Fonction principale pour charger la couche Gold (Star Schema)
    
    Args:
        tables: Dict contenant:
            - dim_cve: DataFrame
            - cvss_v2: DataFrame
            - cvss_v3: DataFrame
            - cvss_v4: DataFrame
            - dim_products: DataFrame
            - bridge_cve_products: DataFrame
        engine: Connexion DB (optionnel)
        if_exists: 'replace' ou 'append'
    
    Returns:
        True si succès, False sinon
    """
    logger.info("=" * 72)
    logger.info("🚀 GOLD LAYER LOAD PIPELINE (STAR SCHEMA)")
    logger.info("=" * 72)
    
    # Validation
    assert if_exists in {'append', 'replace'}, "if_exists must be 'append' or 'replace'"
    
    required_tables = ['dim_cve', 'cvss_v2', 'cvss_v3', 'cvss_v4', 
                       'dim_products', 'bridge_cve_products']
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
            engine
        )
        
        # ÉTAPE 2: Charger dim_cve
        stats['dim_cve'] = load_dimension(
            tables['dim_cve'],
            'dim_cve',
            engine,
            if_exists
        )
        
        # ÉTAPE 3: Charger dim_products
        stats['dim_products'] = load_dimension(
            tables['dim_products'],
            'dim_products',
            engine,
            if_exists
        )
        
        # ÉTAPE 4: Charger les faits CVSS
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
        
        # ÉTAPE 5: Charger bridge_cve_products
        stats['bridge'] = load_bridge(
            tables['bridge_cve_products'],
            engine,
            if_exists
        )
        
        # ÉTAPE 6: Rafraîchir les vues matérialisées
        refresh_materialized_views(engine)
        
        # ÉTAPE 7: Analyser les tables
        schema = get_schema_name("gold")
        with engine.begin() as conn:
            for table in ['dim_cve', 'dim_cvss_source', 'dim_products',
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
        logger.info(f"  - dim_products: {stats['dim_products']:,} rows")
        logger.info("\nFACTS:")
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
# CLI Entry Point
# -------------------------------------------------------------------
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Load data to Gold layer (Star Schema)")
    parser.add_argument(
        '--test',
        action='store_true',
        help='Run test with sample data'
    )
    args = parser.parse_args()
    
    if args.test:
        logger.info("🧪 Running test mode...")
        
        # Créer des données de test
        test_dim_cve = pd.DataFrame([{
            'cve_id': 'CVE-2024-TEST',
            'title': 'Test CVE',
            'description': 'Test description',
            'category': 'test',
            'published_date': pd.Timestamp.now(),
            'last_modified': pd.Timestamp.now(),
            'loaded_at': pd.Timestamp.now(),
            'remotely_exploit': True,
            'source_identifier': 'test'
        }])
        
        test_cvss_v3 = pd.DataFrame([{
            'cve_id': 'CVE-2024-TEST',
            'cvss_source': 'nvd@nist.gov',
            'cvss_version': 'CVSS 3.1',
            'cvss_score': 7.5,
            'cvss_severity': 'HIGH',
            'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
            'cvss_v3_base_av': 'N',
            'cvss_v3_base_ac': 'L',
            'cvss_v3_base_pr': 'N',
            'cvss_v3_base_ui': 'N',
            'cvss_v3_base_s': 'U',
            'cvss_v3_base_c': 'H',
            'cvss_v3_base_i': 'N',
            'cvss_v3_base_a': 'N',
            'cvss_exploitability_score': 3.9,
            'cvss_impact_score': 3.6
        }])
        
        test_products = pd.DataFrame([{
            'product_id': 1,
            'vendor': 'Test Vendor',
            'product_name': 'Test Product',
            'total_cves': 1,
            'first_cve_date': pd.Timestamp.now(),
            'last_cve_date': pd.Timestamp.now()
        }])
        
        test_bridge = pd.DataFrame([{
            'cve_id': 'CVE-2024-TEST',
            'product_id': 1
        }])
        
        tables = {
            'dim_cve': test_dim_cve,
            'cvss_v2': pd.DataFrame(),
            'cvss_v3': test_cvss_v3,
            'cvss_v4': pd.DataFrame(),
            'dim_products': test_products,
            'bridge_cve_products': test_bridge
        }
        
        success = load_gold_layer(tables, if_exists='replace')
        
        sys.exit(0 if success else 1)
    else:
        logger.info("💡 Usage:")
        logger.info("   from batch.load.load_gold_layer import load_gold_layer")
        logger.info("   tables = {")
        logger.info("       'dim_cve': df_cve,")
        logger.info("       'cvss_v2': df_v2,")
        logger.info("       'cvss_v3': df_v3,")
        logger.info("       'cvss_v4': df_v4,")
        logger.info("       'dim_products': df_products,")
        logger.info("       'bridge_cve_products': df_bridge")
        logger.info("   }")
        logger.info("   success = load_gold_layer(tables, if_exists='replace')")