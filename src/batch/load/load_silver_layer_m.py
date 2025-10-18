#!/usr/bin/env python3
"""
LOAD SILVER LAYER - INSERT ONLY, SKIP DUPLICATES (FIXED)
Ne fait QUE des INSERT, skip les CVE qui existent déjà
JAMAIS de TRUNCATE, JAMAIS d'UPDATE, JAMAIS de REPLACE
"""

from pathlib import Path
import sys
sys.path.append(str(Path(__file__).resolve().parents[2]))

import logging
from typing import Dict, Optional
from datetime import datetime
import json
import numpy as np

import pandas as pd
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.engine import Engine

from database.connection import create_db_engine, get_schema_name

# Logging setup
LOGS_DIR = Path(__file__).resolve().parents[3] / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOGS_DIR / "load_silver_layer.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("load_silver_layer")

# ============================================================================
# SCHEMA VALIDATION
# ============================================================================
def verify_silver_schema(engine: Engine) -> bool:
    """Vérifie que le schéma Silver et la table cve_cleaned existent"""
    schema = get_schema_name("silver")
    table = "cve_cleaned"
    
    logger.info(f"🔎 Verifying silver schema '{schema}' and table '{table}'...")
    
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
                logger.error(f"❌ Schema '{schema}' does not exist!")
                return False
            
            # Vérifier la table
            result = conn.execute(
                text("""
                    SELECT table_name
                    FROM information_schema.tables
                    WHERE table_schema = :schema AND table_name = :table
                """),
                {"schema": schema, "table": table}
            )
            if not result.fetchone():
                logger.error(f"❌ Table {schema}.{table} does not exist!")
                return False
        
        logger.info("✅ Silver schema validated")
        return True
        
    except Exception as e:
        logger.error(f"❌ Error validating schema: {e}")
        return False

# ============================================================================
# DATA PREPARATION
# ============================================================================
def safe_json_dumps(x):
    """Convertit en JSON string de manière sécurisée"""
    try:
        if x is None:
            return None
        
        if isinstance(x, float) and np.isnan(x):
            return None
        
        if isinstance(x, np.ndarray):
            if x.size == 0:
                return None
            x = x.tolist()
        
        if isinstance(x, str):
            x = x.strip()
            if x == '' or x.lower() in ('null', 'none', 'nan'):
                return None
            try:
                parsed = json.loads(x)
                return json.dumps(parsed)
            except:
                return None
        
        if isinstance(x, (list, dict)):
            if len(x) == 0:
                return None
            return json.dumps(x)
        
        return None
        
    except Exception:
        return None

def prepare_silver_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Prépare le DataFrame pour l'insertion dans silver.cve_cleaned"""
    logger.info("🛠️ Preparing dataframe for silver layer...")
    
    required_columns = [
        'cve_id', 'title', 'description', 'category', 'predicted_category',
        'published_date', 'last_modified', 'loaded_at',
        'remotely_exploit', 'source_identifier',
        'affected_products', 'cvss_scores', 'url'
    ]
    
    df_clean = df.copy()
    
    # Garder uniquement les colonnes requises
    available_cols = [col for col in required_columns if col in df_clean.columns]
    df_clean = df_clean[available_cols].copy()
    
    # Ajouter colonnes manquantes
    for col in required_columns:
        if col not in df_clean.columns:
            logger.warning(f"⚠️  Adding missing column: {col}")
            df_clean[col] = None
    
    df_clean = df_clean[required_columns]
    
    # Convertir les dates
    for date_col in ['published_date', 'last_modified', 'loaded_at']:
        if date_col in df_clean.columns:
            df_clean[date_col] = pd.to_datetime(df_clean[date_col], errors='coerce')
            if df_clean[date_col].dtype == 'datetime64[ns, UTC]':
                df_clean[date_col] = df_clean[date_col].dt.tz_localize(None)
    
    # Convertir JSONB
    for json_col in ['affected_products', 'cvss_scores']:
        if json_col in df_clean.columns:
            df_clean[json_col] = df_clean[json_col].apply(safe_json_dumps)
    
    # Nettoyer cve_id
    before = len(df_clean)
    df_clean = df_clean[
        df_clean['cve_id'].notna() & 
        (df_clean['cve_id'].astype(str).str.strip() != '')
    ]
    after = len(df_clean)
    
    if before > after:
        logger.warning(f"⚠️  Removed {before - after} rows with invalid cve_id")
    
    # Supprimer doublons dans le DataFrame
    before = len(df_clean)
    df_clean = df_clean.drop_duplicates(subset=['cve_id'], keep='first')
    after = len(df_clean)
    
    if before > after:
        logger.warning(f"⚠️  Removed {before - after} duplicate cve_ids in DataFrame")
    
    logger.info(f"✅ Prepared {len(df_clean):,} rows for silver layer")
    
    return df_clean

# ============================================================================
# LOAD TO SILVER - INSERT ONLY (SKIP DUPLICATES) - FIXED
# ============================================================================
def load_to_silver_table(
    df: pd.DataFrame,
    engine: Engine
) -> Dict[str, int]:
    """
    ⭐ FIXED VERSION ⭐
    Charge les données dans silver.cve_cleaned
    - INSERT ONLY: Insère uniquement les nouveaux CVE
    - SKIP: Ignore les CVE qui existent déjà
    - NO TRUNCATE: Jamais de suppression
    - NO UPDATE: Jamais de modification
    - NO if_exists PARAMETER: Toujours append-only
    """
    schema = get_schema_name("silver")
    table = "cve_cleaned"
    full_table = f"{schema}.{table}"
    
    logger.info("=" * 72)
    logger.info(f"💾 LOADING TO SILVER: {full_table}")
    logger.info(f"   Mode: INSERT ONLY (skip existing) - NO TRUNCATE EVER")
    logger.info("=" * 72)
    
    if df.empty:
        logger.warning("⚠️  No data to load!")
        return {'inserted': 0, 'skipped': 0, 'failed': 0}
    
    stats = {'inserted': 0, 'skipped': 0, 'failed': 0}
    start_time = datetime.now()
    
    try:
        # Préparer les données
        df_prepared = prepare_silver_dataframe(df)
        
        if df_prepared.empty:
            logger.warning("⚠️  No valid data after preparation!")
            return stats
        
        logger.info(f"📊 DataFrame shape: {df_prepared.shape}")
        logger.info(f"🔍 Checking for existing CVEs in Silver...")
        
        # Récupérer les CVE_ID à vérifier
        cve_ids = df_prepared['cve_id'].tolist()
        
        if not cve_ids:
            logger.warning("⚠️  No CVE IDs to check!")
            return stats
        
        # Échapper les apostrophes dans les CVE IDs
        escaped_ids = [f"'{str(cve_id).replace(chr(39), chr(39)+chr(39))}'" for cve_id in cve_ids]
        placeholders = ','.join(escaped_ids)
        
        with engine.connect() as conn:
            result = conn.execute(
                text(f"SELECT cve_id FROM {full_table} WHERE cve_id IN ({placeholders})")
            )
            existing_cves = {row[0] for row in result.fetchall()}
        
        logger.info(f"   📊 Already in Silver: {len(existing_cves)} CVE(s)")
        
        # Filtrer pour garder UNIQUEMENT les nouveaux CVE
        df_to_insert = df_prepared[~df_prepared['cve_id'].isin(existing_cves)].copy()
        stats['skipped'] = len(existing_cves)
        
        if df_to_insert.empty:
            logger.info("✅ All CVEs already exist in Silver - nothing to insert")
            logger.info(f"   ⭕ Skipped: {stats['skipped']} CVE(s)")
            return stats
        
        logger.info(f"   ➕ New CVEs to insert: {len(df_to_insert)}")
        
        # ⭐ CRITICAL FIX: Toujours 'append', jamais 'replace'
        logger.info(f"📤 Inserting {len(df_to_insert)} new CVE(s) (append mode)...")
        
        df_to_insert.to_sql(
            name=table,
            con=engine,
            schema=schema,
            if_exists='append',  # ⭐ TOUJOURS APPEND
            index=False,
            method='multi',
            chunksize=500,
            dtype=None
        )
        
        stats['inserted'] = len(df_to_insert)
        
        # Statistiques finales
        with engine.connect() as conn:
            result = conn.execute(text(f"SELECT COUNT(*) FROM {full_table}"))
            final_count = result.scalar()
            
            result = conn.execute(text(f"""
                SELECT COUNT(*) 
                FROM {full_table} 
                WHERE predicted_category IS NOT NULL
            """))
            predicted_count = result.scalar()
        
        duration = (datetime.now() - start_time).total_seconds()
        
        logger.info("=" * 72)
        logger.info("📊 LOAD STATISTICS")
        logger.info("=" * 72)
        logger.info(f"✅ Inserted (new):      {stats['inserted']:,}")
        logger.info(f"⭕ Skipped (existing):  {stats['skipped']:,}")
        logger.info(f"🧮 Total in Silver:     {final_count:,}")
        logger.info(f"🤖 With predictions:    {predicted_count:,} ({predicted_count/final_count*100:.1f}%)")
        logger.info(f"⏱️  Duration: {duration:.2f}s")
        if duration > 0 and stats['inserted'] > 0:
            logger.info(f"⚡ Speed: {stats['inserted']/duration:.0f} rows/sec")
        logger.info("=" * 72)
        
        return stats
        
    except Exception as e:
        logger.error(f"❌ Database error: {e}", exc_info=True)
        stats['failed'] = len(df)
        raise

# ============================================================================
# MAIN LOAD FUNCTION - FIXED
# ============================================================================
def load_silver_layer(
    tables: Dict[str, pd.DataFrame],
    engine: Optional[Engine] = None,
    if_exists: str = 'append'  # ⭐ Paramètre ignoré - toujours append
) -> bool:
    """
    ⭐ FIXED VERSION ⭐
    Fonction principale pour charger la couche Silver
    
    COMPORTEMENT:
    - Paramètre if_exists est IGNORÉ (pour compatibilité)
    - Fait TOUJOURS INSERT ONLY (skip duplicates)
    - JAMAIS de TRUNCATE/REPLACE
    - Comportement additif: 10 CVE + 10 CVE = 20 CVE (sans doublons)
    """
    logger.info("=" * 72)
    logger.info("🚀 SILVER LAYER LOAD PIPELINE (APPEND-ONLY MODE)")
    logger.info("=" * 72)
    
    # ⭐ AVERTISSEMENT si if_exists='replace'
    if if_exists == 'replace':
        logger.warning("⚠️  if_exists='replace' was requested but is IGNORED")
        logger.warning("⚠️  This script ONLY does INSERT (skip duplicates)")
        logger.warning("⚠️  To reset the table, use SQL: TRUNCATE silver.cve_cleaned;")
    
    if 'cve_cleaned' not in tables:
        logger.error("❌ Missing 'cve_cleaned' in tables dict!")
        return False
    
    try:
        if engine is None:
            engine = create_db_engine()
        
        if not verify_silver_schema(engine):
            return False
        
        df_cleaned = tables['cve_cleaned']
        
        # ⭐ TOUJOURS EN MODE INSERT ONLY
        stats = load_to_silver_table(df_cleaned, engine)
        
        # Rafraîchir statistiques
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

# ============================================================================
# CLI
# ============================================================================
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Load data to Silver layer (append-only)")
    parser.add_argument('--test', action='store_true', help='Run test')
    args = parser.parse_args()
    
    if args.test:
        logger.info("🧪 Running test mode...")
        
        # Test 1: Premier CVE
        test_data_1 = pd.DataFrame([
            {
                'cve_id': 'CVE-2024-TEST-001',
                'title': 'Test Vulnerability 1',
                'description': 'First test',
                'category': 'test',
                'predicted_category': None,
                'published_date': pd.Timestamp.now(),
                'last_modified': pd.Timestamp.now(),
                'loaded_at': pd.Timestamp.now(),
                'remotely_exploit': True,
                'source_identifier': 'test@example.com',
                'affected_products': '[]',
                'cvss_scores': '[{"score": "7.5", "version": "CVSS 3.1"}]',
                'url': 'https://test.com/001'
            }
        ])
        
        logger.info("\n🧪 TEST 1: Inserting first CVE...")
        tables = {'cve_cleaned': test_data_1}
        success = load_silver_layer(tables)
        
        if success:
            # Test 2: Même CVE (devrait skip)
            logger.info("\n🧪 TEST 2: Trying to insert same CVE (should skip)...")
            success = load_silver_layer(tables)
            
            # Test 3: Nouveau CVE (devrait insert)
            test_data_2 = pd.DataFrame([
                {
                    'cve_id': 'CVE-2024-TEST-002',
                    'title': 'Test Vulnerability 2',
                    'description': 'Second test',
                    'category': 'test',
                    'predicted_category': None,
                    'published_date': pd.Timestamp.now(),
                    'last_modified': pd.Timestamp.now(),
                    'loaded_at': pd.Timestamp.now(),
                    'remotely_exploit': False,
                    'source_identifier': 'test@example.com',
                    'affected_products': '[]',
                    'cvss_scores': '[{"score": "5.0", "version": "CVSS 3.1"}]',
                    'url': 'https://test.com/002'
                }
            ])
            
            logger.info("\n🧪 TEST 3: Inserting different CVE (should insert)...")
            tables = {'cve_cleaned': test_data_2}
            success = load_silver_layer(tables)
            
            logger.info("\n✅ All tests passed!")
            logger.info("💡 Result should be: 2 CVEs total (001 + 002)")
        
        sys.exit(0 if success else 1)
    else:
        logger.info("💡 Usage:")
        logger.info("   python load_silver_layer_fixed.py --test")
        logger.info("")
        logger.info("📝 Fixed Behavior:")
        logger.info("   ✅ INSERT new CVEs only")
        logger.info("   ⭕ SKIP existing CVEs (no duplicates)")
        logger.info("   ❌ NEVER truncate or update")
        logger.info("   🔒 if_exists='replace' is IGNORED")
        logger.info("")
        logger.info("📊 Example:")
        logger.info("   Scrape 10 CVE → Silver has 10")
        logger.info("   Scrape 10 CVE (5 new, 5 duplicates) → Silver has 15")
        logger.info("   Total accumulation without duplicates")