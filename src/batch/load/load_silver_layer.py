#!/usr/bin/env python3
"""
LOAD SILVER LAYER
Charge les données nettoyées dans la couche Silver (table unique: cve_cleaned)
Inclut le support de predicted_category (ML)
"""

from pathlib import Path
import sys
sys.path.append(str(Path(__file__).resolve().parents[2]))

import logging
from typing import Dict, Optional
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

# -------------------------------------------------------------------
# Schema Validation
# -------------------------------------------------------------------
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
                logger.error(f"❌ Schema '{schema}' does not exist! Run silver.sql first.")
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
                logger.error(f"❌ Table {schema}.{table} does not exist! Run silver.sql first.")
                return False
            
            # Vérifier que predicted_category existe
            result = conn.execute(
                text("""
                    SELECT column_name
                    FROM information_schema.columns
                    WHERE table_schema = :schema 
                    AND table_name = :table 
                    AND column_name = 'predicted_category'
                """),
                {"schema": schema, "table": table}
            )
            
            if not result.fetchone():
                logger.warning("⚠️  Column 'predicted_category' not found! Schema may need update.")
                logger.warning("   Run: psql -d your_db -f database/schemas/silver.sql")
        
        logger.info("✅ Silver schema validated")
        return True
        
    except Exception as e:
        logger.error(f"❌ Error validating schema: {e}")
        return False

# -------------------------------------------------------------------
# Data Preparation
# -------------------------------------------------------------------
def prepare_silver_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Prépare le DataFrame pour l'insertion dans silver.cve_cleaned
    - Nettoie les colonnes et ne garde que celles nécessaires
    - Convertit les types de données correctement
    - Gère les JSONB pour PostgreSQL
    - Inclut predicted_category
    """
    logger.info("🛠️ Preparing dataframe for silver layer...")
    
    required_columns = [
        'cve_id', 'title', 'description', 'category', 'predicted_category',
        'published_date', 'last_modified', 'loaded_at',
        'remotely_exploit', 'source_identifier',
        'affected_products', 'cvss_scores', 'url'
    ]
    
    # Créer une copie propre du DataFrame
    df_clean = df.copy()
    
    # Ne garder QUE les colonnes requises (ignorer les autres)
    available_cols = [col for col in required_columns if col in df_clean.columns]
    df_clean = df_clean[available_cols].copy()
    
    # Ajouter les colonnes manquantes avec None
    for col in required_columns:
        if col not in df_clean.columns:
            logger.warning(f"⚠️  Adding missing column: {col}")
            df_clean[col] = None
    
    # Réordonner pour avoir exactement les colonnes requises dans l'ordre
    df_clean = df_clean[required_columns]
    
    # Convertir les dates en datetime (sans timezone)
    for date_col in ['published_date', 'last_modified', 'loaded_at']:
        if date_col in df_clean.columns:
            df_clean[date_col] = pd.to_datetime(df_clean[date_col], errors='coerce')
            # Supprimer timezone si présente
            if df_clean[date_col].dtype == 'datetime64[ns, UTC]':
                df_clean[date_col] = df_clean[date_col].dt.tz_localize(None)
    
    # Convertir JSONB columns en string JSON pour PostgreSQL
    import json
    import numpy as np
    
    def safe_json_dumps(x):
        """Convertit en JSON string de manière sécurisée"""
        try:
            # Gérer None
            if x is None:
                return None
            
            # Gérer NaN (float)
            if isinstance(x, float) and np.isnan(x):
                return None
            
            # Gérer numpy array vide ou None-like
            if isinstance(x, np.ndarray):
                if x.size == 0:
                    return None
                # Convertir en liste Python
                x = x.tolist()
            
            # Si c'est une string, vérifier si c'est du JSON valide
            if isinstance(x, str):
                x = x.strip()
                if x == '' or x.lower() in ('null', 'none', 'nan'):
                    return None
                # Essayer de parser pour valider
                try:
                    parsed = json.loads(x)
                    return json.dumps(parsed)  # Re-dump pour normaliser
                except:
                    return None
            
            # Si c'est une liste ou dict, dumper
            if isinstance(x, (list, dict)):
                if len(x) == 0:
                    return None
                return json.dumps(x)
            
            # Autres cas: retourner None
            return None
            
        except Exception as e:
            # En cas d'erreur, logger et retourner None
            return None
    
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
    
    # Supprimer les doublons sur cve_id
    before = len(df_clean)
    df_clean = df_clean.drop_duplicates(subset=['cve_id'], keep='first')
    after = len(df_clean)
    
    if before > after:
        logger.warning(f"⚠️  Removed {before - after} duplicate cve_ids")
    
    # Statistiques sur predicted_category
    if 'predicted_category' in df_clean.columns:
        predicted_count = df_clean['predicted_category'].notna().sum()
        prediction_rate = (predicted_count / len(df_clean) * 100) if len(df_clean) > 0 else 0
        logger.info(f"🤖 Prediction stats: {predicted_count:,}/{len(df_clean):,} ({prediction_rate:.1f}%) with predictions")
    
    logger.info(f"✅ Prepared {len(df_clean):,} rows for silver layer")
    logger.info(f"📋 Columns: {list(df_clean.columns)}")
    
    return df_clean

# -------------------------------------------------------------------
# Load to Silver
# -------------------------------------------------------------------
def load_to_silver_table(
    df: pd.DataFrame,
    engine: Engine,
    if_exists: str = 'replace'
) -> Dict[str, int]:
    """
    Charge les données dans silver.cve_cleaned
    
    Args:
        df: DataFrame à charger
        engine: Connexion DB
        if_exists: 'replace' ou 'append'
    
    Returns:
        Dict avec statistiques (inserted, skipped, failed)
    """
    schema = get_schema_name("silver")
    table = "cve_cleaned"
    full_table = f"{schema}.{table}"
    
    logger.info("=" * 72)
    logger.info(f"💾 LOADING TO SILVER: {full_table}")
    logger.info(f"   Mode: {if_exists}")
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
        logger.info(f"📋 Columns to insert: {list(df_prepared.columns)}")
        
        # Truncate si replace
        if if_exists == 'replace':
            logger.info(f"🗑️  Truncating table {full_table}...")
            with engine.begin() as conn:
                conn.execute(text(f"TRUNCATE TABLE {full_table} CASCADE;"))
            logger.info("✅ Table truncated")
        
        logger.info(f"📤 Inserting {len(df_prepared):,} rows...")
        
        # Utiliser pandas to_sql
        # IMPORTANT: dtype=None laisse pandas inférer les types
        rows_inserted = df_prepared.to_sql(
            name=table,
            con=engine,
            schema=schema,
            if_exists='append',  # Toujours append après truncate
            index=False,
            method='multi',
            chunksize=500,  # Réduire la taille des chunks
            dtype=None  # Laisser pandas gérer les types
        )
        
        # Compter les lignes finales
        with engine.connect() as conn:
            result = conn.execute(text(f"SELECT COUNT(*) FROM {full_table}"))
            final_count = result.scalar()
            
            # Compter les prédictions
            result = conn.execute(text(f"""
                SELECT COUNT(*) 
                FROM {full_table} 
                WHERE predicted_category IS NOT NULL
            """))
            predicted_count = result.scalar()
        
        stats['inserted'] = final_count if if_exists == 'replace' else rows_inserted
        
        duration = (datetime.now() - start_time).total_seconds()
        
        logger.info("=" * 72)
        logger.info("📊 LOAD STATISTICS")
        logger.info("=" * 72)
        logger.info(f"✅ Rows inserted: {stats['inserted']:,}")
        logger.info(f"🧮 Total rows in {table}: {final_count:,}")
        logger.info(f"🤖 CVEs with predictions: {predicted_count:,} ({predicted_count/final_count*100:.1f}%)")
        logger.info(f"⏱️  Duration: {duration:.2f}s")
        if duration > 0:
            logger.info(f"⚡ Speed: {stats['inserted']/duration:.0f} rows/sec")
        logger.info("=" * 72)
        
        return stats
        
    except SQLAlchemyError as e:
        logger.error(f"❌ Database error: {e}")
        stats['failed'] = len(df)
        raise
    except Exception as e:
        logger.error(f"❌ Unexpected error: {e}", exc_info=True)
        stats['failed'] = len(df)
        raise

# -------------------------------------------------------------------
# Main Load Function
# -------------------------------------------------------------------
def load_silver_layer(
    tables: Dict[str, pd.DataFrame],
    engine: Optional[Engine] = None,
    if_exists: str = 'replace'
) -> bool:
    """
    Fonction principale pour charger la couche Silver
    
    Args:
        tables: Dict avec clé 'cve_cleaned' contenant le DataFrame
        engine: Connexion DB (optionnel)
        if_exists: 'replace' ou 'append'
    
    Returns:
        True si succès, False sinon
    """
    logger.info("=" * 72)
    logger.info("🚀 SILVER LAYER LOAD PIPELINE")
    logger.info("=" * 72)
    
    # Validation
    assert if_exists in {'append', 'replace'}, "if_exists must be 'append' or 'replace'"
    
    if 'cve_cleaned' not in tables:
        logger.error("❌ Missing 'cve_cleaned' in tables dict!")
        return False
    
    try:
        # Créer engine si nécessaire
        if engine is None:
            engine = create_db_engine()
        
        # Vérifier le schéma
        if not verify_silver_schema(engine):
            return False
        
        # Charger les données
        df_cleaned = tables['cve_cleaned']
        stats = load_to_silver_table(df_cleaned, engine, if_exists=if_exists)
        
        # Rafraîchir les statistiques
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
    


# -------------------------------------------------------------------
# CLI Entry Point
# -------------------------------------------------------------------
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Load data to Silver layer")
    parser.add_argument(
        '--test',
        action='store_true',
        help='Run test with sample data'
    )
    args = parser.parse_args()
    
    if args.test:
        logger.info("🧪 Running test mode...")
        
        # Créer des données de test
        test_data = pd.DataFrame([
            {
                'cve_id': 'CVE-2024-TEST-001',
                'title': 'SQL Injection in Web App',
                'description': 'A SQL injection vulnerability was found',
                'category': 'sql',
                'predicted_category': 'sql',  # Prediction correcte
                'published_date': pd.Timestamp.now(),
                'last_modified': pd.Timestamp.now(),
                'loaded_at': pd.Timestamp.now(),
                'remotely_exploit': True,
                'source_identifier': 'test',
                'affected_products': '[]',
                'cvss_scores': '[]',
                'url': 'https://test.com/001'
            },
            {
                'cve_id': 'CVE-2024-TEST-002',
                'title': 'Buffer Overflow in Network Service',
                'description': 'A buffer overflow allows remote code execution',
                'category': 'overflow',
                'predicted_category': None,  # Pas de prédiction
                'published_date': pd.Timestamp.now(),
                'last_modified': pd.Timestamp.now(),
                'loaded_at': pd.Timestamp.now(),
                'remotely_exploit': True,
                'source_identifier': 'test',
                'affected_products': '[]',
                'cvss_scores': '[]',
                'url': 'https://test.com/002'
            }
        ])
        
        tables = {'cve_cleaned': test_data}
        success = load_silver_layer(tables, if_exists='replace')
        
        sys.exit(0 if success else 1)
    else:
        logger.info("💡 Usage:")
        logger.info("   from batch.load.load_silver_layer import load_silver_layer")
        logger.info("   tables = {'cve_cleaned': your_dataframe}")
        logger.info("   success = load_silver_layer(tables, if_exists='replace')")
        logger.info("")
        logger.info("📝 Note: DataFrame must include 'predicted_category' column")
        logger.info("   Use eda_bronze_to_silver.py to generate it automatically")