#!/usr/bin/env python3
"""
LOAD SILVER LAYER - INSERT ONLY, SKIP DUPLICATES (FIXED)
Ne fait QUE des INSERT, skip les CVE qui existent déjà
JAMAIS de TRUNCATE, JAMAIS d'UPDATE, JAMAIS de REPLACE

Table cible: silver.cve_cleaned
Colonnes: cve_id, vulnarbilit, published_date, last_modified, loaded_at,
          remotely_exploit, source_identifier, affected_products (TEXT JSON),
          cvss_scores (TEXT JSON)
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
from sqlalchemy.engine import Engine

from database.connection import create_db_engine, get_schema_name

# Logging setup
LOGS_DIR = Path(__file__).resolve().parents[3] / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOGS_DIR / "load_silver_layer.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(LOG_FILE, encoding="utf-8"), logging.StreamHandler()]
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

            # Sanity: colonne vulnarbilit
            result = conn.execute(
                text("""
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = :schema AND table_name = :table
                      AND column_name = 'vulnarbilit'
                """),
                {"schema": schema, "table": table}
            )
            if not result.fetchone():
                logger.error(f"❌ Column 'vulnarbilit' missing in {schema}.{table}!")
                return False
        
        logger.info("✅ Silver schema validated")
        return True
        
    except Exception as e:
        logger.error(f"❌ Error validating schema: {e}")
        return False

# ============================================================================
# DATA PREPARATION
# ============================================================================
def _is_nan_float(x) -> bool:
    return isinstance(x, float) and np.isnan(x)

def safe_json_text(x):
    """Convertit en JSON TEXT compact (ou None si vide/invalid)"""
    try:
        if x is None or _is_nan_float(x):
            return None
        if isinstance(x, (list, dict)):
            if len(x) == 0:
                return None
            return json.dumps(x, ensure_ascii=False, separators=(",", ":"))
        if isinstance(x, str):
            s = x.strip()
            if s == "" or s.lower() in ("null", "none", "nan", "[]", "{}"):
                return None
            try:
                parsed = json.loads(s)
                if isinstance(parsed, (list, dict)) and len(parsed) == 0:
                    return None
                return json.dumps(parsed, ensure_ascii=False, separators=(",", ":"))
            except Exception:
                return None
        return None
    except Exception:
        return None

def prepare_silver_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Prépare le DataFrame pour l'insertion dans silver.cve_cleaned"""
    logger.info("🛠️ Preparing dataframe for silver layer...")
    
    required_columns = [
        'cve_id', 'vulnarbilit',
        'published_date', 'last_modified', 'loaded_at',
        'remotely_exploit', 'source_identifier',
        'affected_products', 'cvss_scores'
    ]
    
    df_clean = df.copy()
    
    # Garder uniquement les colonnes requises + ajouter manquantes
    for col in required_columns:
        if col not in df_clean.columns:
            logger.warning(f"⚠️  Adding missing column: {col}")
            df_clean[col] = None
    df_clean = df_clean[required_columns].copy()
    
    # Convertir les dates -> timestamp naïf
    for date_col in ['published_date', 'last_modified', 'loaded_at']:
        df_clean[date_col] = pd.to_datetime(df_clean[date_col], errors='coerce')
        if pd.api.types.is_datetime64tz_dtype(df_clean[date_col]):
            df_clean[date_col] = df_clean[date_col].dt.tz_convert(None)
    
    # JSON en TEXT
    for json_col in ['affected_products', 'cvss_scores']:
        df_clean[json_col] = df_clean[json_col].apply(safe_json_text)
    
    # Defaults/normalisation
    df_clean['vulnarbilit'] = df_clean['vulnarbilit'].fillna('uncategorized').replace('', 'uncategorized')
    
    if 'remotely_exploit' in df_clean.columns:
        def _coerce_bool(v):
            if v is None or _is_nan_float(v):
                return None
            s = str(v).strip().lower()
            if s in {'true','yes','y','1'}: return True
            if s in {'false','no','n','0'}: return False
            return None
        df_clean['remotely_exploit'] = df_clean['remotely_exploit'].apply(_coerce_bool)
    
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
    Insert-only loader for silver.cve_cleaned (skip duplicates).
    """
    schema = get_schema_name("silver")
    table = "cve_cleaned"
    full_table = f"{schema}.{table}"

    logger.info("=" * 72)
    logger.info("LOADING TO SILVER: %s", full_table)
    logger.info("Mode: INSERT ONLY (skip existing) - NO TRUNCATE EVER")
    logger.info("=" * 72)

    if df.empty:
        logger.warning("No data to load.")
        return {"inserted": 0, "skipped": 0, "failed": 0}

    stats = {"inserted": 0, "skipped": 0, "failed": 0}
    start_time = datetime.now()

    try:
        # Prepare data
        df_prepared = prepare_silver_dataframe(df)
        if df_prepared.empty:
            logger.warning("No valid data after preparation.")
            return stats

        logger.info("DataFrame shape: %s", df_prepared.shape)
        logger.info("Checking for existing CVEs in Silver...")

        # Collect CVE IDs
        cve_ids = df_prepared["cve_id"].tolist()
        if not cve_ids:
            logger.warning("No CVE IDs to check.")
            return stats

        # Build IN list safely
        escaped_ids = ["'" + str(c).replace("'", "''") + "'" for c in cve_ids]
        placeholders = ",".join(escaped_ids)

        with engine.connect() as conn:
            result = conn.execute(
                text(f"SELECT cve_id FROM {full_table} WHERE cve_id IN ({placeholders})")
            )
            existing_cves = {row[0] for row in result.fetchall()}

        logger.info("Already in Silver: %d CVE(s)", len(existing_cves))

        # Filter to new rows
        df_to_insert = df_prepared[~df_prepared["cve_id"].isin(existing_cves)].copy()
        stats["skipped"] = len(existing_cves)

        if df_to_insert.empty:
            logger.info("All CVEs already exist in Silver - nothing to insert.")
            logger.info("Skipped: %d CVE(s)", stats["skipped"])
            return stats

        logger.info("New CVEs to insert: %d", len(df_to_insert))

        # Append insert
        logger.info("Inserting rows (append mode)...")
        df_to_insert.to_sql(
            name=table,
            con=engine,
            schema=schema,
            if_exists="append",
            index=False,
            method="multi",
            chunksize=500,
            dtype=None,
        )

        stats["inserted"] = len(df_to_insert)

        # Final stats
        with engine.connect() as conn:
            final_count = conn.execute(text(f"SELECT COUNT(*) FROM {full_table}")).scalar()

        duration = (datetime.now() - start_time).total_seconds()

        logger.info("=" * 72)
        logger.info("LOAD STATISTICS")
        logger.info("=" * 72)
        logger.info("Inserted (new): %d", stats["inserted"])
        logger.info("Skipped (existing): %d", stats["skipped"])
        logger.info("Total in Silver: %d", final_count)
        logger.info("Duration: %.2fs", duration)
        logger.info("=" * 72)

        return stats

    except Exception as e:
        logger.error("Database error: %s", e, exc_info=True)
        stats["failed"] = len(df)
        raise


# ============================================================================
# MAIN LOAD FUNCTION - FIXED
# ============================================================================
def load_silver_layer(
    tables: Dict[str, pd.DataFrame],
    engine: Optional[Engine] = None,
    if_exists: str = 'append'  # Paramètre ignoré - toujours append
) -> bool:
    """
    Fonction principale pour charger la couche Silver (append-only, skip duplicates)
    """
    logger.info("=" * 72)
    logger.info("🚀 SILVER LAYER LOAD PIPELINE (APPEND-ONLY MODE)")
    logger.info("=" * 72)
    
    if 'cve_cleaned' not in tables:
        logger.error("❌ Missing 'cve_cleaned' in tables dict!")
        return False
    
    try:
        if engine is None:
            engine = create_db_engine()
        
        if not verify_silver_schema(engine):
            return False
        
        df_cleaned = tables['cve_cleaned']
        
        # Toujours en INSERT ONLY
        _ = load_to_silver_table(df_cleaned, engine)
        
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
# CLI (optional quick test)
# ============================================================================
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Load data to Silver layer (append-only)")
    parser.add_argument('--test', action='store_true', help='Run test')
    args = parser.parse_args()
    
    if args.test:
        logger.info("🧪 Running test mode...")
        test_data_1 = pd.DataFrame([
            {
                'cve_id': 'CVE-2024-TEST-001',
                'vulnarbilit': 'xss',
                'published_date': pd.Timestamp.now(),
                'last_modified': pd.Timestamp.now(),
                'loaded_at': pd.Timestamp.now(),
                'remotely_exploit': True,
                'source_identifier': 'test@example.com',
                'affected_products': '[]',
                'cvss_scores': '[{"score":"7.5","version":"3.1"}]'
            }
        ])
        tables = {'cve_cleaned': test_data_1}
        ok = load_silver_layer(tables)
        sys.exit(0 if ok else 1)
    else:
        logger.info("💡 Usage: python load_silver_layer.py --test")
