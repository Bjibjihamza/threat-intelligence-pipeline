#!/usr/bin/env python3
"""
BRONZE ➜ SILVER: EDA & DATA CLEANING (FIXED VERSION)
⭐ CHANGEMENT: if_exists='append' par défaut (pas 'replace')

Peut être utilisé:
1. Comme module importé par le scraper (traite seulement les CVE scrapés)
2. Comme script standalone CLI (traite toute la DB)
"""

from pathlib import Path
import sys
sys.path.append(str(Path(__file__).resolve().parents[2]))

import argparse
import logging
from typing import Optional
import json
import numpy as np
import pandas as pd
from dateutil import parser
from sqlalchemy.engine import Engine

from database.connection import create_db_engine, get_schema_name
from src.stream.load.load_silver_layer import load_silver_layer

# -------------------------------------------------------------------
# Logging
# -------------------------------------------------------------------
LOGS_DIR = Path(__file__).resolve().parents[3] / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOGS_DIR / "eda_bronze_to_silver.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("eda_bronze_to_silver")

pd.set_option("display.max_columns", None)
pd.set_option("display.float_format", "{:.2f}".format)

# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------
def _is_nan_float(x) -> bool:
    return isinstance(x, float) and np.isnan(x)

def _is_empty_json_like(x) -> bool:
    if x is None: return True
    if _is_nan_float(x): return True
    if isinstance(x, str):
        s = x.strip().lower()
        return s in ("", "[]", "null", "none")
    if isinstance(x, (list, tuple, np.ndarray, dict)):
        return len(x) == 0
    return False

def _safe_json_load(x):
    try:
        if isinstance(x, str):
            return json.loads(x)
        return x
    except Exception:
        return None

def _parse_date_safe(v):
    """Parse date with fallback to fuzzy parsing"""
    if pd.isna(v): 
        return pd.NaT
    for fuzzy in (False, True):
        try:
            return parser.parse(str(v), fuzzy=fuzzy)
        except Exception:
            pass
    return pd.NaT

# -------------------------------------------------------------------
# Prediction Function (Placeholder)
# -------------------------------------------------------------------
def predict_category_from_text(title: str, description: str) -> str:
    """
    Placeholder pour prédiction ML
    TODO: Implémenter avec un modèle entraîné
    """
    return None

def add_predicted_category(df: pd.DataFrame) -> pd.DataFrame:
    """Ajoute colonne predicted_category"""
    logger.info("\n🤖 ADDING PREDICTED CATEGORY COLUMN...")
    
    if 'title' not in df.columns:
        df['title'] = ''
    if 'description' not in df.columns:
        df['description'] = ''
    
    df['predicted_category'] = df.apply(
        lambda row: predict_category_from_text(
            str(row['title']) if pd.notna(row['title']) else '',
            str(row['description']) if pd.notna(row['description']) else ''
        ),
        axis=1
    )
    
    predicted_count = df['predicted_category'].notna().sum()
    logger.info(f"   ✅ Predictions: {predicted_count:,} / {len(df):,}")
    
    return df

# -------------------------------------------------------------------
# EDA: Data Quality Assessment
# -------------------------------------------------------------------
def perform_eda(df: pd.DataFrame) -> pd.DataFrame:
    """
    Analyse exploratoire des données
    Peut être appelée sur n'importe quel DataFrame (complet ou partiel)
    """
    logger.info("=" * 72)
    logger.info("🔍 EXPLORATORY DATA ANALYSIS")
    logger.info("=" * 72)
    
    # 1. Vue d'ensemble
    logger.info(f"\n📊 OVERVIEW:")
    logger.info(f"   Total rows: {len(df):,}")
    logger.info(f"   Total columns: {len(df.columns)}")
    logger.info(f"   Memory usage: {df.memory_usage(deep=True).sum() / 1024**2:.2f} MB")
    
    # 2. Analyse des valeurs manquantes
    logger.info(f"\n🔎 MISSING VALUES ANALYSIS:")
    missing = df.isnull().sum()
    missing_pct = (missing / len(df) * 100).round(2)
    missing_df = pd.DataFrame({
        'Missing': missing,
        'Percentage': missing_pct
    }).sort_values('Missing', ascending=False)
    
    for col, row in missing_df.iterrows():
        if row['Missing'] > 0:
            logger.info(f"   {col}: {row['Missing']:,} ({row['Percentage']:.2f}%)")
    
    # 3. Analyse des duplicatas
    logger.info(f"\n🔄 DUPLICATES ANALYSIS:")
    duplicates = df.duplicated(subset=['cve_id']).sum()
    logger.info(f"   Duplicate CVE IDs: {duplicates:,}")
    
    # 4. Analyse des dates
    logger.info(f"\n📅 DATE ANALYSIS:")
    if 'published_date' in df.columns:
        df['published_date_parsed'] = pd.to_datetime(
            df['published_date'].apply(_parse_date_safe), 
            errors='coerce'
        )
        valid_dates = df['published_date_parsed'].notna().sum()
        logger.info(f"   Valid published dates: {valid_dates:,} / {len(df):,}")
        
        if valid_dates > 0:
            logger.info(f"   Date range: {df['published_date_parsed'].min()} to {df['published_date_parsed'].max()}")
    
    # 5. Analyse CVSS
    logger.info(f"\n🎯 CVSS SCORES ANALYSIS:")
    if 'cvss_scores' in df.columns:
        has_cvss = ~df['cvss_scores'].apply(_is_empty_json_like)
        logger.info(f"   CVEs with CVSS: {has_cvss.sum():,} ({has_cvss.sum()/len(df)*100:.2f}%)")
    
    # 6. Analyse des catégories
    logger.info(f"\n📑 CATEGORY ANALYSIS:")
    if 'category' in df.columns:
        cat_counts = df['category'].value_counts()
        logger.info(f"   Total categories: {len(cat_counts)}")
        if len(cat_counts) > 0:
            logger.info(f"   Top categories:")
            for cat, count in cat_counts.head(5).items():
                logger.info(f"      - {cat}: {count:,}")
    
    logger.info("\n" + "=" * 72)
    
    return df

# -------------------------------------------------------------------
# Data Cleaning
# -------------------------------------------------------------------
def clean_silver_data(df: pd.DataFrame) -> pd.DataFrame:
    """
    Nettoie les données pour Silver layer
    """
    logger.info("=" * 72)
    logger.info("🧹 DATA CLEANING")
    logger.info("=" * 72)
    
    df = df.copy()
    initial_rows = len(df)
    
    # 1. Supprimer les duplicatas
    logger.info("\n🔄 Removing duplicates...")
    df = df.drop_duplicates(subset=['cve_id'], keep='first')
    removed = initial_rows - len(df)
    if removed > 0:
        logger.info(f"   ⚠️  Removed {removed:,} duplicate CVE IDs")
    
    # 2. Nettoyer les dates
    logger.info("\n📅 Cleaning dates...")
    for col in ['published_date', 'last_modified']:
        if col in df.columns:
            df[col] = pd.to_datetime(df[col].apply(_parse_date_safe), errors='coerce')
    
    # 3. Gérer loaded_at
    if 'loaded_at' in df.columns:
        df['loaded_at'] = pd.to_datetime(df['loaded_at'], errors='coerce').dt.tz_localize(None)
    else:
        df['loaded_at'] = pd.Timestamp.utcnow().tz_localize(None)
    
    # 4. Supprimer les lignes sans dates critiques
    before_dates = len(df)
    df = df.dropna(subset=['published_date', 'last_modified'])
    removed_dates = before_dates - len(df)
    if removed_dates > 0:
        logger.info(f"   ⚠️  Removed {removed_dates:,} rows with invalid dates")
    
    # 5. Nettoyer category
    if 'category' not in df.columns:
        df['category'] = 'undefined'
    df['category'] = df['category'].fillna('undefined').replace('', 'undefined')
    
    # 6. Standardiser remotely_exploit
    if 'remotely_exploit' in df.columns:
        df['remotely_exploit'] = df['remotely_exploit'].map({
            'Yes !': True, 'Yes': True, 'True': True, True: True,
            'No': False, 'False': False, False: False
        })
    
    # 7. Conserver source_identifier
    if 'source_identifier' not in df.columns and 'source' in df.columns:
        df['source_identifier'] = df['source']
    
    # 8. Filtrer CVE sans CVSS
    logger.info("\n🎯 Filtering CVEs without CVSS scores...")
    if 'cvss_scores' in df.columns:
        has_cvss = ~df['cvss_scores'].apply(_is_empty_json_like)
        before_cvss = len(df)
        df = df[has_cvss].copy()
        removed_cvss = before_cvss - len(df)
        if removed_cvss > 0:
            logger.info(f"   ⚠️  Removed {removed_cvss:,} rows without CVSS")
    
    # 9. Ajouter predicted_category
    df = add_predicted_category(df)
    
    # 10. Résumé
    logger.info(f"\n✅ CLEANING SUMMARY:")
    logger.info(f"   Initial rows: {initial_rows:,}")
    logger.info(f"   Final rows: {len(df):,}")
    logger.info(f"   Removed: {initial_rows - len(df):,}")
    logger.info(f"   Quality: {len(df)/initial_rows*100:.2f}%")
    
    logger.info("\n" + "=" * 72)
    
    return df

# -------------------------------------------------------------------
# Silver Layer Creation
# -------------------------------------------------------------------
def create_silver_layer(df: pd.DataFrame) -> pd.DataFrame:
    """Crée le format Silver avec colonnes standardisées"""
    logger.info("=" * 72)
    logger.info("🏗️  CREATING SILVER LAYER")
    logger.info("=" * 72)
    
    silver_columns = [
        'cve_id', 'title', 'description', 'category', 'predicted_category',
        'published_date', 'last_modified', 'loaded_at',
        'remotely_exploit', 'source_identifier',
        'affected_products', 'cvss_scores', 'url'
    ]
    
    for col in silver_columns:
        if col not in df.columns:
            df[col] = None
    
    silver_df = df[silver_columns].copy()
    
    logger.info(f"✅ Silver layer: {len(silver_df):,} rows")
    logger.info(f"📊 Columns: {list(silver_df.columns)}")
    
    return silver_df

# -------------------------------------------------------------------
# Main Pipeline Functions
# -------------------------------------------------------------------
def load_bronze_data(engine: Engine, limit: Optional[int] = None) -> pd.DataFrame:
    """Charge les données depuis Bronze (toute la DB)"""
    logger.info("=" * 72)
    logger.info("📥 LOADING BRONZE DATA")
    logger.info("=" * 72)
    
    bronze_schema = get_schema_name("bronze")
    
    if limit:
        query = f"""
            SELECT *
            FROM {bronze_schema}.cve_details
            ORDER BY published_date DESC NULLS LAST
            LIMIT {int(limit)}
        """
    else:
        query = f"SELECT * FROM {bronze_schema}.cve_details;"
    
    df = pd.read_sql(query, engine)
    logger.info(f"✅ Loaded {len(df):,} rows")
    
    return df

def run_eda_to_silver(limit: Optional[int] = None, if_exists: str = 'append') -> bool:
    """
    ⭐ FIXED VERSION ⭐
    Pipeline complet pour CLI: Bronze → EDA → Silver
    Traite TOUTE la base de données Bronze
    
    CHANGEMENT: if_exists='append' par défaut (plus 'replace')
    """
    logger.info("=" * 72)
    logger.info("🚀 FULL DATABASE: BRONZE ➜ SILVER PIPELINE")
    logger.info("=" * 72)
    
    # ⭐ Avertissement si replace
    if if_exists == 'replace':
        logger.warning("⚠️  WARNING: if_exists='replace' is deprecated!")
        logger.warning("⚠️  Using 'append' mode instead (skip duplicates)")
        logger.warning("⚠️  To reset table: TRUNCATE silver.cve_cleaned;")
        if_exists = 'append'
    
    try:
        engine = create_db_engine()
        
        # Charger toute la DB Bronze
        df_bronze = load_bronze_data(engine, limit=limit)
        
        if df_bronze.empty:
            logger.warning("⚠️  No data in bronze!")
            return False
        
        # EDA
        df_with_eda = perform_eda(df_bronze)
        
        # Cleaning
        df_cleaned = clean_silver_data(df_with_eda)
        
        if df_cleaned.empty:
            logger.error("❌ No data after cleaning!")
            return False
        
        # Silver
        silver_df = create_silver_layer(df_cleaned)
        
        # Load (toujours append)
        logger.info("\n💾 Loading to Silver (append mode)...")
        tables = {"cve_cleaned": silver_df}
        success = load_silver_layer(tables, engine, if_exists='append')
        
        if success:
            logger.info("\n" + "=" * 72)
            logger.info("🎉 FULL DATABASE PIPELINE COMPLETED")
            logger.info("=" * 72)
        
        return success
        
    except Exception as e:
        logger.error(f"❌ Pipeline failed: {e}", exc_info=True)
        return False

# -------------------------------------------------------------------
# CLI
# -------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="Bronze ➜ Silver: EDA & Cleaning Pipeline (append-only)"
    )
    parser.add_argument(
        '--limit', 
        type=int, 
        default=None,
        help='Limit rows (for testing)'
    )
    parser.add_argument(
        '--if-exists',
        choices=['append', 'replace'],
        default='append',  # ⭐ CHANGÉ de 'replace' à 'append'
        help='Mode de chargement (replace is deprecated, always uses append)'
    )
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    
    print(f"\n🚀 Running {Path(__file__).name}")
    print(f"   Limit: {args.limit or 'None (full DB)'}")
    print(f"   Mode: {args.if_exists} (always append)")
    
    if args.if_exists == 'replace':
        print("\n⚠️  WARNING: 'replace' mode is deprecated!")
        print("   Using 'append' instead (skips duplicates)")
        print("   To reset table: TRUNCATE silver.cve_cleaned;\n")
    
    success = run_eda_to_silver(limit=args.limit, if_exists=args.if_exists)
    sys.exit(0 if success else 1)