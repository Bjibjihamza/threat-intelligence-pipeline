#!/usr/bin/env python3
"""
BRONZE ➜ SILVER: EDA & DATA CLEANING
- Nettoie les données brutes
- Standardise les formats
- Enlève les duplicatas et valeurs manquantes critiques
- Prépare les données pour la modélisation Gold
- Ajoute predicted_category (à entraîner ultérieurement)
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
from batch.load.load_silver_layer import load_silver_layer

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

# -------------------------------------------------------------------
# Prediction Function (Placeholder)
# -------------------------------------------------------------------
def predict_category_from_text(title: str, description: str) -> str:
    """
    Fonction placeholder pour prédire la catégorie à partir du titre et de la description.
    
    Cette fonction sera implémentée plus tard avec un modèle ML entraîné.
    Pour l'instant, elle retourne None pour indiquer qu'aucune prédiction n'a été faite.
    
    Args:
        title: Le titre du CVE
        description: La description du CVE
        
    Returns:
        str or None: La catégorie prédite (None pour l'instant)
    """
    # TODO: Implémenter la logique de prédiction avec un modèle ML
    # Exemples d'approches possibles:
    # 1. Modèle de classification (Random Forest, XGBoost, etc.)
    # 2. Modèle NLP (BERT, transformers)
    # 3. Règles basées sur des mots-clés
    
    return None

def add_predicted_category(df: pd.DataFrame) -> pd.DataFrame:
    """
    Ajoute une colonne 'predicted_category' au DataFrame.
    
    Cette colonne contiendra les prédictions de catégories basées sur 
    le titre et la description. Pour l'instant, elle reste vide (None).
    
    Args:
        df: DataFrame avec colonnes 'title' et 'description'
        
    Returns:
        DataFrame avec la nouvelle colonne 'predicted_category'
    """
    logger.info("\n🤖 ADDING PREDICTED CATEGORY COLUMN...")
    
    # S'assurer que les colonnes nécessaires existent
    if 'title' not in df.columns:
        df['title'] = ''
    if 'description' not in df.columns:
        df['description'] = ''
    
    # Appliquer la fonction de prédiction (placeholder pour l'instant)
    df['predicted_category'] = df.apply(
        lambda row: predict_category_from_text(
            str(row['title']) if pd.notna(row['title']) else '',
            str(row['description']) if pd.notna(row['description']) else ''
        ),
        axis=1
    )
    
    # Statistiques
    predicted_count = df['predicted_category'].notna().sum()
    total_count = len(df)
    
    logger.info(f"   ✅ Column 'predicted_category' added")
    logger.info(f"   📊 Predictions made: {predicted_count:,} / {total_count:,}")
    logger.info(f"   ℹ️  Note: Prediction model not yet trained (all values are None)")
    
    return df

# -------------------------------------------------------------------
# Data Loading
# -------------------------------------------------------------------
def load_bronze_data(engine: Engine, limit: Optional[int] = None) -> pd.DataFrame:
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
    logger.info(f"✅ Loaded {len(df):,} rows from bronze layer")
    logger.info(f"📊 Columns: {list(df.columns)}")
    
    return df

# -------------------------------------------------------------------
# EDA: Data Quality Assessment
# -------------------------------------------------------------------
def perform_eda(df: pd.DataFrame) -> pd.DataFrame:
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
        logger.info(f"   CVEs with CVSS scores: {has_cvss.sum():,} ({has_cvss.sum()/len(df)*100:.2f}%)")
        
        # Compter les versions CVSS
        cvss_versions = {'v2': 0, 'v3': 0, 'v4': 0}
        for _, row in df[has_cvss].iterrows():
            scores = _safe_json_load(row['cvss_scores'])
            if isinstance(scores, list):
                for s in scores:
                    if isinstance(s, dict):
                        ver = s.get('version', '')
                        if 'CVSS 2.0' in ver: cvss_versions['v2'] += 1
                        elif 'CVSS 3' in ver: cvss_versions['v3'] += 1
                        elif 'CVSS 4.0' in ver: cvss_versions['v4'] += 1
        
        logger.info(f"   CVSS v2 entries: {cvss_versions['v2']:,}")
        logger.info(f"   CVSS v3 entries: {cvss_versions['v3']:,}")
        logger.info(f"   CVSS v4 entries: {cvss_versions['v4']:,}")
    
    # 6. Analyse des produits affectés
    logger.info(f"\n🏢 AFFECTED PRODUCTS ANALYSIS:")
    if 'affected_products' in df.columns:
        has_products = ~df['affected_products'].apply(_is_empty_json_like)
        logger.info(f"   CVEs with affected products: {has_products.sum():,} ({has_products.sum()/len(df)*100:.2f}%)")
    
    # 7. Analyse des catégories existantes
    logger.info(f"\n📑 CATEGORY ANALYSIS:")
    if 'category' in df.columns:
        cat_counts = df['category'].value_counts()
        logger.info(f"   Total categories: {len(cat_counts)}")
        logger.info(f"   Top 5 categories:")
        for cat, count in cat_counts.head(5).items():
            logger.info(f"      - {cat}: {count:,} ({count/len(df)*100:.2f}%)")
    
    logger.info("\n" + "=" * 72)
    
    return df

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
# Data Cleaning
# -------------------------------------------------------------------
def clean_silver_data(df: pd.DataFrame) -> pd.DataFrame:
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
    
    # 2. Nettoyer et parser les dates
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
        logger.info(f"   ⚠️  Removed {removed_dates:,} rows with invalid critical dates")
    
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
    
    # 8. Supprimer les lignes sans CVSS scores (critique pour analyse)
    logger.info("\n🎯 Filtering CVEs without CVSS scores...")
    if 'cvss_scores' in df.columns:
        has_cvss = ~df['cvss_scores'].apply(_is_empty_json_like)
        before_cvss = len(df)
        df = df[has_cvss].copy()
        removed_cvss = before_cvss - len(df)
        if removed_cvss > 0:
            logger.info(f"   ⚠️  Removed {removed_cvss:,} rows without CVSS scores")
    
    # 9. NOUVEAU: Ajouter la colonne predicted_category
    df = add_predicted_category(df)
    
    # 10. Statistiques finales
    logger.info(f"\n✅ CLEANING SUMMARY:")
    logger.info(f"   Initial rows: {initial_rows:,}")
    logger.info(f"   Final rows: {len(df):,}")
    logger.info(f"   Total removed: {initial_rows - len(df):,}")
    logger.info(f"   Data quality: {len(df)/initial_rows*100:.2f}%")
    
    logger.info("\n" + "=" * 72)
    
    return df

# -------------------------------------------------------------------
# Silver Layer Creation
# -------------------------------------------------------------------
def create_silver_layer(df: pd.DataFrame) -> pd.DataFrame:
    """
    Crée la couche Silver avec données nettoyées et standardisées
    Pas de transformation en modèle en étoile ici (ce sera fait en Gold)
    """
    logger.info("=" * 72)
    logger.info("🏗️  CREATING SILVER LAYER")
    logger.info("=" * 72)
    
    # Sélectionner et ordonner les colonnes pour Silver (avec predicted_category)
    silver_columns = [
        'cve_id', 'title', 'description', 'category', 'predicted_category',
        'published_date', 'last_modified', 'loaded_at',
        'remotely_exploit', 'source_identifier',
        'affected_products', 'cvss_scores', 'url'
    ]
    
    # S'assurer que toutes les colonnes existent
    for col in silver_columns:
        if col not in df.columns:
            df[col] = None
    
    silver_df = df[silver_columns].copy()
    
    logger.info(f"✅ Silver layer created with {len(silver_df):,} rows")
    logger.info(f"📊 Columns: {list(silver_df.columns)}")
    
    return silver_df

# -------------------------------------------------------------------
# Main Pipeline
# -------------------------------------------------------------------
def run_eda_to_silver(limit: Optional[int] = None, if_exists: str = 'replace') -> bool:
    """
    Pipeline complet: Bronze → EDA → Cleaning → Silver
    """
    logger.info("=" * 72)
    logger.info("🚀 BRONZE ➜ SILVER PIPELINE (EDA + CLEANING)")
    logger.info("=" * 72)
    
    try:
        # 1. Connexion DB
        engine = create_db_engine()
        
        # 2. Charger les données Bronze
        df_bronze = load_bronze_data(engine, limit=limit)
        
        if df_bronze.empty:
            logger.warning("⚠️  No data in bronze layer!")
            return False
        
        # 3. EDA
        df_with_eda = perform_eda(df_bronze)
        
        # 4. Cleaning (inclut l'ajout de predicted_category)
        df_cleaned = clean_silver_data(df_with_eda)
        
        if df_cleaned.empty:
            logger.error("❌ No data remaining after cleaning!")
            return False
        
        # 5. Créer Silver layer
        silver_df = create_silver_layer(df_cleaned)
        
        # 6. Charger dans Silver
        logger.info("\n💾 Loading to Silver layer...")
        tables = {"cve_cleaned": silver_df}
        success = load_silver_layer(tables, engine, if_exists=if_exists)
        
        if success:
            logger.info("\n" + "=" * 72)
            logger.info("🎉 PIPELINE COMPLETED SUCCESSFULLY")
            logger.info("=" * 72)
        else:
            logger.error("\n❌ Pipeline failed during load")
        
        return success
        
    except Exception as e:
        logger.error(f"❌ Pipeline failed with error: {e}", exc_info=True)
        return False

# -------------------------------------------------------------------
# CLI
# -------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="Bronze ➜ Silver: EDA & Data Cleaning Pipeline"
    )
    parser.add_argument(
        '--limit', 
        type=int, 
        default=None,
        help='Limit number of rows to process (for testing)'
    )
    parser.add_argument(
        '--if-exists',
        choices=['append', 'replace'],
        default='replace',
        help='How to handle existing data in silver layer'
    )
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    print(f"\n🚀 Running {Path(__file__).name}")
    print(f"   Limit: {args.limit or 'None (all data)'}")
    print(f"   Mode: {args.if_exists}\n")
    
    success = run_eda_to_silver(limit=args.limit, if_exists=args.if_exists)
    sys.exit(0 if success else 1)