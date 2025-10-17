#!/usr/bin/env python3
"""
SILVER ➜ GOLD TRANSFORMATION
- Modélisation en étoile (Star Schema)
- Extraction des métriques CVSS depuis les vecteurs
- Création des dimensions: dim_cve, dim_products, dim_cvss_source
- Création des faits: cvss_v2, cvss_v3, cvss_v4
- Création du bridge: bridge_cve_products
"""

from pathlib import Path
import sys
sys.path.append(str(Path(__file__).resolve().parents[2]))

import argparse
import logging
from typing import Optional, Dict, Any
import json
import pandas as pd
from sqlalchemy.engine import Engine

from database.connection import create_db_engine, get_schema_name
from batch.load.load_gold_layer import load_gold_layer
from utils.cvss_parser import CVSSVectorParser

# -------------------------------------------------------------------
# Logging
# -------------------------------------------------------------------
LOGS_DIR = Path(__file__).resolve().parents[3] / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOGS_DIR / "transformation_to_gold.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("transformation_to_gold")

pd.set_option("display.max_columns", None)
pd.set_option("display.float_format", "{:.2f}".format)

# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------
def _safe_json_load(x):
    """Charge du JSON de manière sécurisée"""
    try:
        if isinstance(x, str):
            x = x.strip()
            if x and x not in ('null', 'none', 'nan', ''):
                return json.loads(x)
        elif isinstance(x, (list, dict)):
            return x
    except:
        pass
    return None

def _is_empty_json_like(x) -> bool:
    """Vérifie si une valeur est vide/None de manière sécurisée"""
    try:
        # None
        if x is None:
            return True
        
        # NaN (float)
        import numpy as np
        if isinstance(x, float) and np.isnan(x):
            return True
        
        # Numpy array vide
        if isinstance(x, np.ndarray):
            return x.size == 0
        
        # String vide ou null-like
        if isinstance(x, str):
            s = x.strip().lower()
            return s in ("", "[]", "null", "none", "nan")
        
        # Collections vides
        if isinstance(x, (list, tuple, dict)):
            return len(x) == 0
        
        return False
    except:
        # En cas d'erreur, considérer comme vide
        return True

# -------------------------------------------------------------------
# Load Silver Data
# -------------------------------------------------------------------
def load_silver_data(engine: Engine, limit: Optional[int] = None) -> pd.DataFrame:
    logger.info("=" * 72)
    logger.info("📥 LOADING SILVER DATA")
    logger.info("=" * 72)
    
    silver_schema = get_schema_name("silver")
    
    if limit:
        query = f"""
            SELECT *
            FROM {silver_schema}.cve_cleaned
            ORDER BY published_date DESC
            LIMIT {int(limit)}
        """
    else:
        query = f"SELECT * FROM {silver_schema}.cve_cleaned;"
    
    df = pd.read_sql(query, engine)
    logger.info(f"✅ Loaded {len(df):,} rows from silver layer")
    
    return df

# -------------------------------------------------------------------
# DIMENSION: dim_cve
# -------------------------------------------------------------------
def create_dim_cve(df: pd.DataFrame) -> pd.DataFrame:
    logger.info("🔨 Building dimension: dim_cve...")
    
    columns = [
        'cve_id', 'title', 'description', 'category',
        'published_date', 'last_modified', 'loaded_at',
        'remotely_exploit', 'source_identifier'
    ]
    
    # S'assurer que les colonnes existent
    for col in columns:
        if col not in df.columns:
            df[col] = None
    
    # Agréger par CVE (au cas où il y aurait des doublons)
    dim_cve = df.groupby('cve_id', as_index=False).agg({
        'title': 'first',
        'description': 'first',
        'category': 'first',
        'published_date': 'first',
        'last_modified': 'max',
        'loaded_at': 'max',
        'remotely_exploit': 'first',
        'source_identifier': 'first'
    })
    
    logger.info(f"✅ dim_cve: {len(dim_cve):,} unique CVEs")
    
    return dim_cve

# -------------------------------------------------------------------
# CVSS Version Info
# -------------------------------------------------------------------
def get_version_info(version_str: str | None):
    """Détermine la version CVSS et retourne (key, label)"""
    if version_str == "CVSS 2.0": 
        return "v2", "CVSS 2.0"
    if version_str == "CVSS 3.0": 
        return "v3", "CVSS 3.0"
    if version_str == "CVSS 3.1": 
        return "v3", "CVSS 3.1"
    if version_str == "CVSS 4.0": 
        return "v4", "CVSS 4.0"
    return None, None

# -------------------------------------------------------------------
# FACTS: cvss_v2, cvss_v3, cvss_v4
# -------------------------------------------------------------------
def create_cvss_facts(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    logger.info("🔨 Building CVSS facts with vector extraction...")
    
    records_v2 = []
    records_v3 = []
    records_v4 = []
    
    for _, row in df.iterrows():
        cve_id = row['cve_id']
        scores = _safe_json_load(row.get('cvss_scores'))
        
        if _is_empty_json_like(scores):
            continue
        
        # S'assurer que scores est une liste
        if isinstance(scores, dict):
            scores = [scores]
        
        for score_entry in scores:
            if not isinstance(score_entry, dict):
                continue
            
            version = score_entry.get('version')
            version_key, version_label = get_version_info(version)
            
            if not version_key:
                continue
            
            source = score_entry.get('source_identifier') or score_entry.get('source') or 'unknown'
            vector = score_entry.get('vector') or ''
            score = score_entry.get('score')
            severity = score_entry.get('severity')
            exploitability = score_entry.get('exploitability_score')
            impact = score_entry.get('impact_score')
            
            # Parser le vecteur CVSS pour extraire les métriques
            if version_key == 'v2':
                metrics = CVSSVectorParser.parse_vector(vector, 'v2')
                records_v2.append({
                    'cve_id': cve_id,
                    'cvss_source': source,
                    'cvss_score': score,
                    'cvss_severity': severity,
                    'cvss_vector': vector,
                    'cvss_v2_av': metrics.get('cvss_v2_av'),
                    'cvss_v2_ac': metrics.get('cvss_v2_ac'),
                    'cvss_v2_au': metrics.get('cvss_v2_au'),
                    'cvss_v2_c': metrics.get('cvss_v2_c'),
                    'cvss_v2_i': metrics.get('cvss_v2_i'),
                    'cvss_v2_a': metrics.get('cvss_v2_a'),
                    'cvss_exploitability_score': exploitability,
                    'cvss_impact_score': impact,
                })
            
            elif version_key == 'v3':
                metrics = CVSSVectorParser.parse_vector(vector, 'v3')
                records_v3.append({
                    'cve_id': cve_id,
                    'cvss_source': source,
                    'cvss_version': version_label,
                    'cvss_score': score,
                    'cvss_severity': severity,
                    'cvss_vector': vector,
                    'cvss_v3_base_av': metrics.get('cvss_v3_base_av'),
                    'cvss_v3_base_ac': metrics.get('cvss_v3_base_ac'),
                    'cvss_v3_base_pr': metrics.get('cvss_v3_base_pr'),
                    'cvss_v3_base_ui': metrics.get('cvss_v3_base_ui'),
                    'cvss_v3_base_s': metrics.get('cvss_v3_base_s'),
                    'cvss_v3_base_c': metrics.get('cvss_v3_base_c'),
                    'cvss_v3_base_i': metrics.get('cvss_v3_base_i'),
                    'cvss_v3_base_a': metrics.get('cvss_v3_base_a'),
                    'cvss_exploitability_score': exploitability,
                    'cvss_impact_score': impact,
                })
            
            elif version_key == 'v4':
                metrics = CVSSVectorParser.parse_vector(vector, 'v4')
                records_v4.append({
                    'cve_id': cve_id,
                    'cvss_source': source,
                    'cvss_score': score,
                    'cvss_severity': severity,
                    'cvss_vector': vector,
                    'cvss_v4_av': metrics.get('cvss_v4_av'),
                    'cvss_v4_at': metrics.get('cvss_v4_at'),
                    'cvss_v4_ac': metrics.get('cvss_v4_ac'),
                    'cvss_v4_vc': metrics.get('cvss_v4_vc'),
                    'cvss_v4_vi': metrics.get('cvss_v4_vi'),
                    'cvss_v4_va': metrics.get('cvss_v4_va'),
                    'cvss_v4_sc': metrics.get('cvss_v4_sc'),
                    'cvss_v4_si': metrics.get('cvss_v4_si'),
                    'cvss_v4_sa': metrics.get('cvss_v4_sa'),
                })
    
    # Créer les DataFrames
    cvss_v2 = pd.DataFrame(records_v2)
    cvss_v3 = pd.DataFrame(records_v3)
    cvss_v4 = pd.DataFrame(records_v4)
    
    # Convertir les scores en numérique
    for df_cvss in [cvss_v2, cvss_v3, cvss_v4]:
        if not df_cvss.empty and 'cvss_score' in df_cvss.columns:
            df_cvss['cvss_score'] = pd.to_numeric(df_cvss['cvss_score'], errors='coerce')
            
            for col in ['cvss_exploitability_score', 'cvss_impact_score']:
                if col in df_cvss.columns:
                    df_cvss[col] = pd.to_numeric(df_cvss[col], errors='coerce')
    
    logger.info(f"✅ CVSS Facts:")
    logger.info(f"   - cvss_v2: {len(cvss_v2):,} records")
    logger.info(f"   - cvss_v3: {len(cvss_v3):,} records")
    logger.info(f"   - cvss_v4: {len(cvss_v4):,} records")
    
    return cvss_v2, cvss_v3, cvss_v4

# -------------------------------------------------------------------
# DIMENSION: dim_products + BRIDGE: bridge_cve_products
# -------------------------------------------------------------------
def create_products_and_bridge(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    logger.info("🔨 Building dim_products + bridge_cve_products...")
    
    products_dict: Dict[tuple, Dict[str, Any]] = {}
    bridge_records = []
    
    for _, row in df.iterrows():
        cve_id = row['cve_id']
        published_date = row['published_date']
        products = _safe_json_load(row.get('affected_products'))
        
        if _is_empty_json_like(products):
            continue
        
        # S'assurer que products est une liste
        if isinstance(products, dict):
            products = [products]
        
        for prod in products:
            if not isinstance(prod, dict):
                continue
            
            vendor = (prod.get('vendor') or '').strip()
            product = (prod.get('product') or '').strip()
            
            if not vendor or not product:
                continue
            
            # Clé unique: (vendor_lower, product_lower)
            key = (vendor.lower(), product.lower())
            
            # Ajouter au dictionnaire des produits
            if key not in products_dict:
                products_dict[key] = {
                    'vendor': vendor,
                    'product_name': product,
                    'cve_count': 0
                }
            
            products_dict[key]['cve_count'] += 1
            
            # Ajouter au bridge
            bridge_records.append({
                'vendor_key': key[0],
                'product_key': key[1],
                'cve_id': cve_id,
                'published_date': published_date
            })
    
    # Créer dim_products
    if not products_dict:
        dim_products = pd.DataFrame(columns=[
            'product_id', 'vendor', 'product_name', 'total_cves',
            'first_cve_date', 'last_cve_date'
        ])
        bridge = pd.DataFrame(columns=['cve_id', 'product_id'])
        logger.info("✅ dim_products: 0 products")
        logger.info("✅ bridge_cve_products: 0 records")
        return dim_products, bridge
    
    # Créer le DataFrame des produits avec IDs
    dim_products = pd.DataFrame([
        {
            'product_id': i,
            'vendor': d['vendor'],
            'product_name': d['product_name'],
            'total_cves': d['cve_count']
        }
        for i, (_, d) in enumerate(products_dict.items(), start=1)
    ])
    
    # Créer le bridge avec product_id
    bridge_df = pd.DataFrame(bridge_records)
    
    # Lookup table pour associer les clés aux product_id
    lookup = {
        (r['vendor'].lower(), r['product_name'].lower()): r['product_id']
        for _, r in dim_products.iterrows()
    }
    
    bridge_df['product_id'] = bridge_df.apply(
        lambda x: lookup.get((x['vendor_key'], x['product_key'])),
        axis=1
    )
    
    # Calculer first_cve_date et last_cve_date par produit
    stats = bridge_df.groupby('product_id')['published_date'].agg([
        ('first_cve_date', 'min'),
        ('last_cve_date', 'max')
    ]).reset_index()
    
    # Merger avec dim_products
    dim_products = dim_products.merge(stats, on='product_id', how='left')
    
    # Créer le bridge final
    bridge = bridge_df[['cve_id', 'product_id']].dropna().drop_duplicates().reset_index(drop=True)
    
    logger.info(f"✅ dim_products: {len(dim_products):,} unique products")
    logger.info(f"✅ bridge_cve_products: {len(bridge):,} CVE-Product relationships")
    
    return dim_products, bridge

# -------------------------------------------------------------------
# Main Transformation Pipeline
# -------------------------------------------------------------------
def transform_silver_to_gold(df_silver: pd.DataFrame) -> Dict[str, pd.DataFrame]:
    logger.info("=" * 72)
    logger.info("🚀 SILVER ➜ GOLD TRANSFORMATION (STAR SCHEMA)")
    logger.info("=" * 72)
    
    # 1. Dimensions
    dim_cve = create_dim_cve(df_silver)
    dim_products, bridge_cve_products = create_products_and_bridge(df_silver)
    
    # 2. Facts (CVSS)
    cvss_v2, cvss_v3, cvss_v4 = create_cvss_facts(df_silver)
    
    # 3. Préparer le dictionnaire de tables
    gold_tables = {
        'dim_cve': dim_cve,
        'cvss_v2': cvss_v2,
        'cvss_v3': cvss_v3,
        'cvss_v4': cvss_v4,
        'dim_products': dim_products,
        'bridge_cve_products': bridge_cve_products,
    }
    
    # 4. Afficher les statistiques
    logger.info("\n" + "=" * 72)
    logger.info("📊 GOLD LAYER STATISTICS")
    logger.info("=" * 72)
    
    for table_name, df_table in gold_tables.items():
        if df_table.empty:
            logger.info(f"🔹 {table_name}: 0 rows")
        else:
            mem = df_table.memory_usage(deep=True).sum() / 1024**2
            logger.info(f"🔹 {table_name}: {len(df_table):,} rows | {len(df_table.columns)} cols | {mem:.2f} MB")
    
    logger.info("=" * 72)
    logger.info("✅ Transformation complete")
    
    return gold_tables

# -------------------------------------------------------------------
# Main Pipeline Runner
# -------------------------------------------------------------------
def run_silver_to_gold(limit: Optional[int] = None, if_exists: str = 'replace') -> bool:
    """
    Pipeline complet: Silver → Transformation → Gold
    """
    logger.info("=" * 72)
    logger.info("🚀 SILVER ➜ GOLD PIPELINE")
    logger.info("=" * 72)
    
    try:
        # 1. Connexion DB
        engine = create_db_engine()
        
        # 2. Charger Silver
        df_silver = load_silver_data(engine, limit=limit)
        
        if df_silver.empty:
            logger.warning("⚠️  No data in silver layer!")
            return False
        
        # 3. Transformer en modèle en étoile
        gold_tables = transform_silver_to_gold(df_silver)
        
        # 4. Charger dans Gold
        logger.info("\n💾 Loading to Gold layer...")
        success = load_gold_layer(gold_tables, engine, if_exists=if_exists)
        
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
        description="Silver ➜ Gold: Star Schema Transformation Pipeline"
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
        help='How to handle existing data in gold layer'
    )
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    print(f"\n🚀 Running {Path(__file__).name}")
    print(f"   Limit: {args.limit or 'None (all data)'}")
    print(f"   Mode: {args.if_exists}\n")
    
    success = run_silver_to_gold(limit=args.limit, if_exists=args.if_exists)
    sys.exit(0 if success else 1)