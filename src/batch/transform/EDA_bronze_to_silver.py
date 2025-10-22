#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BRONZE ➜ SILVER: EDA & CLEANING (1 seule colonne de classe: vulnarbilit)
- Charge depuis raw.cve_details
- EDA (overview, missing, duplicates, dates, CVSS, produits, catégories)
- Nettoyage / standardisation
- Mappe le CWE brut (bronze.category) -> classe normalisée 'vulnarbilit'
- Sortie (pas de title/description/url/predicted_category):
    cve_id, vulnarbilit, published_date, last_modified, loaded_at,
    remotely_exploit, source_identifier, affected_products, cvss_scores
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
import re

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

def _parse_date_safe(v):
    """Parse date with fallback to fuzzy parsing."""
    if pd.isna(v):
        return pd.NaT
    for fuzzy in (False, True):
        try:
            return parser.parse(str(v), fuzzy=fuzzy)
        except Exception:
            pass
    return pd.NaT

# -------------------------------------------------------------------
# CWE -> classe 'vulnarbilit'
# -------------------------------------------------------------------
_INJECTION = {74,77,78,88,89,90,91,93,94,95,96,97,98,113,470,471,643,917,943}
_XSS = {79,80,83,84,86,91}
_PATH_TRAVERSAL = {22,23,35,36,73}
_OPEN_REDIRECT = {601}
_XML_XXE = {611}
_SSRF = {918}
_DESERIALIZATION = {502}
_AUTHN_AUTHZ = {287,306,352,863,285,284,269,264,732,276,620,798,862}
_INFO_DISCLOSURE = {200,209,319,532}
_CRYPTO = {310,326,327,331,338,759,760}
_RACE_CONDITION = {362,367}
_RESOURCE_MGMT_DOS = {399,400,401,404,674,770,772,775,776,778,779,835}
_CODE_EXECUTION = {94,502,119,120,121,122,787,88,78}
_MEMORY = {
    119,120,121,122,123,124,125,126,127,128,129,
    131,134,170,187,190,191,192,193,194,195,196,
    362,364,369,400,401,404,415,416,476,562,590,
    683,684,686,687,688,691,703,704,705,707,710,
    787,788,789,805,823,825,826,834
}

_RULES = [
    ("xss", _XSS),
    ("sql_injection", {89}),
    ("injection", _INJECTION),
    ("path_traversal", _PATH_TRAVERSAL),
    ("ssrf", _SSRF),
    ("xxe", _XML_XXE),
    ("deserialization", _DESERIALIZATION),
    ("open_redirect", _OPEN_REDIRECT),
    ("authn_authz", _AUTHN_AUTHZ),
    ("information_disclosure", _INFO_DISCLOSURE),
    ("cryptography", _CRYPTO),
    ("race_condition", _RACE_CONDITION),
    ("memory_corruption", _MEMORY),
    ("resource_management_dos", _RESOURCE_MGMT_DOS),
    ("config_permissions", {16,254,255,256,257,258,259,260,276,284,285,732}),
    ("input_validation", {20,116,1190,1284,1285}),
    ("code_execution", _CODE_EXECUTION),
]

def cwe_to_vulnarbilit(cwe_code: str) -> str:
    """
    Map heuristique: 'CWE-xxx' -> classe 'vulnarbilit' (xss, injection, ...)
    """
    if not cwe_code or not isinstance(cwe_code, str):
        return "uncategorized"
    m = re.search(r"CWE-(\d+)", cwe_code)
    if not m:
        return "uncategorized"
    try:
        n = int(m.group(1))
    except Exception:
        return "uncategorized"

    for cls, ids in _RULES:
        if n in ids:
            return cls

    # fallbacks fréquents
    if 119 <= n <= 129:
        return "memory_corruption"
    if n in {131,134,170,187,190,191,192,193,194,195,196,416,476,787,788,789,805,823}:
        return "memory_corruption"

    return "uncategorized"

# -------------------------------------------------------------------
# Bronze Load
# -------------------------------------------------------------------
def load_bronze_data(engine: Engine, limit: Optional[int] = None) -> pd.DataFrame:
    logger.info("=" * 72)
    logger.info("📥 LOADING BRONZE DATA")
    logger.info("=" * 72)

    bronze = get_schema_name("bronze")
    if limit:
        q = f"""
            SELECT *
            FROM {bronze}.cve_details
            ORDER BY published_date DESC NULLS LAST
            LIMIT {int(limit)}
        """
    else:
        q = f"SELECT * FROM {bronze}.cve_details;"
    df = pd.read_sql(q, engine)
    logger.info(f"✅ Loaded {len(df):,} rows from bronze layer")
    logger.info(f"📊 Columns: {list(df.columns)}")
    return df

# -------------------------------------------------------------------
# EDA (préserve toutes les sections d'avant)
# -------------------------------------------------------------------
def perform_eda(df: pd.DataFrame) -> pd.DataFrame:
    logger.info("=" * 72)
    logger.info("🔍 EXPLORATORY DATA ANALYSIS")
    logger.info("=" * 72)

    # Overview
    logger.info(f"\n📊 OVERVIEW:")
    logger.info(f"   Total rows: {len(df):,}")
    logger.info(f"   Total columns: {len(df.columns)}")
    logger.info(f"   Memory usage: {df.memory_usage(deep=True).sum() / 1024**2:.2f} MB")

    # Missing values
    logger.info(f"\n🔎 MISSING VALUES ANALYSIS:")
    missing = df.isnull().sum()
    missing_pct = (missing / len(df) * 100).round(2)
    miss_df = pd.DataFrame({'Missing': missing, 'Percentage': missing_pct}).sort_values('Missing', ascending=False)
    for col, row in miss_df.iterrows():
        if row['Missing'] > 0:
            logger.info(f"   {col}: {row['Missing']:,} ({row['Percentage']:.2f}%)")

    # Duplicates
    logger.info(f"\n🔄 DUPLICATES ANALYSIS:")
    logger.info(f"   Duplicate CVE IDs: {df.duplicated(subset=['cve_id']).sum():,}")

    # Dates
    logger.info(f"\n📅 DATE ANALYSIS:")
    if 'published_date' in df.columns:
        df['published_date_parsed'] = pd.to_datetime(df['published_date'].apply(_parse_date_safe), errors='coerce')
        valid_dates = df['published_date_parsed'].notna().sum()
        logger.info(f"   Valid published dates: {valid_dates:,} / {len(df):,}")
        if valid_dates > 0:
            logger.info(f"   Date range: {df['published_date_parsed'].min()} to {df['published_date_parsed'].max()}")

    # CVSS
    logger.info(f"\n🎯 CVSS SCORES ANALYSIS:")
    if 'cvss_scores' in df.columns:
        has_cvss = ~df['cvss_scores'].apply(_is_empty_json_like)
        logger.info(f"   CVEs with CVSS scores: {has_cvss.sum():,} ({has_cvss.mean()*100:.2f}%)")
        cvss_versions = {'v2': 0, 'v3': 0, 'v4': 0}
        for _, row in df[has_cvss].iterrows():
            scores = _safe_json_load(row['cvss_scores'])
            if isinstance(scores, list):
                for s in scores:
                    if isinstance(s, dict):
                        ver = str(s.get('version', '')).lower()
                        if '2.0' in ver:
                            cvss_versions['v2'] += 1
                        elif '3' in ver:
                            cvss_versions['v3'] += 1
                        elif '4.0' in ver:
                            cvss_versions['v4'] += 1
        logger.info(f"   CVSS v2 entries: {cvss_versions['v2']:,}")
        logger.info(f"   CVSS v3 entries: {cvss_versions['v3']:,}")
        logger.info(f"   CVSS v4 entries: {cvss_versions['v4']:,}")

    # Products
    logger.info(f"\n🏢 AFFECTED PRODUCTS ANALYSIS:")
    if 'affected_products' in df.columns:
        has_products = ~df['affected_products'].apply(_is_empty_json_like)
        logger.info(f"   CVEs with affected products: {has_products.sum():,} ({has_products.mean()*100:.2f}%)")

    # Category (bronze) simple stats pour info
    logger.info(f"\n📑 BRONZE CATEGORY (CWE) SNAPSHOT:")
    if 'category' in df.columns:
        cat_counts = df['category'].fillna('undefined').value_counts()
        logger.info(f"   Total CWE codes: {len(cat_counts)}")
        for cat, count in cat_counts.head(5).items():
            logger.info(f"      - {cat}: {count:,} ({count/len(df)*100:.2f}%)")

    logger.info("\n" + "=" * 72)
    return df

# -------------------------------------------------------------------
# Cleaning
# -------------------------------------------------------------------
def clean_silver_data(df: pd.DataFrame) -> pd.DataFrame:
    logger.info("=" * 72)
    logger.info("🧹 DATA CLEANING")
    logger.info("=" * 72)

    df = df.copy()
    initial_rows = len(df)

    # 1) Drop duplicates
    df = df.drop_duplicates(subset=['cve_id'], keep='first')

    # 2) Parse dates
    for col in ['published_date', 'last_modified']:
        if col in df.columns:
            df[col] = pd.to_datetime(df[col].apply(_parse_date_safe), errors='coerce')

    # 3) loaded_at
    if 'loaded_at' in df.columns:
        df['loaded_at'] = pd.to_datetime(df['loaded_at'], errors='coerce').dt.tz_localize(None)
    else:
        df['loaded_at'] = pd.Timestamp.utcnow().tz_localize(None)

    # 4) Remove rows without critical dates
    df = df.dropna(subset=['published_date', 'last_modified'])

    # 5) Compute 'vulnarbilit' from Bronze 'category' (CWE-xxx)
    if 'category' not in df.columns:
        df['category'] = None
    df['vulnarbilit'] = df['category'].apply(cwe_to_vulnarbilit)

    # 6) Normalize remotely_exploit
    if 'remotely_exploit' in df.columns:
        df['remotely_exploit'] = df['remotely_exploit'].map({
            'Yes !': True, 'Yes': True, 'True': True, True: True,
            'No': False, 'False': False, False: False
        }).astype('boolean')

    # 7) Ensure source_identifier exists
    if 'source_identifier' not in df.columns and 'source' in df.columns:
        df['source_identifier'] = df['source']

    # 8) Keep only rows with CVSS scores
    if 'cvss_scores' in df.columns:
        has_cvss = ~df['cvss_scores'].apply(_is_empty_json_like)
        df = df[has_cvss].copy()

    # Summary
    logger.info(f"\n✅ CLEANING SUMMARY:")
    logger.info(f"   Initial rows: {initial_rows:,}")
    logger.info(f"   Final rows:   {len(df):,}")
    logger.info(f"   Removed:      {initial_rows - len(df):,}")
    logger.info("\n" + "=" * 72)
    return df

# -------------------------------------------------------------------
# Build Silver output (aligné schéma)
# -------------------------------------------------------------------
def create_silver_layer(df: pd.DataFrame) -> pd.DataFrame:
    logger.info("=" * 72)
    logger.info("🏗️  CREATING SILVER LAYER")
    logger.info("=" * 72)

    silver_cols = [
        'cve_id',
        'vulnarbilit',       # unique class
        'published_date',
        'last_modified',
        'loaded_at',
        'remotely_exploit',
        'source_identifier',
        'affected_products', # JSON text
        'cvss_scores',       # JSON text
    ]
    for c in silver_cols:
        if c not in df.columns:
            df[c] = None

    silver_df = df[silver_cols].copy()

    # JSON (list/dict) -> TEXT JSON
    for col in ['affected_products', 'cvss_scores']:
        silver_df[col] = silver_df[col].apply(
            lambda x: json.dumps(x, ensure_ascii=False) if isinstance(x, (list, dict)) else (x if x is not None else None)
        )

    logger.info(f"✅ Silver layer created with {len(silver_df):,} rows")
    logger.info(f"📊 Columns: {list(silver_df.columns)}")
    return silver_df

# -------------------------------------------------------------------
# Pipeline
# -------------------------------------------------------------------
def run_eda_to_silver(limit: Optional[int] = None, if_exists: str = 'replace') -> bool:
    logger.info("=" * 72)
    logger.info("🚀 BRONZE ➜ SILVER PIPELINE (EDA + CLEANING)")
    logger.info("=" * 72)

    try:
        engine = create_db_engine()
        df_bronze = load_bronze_data(engine, limit=limit)
        if df_bronze.empty:
            logger.warning("⚠️  No data in bronze layer!")
            return False

        df_with_eda = perform_eda(df_bronze)
        df_cleaned  = clean_silver_data(df_with_eda)
        if df_cleaned.empty:
            logger.error("❌ No data remaining after cleaning!")
            return False

        silver_df = create_silver_layer(df_cleaned)

        logger.info("\n💾 Loading to Silver layer...")
        ok = load_silver_layer({"cve_cleaned": silver_df}, engine, if_exists=if_exists, convert_jsonb=False)

        if ok:
            logger.info("\n" + "=" * 72)
            logger.info("🎉 PIPELINE COMPLETED SUCCESSFULLY")
            logger.info("=" * 72)
        else:
            logger.error("\n❌ Pipeline failed during load")

        return ok

    except Exception as e:
        logger.error(f"❌ Pipeline failed with error: {e}", exc_info=True)
        return False

# -------------------------------------------------------------------
# CLI
# -------------------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Bronze ➜ Silver: EDA & Cleaning (vulnarbilit)")
    p.add_argument('--limit', type=int, default=None, help='Limit rows (test)')
    p.add_argument('--if-exists', choices=['append', 'replace'], default='replace',
                   help='How to handle existing data in silver layer')
    return p.parse_args()

if __name__ == "__main__":
    args = parse_args()
    print(f"\n🚀 Running {Path(__file__).name}")
    print(f"   Limit: {args.limit or 'None (all data)'}")
    print(f"   Mode:  {args.if_exists}\n")
    ok = run_eda_to_silver(limit=args.limit, if_exists=args.if_exists)
    sys.exit(0 if ok else 1)
