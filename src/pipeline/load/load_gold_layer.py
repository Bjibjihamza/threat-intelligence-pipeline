#!/usr/bin/env python3
# =============================================================================
# src/pipeline/load/load_gold_layer.py
# UNIFIED GOLD LAYER LOADER
# =============================================================================
# Used by both:
#   - batch/transform/transformation_to_gold.py
#   - stream/transform/transformation_to_gold.py
#
# Loads to gold schema:
# - dim_cve, dim_cvss_source, dim_vendor, dim_products
# - cvss_v2, cvss_v3, cvss_v4
# - bridge_cve_products
#
# Mode: APPEND-ONLY (skip existing rows)
# =============================================================================

from pathlib import Path
import sys
import logging
from typing import Dict, Optional, Set
from datetime import datetime

import pandas as pd
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.engine import Engine

# Determine project root dynamically
THIS_FILE = Path(__file__).resolve()
PROJECT_ROOT = THIS_FILE.parents[3]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

from src.database.connection import create_db_engine, get_schema_name

# -------------------------------------------------------------------
# Logging
# -------------------------------------------------------------------
LOGS_DIR = PROJECT_ROOT / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOGS_DIR / "load_gold_unified.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("unified_gold_loader")

# -------------------------------------------------------------------
# Schema Validation
# -------------------------------------------------------------------
def verify_gold_schema(engine: Engine) -> bool:
    """Verify that Gold schema and all required tables exist."""
    schema = get_schema_name("gold")
    required_tables = [
        "dim_cve",
        "dim_cvss_source",
        "dim_vendor",
        "dim_products",
        "cvss_v2",
        "cvss_v3",
        "cvss_v4",
        "bridge_cve_products",
    ]
    
    logger.info(f"🔎 Verifying gold schema '{schema}'...")
    
    try:
        with engine.connect() as conn:
            # Check schema exists
            if not conn.execute(
                text("SELECT 1 FROM information_schema.schemata WHERE schema_name = :s"),
                {"s": schema}
            ).fetchone():
                logger.error(f"❌ Schema '{schema}' does not exist! Run gold.sql first.")
                return False
            
            # Check all tables exist
            for table in required_tables:
                if not conn.execute(
                    text("""
                        SELECT 1 FROM information_schema.tables
                        WHERE table_schema = :s AND table_name = :t
                    """),
                    {"s": schema, "t": table}
                ).fetchone():
                    logger.error(f"❌ Table {schema}.{table} does not exist! Run gold.sql first.")
                    return False
        
        logger.info(f"✅ Gold schema validated ({len(required_tables)} tables)")
        return True
        
    except Exception as e:
        logger.error(f"❌ Schema validation error: {e}")
        return False

# -------------------------------------------------------------------
# dim_cvss_source Loader
# -------------------------------------------------------------------
def load_dim_cvss_source(
    cvss_v2: pd.DataFrame,
    cvss_v3: pd.DataFrame,
    cvss_v4: pd.DataFrame,
    engine: Engine,
    if_exists: str = "append"
) -> Dict[str, int]:
    """
    Load dim_cvss_source and return mapping: source_name -> source_id.
    Append-only: only adds new sources.
    """
    schema = get_schema_name("gold")
    logger.info("🔨 Loading dim_cvss_source (append-only)...")

    # Collect unique sources from all CVSS tables
    sources: Set[str] = set()
    for df in [cvss_v2, cvss_v3, cvss_v4]:
        if not df.empty and "cvss_source" in df.columns:
            vals = (
                df["cvss_source"]
                .dropna()
                .astype(str)
                .str.replace("\xa0", " ", regex=False)
                .str.strip()
                .str[:100]
            )
            sources.update(vals.unique())

    if not sources:
        logger.info("ℹ️  No CVSS sources found")
        return {}

    # Get existing sources
    with engine.connect() as conn:
        existing = {
            row[0] for row in conn.execute(
                text(f"SELECT source_name FROM {schema}.dim_cvss_source")
            )
        }

    # Insert new sources
    new_sources = sorted(s for s in sources if s and s not in existing)
    if new_sources:
        pd.DataFrame({"source_name": new_sources}).to_sql(
            name="dim_cvss_source",
            con=engine,
            schema=schema,
            if_exists="append",
            index=False,
            method="multi",
            chunksize=1000
        )
        logger.info(f"✅ Inserted {len(new_sources):,} new sources")

    # Return complete mapping
    with engine.connect() as conn:
        mapping = {
            row[1]: row[0] for row in conn.execute(
                text(f"SELECT source_id, source_name FROM {schema}.dim_cvss_source")
            )
        }

    logger.info(f"✅ dim_cvss_source total: {len(mapping):,} sources")
    return mapping

# -------------------------------------------------------------------
# Dimension Helpers
# -------------------------------------------------------------------
def _reindex_for_table(df: pd.DataFrame, table_name: str) -> pd.DataFrame:
    """Ensure DataFrame has exact columns expected by table."""
    column_specs = {
        "dim_cve": [
            "cve_id", "vulnarbilit", "published_date", "last_modified",
            "loaded_at", "remotely_exploit", "source_identifier"
        ],
        "dim_vendor": [
            "vendor_id", "vendor_name", "total_products",
            "total_cves", "first_cve_date", "last_cve_date"
        ],
        "dim_products": [
            "product_id", "vendor_id", "product_name",
            "total_cves", "first_cve_date", "last_cve_date"
        ],
    }
    
    cols = column_specs.get(table_name)
    return df.reindex(columns=cols) if cols else df

def _prepare_dim_cve(df: pd.DataFrame) -> pd.DataFrame:
    """Prepare dim_cve with proper types and null handling."""
    df = df.copy()
    
    # CVE ID
    df["cve_id"] = df["cve_id"].astype(str).str.slice(0, 20)
    
    # Vulnerability class
    df["vulnarbilit"] = (
        df["vulnarbilit"]
        .fillna("uncategorized")
        .astype(str)
        .str.slice(0, 50)
    )

    # Dates
    for col in ["published_date", "last_modified", "loaded_at"]:
        df[col] = pd.to_datetime(df[col], errors="coerce")
    
    now = pd.Timestamp.utcnow().tz_localize(None)
    df["published_date"] = df["published_date"].fillna(now)
    df["last_modified"] = df["last_modified"].fillna(df["published_date"])
    df["loaded_at"] = df["loaded_at"].fillna(now)

    # Boolean
    if "remotely_exploit" in df.columns:
        df["remotely_exploit"] = df["remotely_exploit"].astype("boolean")

    # Source identifier
    if "source_identifier" in df.columns:
        df["source_identifier"] = (
            df["source_identifier"]
            .astype(str)
            .str.replace("\xa0", " ", regex=False)
            .str.strip()
        )
    
    return df

# -------------------------------------------------------------------
# Dimension Loader
# -------------------------------------------------------------------
def load_dimension(
    df: pd.DataFrame,
    table_name: str,
    engine: Engine,
    if_exists: str = "append"
) -> int:
    """
    Load dimension table (append-only, skip existing).
    Returns number of rows inserted.
    """
    schema = get_schema_name("gold")
    full_table = f"{schema}.{table_name}"
    
    logger.info(f"🔨 Loading {table_name} (append-only)...")

    if df.empty:
        logger.info(f"ℹ️  No data for {table_name}")
        return 0

    # Prepare data
    if table_name == "dim_cve":
        df = _prepare_dim_cve(df)
    df = _reindex_for_table(df, table_name)

    # Detect primary key column
    if table_name == "dim_cve":
        pk_col = "cve_id"
    elif table_name == "dim_vendor":
        pk_col = "vendor_id"
    elif table_name == "dim_products":
        pk_col = "product_id"
    else:
        pk_col = None

    # Skip existing rows
    if pk_col and pk_col in df.columns:
        ids = df[pk_col].dropna().tolist()
        
        # Build safe IN clause
        if table_name == "dim_cve":
            # String PK
            escaped = ["'" + str(v).replace("'", "''") + "'" for v in ids]
        else:
            # Integer PK
            escaped = [str(int(v)) for v in ids if pd.notna(v)]
        
        if escaped:
            placeholders = ",".join(escaped)
            
            with engine.connect() as conn:
                existing = {
                    row[0] for row in conn.execute(
                        text(f"SELECT {pk_col} FROM {full_table} WHERE {pk_col} IN ({placeholders})")
                    )
                }
            
            df = df[~df[pk_col].isin(existing)].copy()

            if df.empty:
                logger.info(f"✅ All records already exist in {table_name}")
                return 0

    # Insert new rows
    try:
        df.to_sql(
            name=table_name,
            con=engine,
            schema=schema,
            if_exists="append",
            index=False,
            method="multi",
            chunksize=1000
        )
        logger.info(f"✅ {table_name}: {len(df):,} rows inserted")
        return len(df)
        
    except Exception as e:
        logger.error(f"❌ Load error for {table_name}: {e}", exc_info=True)
        return 0

# -------------------------------------------------------------------
# CVSS Fact Loader
# -------------------------------------------------------------------
def load_fact_cvss(
    df: pd.DataFrame,
    table_name: str,
    source_mapping: Dict[str, int],
    engine: Engine,
    if_exists: str = "append"
) -> int:
    """
    Load CVSS fact table (append-only, skip existing).
    Returns number of rows inserted.
    """
    schema = get_schema_name("gold")
    full_table = f"{schema}.{table_name}"
    
    logger.info(f"🔨 Loading {table_name} (append-only)...")

    if df.empty:
        logger.info(f"ℹ️  No data for {table_name}")
        return 0

    df = df.copy()

    # Validate CVE ID
    if "cve_id" in df:
        df = df[df["cve_id"].notna()]
        df["cve_id"] = df["cve_id"].astype(str).str.slice(0, 20)

    # Validate vector
    if "cvss_vector" in df:
        df = df[df["cvss_vector"].astype(str).str.len() > 0]

    # Map source to source_id
    if "cvss_source" in df.columns:
        df["cvss_source"] = (
            df["cvss_source"]
            .astype(str)
            .str.replace("\xa0", " ", regex=False)
            .str.strip()
            .str[:100]
        )
        df["source_id"] = df["cvss_source"].map(source_mapping)
        df = df.drop(columns=["cvss_source"])
        df = df[df["source_id"].notna()]

    if df.empty:
        logger.info(f"ℹ️  No valid rows for {table_name} after mapping")
        return 0

    # Skip existing (composite key: cve_id + source_id + vector)
    df["_key"] = (
        df["cve_id"].astype(str) + "|" +
        df["source_id"].astype(str) + "|" +
        df["cvss_vector"].astype(str)
    )
    
    with engine.connect() as conn:
        existing = {
            row[0] for row in conn.execute(
                text(f"""
                    SELECT cve_id || '|' || source_id::TEXT || '|' || cvss_vector
                    FROM {full_table}
                """)
            )
        }
    
    df = df[~df["_key"].isin(existing)].drop(columns=["_key"])

    if df.empty:
        logger.info(f"✅ All rows already exist in {table_name}")
        return 0

    # Insert new rows
    try:
        df.to_sql(
            name=table_name,
            con=engine,
            schema=schema,
            if_exists="append",
            index=False,
            method="multi",
            chunksize=1000
        )
        logger.info(f"✅ {table_name}: {len(df):,} rows inserted")
        return len(df)
        
    except Exception as e:
        logger.error(f"❌ Load error for {table_name}: {e}", exc_info=True)
        return 0

# -------------------------------------------------------------------
# Bridge Loader
# -------------------------------------------------------------------
def load_bridge(
    df: pd.DataFrame,
    engine: Engine,
    if_exists: str = "append"
) -> int:
    """
    Load bridge_cve_products (append-only, skip existing).
    Returns number of rows inserted.
    """
    schema = get_schema_name("gold")
    table_name = "bridge_cve_products"
    full_table = f"{schema}.{table_name}"
    
    logger.info(f"🔨 Loading {table_name} (append-only)...")

    if df.empty:
        logger.info(f"ℹ️  No data for {table_name}")
        return 0

    # Prepare data
    df = df[["cve_id", "product_id"]].dropna().drop_duplicates()
    df["cve_id"] = df["cve_id"].astype(str).str.slice(0, 20)

    # Skip existing (composite key: cve_id + product_id)
    df["_key"] = df["cve_id"].astype(str) + "|" + df["product_id"].astype(str)
    
    with engine.connect() as conn:
        existing = {
            row[0] for row in conn.execute(
                text(f"SELECT cve_id || '|' || product_id::TEXT FROM {full_table}")
            )
        }
    
    df = df[~df["_key"].isin(existing)].drop(columns=["_key"])

    if df.empty:
        logger.info(f"✅ All relationships already exist in {table_name}")
        return 0

    # Insert new rows
    try:
        df.to_sql(
            name=table_name,
            con=engine,
            schema=schema,
            if_exists="append",
            index=False,
            method="multi",
            chunksize=1000
        )
        logger.info(f"✅ {table_name}: {len(df):,} relationships inserted")
        return len(df)
        
    except Exception as e:
        logger.error(f"❌ Load error for {table_name}: {e}", exc_info=True)
        return 0

# -------------------------------------------------------------------
# Main Orchestrator
# -------------------------------------------------------------------
def load_gold_layer(
    tables: Dict[str, pd.DataFrame],
    engine: Optional[Engine] = None,
    if_exists: str = "append"
) -> bool:
    """
    UNIFIED entry point: Load all Gold tables (append-only, skip duplicates).
    
    Args:
        tables: Dictionary with all Gold tables
        engine: SQLAlchemy engine (creates new if None)
        if_exists: Mode ('append' or 'replace') - always uses append internally
    
    Returns:
        Boolean indicating success
    """
    logger.info("=" * 72)
    logger.info("🎯 UNIFIED GOLD LAYER LOAD PIPELINE")
    logger.info("=" * 72)

    # Validate required tables
    required = [
        "dim_cve", "dim_vendor", "dim_products",
        "cvss_v2", "cvss_v3", "cvss_v4",
        "bridge_cve_products"
    ]
    missing = [t for t in required if t not in tables]
    if missing:
        logger.error(f"❌ Missing required tables: {missing}")
        return False

    try:
        if engine is None:
            engine = create_db_engine()

        if not verify_gold_schema(engine):
            return False

        start_time = datetime.now()

        # 1. Load dim_cvss_source first (needed for mapping)
        source_map = load_dim_cvss_source(
            tables["cvss_v2"],
            tables["cvss_v3"],
            tables["cvss_v4"],
            engine,
            "append"
        )

        # 2. Load dimensions
        stats = {}
        stats["dim_cve"] = load_dimension(
            tables["dim_cve"], "dim_cve", engine, "append"
        )
        stats["dim_vendor"] = load_dimension(
            tables["dim_vendor"], "dim_vendor", engine, "append"
        )
        stats["dim_products"] = load_dimension(
            tables["dim_products"], "dim_products", engine, "append"
        )

        # 3. Load CVSS facts
        stats["cvss_v2"] = load_fact_cvss(
            tables["cvss_v2"], "cvss_v2", source_map, engine, "append"
        )
        stats["cvss_v3"] = load_fact_cvss(
            tables["cvss_v3"], "cvss_v3", source_map, engine, "append"
        )
        stats["cvss_v4"] = load_fact_cvss(
            tables["cvss_v4"], "cvss_v4", source_map, engine, "append"
        )

        # 4. Load bridge
        stats["bridge"] = load_bridge(tables["bridge_cve_products"], engine, "append")

        # 5. Update statistics
        schema = get_schema_name("gold")
        with engine.begin() as conn:
            for table in [
                "dim_cve", "dim_cvss_source", "dim_vendor", "dim_products",
                "cvss_v2", "cvss_v3", "cvss_v4", "bridge_cve_products"
            ]:
                conn.execute(text(f"ANALYZE {schema}.{table};"))

        duration = (datetime.now() - start_time).total_seconds()

        # Summary
        logger.info("\n" + "=" * 72)
        logger.info("📊 GOLD LOAD STATISTICS")
        logger.info("=" * 72)
        logger.info(f"✅ dim_cve:        {stats['dim_cve']:,} rows")
        logger.info(f"✅ dim_vendor:     {stats['dim_vendor']:,} rows")
        logger.info(f"✅ dim_products:   {stats['dim_products']:,} rows")
        logger.info(f"✅ cvss_v2:        {stats['cvss_v2']:,} rows")
        logger.info(f"✅ cvss_v3:        {stats['cvss_v3']:,} rows")
        logger.info(f"✅ cvss_v4:        {stats['cvss_v4']:,} rows")
        logger.info(f"✅ bridge:         {stats['bridge']:,} relationships")
        logger.info(f"⏱️  Duration:       {duration:.2f}s")
        logger.info("=" * 72)
        logger.info("🎉 UNIFIED GOLD LAYER LOAD COMPLETED")
        logger.info("=" * 72)

        return True

    except Exception as e:
        logger.error(f"❌ Gold layer load failed: {e}", exc_info=True)
        return False

# -------------------------------------------------------------------
# CLI Helper (for testing)
# -------------------------------------------------------------------
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Load data to Gold layer (unified loader, append-only)"
    )
    parser.add_argument(
        '--test',
        action='store_true',
        help='Run test mode'
    )
    args = parser.parse_args()
    
    if args.test:
        logger.info("🧪 Test mode: This module is meant to be imported by transformation scripts")
        logger.info("💡 Usage: from src.pipeline.load.load_gold_layer import load_gold_layer")
    else:
        logger.info("💡 This module is intended to be imported, not run directly")
        logger.info("💡 Import: from src.pipeline.load.load_gold_layer import load_gold_layer")