# ============================================================================
# LOAD SILVER LAYER TO POSTGRESQL
# ============================================================================
# Description: Loads transformed Silver layer tables from bronze to silver schema
# Author: Data Engineering Team
# Date: 2025-10-14
# ============================================================================

from pathlib import Path
import logging
from datetime import datetime

import numpy as np
import pandas as pd
from sqlalchemy import create_engine, text

# ----------------------------------------------------------------------------
# Logging (write to project_root/logs/load_silver.log)
# ----------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[3]   # .../threat-intelligence-pipeline
LOGS_DIR = PROJECT_ROOT / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOGS_DIR / "load_silver.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------------
# DB connection
# ----------------------------------------------------------------------------
def create_db_engine():
    """Create PostgreSQL engine"""
    DB_CONFIG = {
        "user": "postgres",
        "password": "tip_pwd",
        "host": "localhost",
        "port": "5432",
        "database": "tip",
    }
    try:
        engine = create_engine(
            f"postgresql+psycopg2://{DB_CONFIG['user']}:{DB_CONFIG['password']}"
            f"@{DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['database']}"
        )
        logger.info("✅ Database connection established")
        return engine
    except Exception as e:
        logger.error(f"❌ Failed to connect to database: {e}")
        raise

# ----------------------------------------------------------------------------
# Schema validation
# ----------------------------------------------------------------------------
def verify_silver_schema(engine):
    """Verify that silver schema and tables exist"""
    logger.info("🔍 Verifying silver schema...")

    with engine.connect() as conn:
        # schema
        result = conn.execute(text("""
            SELECT schema_name 
            FROM information_schema.schemata 
            WHERE schema_name = 'silver'
        """))
        if not result.fetchone():
            logger.error("❌ Silver schema does not exist! Run silver.sql first.")
            return False

        # tables
        expected = {'dim_cve', 'fact_cvss_scores', 'dim_products', 'bridge_cve_products'}
        result = conn.execute(text("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'silver'
        """))
        existing = {r[0] for r in result.fetchall()}
        missing = expected - existing
        if missing:
            logger.error(f"❌ Missing tables in silver schema: {sorted(missing)}")
            return False

    logger.info("✅ Silver schema validated")
    return True

# ----------------------------------------------------------------------------
# Dependency-safe reset (no DROP)
# ----------------------------------------------------------------------------
def reset_silver_tables(engine):
    """
    Truncate all Silver tables in dependency-safe order (no DROP).
    Resets identity sequences, avoids FK/MV dependency errors.
    """
    with engine.begin() as conn:
        conn.execute(text("""
            TRUNCATE TABLE
                silver.bridge_cve_products,
                silver.fact_cvss_scores,
                silver.dim_products,
                silver.dim_cve
            RESTART IDENTITY;
        """))

# ----------------------------------------------------------------------------
# Sanitizer (avoid non-scalar / NaN issues)
# ----------------------------------------------------------------------------
def _clean_for_sql(df: pd.DataFrame) -> pd.DataFrame:
    """Ensure only Python scalars reach the DB driver."""
    df = df.replace({np.nan: None})
    # force object cols to generic Python objects (prevents numpy dtypes leaking)
    for col in df.select_dtypes(include=['object']).columns:
        df[col] = df[col].astype(object)
    return df

# ----------------------------------------------------------------------------
# Loaders
# ----------------------------------------------------------------------------
def load_dim_cve(df, engine, if_exists='append'):
    logger.info("📥 Loading dim_cve...")
    try:
        df_load = df[[
            'cve_id', 'title', 'description', 'category',
            'published_date', 'last_modified', 'loaded_at',
            'remotely_exploit'
        ]].copy()

        df_load['published_date'] = pd.to_datetime(df_load['published_date'])
        df_load['last_modified']  = pd.to_datetime(df_load['last_modified'])
        df_load['loaded_at']      = pd.to_datetime(df_load['loaded_at'])
        df_load['remotely_exploit'] = df_load['remotely_exploit'].astype(bool)

        df_load = _clean_for_sql(df_load)

        df_load.to_sql(
            'dim_cve', engine, schema='silver',
            if_exists=if_exists, index=False, method='multi', chunksize=500
        )
        logger.info(f"✅ dim_cve loaded: {len(df_load):,} rows")
        return True
    except Exception as e:
        logger.error(f"❌ Failed to load dim_cve: {e}")
        return False

def load_fact_cvss_scores(df, engine, if_exists='append'):
    logger.info("📥 Loading fact_cvss_scores...")
    try:
        # keep all columns except the autoincrement/local id
        cols = [c for c in df.columns if c != 'cvss_score_id']
        df_load = df[cols].copy()

        # normalize numbers
        for col in ['cvss_score', 'cvss_exploitability_score', 'cvss_impact_score']:
            if col in df_load.columns:
                df_load[col] = pd.to_numeric(df_load[col], errors='coerce')

        # --- DEDUPLICATION on unique key (cve_id, cvss_version) ---
        # Build sort keys for deterministic winner selection:
        # 1) prefer non-null cvss_vector
        # 2) prefer higher cvss_score
        # 3) prefer later last_modified if present
        # 4) stable tie-breaker on cve_id, cvss_version
        
        sort_cols = []
        ascending_flags = []
        
        # Sort key 1: cvss_vector presence (True = has vector, should come last)
        if 'cvss_vector' in df_load.columns:
            df_load['_sort_vector'] = df_load['cvss_vector'].notna()
            sort_cols.append('_sort_vector')
            ascending_flags.append(True)  # False < True, so True (has vector) comes last
        
        # Sort key 2: cvss_score (higher is better, should come last)
        if 'cvss_score' in df_load.columns:
            df_load['_sort_score'] = df_load['cvss_score'].fillna(-1)
            sort_cols.append('_sort_score')
            ascending_flags.append(True)  # Higher scores come last
        
        # Sort key 3: last_modified (later is better, should come last)
        if 'last_modified' in df_load.columns:
            df_load['_sort_modified'] = pd.to_datetime(df_load['last_modified'], errors='coerce')
            sort_cols.append('_sort_modified')
            ascending_flags.append(True)  # Later dates come last
        
        # Stable tie-breakers
        sort_cols.extend(['cve_id', 'cvss_version'])
        ascending_flags.extend([True, True])  # Alphabetical order
        
        # Sort with matching ascending list
        df_load = df_load.sort_values(by=sort_cols, ascending=ascending_flags)
        
        # Remove duplicates, keeping the last (best) row
        before = len(df_load)
        df_load = df_load.drop_duplicates(subset=['cve_id', 'cvss_version'], keep='last')
        dropped = before - len(df_load)
        
        if dropped > 0:
            logger.warning(f"   ⚠ Dropped {dropped:,} duplicate (cve_id, cvss_version) rows to satisfy uk_fact_cvss_cve_version")
            
            # Show top offending CVEs for debugging
            dup_keys = (df[cols]
                        .groupby(['cve_id','cvss_version'], dropna=False)
                        .size().reset_index(name='n')).query('n > 1').sort_values('n', ascending=False)
            if len(dup_keys) > 0:
                sample = dup_keys.head(5).to_dict(orient='records')
                logger.warning(f"   ↪ Examples of duplicates: {sample}")
        
        # Clean helper columns
        helper_cols = [c for c in df_load.columns if c.startswith('_sort_')]
        df_load = df_load.drop(columns=helper_cols, errors='ignore')
        
        # Clean for SQL
        df_load = _clean_for_sql(df_load)
        
        # Write to database
        df_load.to_sql(
            'fact_cvss_scores', engine, schema='silver',
            if_exists=if_exists, index=False, method='multi', chunksize=1000
        )
        logger.info(f"✅ fact_cvss_scores loaded: {len(df_load):,} rows (deduped from {before:,})")
        return True
        
    except Exception as e:
        logger.error(f"❌ Failed to load fact_cvss_scores: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False
    
    
def load_dim_products(df, engine, if_exists='append'):
    logger.info("📥 Loading dim_products...")
    try:
        df_load = df[['vendor', 'product_name', 'total_cves',
                      'first_cve_date', 'last_cve_date']].copy()

        df_load['first_cve_date'] = pd.to_datetime(df_load['first_cve_date'])
        df_load['last_cve_date']  = pd.to_datetime(df_load['last_cve_date'])

        df_load = _clean_for_sql(df_load)

        df_load.to_sql(
            'dim_products', engine, schema='silver',
            if_exists=if_exists, index=False, method='multi', chunksize=500
        )
        logger.info(f"✅ dim_products loaded: {len(df_load):,} rows")
        return True
    except Exception as e:
        logger.error(f"❌ Failed to load dim_products: {e}")
        return False

def load_bridge_cve_products(df, engine, if_exists='append'):
    logger.info("📥 Loading bridge_cve_products...")
    try:
        df_load = df[['cve_id', 'product_id']].drop_duplicates().copy()
        df_load = _clean_for_sql(df_load)

        df_load.to_sql(
            'bridge_cve_products', engine, schema='silver',
            if_exists=if_exists, index=False, method='multi', chunksize=1000
        )
        logger.info(f"✅ bridge_cve_products loaded: {len(df_load):,} rows")
        return True
    except Exception as e:
        logger.error(f"❌ Failed to load bridge_cve_products: {e}")
        return False

# ----------------------------------------------------------------------------
# Orchestrator
# ----------------------------------------------------------------------------
def load_silver_layer(silver_tables, engine, if_exists='append'):
    """
    Load all Silver layer tables to PostgreSQL.
    silver_tables: dict with keys 'dim_cve', 'fact_cvss_scores', 'dim_products', 'bridge_cve_products'
    """
    logger.info("=" * 70)
    logger.info("🚀 STARTING SILVER LAYER LOAD")
    logger.info("=" * 70)

    start = datetime.now()

    # Validate schema
    if not verify_silver_schema(engine):
        return False

    # If caller asked 'replace', do TRUNCATE+APPEND instead of DROP
    if if_exists == 'replace':
        logger.info("🧨 'replace' detected → TRUNCATE + APPEND (no DROP)")
        reset_silver_tables(engine)
        if_exists = 'append'

    success = True
    # Load in FK-safe order: dims → fact → bridge
    success &= load_dim_cve(silver_tables['dim_cve'], engine, if_exists)
    success &= load_dim_products(silver_tables['dim_products'], engine, if_exists)
    success &= load_fact_cvss_scores(silver_tables['fact_cvss_scores'], engine, if_exists)
    success &= load_bridge_cve_products(silver_tables['bridge_cve_products'], engine, if_exists)

    if success:
        with engine.connect() as conn:
            logger.info("\n" + "=" * 70)
            logger.info("📊 LOADING STATISTICS")
            logger.info("=" * 70)
            for table in ['dim_cve', 'fact_cvss_scores', 'dim_products', 'bridge_cve_products']:
                row = conn.execute(text(f"""
                    SELECT 
                        COUNT(*) AS row_count,
                        pg_size_pretty(pg_total_relation_size('silver.{table}')) AS size
                    FROM silver.{table}
                """)).fetchone()
                logger.info(f"\n🔹 {table.upper()}")
                logger.info(f"   Rows: {row[0]:,}")
                logger.info(f"   Size: {row[1]}")

    dur = (datetime.now() - start).total_seconds()
    logger.info("\n" + "=" * 70)
    logger.info(("✅ LOADING COMPLETED SUCCESSFULLY" if success else "❌ LOADING FAILED")
                + f" in {dur:.2f}s")
    logger.info("=" * 70)
    return success

# ----------------------------------------------------------------------------
# Refresh MVs
# ----------------------------------------------------------------------------
def refresh_materialized_views(engine):
    """Refresh all materialized views in silver schema"""
    logger.info("\n🔄 Refreshing materialized views...")
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT silver.refresh_all_mv()"))
            conn.commit()
        logger.info("✅ Materialized views refreshed")
        return True
    except Exception as e:
        logger.error(f"❌ Failed to refresh materialized views: {e}")
        return False

# ----------------------------------------------------------------------------
# CLI usage hint
# ----------------------------------------------------------------------------
if __name__ == "__main__":
    logger.info("💡 Import this module and call its functions from your transform script.")
    logger.info("   Example:")
    logger.info("     from tip.load.load_silver_layer import create_db_engine, load_silver_layer, refresh_materialized_views")
