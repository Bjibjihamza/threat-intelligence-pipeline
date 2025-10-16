# ============================================================================
# LOAD SILVER LAYER TO POSTGRESQL (V2.1 - With dim_cvss_source + source_identifier)
# - dim_cve includes source_identifier (top-level CVE origin, kept from Bronze)
# - fact_cvss_scores uses FK to dim_cvss_source (cvss_source from JSON)
# ============================================================================

from pathlib import Path
import logging
from datetime import datetime

import numpy as np
import pandas as pd
from sqlalchemy import create_engine, text

# Logging
PROJECT_ROOT = Path(__file__).resolve().parents[3]
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

# ============================================================================
# DB CONNECTION
# ============================================================================
def create_db_engine():
    DB_CONFIG = {"user":"postgres","password":"tip_pwd","host":"localhost","port":"5432","database":"tip"}
    engine = create_engine(
        f"postgresql+psycopg2://{DB_CONFIG['user']}:{DB_CONFIG['password']}"
        f"@{DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['database']}"
    )
    logger.info("✅ Database connection established")
    return engine

# ============================================================================
# SCHEMA VALIDATION
# ============================================================================
def verify_silver_schema(engine):
    logger.info("🔍 Verifying silver schema...")
    with engine.connect() as conn:
        if not conn.execute(text("SELECT 1 FROM information_schema.schemata WHERE schema_name='silver'")).fetchone():
            logger.error("❌ Silver schema does not exist! Run silver_v2.sql first.")
            return False
        expected = {'dim_cve','dim_cvss_source','fact_cvss_scores','dim_products','bridge_cve_products'}
        existing = {r[0] for r in conn.execute(text(
            "SELECT table_name FROM information_schema.tables WHERE table_schema='silver'"
        ))}
        missing = expected - existing
        if missing:
            logger.error(f"❌ Missing tables: {sorted(missing)}")
            return False
    logger.info("✅ Silver schema validated")
    return True

# ============================================================================
# RESET TABLES
# ============================================================================
def reset_silver_tables(engine):
    with engine.begin() as conn:
        conn.execute(text("""
            TRUNCATE TABLE
                silver.bridge_cve_products,
                silver.fact_cvss_scores,
                silver.dim_products,
                silver.dim_cvss_source,
                silver.dim_cve
            RESTART IDENTITY CASCADE;
        """))
    logger.info("✅ Tables truncated")

# ============================================================================
# SANITIZER
# ============================================================================
def _clean_for_sql(df: pd.DataFrame) -> pd.DataFrame:
    df = df.replace({np.nan: None})
    for col in df.select_dtypes(include=['object']).columns:
        df[col] = df[col].astype(object)
    return df

# ============================================================================
# LOADERS
# ============================================================================
def load_dim_cve(df, engine, if_exists='append'):
    """Load CVE dimension (includes source_identifier)."""
    logger.info("📥 Loading dim_cve...")
    try:
        for c in ['source_identifier']:
            if c not in df.columns:
                df[c] = None
        df_load = df[['cve_id','title','description','category',
                      'published_date','last_modified','loaded_at',
                      'remotely_exploit','source_identifier']].copy()

        df_load['published_date'] = pd.to_datetime(df_load['published_date'])
        df_load['last_modified'] = pd.to_datetime(df_load['last_modified'])
        df_load['loaded_at'] = pd.to_datetime(df_load['loaded_at'])
        # Keep remotely_exploit as nullable bool
        df_load = _clean_for_sql(df_load)

        df_load.to_sql('dim_cve', engine, schema='silver',
                       if_exists=if_exists, index=False, method='multi', chunksize=500)
        logger.info(f"✅ dim_cve loaded: {len(df_load):,} rows")
        return True
    except Exception as e:
        logger.error(f"❌ Failed to load dim_cve: {e}")
        return False

from psycopg2.extras import execute_values

def upsert_dim_cvss_source(distinct_sources: pd.Series, engine) -> pd.DataFrame:
    """
    Upsert into silver.dim_cvss_source(source_name) via psycopg2.execute_values.
    Returns a mapping DataFrame with columns [source_name, source_id].
    """
    # Nettoyage des valeurs (dropna, trim, non vides) + limite à 100 caractères (VARCHAR(100))
    names = [
        str(s).strip()[:100]
        for s in distinct_sources.dropna().unique().tolist()
        if str(s).strip() != ""
    ]

    if not names:
        return pd.DataFrame(columns=['source_id', 'source_name'])

    # INSERT ... ON CONFLICT DO NOTHING (batch)
    raw_conn = engine.raw_connection()
    try:
        with raw_conn.cursor() as cur:
            execute_values(
                cur,
                """
                INSERT INTO silver.dim_cvss_source (source_name)
                VALUES %s
                ON CONFLICT (source_name) DO NOTHING
                """,
                [(n,) for n in names],  # list of tuples
                page_size=1000
            )
        raw_conn.commit()
    finally:
        raw_conn.close()

    # Récupérer le mapping source_name → source_id
    with engine.connect() as conn:
        rows = conn.execute(
            text("""
                SELECT source_id, source_name
                FROM silver.dim_cvss_source
                WHERE source_name = ANY(:names)
            """),
            {"names": names}
        ).fetchall()

    return pd.DataFrame(rows, columns=['source_id', 'source_name'])


from psycopg2.extras import execute_values

def load_fact_cvss_scores(df_load, engine):
    if df_load.empty:
        logger.warning("⚠ No fact_cvss_scores to load")
        return

    logger.info("📥 Loading fact_cvss_scores (batch insert)")

    # Normaliser les types
    df_load = df_load.replace({np.nan: None})

    # Liste des colonnes dans le même ordre que la table
    cols = [
        "cve_id", "source_id", "cvss_version", "cvss_score", "cvss_severity",
        "cvss_vector", "cvss_exploitability_score", "cvss_impact_score",
        "cvss_av", "cvss_ac", "cvss_au", "cvss_c", "cvss_i", "cvss_a",
        "cvss_pr", "cvss_ui", "cvss_s", "cvss_at", "cvss_vc", "cvss_vi",
        "cvss_va", "cvss_sc", "cvss_si", "cvss_sa"
    ]

    tuples = [tuple(row[c] for c in cols) for _, row in df_load.iterrows()]

    sql = f"""
        INSERT INTO silver.fact_cvss_scores ({', '.join(cols)})
        VALUES %s
        ON CONFLICT DO NOTHING
    """

    conn = engine.raw_connection()
    try:
        with conn.cursor() as cur:
            execute_values(cur, sql, tuples, page_size=1000)
        conn.commit()
        logger.info(f"✅ fact_cvss_scores loaded: {len(tuples)} rows")
    finally:
        conn.close()




def load_dim_products(df, engine, if_exists='append'):
    logger.info("📥 Loading dim_products...")
    try:
        df_load = df[['vendor','product_name','total_cves','first_cve_date','last_cve_date']].copy()
        df_load['first_cve_date'] = pd.to_datetime(df_load['first_cve_date'])
        df_load['last_cve_date'] = pd.to_datetime(df_load['last_cve_date'])
        df_load = _clean_for_sql(df_load)
        df_load.to_sql('dim_products', engine, schema='silver',
                       if_exists=if_exists, index=False, method='multi', chunksize=500)
        logger.info(f"✅ dim_products loaded: {len(df_load):,} rows")
        return True
    except Exception as e:
        logger.error(f"❌ Failed to load dim_products: {e}")
        return False

def load_bridge_cve_products(df, engine, if_exists='append'):
    logger.info("📥 Loading bridge_cve_products...")
    try:
        df_load = df[['cve_id','product_id']].drop_duplicates().copy()
        df_load = _clean_for_sql(df_load)
        df_load.to_sql('bridge_cve_products', engine, schema='silver',
                       if_exists=if_exists, index=False, method='multi', chunksize=2000)
        logger.info(f"✅ bridge_cve_products loaded: {len(df_load):,} rows")
        return True
    except Exception as e:
        logger.error(f"❌ Failed to load bridge_cve_products: {e}")
        return False

# ============================================================================
# ORCHESTRATOR
# ============================================================================
# ============================================================================
# ORCHESTRATOR
# ============================================================================
def load_silver_layer(silver_tables, engine, if_exists='append'):
    logger.info("=" * 70)
    logger.info("🚀 STARTING SILVER LAYER LOAD (with dim_cvss_source)")
    logger.info("=" * 70)

    start = datetime.now()
    if not verify_silver_schema(engine):
        return False

    if if_exists == 'replace':
        logger.info("🧨 'replace' mode → TRUNCATE + APPEND")
        reset_silver_tables(engine)
        if_exists = 'append'

    try:
        success = True
        
        # Step 1: Load dimension tables first
        success &= load_dim_cve(silver_tables['dim_cve'], engine, if_exists)
        success &= load_dim_products(silver_tables['dim_products'], engine, if_exists)
        
        # Step 2: Upsert CVSS sources and load fact table
        # Extract distinct sources from fact_cvss_scores
        df_fact = silver_tables['fact_cvss_scores']
        if not df_fact.empty and 'cvss_source' in df_fact.columns:
            logger.info("📥 Upserting dim_cvss_source...")
            source_mapping = upsert_dim_cvss_source(df_fact['cvss_source'], engine)
            logger.info(f"✅ dim_cvss_source: {len(source_mapping):,} sources")
            
            # Map cvss_source → source_id
            df_fact = df_fact.merge(
                source_mapping,
                left_on='cvss_source',
                right_on='source_name',
                how='left'
            )
            # Drop the temporary column
            df_fact = df_fact.drop(columns=['cvss_source', 'source_name'], errors='ignore')
        
        # Load fact_cvss_scores (no if_exists parameter)
        load_fact_cvss_scores(df_fact, engine)
        
        # Step 3: Load bridge table
        success &= load_bridge_cve_products(silver_tables['bridge_cve_products'], engine, if_exists)

        if success:
            with engine.connect() as conn:
                logger.info("\n" + "=" * 70)
                logger.info("📊 LOADING STATISTICS")
                logger.info("=" * 70)
                for table in ['dim_cve','dim_cvss_source','fact_cvss_scores','dim_products','bridge_cve_products']:
                    row = conn.execute(text(f"""
                        SELECT 
                            COUNT(*) AS row_count,
                            pg_size_pretty(pg_total_relation_size('silver.{table}')) AS size
                        FROM silver.{table}
                    """)).fetchone()
                    logger.info(f"\n🔹 {table.upper()}")
                    logger.info(f"   Rows: {row[0]:,}")
                    logger.info(f"   Size: {row[1]}")

                logger.info("\n" + "=" * 70)
                logger.info("📊 CVSS SOURCE STATISTICS (from JSON)")
                logger.info("=" * 70)
                result = conn.execute(text("""
                    SELECT 
                        s.source_name,
                        COUNT(*) as score_count,
                        COUNT(DISTINCT f.cve_id) as cve_count
                    FROM silver.fact_cvss_scores f
                    LEFT JOIN silver.dim_cvss_source s ON f.source_id = s.source_id
                    WHERE s.source_name IS NOT NULL
                    GROUP BY s.source_name
                    ORDER BY score_count DESC
                    LIMIT 10
                """))
                for row in result:
                    logger.info(f"  • {row[0]}: {row[1]:,} scores ({row[2]:,} CVEs)")

        dur = (datetime.now() - start).total_seconds()
        logger.info("\n" + "=" * 70)
        logger.info(("✅ LOADING COMPLETED" if success else "❌ LOADING FAILED") + f" in {dur:.2f}s")
        logger.info("=" * 70)
        return success

    except Exception as e:
        logger.error(f"\n❌ Pipeline failed: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False
# ============================================================================
# REFRESH MATERIALIZED VIEWS
# ============================================================================
def refresh_materialized_views(engine):
    logger.info("\n🔄 Refreshing materialized views...")
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT silver.refresh_all_mv()"))
            conn.commit()
        logger.info("✅ Materialized views refreshed")
        return True
    except Exception as e:
        logger.error(f"❌ Failed to refresh MVs: {e}")
        return False

if __name__ == "__main__":
    logger.info("💡 Import this module from your transform script")
