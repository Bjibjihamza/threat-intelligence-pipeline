# ============================================================================
# LOAD SILVER LAYER TO POSTGRESQL
# ============================================================================
# Description: Loads transformed Silver layer tables from bronze to silver schema
# Author: Data Engineering Team
# Date: 2025-10-14
# ============================================================================

import sys
import pandas as pd
from sqlalchemy import create_engine, text
from datetime import datetime
import logging

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('../../../logs/load_silver.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(_name_)

# ============================================================================
# DATABASE CONNECTION
# ============================================================================
def create_db_engine():
    """Create PostgreSQL engine"""
    DB_CONFIG = {
        "user": "postgres",
        "password": "tip_pwd",
        "host": "localhost",
        "port": "5432",
        "database": "tip"
    }
    
    try:
        engine = create_engine(
            f"postgresql+psycopg2://{DB_CONFIG['user']}:{DB_CONFIG['password']}@"
            f"{DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['database']}"
        )
        logger.info("✅ Database connection established")
        return engine
    except Exception as e:
        logger.error(f"❌ Failed to connect to database: {e}")
        raise

# ============================================================================
# SCHEMA VALIDATION
# ============================================================================
def verify_silver_schema(engine):
    """Verify that silver schema and tables exist"""
    logger.info("🔍 Verifying silver schema...")
    
    with engine.connect() as conn:
        # Check if schema exists
        result = conn.execute(text("""
            SELECT schema_name 
            FROM information_schema.schemata 
            WHERE schema_name = 'silver'
        """))
        
        if not result.fetchone():
            logger.error("❌ Silver schema does not exist!")
            logger.info("💡 Please run the silver.sql script first")
            return False
        
        # Check if tables exist
        expected_tables = ['dim_cve', 'fact_cvss_scores', 'dim_products', 'bridge_cve_products']
        result = conn.execute(text("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'silver'
        """))
        
        existing_tables = [row[0] for row in result.fetchall()]
        missing_tables = set(expected_tables) - set(existing_tables)
        
        if missing_tables:
            logger.error(f"❌ Missing tables in silver schema: {missing_tables}")
            return False
        
        logger.info("✅ Silver schema validated")
        return True

# ============================================================================
# DATA LOADING FUNCTIONS
# ============================================================================
def load_dim_cve(df, engine, if_exists='append'):
    """Load dim_cve table"""
    logger.info("📥 Loading dim_cve...")
    
    try:
        # Prepare data
        df_load = df[[
            'cve_id', 'title', 'description', 'category',
            'published_date', 'last_modified', 'loaded_at',
            'remotely_exploit'
        ]].copy()
        
        # Ensure correct data types
        df_load['published_date'] = pd.to_datetime(df_load['published_date'])
        df_load['last_modified'] = pd.to_datetime(df_load['last_modified'])
        df_load['loaded_at'] = pd.to_datetime(df_load['loaded_at'])
        df_load['remotely_exploit'] = df_load['remotely_exploit'].astype(bool)
        
        # Load to database
        rows_loaded = df_load.to_sql(
            'dim_cve',
            engine,
            schema='silver',
            if_exists=if_exists,
            index=False,
            method='multi',
            chunksize=1000
        )
        
        logger.info(f"✅ dim_cve loaded: {len(df_load):,} rows")
        return True
        
    except Exception as e:
        logger.error(f"❌ Failed to load dim_cve: {e}")
        return False

def load_fact_cvss_scores(df, engine, if_exists='append'):
    """Load fact_cvss_scores table"""
    logger.info("📥 Loading fact_cvss_scores...")
    
    try:
        # Prepare data - remove cvss_score_id if present (it's auto-generated)
        columns_to_load = [col for col in df.columns if col != 'cvss_score_id']
        df_load = df[columns_to_load].copy()
        
        # Ensure numeric columns are correct type
        numeric_cols = ['cvss_score', 'cvss_exploitability_score', 'cvss_impact_score']
        for col in numeric_cols:
            if col in df_load.columns:
                df_load[col] = pd.to_numeric(df_load[col], errors='coerce')
        
        # Load to database
        rows_loaded = df_load.to_sql(
            'fact_cvss_scores',
            engine,
            schema='silver',
            if_exists=if_exists,
            index=False,
            method='multi',
            chunksize=1000
        )
        
        logger.info(f"✅ fact_cvss_scores loaded: {len(df_load):,} rows")
        return True
        
    except Exception as e:
        logger.error(f"❌ Failed to load fact_cvss_scores: {e}")
        return False

def load_dim_products(df, engine, if_exists='append'):
    """Load dim_products table"""
    logger.info("📥 Loading dim_products...")
    
    try:
        # Prepare data - remove product_id if present (it's auto-generated)
        df_load = df[[
            'vendor', 'product_name', 'total_cves',
            'first_cve_date', 'last_cve_date'
        ]].copy()
        
        # Ensure date columns are correct type
        df_load['first_cve_date'] = pd.to_datetime(df_load['first_cve_date'])
        df_load['last_cve_date'] = pd.to_datetime(df_load['last_cve_date'])
        
        # Load to database
        rows_loaded = df_load.to_sql(
            'dim_products',
            engine,
            schema='silver',
            if_exists=if_exists,
            index=False,
            method='multi',
            chunksize=1000
        )
        
        logger.info(f"✅ dim_products loaded: {len(df_load):,} rows")
        return True
        
    except Exception as e:
        logger.error(f"❌ Failed to load dim_products: {e}")
        return False

def load_bridge_cve_products(df, engine, if_exists='append'):
    """Load bridge_cve_products table"""
    logger.info("📥 Loading bridge_cve_products...")
    
    try:
        # Prepare data - remove bridge_id if present (it's auto-generated)
        df_load = df[['cve_id', 'product_id']].copy()
        
        # Ensure no duplicates
        df_load = df_load.drop_duplicates()
        
        # Load to database
        rows_loaded = df_load.to_sql(
            'bridge_cve_products',
            engine,
            schema='silver',
            if_exists=if_exists,
            index=False,
            method='multi',
            chunksize=1000
        )
        
        logger.info(f"✅ bridge_cve_products loaded: {len(df_load):,} rows")
        return True
        
    except Exception as e:
        logger.error(f"❌ Failed to load bridge_cve_products: {e}")
        return False

# ============================================================================
# MAIN LOADING FUNCTION
# ============================================================================
def load_silver_layer(silver_tables, engine, if_exists='append'):
    """
    Load all Silver layer tables to PostgreSQL
    
    Parameters:
    -----------
    silver_tables : dict
        Dictionary containing DataFrames:
        - 'dim_cve': CVE dimension
        - 'fact_cvss_scores': CVSS scores fact table
        - 'dim_products': Products dimension
        - 'bridge_cve_products': CVE-Product bridge table
    engine : sqlalchemy.Engine
        Database connection engine
    if_exists : str
        How to behave if table exists: 'append', 'replace', 'fail'
    
    Returns:
    --------
    bool : Success status
    """
    logger.info("="*70)
    logger.info("🚀 STARTING SILVER LAYER LOAD")
    logger.info("="*70)
    
    start_time = datetime.now()
    
    # Verify schema
    if not verify_silver_schema(engine):
        return False
    
    # Load tables in correct order (respecting foreign keys)
    success = True
    
    # 1. Load dimensions first (no foreign key dependencies)
    success &= load_dim_cve(silver_tables['dim_cve'], engine, if_exists)
    success &= load_dim_products(silver_tables['dim_products'], engine, if_exists)
    
    # 2. Load fact table (depends on dim_cve)
    success &= load_fact_cvss_scores(silver_tables['fact_cvss_scores'], engine, if_exists)
    
    # 3. Load bridge table (depends on both dim_cve and dim_products)
    success &= load_bridge_cve_products(silver_tables['bridge_cve_products'], engine, if_exists)
    
    # Print statistics
    if success:
        with engine.connect() as conn:
            logger.info("\n" + "="*70)
            logger.info("📊 LOADING STATISTICS")
            logger.info("="*70)
            
            for table in ['dim_cve', 'fact_cvss_scores', 'dim_products', 'bridge_cve_products']:
                result = conn.execute(text(f"""
                    SELECT 
                        COUNT(*) as row_count,
                        pg_size_pretty(pg_total_relation_size('silver.{table}')) as size
                    FROM silver.{table}
                """))
                row = result.fetchone()
                logger.info(f"\n🔹 {table.upper()}")
                logger.info(f"   Rows: {row[0]:,}")
                logger.info(f"   Size: {row[1]}")
    
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    logger.info("\n" + "="*70)
    if success:
        logger.info(f"✅ LOADING COMPLETED SUCCESSFULLY in {duration:.2f}s")
    else:
        logger.info(f"❌ LOADING FAILED after {duration:.2f}s")
    logger.info("="*70)
    
    return success

# ============================================================================
# REFRESH MATERIALIZED VIEWS
# ============================================================================
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

# ============================================================================
# MAIN EXECUTION
# ============================================================================
if _name_ == "_main_":
    """
    Usage:
    ------
    1. Run your EDA_bronze_to_silver.py to create silver_tables
    2. Import this module and call load_silver_layer(silver_tables, engine)
    
    Example:
    --------
    from load_silver_layer import load_silver_layer, create_db_engine
    
    # After running EDA_bronze_to_silver.py
    engine = create_db_engine()
    success = load_silver_layer(silver_tables, engine, if_exists='append')
    
    if success:
        refresh_materialized_views(engine)
    """
    logger.info("💡 This script should be imported and used with silver_tables from EDA")
    logger.info("\nExample usage:")
    logger.info("  from load_silver_layer import load_silver_layer, create_db_engine")
    logger.info("  engine = create_db_engine()")
    logger.info("  load_silver_layer(silver_tables, engine)")