# ============================================================================
# LOAD BRONZE LAYER - Direct Scraper to PostgreSQL
# ============================================================================
# Description: Load raw CVE data directly from scraper to Bronze schema
# Author: Data Engineering Team
# Date: 2025-10-14
# ============================================================================

from pathlib import Path
import logging
from datetime import datetime, timezone
import pandas as pd
from sqlalchemy import create_engine, text, types
from sqlalchemy.exc import SQLAlchemyError

# ----------------------------------------------------------------------------
# Logging Configuration
# ----------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[3]
LOGS_DIR = PROJECT_ROOT / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOGS_DIR / "load_bronze.log"

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
# Database Connection
# ----------------------------------------------------------------------------
def create_db_engine():
    """Create PostgreSQL engine for bronze layer"""
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
# Schema Validation
# ----------------------------------------------------------------------------
def verify_bronze_schema(engine):
    """Verify that raw schema and cve_details table exist"""
    logger.info("🔍 Verifying bronze (raw) schema...")
    
    with engine.connect() as conn:
        # Check schema
        result = conn.execute(text("""
            SELECT schema_name 
            FROM information_schema.schemata 
            WHERE schema_name = 'raw'
        """))
        if not result.fetchone():
            logger.error("❌ Raw schema does not exist! Run bronze.sql first.")
            return False
        
        # Check table
        result = conn.execute(text("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'raw' AND table_name = 'cve_details'
        """))
        if not result.fetchone():
            logger.error("❌ Table raw.cve_details does not exist!")
            return False
    
    logger.info("✅ Bronze schema validated")
    return True

# ----------------------------------------------------------------------------
# Data Preparation
# ----------------------------------------------------------------------------
def prepare_dataframe(cve_data_list):
    """
    Convert list of CVE dictionaries to DataFrame ready for PostgreSQL
    
    Args:
        cve_data_list: List of dicts from CVEScraper.scrape_cve_page()
    
    Returns:
        pd.DataFrame: Prepared DataFrame with proper types
    """
    logger.info("🔧 Preparing data for database insertion...")
    
    if not cve_data_list:
        logger.warning("⚠️  No data to prepare!")
        return pd.DataFrame()
    
    # Convert to DataFrame
    df = pd.DataFrame(cve_data_list)
    
    # Add loaded_at timestamp
    df['loaded_at'] = datetime.now(timezone.utc)
    
    # Convert JSON lists to strings (PostgreSQL will store as TEXT/JSONB)
    import json
    for col in ['affected_products', 'cvss_scores']:
        if col in df.columns:
            df[col] = df[col].apply(
                lambda x: json.dumps(x, ensure_ascii=False) if isinstance(x, list) else '[]'
            )
    
    # Ensure all other columns are strings (except loaded_at)
    for col in df.columns:
        if col not in ['loaded_at', 'affected_products', 'cvss_scores']:
            df[col] = df[col].astype(str).replace({'nan': '', 'None': ''})
    
    logger.info(f"✅ Prepared {len(df):,} rows for insertion")
    return df

# ----------------------------------------------------------------------------
# Load Functions
# ----------------------------------------------------------------------------
def load_to_bronze(df, engine, batch_size=500):
    """
    Load DataFrame to raw.cve_details table
    Uses INSERT ... ON CONFLICT DO NOTHING to skip duplicates
    
    Args:
        df: DataFrame with CVE data
        engine: SQLAlchemy engine
        batch_size: Number of rows per batch
    
    Returns:
        dict: Statistics about the load operation
    """
    logger.info("="*70)
    logger.info("🚀 LOADING TO BRONZE LAYER (raw.cve_details)")
    logger.info("="*70)
    
    if df.empty:
        logger.warning("⚠️  No data to load!")
        return {'inserted': 0, 'skipped': 0, 'failed': 0}
    
    stats = {'inserted': 0, 'skipped': 0, 'failed': 0}
    start_time = datetime.now()
    
    try:
        # Define column types for PostgreSQL
        dtype_map = {col: types.Text() for col in df.columns}
        dtype_map['loaded_at'] = types.DateTime(timezone=True)
        
        # Use temporary staging table
        temp_table = "cve_details_staging"
        
        with engine.begin() as conn:
            # Load to temp table
            logger.info(f"📥 Loading {len(df):,} rows to staging table...")
            df.to_sql(
                temp_table, 
                conn, 
                schema='raw',
                if_exists='replace',
                index=False,
                dtype=dtype_map,
                method='multi',
                chunksize=batch_size
            )
            
            # Get count before insertion
            count_before = conn.execute(
                text("SELECT COUNT(*) FROM raw.cve_details")
            ).scalar()
            
            # Insert with conflict handling
            logger.info("🔄 Inserting new rows (skipping duplicates on cve_id)...")
            result = conn.execute(text(f"""
                INSERT INTO raw.cve_details
                SELECT * FROM raw.{temp_table}
                ON CONFLICT (cve_id) DO NOTHING;
            """))
            
            # Get count after insertion
            count_after = conn.execute(
                text("SELECT COUNT(*) FROM raw.cve_details")
            ).scalar()
            
            stats['inserted'] = count_after - count_before
            stats['skipped'] = len(df) - stats['inserted']
            
            # Drop staging table
            conn.execute(text(f"DROP TABLE IF EXISTS raw.{temp_table};"))
            
        duration = (datetime.now() - start_time).total_seconds()
        
        # Log statistics
        logger.info("="*70)
        logger.info("📊 LOAD STATISTICS")
        logger.info("="*70)
        logger.info(f"✅ Inserted:  {stats['inserted']:,} new CVEs")
        logger.info(f"⏭️  Skipped:   {stats['skipped']:,} duplicates")
        logger.info(f"⏱️  Duration:  {duration:.2f}s")
        logger.info(f"📈 Total CVEs in database: {count_after:,}")
        logger.info("="*70)
        
        return stats
        
    except SQLAlchemyError as e:
        logger.error(f"❌ Database error during load: {e}")
        stats['failed'] = len(df)
        raise
    except Exception as e:
        logger.error(f"❌ Unexpected error during load: {e}")
        stats['failed'] = len(df)
        raise

# ----------------------------------------------------------------------------
# Main Orchestrator
# ----------------------------------------------------------------------------
def load_bronze_layer(cve_data_list, engine=None):
    """
    Main function to load scraped CVE data to bronze layer
    
    Args:
        cve_data_list: List of dicts from CVEScraper
        engine: Optional SQLAlchemy engine (creates new if None)
    
    Returns:
        dict: Load statistics
    """
    logger.info("="*70)
    logger.info("🎯 BRONZE LAYER LOAD PIPELINE")
    logger.info("="*70)
    
    # Create engine if not provided
    if engine is None:
        engine = create_db_engine()
    
    # Validate schema
    if not verify_bronze_schema(engine):
        logger.error("❌ Schema validation failed!")
        return None
    
    # Prepare data
    df = prepare_dataframe(cve_data_list)
    
    if df.empty:
        logger.warning("⚠️  No valid data to load")
        return {'inserted': 0, 'skipped': 0, 'failed': 0}
    
    # Load to database
    stats = load_to_bronze(df, engine)
    
    logger.info("\n" + "="*70)
    logger.info("🎉 BRONZE LAYER LOAD COMPLETED")
    logger.info("="*70)
    
    return stats

# ----------------------------------------------------------------------------
# CLI Helper
# ----------------------------------------------------------------------------
def load_from_csv(csv_path, engine=None):
    """
    Helper function to load from existing CSV (backward compatibility)
    
    Args:
        csv_path: Path to CSV file
        engine: Optional SQLAlchemy engine
    
    Returns:
        dict: Load statistics
    """
    logger.info(f"📂 Loading data from CSV: {csv_path}")
    
    import json
    
    # Read CSV
    df = pd.read_csv(
        csv_path,
        dtype=str,
        keep_default_na=False,
        on_bad_lines='skip',
        quotechar='"',
        escapechar='\\',
        engine='python'
    )
    
    # Convert back to list of dicts (to match scraper output format)
    cve_data_list = []
    for _, row in df.iterrows():
        cve_dict = row.to_dict()
        
        # Parse JSON strings back to lists
        for col in ['affected_products', 'cvss_scores']:
            if col in cve_dict:
                try:
                    cve_dict[col] = json.loads(cve_dict[col])
                except:
                    cve_dict[col] = []
        
        cve_data_list.append(cve_dict)
    
    # Use main load function
    return load_bronze_layer(cve_data_list, engine)

# ----------------------------------------------------------------------------
# Main Entry Point
# ----------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        # Load from CSV file (backward compatibility)
        csv_file = sys.argv[1]
        logger.info(f"📥 Loading from CSV: {csv_file}")
        stats = load_from_csv(csv_file)
    else:
        logger.info("💡 Usage:")
        logger.info("   python load_bronze_layer.py <csv_file>")
        logger.info("")
        logger.info("   Or import and use programmatically:")
        logger.info("   from tip.load.load_bronze_layer import load_bronze_layer")
        logger.info("   stats = load_bronze_layer(cve_data_list)")