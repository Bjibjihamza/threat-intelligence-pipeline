# Silver Layer - Loading Guide

## 📋 Overview

This guide explains how to load your transformed CVE data from the Bronze layer to the Silver layer in PostgreSQL.

## 🏗 Architecture


Bronze Layer (raw.cve_details)
         ↓
    Transformation
         ↓
Silver Layer (normalized star schema)
    ├── dim_cve              (CVE dimension)
    ├── fact_cvss_scores     (CVSS metrics)
    ├── dim_products         (Products dimension)
    └── bridge_cve_products  (CVE-Product relationships)


## 📂 Project Structure


src/tip/
├── transform/
│   ├── EDA_bronze_to_silver.py              # Original transformation script
│   └── EDA_bronze_to_silver_with_load.py    # Transformation + Loading
├── load/
│   ├── load_raw_to_postgres.py              # Bronze layer loader
│   └── load_silver_layer.py                 # Silver layer loader
└── cli/
    └── architecture/
        └── Silver/
            └── silver.sql                    # Silver schema definition


## 🚀 Quick Start

### Step 1: Create Silver Schema

First, create the Silver layer schema in PostgreSQL:

bash
# Navigate to the SQL file location
cd src/tip/cli/architecture/Silver

# Execute the SQL script
psql -U postgres -d tip -f silver.sql


Or using DBeaver/pgAdmin:
1. Open silver.sql
2. Execute the entire script

### Step 2: Run the Complete Pipeline

bash
cd src/tip/transform

# Run the complete transformation + loading pipeline
python EDA_bronze_to_silver_with_load.py


This script will:
1. ✅ Load raw data from Bronze layer
2. ✅ Transform data (dates, CVSS scores, products)
3. ✅ Create normalized Silver tables
4. ✅ Load data to PostgreSQL
5. ✅ Refresh materialized views

## 📖 Detailed Usage

### Option 1: Complete Pipeline (Recommended)

python
# Run from terminal
python EDA_bronze_to_silver_with_load.py


*Output:*

🚀 BRONZE → SILVER TRANSFORMATION
📥 Loading raw data from bronze layer...
✅ Loaded: 327,832 rows × 12 columns
📅 Processing dates...
✅ Dates processed: 327,832 valid rows
🧹 Cleaning data...
✅ Data cleaned: 327,832 rows
🔨 Creating dim_cve...
✅ dim_cve: 327,832 unique CVEs
...
💾 LOADING TO DATABASE
✅ dim_cve loaded: 327,832 rows
✅ fact_cvss_scores loaded: 512,445 rows
✅ dim_products loaded: 45,678 rows
✅ bridge_cve_products loaded: 890,234 rows
🎉 PIPELINE COMPLETED SUCCESSFULLY!


### Option 2: Step-by-Step (Manual)

python
# 1. Import modules
from EDA_bronze_to_silver import create_silver_layer, load_raw_data, create_db_engine
from load_silver_layer import load_silver_layer, refresh_materialized_views

# 2. Create engine
engine = create_db_engine()

# 3. Load and transform
df_raw = load_raw_data(engine)
silver_tables = create_silver_layer(df_raw)

# 4. Load to database
success = load_silver_layer(silver_tables, engine, if_exists='replace')

# 5. Refresh views
if success:
    refresh_materialized_views(engine)


### Option 3: Using Jupyter Notebook

python
# In your notebook
%run EDA_bronze_to_silver.py

# Tables are now available as:
# - dim_cve
# - fact_cvss_scores
# - dim_products
# - bridge_cve_products

# Load to database
from load.load_silver_layer import load_silver_layer, create_db_engine

engine = create_db_engine()
load_silver_layer(silver_tables, engine, if_exists='replace')


## 🔧 Configuration

### Database Connection

Edit in both load_silver_layer.py and EDA_bronze_to_silver_with_load.py:

python
DB_CONFIG = {
    "user": "postgres",
    "password": "tip_pwd",
    "host": "localhost",
    "port": "5432",
    "database": "tip"
}


### Loading Options

python
# Replace existing data (default for fresh load)
load_silver_layer(silver_tables, engine, if_exists='replace')

# Append to existing data (for incremental loads)
load_silver_layer(silver_tables, engine, if_exists='append')

# Fail if table exists
load_silver_layer(silver_tables, engine, if_exists='fail')


## 📊 Verify Data Loading

sql
-- Check row counts
SELECT 
    'dim_cve' as table_name,
    COUNT(*) as row_count,
    pg_size_pretty(pg_total_relation_size('silver.dim_cve')) as size
FROM silver.dim_cve
UNION ALL
SELECT 'fact_cvss_scores', COUNT(*), 
       pg_size_pretty(pg_total_relation_size('silver.fact_cvss_scores'))
FROM silver.fact_cvss_scores
UNION ALL
SELECT 'dim_products', COUNT(*), 
       pg_size_pretty(pg_total_relation_size('silver.dim_products'))
FROM silver.dim_products
UNION ALL
SELECT 'bridge_cve_products', COUNT(*), 
       pg_size_pretty(pg_total_relation_size('silver.bridge_cve_products'))
FROM silver.bridge_cve_products;

-- Test a simple query
SELECT 
    c.cve_id,
    c.title,
    c.published_date,
    f.cvss_score,
    f.cvss_severity
FROM silver.dim_cve c
JOIN silver.fact_cvss_scores f ON c.cve_id = f.cve_id
WHERE f.cvss_version = 'CVSS 3.1'
  AND f.cvss_score >= 9.0
ORDER BY c.published_date DESC
LIMIT 10;


## 📝 Logging

Logs are saved to:
- logs/bronze_to_silver.log - Transformation logs
- logs/load_silver.log - Loading logs

Monitor progress:
bash
# Watch transformation logs
tail -f ../../../logs/bronze_to_silver.log

# Watch loading logs
tail -f ../../../logs/load_silver.log


## ⚠ Common Issues

### Issue 1: "Silver schema does not exist"

*Solution:*
bash
cd src/tip/cli/architecture/Silver
psql -U postgres -d tip -f silver.sql


### Issue 2: Foreign key violations

*Solution:* Ensure tables are loaded in correct order:
1. dim_cve (no dependencies)
2. dim_products (no dependencies)
3. fact_cvss_scores (depends on dim_cve)
4. bridge_cve_products (depends on both)

The script handles this automatically.

### Issue 3: Duplicate key errors

*Solution:* Use if_exists='replace' for fresh loads:
python
load_silver_layer(silver_tables, engine, if_exists='replace')


### Issue 4: "Module not found"

*Solution:* Ensure you're running from correct directory:
bash
cd src/tip/transform
python EDA_bronze_to_silver_with_load.py


## 🔄 Incremental Loading

For daily/incremental loads:

python
# 1. Load only new CVEs from bronze
df_new = pd.read_sql("""
    SELECT * FROM raw.cve_details 
    WHERE loaded_at > (
        SELECT MAX(loaded_at) FROM silver.dim_cve
    )
""", engine)

# 2. Transform
silver_tables_new = create_silver_layer(df_new)

# 3. Append to existing tables
load_silver_layer(silver_tables_new, engine, if_exists='append')

# 4. Refresh materialized views
refresh_materialized_views(engine)


## 🎯 Performance Tips

1. **Use method='multi' for bulk inserts** (already implemented)
2. *Chunk large datasets:*
   python
   load_silver_layer(silver_tables, engine, if_exists='append')
   
3. *Refresh materialized views after loading:*
   sql
   SELECT silver.refresh_all_mv();
   
4. *Monitor table sizes:*
   sql
   SELECT 
       schemaname,
       tablename,
       pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size
   FROM pg_tables
   WHERE schemaname = 'silver'
   ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
   

## 📈 Next Steps

After loading Silver layer:
1. ✅ Run analytical queries
2. ✅ Create Gold layer aggregations
3. ✅ Build dashboards (Tableau, Power BI, Metabase)
4. ✅ Set up automated ETL jobs

## 🤝 Support

For issues or questions:
1. Check logs in logs/ directory
2. Verify schema with silver.sql
3. Test queries in PostgreSQL client

---

*Last Updated:* 2025-10-14  
*Version:* 1.0.0