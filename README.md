# 🛡️ Threat Intelligence Pipeline (TIP)

A production-grade ETL pipeline for collecting, processing, and analyzing CVE (Common Vulnerabilities and Exposures) data from CVE feeds. This pipeline implements a **Bronze-Silver-Gold** medallion architecture using Python, PostgreSQL, and data engineering best practices.

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Database Setup](#database-setup)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Pipeline Stages](#pipeline-stages)
- [Logging](#logging)
- [Contributing](#contributing)

---

## 🎯 Overview

The Threat Intelligence Pipeline automates the collection and processing of CVE data, transforming raw vulnerability information into structured, analysis-ready datasets. The pipeline:

- **Scrapes** CVE details from web sources (Bronze Layer)
- **Transforms** raw data into normalized dimensional models (Silver Layer)
- **Aggregates** insights for business intelligence (Gold Layer - future)

This enables security analysts, data scientists, and DevOps teams to:
- Track vulnerability trends over time
- Identify affected products and vendors
- Analyze CVSS scores and severity distributions
- Build threat intelligence dashboards

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    BRONZE LAYER (Raw)                       │
│  - Scrape CVE data from cvefeed.io                         │
│  - Store raw JSON/text in PostgreSQL (raw.cve_details)     │
│  - Preserve original structure + timestamps                 │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                   SILVER LAYER (Refined)                    │
│  - Parse JSON fields (CVSS scores, products)               │
│  - Normalize dates and data types                          │
│  - Create dimensional model:                               │
│    • dim_cve (CVE details)                                 │
│    • fact_cvss_scores (CVSS metrics)                       │
│    • dim_products (affected vendors/products)              │
│    • bridge_cve_products (many-to-many relationships)      │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                    GOLD LAYER (Analytics)                   │
│  - Materialized views for dashboards                       │
│  - Aggregated metrics and KPIs                             │
│  - Ready for BI tools (Tableau, Power BI, etc.)            │
└─────────────────────────────────────────────────────────────┘
```

---

## ✨ Features

### Data Extraction
- ✅ Web scraping with BeautifulSoup and requests
- ✅ Batch processing with configurable delays
- ✅ Automatic duplicate detection (skip already-scraped CVEs)
- ✅ Resume capability (KeyboardInterrupt handling)
- ✅ Progress tracking with detailed logging

### Data Transformation
- ✅ Multi-version CVSS parsing (v2.0, v3.0, v3.1, v4.0)
- ✅ CVSS vector decoding into human-readable metrics
- ✅ Date normalization and validation
- ✅ Product/vendor relationship extraction
- ✅ Dimensional modeling (star schema)

### Data Loading
- ✅ PostgreSQL integration with SQLAlchemy
- ✅ Bulk insert with conflict resolution
- ✅ Transaction safety and rollback handling
- ✅ Materialized view refresh automation
- ✅ Data quality constraints (unique keys, foreign keys)

### Monitoring & Logging
- ✅ Comprehensive logging (file + console)
- ✅ Pipeline statistics and metrics
- ✅ Error tracking with stack traces
- ✅ Performance monitoring (duration, throughput)

---

## 📦 Prerequisites

### Required Software
- **Python 3.8+**
- **PostgreSQL 12+**
- **pip** (Python package manager)

### Python Dependencies
```
pandas
numpy
sqlalchemy
psycopg2-binary
requests
beautifulsoup4
python-dateutil
```

---

## 🚀 Installation

### 1. Clone the Repository
```bash
git clone <your-repo-url>
cd threat-intelligence-pipeline
```

### 2. Create Virtual Environment
```bash
# Windows (PowerShell)
python -m venv cenv
.\cenv\Scripts\Activate.ps1

# macOS/Linux
python3 -m venv cenv
source cenv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Database Credentials
Edit `src/tip/load/load_bronze_layer.py` and `load_silver_layer.py`:

```python
DB_CONFIG = {
    "user": "postgres",
    "password": "your_password",  # Change this!
    "host": "localhost",
    "port": "5432",
    "database": "tip",
}
```

---

## 🗄️ Database Setup

### 1. Create Database
```sql
CREATE DATABASE tip;
```

### 2. Run Schema Scripts
Execute the SQL scripts in order (located in your SQL directory):

```bash
psql -U postgres -d tip -f sql/bronze.sql
psql -U postgres -d tip -f sql/silver.sql
psql -U postgres -d tip -f sql/gold.sql  # Optional
```

**Bronze Schema** creates:
- `raw.cve_details` table (with JSONB columns for nested data)

**Silver Schema** creates:
- `silver.dim_cve` (CVE dimension)
- `silver.fact_cvss_scores` (CVSS metrics)
- `silver.dim_products` (product dimension)
- `silver.bridge_cve_products` (CVE-product relationships)

---

## 📖 Usage

### End-to-End Pipeline Execution

#### Step 1: Scrape CVE Data (Bronze Layer)
```bash
cd src/tip/extract
python scrape_cvefeed_bronze.py
```

**Features:**
- Reads CVE IDs from `Data/cve_ids_all_years_2002_2025_from_zip.csv`
- Scrapes CVE details from cvefeed.io
- Loads directly to PostgreSQL `raw.cve_details`
- Batch size: 100 CVEs per database insert
- Auto-skip already scraped CVEs

**Configuration:**
```python
stats = scraper.scrape_and_load_batch(
    cve_urls,
    batch_size=100,  # Adjust for performance
    delay=2          # Seconds between requests (be respectful!)
)
```

#### Step 2: Transform to Silver Layer
```bash
cd ../transform
python EDA_bronze_to_silver.py
```

**Features:**
- Reads from `raw.cve_details`
- Parses JSON fields (CVSS scores, products)
- Creates dimensional tables
- Loads to `silver.*` schema
- Refreshes materialized views

---

## 📁 Project Structure

```
threat-intelligence-pipeline/
│
├── src/tip/                    # Main package
│   ├── extract/               # Data extraction (scraping)
│   │   ├── scrape_cvefeed_bronze.py
│   │   └── extract_cve_ids_all_years_zip.ipynb
│   │
│   ├── load/                  # Data loading to PostgreSQL
│   │   ├── load_bronze_layer.py
│   │   └── load_silver_layer.py
│   │
│   ├── transform/             # Data transformation logic
│   │   ├── EDA_bronze_to_silver.py
│   │   └── EDA._bronze_to_silver.ipynb
│   │
│   ├── utils/                 # Helper functions
│   ├── cli/                   # Command-line interface (future)
│   ├── config.py              # Configuration settings
│   └── __init__.py
│
├── Data/                      # Data files
│   └── cve_ids_all_years_2002_2025_from_zip.csv
│
├── logs/                      # Pipeline logs
│   ├── scraper.log
│   ├── load_bronze.log
│   ├── load_silver.log
│   └── bronze_to_silver.log
│
├── archive/                   # Old versions and experiments
├── .gitignore
├── README.md
└── requirements.txt
```

---

## 🔄 Pipeline Stages

### 🥉 Bronze Layer (Raw)
**Purpose:** Store raw, unprocessed data exactly as scraped.

**Key Components:**
- `CVEScraper` class: Handles web scraping logic
- `load_bronze_layer()`: Bulk insert with duplicate handling
- Table: `raw.cve_details`

**Data Stored:**
- CVE ID, title, description
- Published/modified dates
- CVSS scores (JSON)
- Affected products (JSON)
- Category, exploit status
- Source URL, load timestamp

### 🥈 Silver Layer (Refined)
**Purpose:** Transform raw data into analysis-ready dimensional model.

**Key Components:**
- `create_silver_layer()`: Main transformation orchestrator
- `parse_cvss_vector()`: Decodes CVSS metrics
- Dimensional tables:
  - `dim_cve`: One row per CVE
  - `fact_cvss_scores`: CVSS metrics (can be multiple per CVE)
  - `dim_products`: Unique vendors/products
  - `bridge_cve_products`: Many-to-many relationships

**Transformations Applied:**
- Date parsing and normalization
- JSON parsing (nested arrays → relational tables)
- CVSS vector decoding (AV:N/AC:L → Attack Vector: Network, Attack Complexity: Low)
- Data type validation
- Duplicate removal

### 🥇 Gold Layer (Analytics)
**Purpose:** Aggregated views optimized for dashboards and reporting.

**Future Features:**
- Materialized views for:
  - CVEs by severity over time
  - Top affected vendors/products
  - Exploitability trends
  - CVSS score distributions
- Pre-calculated KPIs
- Data marts for specific use cases

---

## 📊 Example Queries

### Find High-Severity CVEs
```sql
SELECT 
    dc.cve_id,
    dc.title,
    fc.cvss_score,
    fc.cvss_severity
FROM silver.dim_cve dc
JOIN silver.fact_cvss_scores fc ON dc.cve_id = fc.cve_id
WHERE fc.cvss_severity = 'CRITICAL'
  AND fc.cvss_version = 'CVSS 3.1'
ORDER BY fc.cvss_score DESC
LIMIT 10;
```

### Most Vulnerable Products
```sql
SELECT 
    vendor,
    product_name,
    total_cves,
    first_cve_date,
    last_cve_date
FROM silver.dim_products
ORDER BY total_cves DESC
LIMIT 20;
```

### CVEs Affecting a Specific Vendor
```sql
SELECT 
    dc.cve_id,
    dc.published_date,
    fc.cvss_score,
    dp.product_name
FROM silver.dim_cve dc
JOIN silver.bridge_cve_products bcp ON dc.cve_id = bcp.cve_id
JOIN silver.dim_products dp ON bcp.product_id = dp.product_id
JOIN silver.fact_cvss_scores fc ON dc.cve_id = fc.cve_id
WHERE dp.vendor ILIKE '%microsoft%'
  AND fc.cvss_version = 'CVSS 3.1'
ORDER BY dc.published_date DESC;
```

---

## 📝 Logging

All pipeline stages write detailed logs to `logs/` directory:

- **scraper.log**: Web scraping progress, HTTP errors, data extraction
- **load_bronze.log**: Database insertion stats, conflicts, errors
- **load_silver.log**: Transformation metrics, table loading
- **bronze_to_silver.log**: End-to-end pipeline execution

**Log Format:**
```
2025-10-14 01:32:15 - INFO - [342/10000] Scraping CVE-2024-1234...
2025-10-14 01:32:17 - INFO -     ✓ Scores: CVSS 3.1: 7.5
2025-10-14 01:32:17 - INFO -     Found 3 affected product(s)
```

---

## 🛠️ Troubleshooting

### Common Issues

**1. Database Connection Errors**
```
sqlalchemy.exc.OperationalError: could not connect to server
```
**Solution:** Verify PostgreSQL is running and credentials are correct.

**2. Duplicate Key Violations**
```
psycopg2.errors.UniqueViolation: duplicate key value violates unique constraint
```
**Solution:** The pipeline uses `ON CONFLICT DO NOTHING`. If error persists, check unique constraints in schema.

**3. Rate Limiting (HTTP 429)**
```
requests.exceptions.HTTPError: 429 Too Many Requests
```
**Solution:** Increase `delay` parameter in `scrape_and_load_batch()` (default: 2 seconds).

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Code Style
- Follow PEP 8 for Python code
- Use meaningful variable names
- Add docstrings to functions
- Update logs and comments

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 👥 Authors

**Data Engineering Team**  
Contact: [Your Email]

---

## 🙏 Acknowledgments

- CVE data sourced from [cvefeed.io](https://cvefeed.io)
- Inspired by medallion architecture patterns
- Built with ❤️ for the security community

---

## 📅 Roadmap

- [ ] Implement Gold layer with materialized views
- [ ] Add CLI interface for pipeline orchestration
- [ ] Create Docker containerization
- [ ] Build Airflow DAGs for scheduling
- [ ] Add data quality tests (Great Expectations)
- [ ] Integrate with BI tools (Tableau, Grafana)
- [ ] Implement incremental loading (CDC)
- [ ] Add API endpoints for real-time queries

---

**Last Updated:** October 14, 2025  
**Pipeline Version:** 1.0.0
