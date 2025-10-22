# Threat Intelligence Pipeline for CVE Data

## Overview

This project implements an ETL (Extract, Transform, Load) pipeline for building a threat intelligence data warehouse focused on Common Vulnerabilities and Exposures (CVE) data. It processes historical CVE feeds from the National Vulnerability Database (NVD) and real-time CVE alerts from sources like CVEFeed.io via Telegram channels (inspired by the "CVE Monitor" channel).

The pipeline follows a medallion architecture:
- **Bronze Layer**: Raw, unprocessed data ingestion.
- **Silver Layer**: Cleaned and enriched data with exploratory data analysis (EDA).
- **Gold Layer**: Aggregated, business-ready data for BI visualization and querying.

Key features:
- Batch processing for historical NVD JSON feeds (2002–2025).
- Streaming processing for live CVE feeds via Telegram scraping.
- PostgreSQL backend for data warehousing.
- Automated modular execution (e.g., extract scripts trigger load and transform).

This setup enables scalable threat intelligence analysis, such as vulnerability trend tracking, severity scoring (CVSS), and alerting.

## Inspiration

Inspired by the arXiv paper [Building Datasets from Telegram Channels: A Pipeline for Real-Time Threat Intelligence](https://arxiv.org/pdf/2509.20943), which discusses constructing datasets from Telegram channels. We adapted this for CVE monitoring:
- Initial testing on the "CVE Monitor" Telegram channel for real-time alerts.
- Expanded to CVEFeed.io for detailed feeds.
- Combined with historical NVD data for a complete timeline.

## Project Structure

```
threat-intelligence-pipeline/
├── Data/
│   └── Raw/                  # Downloaded NVD JSON ZIPs and download script
│       ├── download_zips.py
│       └── nvdcve-2.0-*.json.zip  # Historical feeds (2002–2025)
├── src/
│   ├── database/
│   │   ├── schemas/          # SQL DDL for medallion layers
│   │   │   ├── bronze.sql
│   │   │   ├── silver.sql
│   │   │   └── gold.sql
│   │   └── connection.py     # DB connection utilities
│   ├── pipeline/
│   │   ├── extract/          # Data extraction scripts
│   │   │   ├── nvd_json_to_bronze.py     # Batch historical load
│   │   │   └── scrape_live_cvefeed_bronze.py  # Streaming Telegram scrape
│   │   ├── load/             # Data loading modules
│   │   │   ├── load_bronze_layer.py
│   │   │   ├── load_silver_layer.py
│   │   │   └── load_gold_layer.py
│   │   └── transform/        # Data transformation & EDA
│   │       ├── nvd_EDA_bronze_to_silver.py
│   │       ├── scrape_EDA_bronze_to_silver.py
│   │       └── transformation_to_gold.py
│   ├── utils/                # Helper utilities (e.g., CVSS parser)
│   └── logs/                 # Runtime logs (e.g., load_bronze.log)
├── .env                      # Environment variables (DB creds, Telegram API)
├── example.env               # Template for .env
├── requirements.txt          # Python dependencies
└── README.md                 # This file
```

**Note**: The `archive/` directory contains legacy code (batch/stream variants) and is not used in the current pipeline.

## Prerequisites

- Python 3.11+ (virtual environment recommended: `python -m venv cenv`).
- PostgreSQL 14+ (with `psycopg2` for connectivity).
- Telegram API credentials (for streaming): Obtain from [my.telegram.org](https://my.telegram.org/apps).

## Installation

1. **Clone/Setup the Project**:
   ```
   git clone <repo-url>  # Or navigate to your local dir
   cd threat-intelligence-pipeline
   ```

2. **Create Virtual Environment**:
   ```
   python -m venv cenv
   source cenv/bin/activate  # Linux/Mac
   # Or on Windows: cenv\Scripts\activate
   ```

3. **Install Dependencies**:
   ```
   pip install -r requirements.txt
   ```

4. **Download Historical NVD Data**:
   Navigate to `Data/Raw/` and run:
   ```
   python download_zips.py
   ```
   This fetches ~200 MB of JSON ZIPs (2002–2025) from [NVD Data Feeds](https://nvd.nist.gov/vuln/data-feeds). Files will appear as `nvdcve-2.0-YYYY.json.zip`.

5. **Configure Environment**:
   Copy `example.env` to `.env` and fill in:
   - Database: `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`.
   - Telegram (for streaming): `TELEGRAM_API_ID`, `TELEGRAM_API_HASH`.

   Example `.env`:
   ```
   DB_HOST=localhost
   DB_PORT=5432
   DB_NAME=threat_intel_db
   DB_USER=your_user
   DB_PASSWORD=your_pass
   TELEGRAM_API_ID=your_api_id
   TELEGRAM_API_HASH=your_api_hash
   ```

6. **Setup PostgreSQL Database**:
   - Create a database: `createdb threat_intel_db` (or via pgAdmin/psql).
   - Run schema scripts in order (from `src/database/schemas/`):
     ```
     psql -h localhost -U your_user -d threat_intel_db -f bronze.sql
     psql -h localhost -U your_user -d threat_intel_db -f silver.sql
     psql -h localhost -U your_user -d threat_intel_db -f gold.sql
     ```
   - This creates tables/views for bronze (raw), silver (cleaned), and gold (aggregated) layers.

## Usage

### Batch Processing (Historical NVD Data)

Load ~313K historical CVEs into the data warehouse:

1. From project root:
   ```
   python src/pipeline/extract/nvd_json_to_bronze.py
   ```

2. **What Happens**:
   - Extracts/unzips JSON from `Data/Raw/`.
   - Loads raw data to bronze layer (`load_bronze_layer.py`).
   - Performs EDA and transforms to silver (`nvd_EDA_bronze_to_silver.py`).
   - Aggregates to gold (`transformation_to_gold.py`).

3. **Verification**:
   - Check `src/logs/load_bronze.log` for output (e.g., "313k rows inserted").
   - Query bronze: `SELECT COUNT(*) FROM bronze.cve_raw;` (should be ~313K).

### Streaming Processing (Live CVE Feeds)

Ingest real-time CVEs from Telegram (CVE Monitor channel via CVEFeed.io):

1. Ensure Telegram API keys are in `.env`.
2. From project root:
   ```
   python src/pipeline/extract/scrape_live_cvefeed_bronze.py
   ```

3. **What Happens**:
   - Scrapes live CVE alerts from Telegram.
   - Loads to bronze (`load_bronze_layer.py`).
   - Performs EDA/transform to silver (`scrape_EDA_bronze_to_silver.py`).
   - Aggregates to gold (`transformation_to_gold.py`).

4. **Notes**:
   - Runs continuously; interrupt with Ctrl+C.
   - Logs in `src/logs/` for monitoring.
   - Handles new CVEs incrementally (avoids duplicates via CVE ID).

### BI Visualization & Querying

Once loaded, query the gold layer for insights:
- **Example Queries** (run in psql or BI tool like Tableau/Metabase):
  ```sql
  -- High-severity CVEs (CVSS >= 7.0) in 2024
  SELECT cve_id, description, cvss_score
  FROM gold.cve_summary
  WHERE published_year = 2024 AND cvss_score >= 7.0
  ORDER BY cvss_score DESC;

  -- Vendor vulnerability trends
  SELECT vendor, COUNT(*) as vuln_count
  FROM gold.cve_summary
  GROUP BY vendor
  ORDER BY vuln_count DESC;
  ```

- **Gold Views** (see `src/database/schemas/gold_views.md` for details): Pre-built views for severity, timelines, vendors, etc.
- Connect to PostgreSQL in your BI tool for dashboards (e.g., CVE trends over time).

## Troubleshooting

- **DB Connection Issues**: Verify `.env` creds and PostgreSQL running (`pg_isready`).
- **Download Failures**: Check internet; NVD feeds may have rate limits.
- **Telegram Scraping Errors**: Ensure API keys valid; session file in `.runtime/telegram.session`.
- **Logs**: Always check `src/logs/` for errors (e.g., insertion failures).
- **Dependencies**: If missing, `pip install psycopg2-binary telethon pandas sqlalchemy`.

## Contributing

- Fork the repo and submit PRs.
- Add tests for new modules.
- Update schemas for schema evolution.

## Acknowledgments

- NVD for CVE data.
- Telethon library for Telegram scraping.
- Inspired by arXiv:2509.20943.