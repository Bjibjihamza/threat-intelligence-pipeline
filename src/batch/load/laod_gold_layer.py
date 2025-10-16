# ===============================================================
# GOLD LAYER LOADER (silver -> gold)
# Version: 1.0 (2025-10-16)
# Author : Data Engineering Team
# ===============================================================

from pathlib import Path
import logging
from datetime import datetime, date, timedelta

import pandas as pd
import numpy as np
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from psycopg2.extras import execute_values

# Reuse your DB connector
from database.connection import create_db_engine

# -------------------------------
# Logging
# -------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[3]
LOGS_DIR = PROJECT_ROOT / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOGS_DIR / "load_gold.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()
    ],
)
logger = logging.getLogger("gold_loader")


# ===============================================================
# DDL (idempotent)
# ===============================================================
DDL_SQL = """
CREATE SCHEMA IF NOT EXISTS gold;

-- Calendar dimension (idempotent inserts later)
CREATE TABLE IF NOT EXISTS gold.dim_calendar (
  dt               DATE PRIMARY KEY,
  year             INT NOT NULL,
  quarter          INT NOT NULL,
  month            INT NOT NULL,
  month_name       TEXT NOT NULL,
  day              INT NOT NULL,
  day_of_week      INT NOT NULL, -- 1=Mon .. 7=Sun
  day_name         TEXT NOT NULL,
  week_of_year     INT NOT NULL,
  is_weekend       BOOLEAN NOT NULL
);

-- Best/Latest CVE snapshot (one row per CVE)
CREATE TABLE IF NOT EXISTS gold.fact_cve_latest (
  cve_id                 VARCHAR(20) PRIMARY KEY,
  title                  TEXT NOT NULL,
  description            TEXT,
  category               VARCHAR(50),
  published_date         TIMESTAMP NOT NULL,
  last_modified          TIMESTAMP NOT NULL,
  remotely_exploit       BOOLEAN,
  source_identifier      TEXT,       -- top-level origin from dim_cve
  cvss_version           VARCHAR(10) NOT NULL,
  cvss_score             NUMERIC(3,1),
  cvss_severity          VARCHAR(10),
  cvss_vector            TEXT,
  source_id              INT,        -- from dim_cvss_source
  source_name            VARCHAR(100),
  loaded_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Daily facts for trends
CREATE TABLE IF NOT EXISTS gold.fact_cve_daily (
  dt                     DATE PRIMARY KEY,
  new_cve_count          INT NOT NULL,
  avg_cvss_score         NUMERIC(4,2),
  max_cvss_score         NUMERIC(3,1),
  critical_count         INT NOT NULL,
  high_count             INT NOT NULL,
  medium_count           INT NOT NULL,
  low_count              INT NOT NULL,
  source_diversity_avg   NUMERIC(4,2)  -- avg distinct sources per CVE on that day
);

-- Vendor/Product risk mart
CREATE TABLE IF NOT EXISTS gold.fact_vendor_product_risk (
  vendor                 VARCHAR(255) NOT NULL,
  product_name           VARCHAR(255) NOT NULL,
  total_cves             INT NOT NULL,
  first_cve_date         TIMESTAMP,
  last_cve_date          TIMESTAMP,
  avg_cvss_score         NUMERIC(4,2),
  max_cvss_score         NUMERIC(3,1),
  critical_count         INT NOT NULL,
  high_count             INT NOT NULL,
  medium_count           INT NOT NULL,
  low_count              INT NOT NULL,
  distinct_sources       INT NOT NULL,
  PRIMARY KEY (vendor, product_name)
);

-- Dashboard MV (pre-joined)
CREATE MATERIALIZED VIEW IF NOT EXISTS gold.mv_overview_dashboard AS
SELECT
  f.cve_id,
  f.title,
  f.published_date::date AS dt,
  f.category,
  f.cvss_version,
  f.cvss_score,
  f.cvss_severity,
  f.source_name,
  f.source_identifier
FROM gold.fact_cve_latest f;

CREATE INDEX IF NOT EXISTS idx_mv_overview_dt ON gold.mv_overview_dashboard(dt);
CREATE INDEX IF NOT EXISTS idx_mv_overview_sev ON gold.mv_overview_dashboard(cvss_severity);
"""


# ===============================================================
# Helpers
# ===============================================================
def ensure_gold_schema(engine: Engine) -> None:
    with engine.begin() as conn:
        conn.execute(text(DDL_SQL))
    logger.info("✅ Ensured gold schema & tables")


def _date_range(start: date, end: date):
    cur = start
    while cur <= end:
        yield cur
        cur += timedelta(days=1)


def upsert_calendar(engine: Engine, start: date, end: date) -> None:
    """
    Upsert calendar rows for [start, end].
    """
    rows = []
    for d in _date_range(start, end):
        rows.append({
            "dt": d,
            "year": d.year,
            "quarter": (d.month - 1) // 3 + 1,
            "month": d.month,
            "month_name": d.strftime("%B"),
            "day": d.day,
            "day_of_week": int(d.strftime("%u")),
            "day_name": d.strftime("%A"),
            "week_of_year": int(d.strftime("%V")),
            "is_weekend": d.weekday() >= 5,
        })
    if not rows:
        return
    df = pd.DataFrame(rows)
    tuples = [
        (
            r["dt"], r["year"], r["quarter"], r["month"], r["month_name"],
            r["day"], r["day_of_week"], r["day_name"], r["week_of_year"], r["is_weekend"]
        )
        for _, r in df.iterrows()
    ]
    sql = """
        INSERT INTO gold.dim_calendar
        (dt, year, quarter, month, month_name, day, day_of_week, day_name, week_of_year, is_weekend)
        VALUES %s
        ON CONFLICT (dt) DO UPDATE SET
          year = EXCLUDED.year,
          quarter = EXCLUDED.quarter,
          month = EXCLUDED.month,
          month_name = EXCLUDED.month_name,
          day = EXCLUDED.day,
          day_of_week = EXCLUDED.day_of_week,
          day_name = EXCLUDED.day_name,
          week_of_year = EXCLUDED.week_of_year,
          is_weekend = EXCLUDED.is_weekend
    """
    raw = engine.raw_connection()
    try:
        with raw.cursor() as cur:
            execute_values(cur, sql, tuples, page_size=2000)
        raw.commit()
    finally:
        raw.close()
    logger.info(f"📅 Upserted calendar rows: {len(tuples):,}")


# ===============================================================
# Transformations (silver -> gold)
# ===============================================================
def load_fact_cve_latest(engine: Engine):
    """
    Choose one 'best' CVSS row per CVE.
    Priority:
      1) Version: 4.0 > 3.1/3.0 > 2.0
      2) Score: higher first
      3) Source: prefer 'nvd@nist.gov' if tie
      4) Lowest source_id as final tiebreak
    """
    logger.info("📥 Loading gold.fact_cve_latest ...")
    sql = """
    WITH ranked AS (
      SELECT
        c.cve_id,
        c.title,
        c.description,
        c.category,
        c.published_date,
        c.last_modified,
        c.remotely_exploit,
        c.source_identifier,  -- top-level origin
        f.cvss_version,
        f.cvss_score,
        f.cvss_severity,
        f.cvss_vector,
        f.source_id,
        s.source_name,
        -- Version rank: lower is better
        CASE
          WHEN f.cvss_version = 'CVSS 4.0' THEN 1
          WHEN f.cvss_version IN ('CVSS 3.1','CVSS 3.0') THEN 2
          WHEN f.cvss_version = 'CVSS 2.0' THEN 3
          ELSE 9
        END AS ver_rank,
        -- Prefer NVD if tie on score & version
        CASE WHEN s.source_name = 'nvd@nist.gov' THEN 0 ELSE 1 END AS nvd_bias,
        ROW_NUMBER() OVER (
          PARTITION BY c.cve_id
          ORDER BY
            CASE
              WHEN f.cvss_version = 'CVSS 4.0' THEN 1
              WHEN f.cvss_version IN ('CVSS 3.1','CVSS 3.0') THEN 2
              WHEN f.cvss_version = 'CVSS 2.0' THEN 3
              ELSE 9
            END ASC,
            f.cvss_score DESC NULLS LAST,
            CASE WHEN s.source_name = 'nvd@nist.gov' THEN 0 ELSE 1 END ASC,
            f.source_id ASC NULLS LAST
        ) AS rn
      FROM silver.dim_cve c
      JOIN silver.fact_cvss_scores f ON c.cve_id = f.cve_id
      LEFT JOIN silver.dim_cvss_source s ON f.source_id = s.source_id
    ),
    best AS (
      SELECT * FROM ranked WHERE rn = 1
    )
    -- Replace snapshot (truncate then insert)
    """
    with engine.begin() as conn:
        conn.execute(text("TRUNCATE TABLE gold.fact_cve_latest"))
        conn.execute(text(sql + """
            INSERT INTO gold.fact_cve_latest
            (cve_id, title, description, category, published_date, last_modified,
             remotely_exploit, source_identifier, cvss_version, cvss_score, cvss_severity,
             cvss_vector, source_id, source_name)
            SELECT
              cve_id, title, description, category, published_date, last_modified,
              remotely_exploit, source_identifier, cvss_version, cvss_score, cvss_severity,
              cvss_vector, source_id, source_name
            FROM best
        """))
    logger.info("✅ Loaded gold.fact_cve_latest")


def load_fact_cve_daily(engine: Engine):
    """
    Build daily aggregates from dim_cve + fact_cvss_scores.
    """
    logger.info("📥 Loading gold.fact_cve_daily ...")
    sql = """
    WITH base AS (
      SELECT
        c.cve_id,
        c.published_date::date AS dt,
        f.cvss_score,
        COALESCE(f.cvss_severity, 'UNKNOWN') AS sev,
        COUNT(DISTINCT f.source_id) OVER (PARTITION BY c.cve_id) AS src_cnt
      FROM silver.dim_cve c
      JOIN silver.fact_cvss_scores f ON c.cve_id = f.cve_id
    ),
    rolled AS (
      SELECT
        dt,
        COUNT(DISTINCT cve_id)               AS new_cve_count,
        AVG(cvss_score)                      AS avg_cvss_score,
        MAX(cvss_score)                      AS max_cvss_score,
        COUNT(*) FILTER (WHERE UPPER(sev) = 'CRITICAL') AS critical_count,
        COUNT(*) FILTER (WHERE UPPER(sev) = 'HIGH')     AS high_count,
        COUNT(*) FILTER (WHERE UPPER(sev) = 'MEDIUM')   AS medium_count,
        COUNT(*) FILTER (WHERE UPPER(sev) = 'LOW')      AS low_count,
        AVG(src_cnt::numeric)                AS source_diversity_avg
      FROM base
      GROUP BY dt
    )
    """
    with engine.begin() as conn:
        conn.execute(text("TRUNCATE TABLE gold.fact_cve_daily"))
        conn.execute(text(sql + """
            INSERT INTO gold.fact_cve_daily
            (dt, new_cve_count, avg_cvss_score, max_cvss_score,
             critical_count, high_count, medium_count, low_count, source_diversity_avg)
            SELECT * FROM rolled
        """))
    logger.info("✅ Loaded gold.fact_cve_daily")


def load_fact_vendor_product_risk(engine: Engine):
    """
    Vendor/product risk mart using silver bridge + facts.
    """
    logger.info("📥 Loading gold.fact_vendor_product_risk ...")
    sql = """
    WITH joined AS (
      SELECT
        p.vendor,
        p.product_name,
        p.total_cves,
        p.first_cve_date,
        p.last_cve_date,
        f.cve_id,
        f.cvss_score,
        COALESCE(f.cvss_severity, 'UNKNOWN') AS sev,
        f.source_id
      FROM silver.dim_products p
      LEFT JOIN silver.bridge_cve_products b ON p.product_id = b.product_id
      LEFT JOIN silver.fact_cvss_scores f ON b.cve_id = f.cve_id
    ),
    rolled AS (
      SELECT
        vendor,
        product_name,
        MAX(total_cves) AS total_cves,
        MIN(first_cve_date) AS first_cve_date,
        MAX(last_cve_date)  AS last_cve_date,
        AVG(cvss_score)     AS avg_cvss_score,
        MAX(cvss_score)     AS max_cvss_score,
        COUNT(*) FILTER (WHERE UPPER(sev) = 'CRITICAL') AS critical_count,
        COUNT(*) FILTER (WHERE UPPER(sev) = 'HIGH')     AS high_count,
        COUNT(*) FILTER (WHERE UPPER(sev) = 'MEDIUM')   AS medium_count,
        COUNT(*) FILTER (WHERE UPPER(sev) = 'LOW')      AS low_count,
        COUNT(DISTINCT source_id)                       AS distinct_sources
      FROM joined
      GROUP BY vendor, product_name
    )
    """
    with engine.begin() as conn:
        conn.execute(text("TRUNCATE TABLE gold.fact_vendor_product_risk"))
        conn.execute(text(sql + """
            INSERT INTO gold.fact_vendor_product_risk
            (vendor, product_name, total_cves, first_cve_date, last_cve_date,
             avg_cvss_score, max_cvss_score, critical_count, high_count,
             medium_count, low_count, distinct_sources)
            SELECT * FROM rolled
        """))
    logger.info("✅ Loaded gold.fact_vendor_product_risk")


def refresh_gold_materialized_views(engine: Engine):
    logger.info("🔄 Refreshing gold materialized views...")
    with engine.begin() as conn:
        conn.execute(text("REFRESH MATERIALIZED VIEW CONCURRENTLY gold.mv_overview_dashboard"))
    logger.info("✅ Gold MVs refreshed")


# ===============================================================
# Orchestrator
# ===============================================================
def run_gold_pipeline(engine: Engine = None):
    start = datetime.now()
    try:
        if engine is None:
            engine = create_db_engine()

        ensure_gold_schema(engine)

        # Calendar: ensure it covers min→max dates in silver
        with engine.connect() as conn:
            row = conn.execute(text("""
                SELECT
                  DATE(MIN(published_date)) AS min_dt,
                  DATE(GREATEST(MAX(last_modified), MAX(published_date))) AS max_dt
                FROM silver.dim_cve
            """)).mappings().first()
        if row and row["min_dt"] and row["max_dt"]:
            upsert_calendar(engine, row["min_dt"], row["max_dt"])
        else:
            # fallback: 5y range
            today = date.today()
            upsert_calendar(engine, today.replace(year=today.year-5), today)

        # Facts
        load_fact_cve_latest(engine)
        load_fact_cve_daily(engine)
        load_fact_vendor_product_risk(engine)

        # MVs
        refresh_gold_materialized_views(engine)

        # Stats
        with engine.connect() as conn:
            stats = {}
            for t in [
                "gold.dim_calendar",
                "gold.fact_cve_latest",
                "gold.fact_cve_daily",
                "gold.fact_vendor_product_risk",
            ]:
                cnt = conn.execute(text(f"SELECT COUNT(*) FROM {t}")).scalar()
                stats[t] = cnt

        dur = (datetime.now() - start).total_seconds()
        logger.info("===========================================")
        logger.info("📊 GOLD LOAD STATS")
        for t, c in stats.items():
            logger.info(f"  • {t}: {c:,} rows")
        logger.info(f"⏱️  Duration: {dur:.2f}s")
        logger.info("===========================================")
        logger.info("🎉 GOLD PIPELINE COMPLETED")
        return True

    except SQLAlchemyError as e:
        logger.error(f"❌ SQLAlchemy error: {e}")
        return False
    except Exception as e:
        logger.exception(f"❌ Unexpected error: {e}")
        return False


if __name__ == "__main__":
    print(f"▶ Running {Path(__file__).name}")
    run_gold_pipeline()