#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LOAD GOLD LAYER (V3 — aligned with vulnarbilit)
- Append-only inserts
- Skips existing rows
- Matches new gold schema (no materialized views; dim_cve uses vulnarbilit)
"""

from pathlib import Path
import sys
sys.path.append(str(Path(__file__).resolve().parents[2]))

import logging
from typing import Dict, Optional, Set
from datetime import datetime

import pandas as pd
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.engine import Engine

from database.connection import create_db_engine, get_schema_name

LOGS_DIR = Path(__file__).resolve().parents[3] / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOGS_DIR / "load_gold_layer.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(LOG_FILE, encoding="utf-8"), logging.StreamHandler()],
)
logger = logging.getLogger("load_gold_layer")


# --------------------- schema validation ----------------------
def verify_gold_schema(engine: Engine) -> bool:
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
    logger.info("Verifying gold schema '%s'...", schema)
    try:
        with engine.connect() as conn:
            r = conn.execute(
                text("SELECT 1 FROM information_schema.schemata WHERE schema_name=:s"),
                {"s": schema},
            ).fetchone()
            if not r:
                logger.error("Schema '%s' does not exist.", schema)
                return False
            for t in required_tables:
                r = conn.execute(
                    text(
                        "SELECT 1 FROM information_schema.tables WHERE table_schema=:s AND table_name=:t"
                    ),
                    {"s": schema, "t": t},
                ).fetchone()
                if not r:
                    logger.error("Table %s.%s does not exist.", schema, t)
                    return False
        logger.info("Gold schema validated.")
        return True
    except Exception as e:
        logger.error("Schema validation error: %s", e)
        return False


# -------------------- dim_cvss_source loader -------------------
def load_dim_cvss_source(cvss_v2: pd.DataFrame, cvss_v3: pd.DataFrame, cvss_v4: pd.DataFrame, engine: Engine,
                         if_exists: str = "append") -> Dict[str, int]:
    schema = get_schema_name("gold")
    logger.info("Loading dim_cvss_source (append-only)...")

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
        logger.info("No CVSS sources found.")
        return {}

    with engine.connect() as conn:
        existing = {row[0] for row in conn.execute(text(f"SELECT source_name FROM {schema}.dim_cvss_source"))}

    new_sources = sorted(s for s in sources if s and s not in existing)
    if new_sources:
        pd.DataFrame({"source_name": new_sources}).to_sql(
            name="dim_cvss_source", con=engine, schema=schema, if_exists="append", index=False, method="multi", chunksize=1000
        )

    with engine.connect() as conn:
        mp = {row[1]: row[0] for row in conn.execute(text(f"SELECT source_id, source_name FROM {schema}.dim_cvss_source"))}

    logger.info("dim_cvss_source total: %s", len(mp))
    return mp


# ------------------ dimension helpers / loaders ----------------
def _reindex_for_table(df: pd.DataFrame, table_name: str) -> pd.DataFrame:
    schemas = {
        "dim_cve": [
            "cve_id",
            "vulnarbilit",
            "published_date",
            "last_modified",
            "loaded_at",
            "remotely_exploit",
            "source_identifier",
        ],
        "dim_vendor": [
            "vendor_id",
            "vendor_name",
            "total_products",
            "total_cves",
            "first_cve_date",
            "last_cve_date",
        ],
        "dim_products": [
            "product_id",
            "vendor_id",
            "product_name",
            "total_cves",
            "first_cve_date",
            "last_cve_date",
        ],
    }
    cols = schemas.get(table_name)
    return df.reindex(columns=cols) if cols else df

def _prepare_dim_cve(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["cve_id"] = df["cve_id"].astype(str).str.slice(0, 20)
    df["vulnarbilit"] = df["vulnarbilit"].fillna("uncategorized").astype(str).str.slice(0, 50)

    for col in ["published_date", "last_modified", "loaded_at"]:
        df[col] = pd.to_datetime(df[col], errors="coerce")
    now = pd.Timestamp.utcnow().tz_localize(None)
    df["published_date"] = df["published_date"].fillna(now)
    df["last_modified"] = df["last_modified"].fillna(df["published_date"])
    df["loaded_at"] = df["loaded_at"].fillna(now)

    if "remotely_exploit" in df.columns:
        df["remotely_exploit"] = df["remotely_exploit"].astype("boolean")

    if "source_identifier" in df.columns:
        df["source_identifier"] = (
            df["source_identifier"].astype(str).str.replace("\xa0", " ", regex=False).str.strip()
        )
    return df

def load_dimension(df: pd.DataFrame, table_name: str, engine: Engine, if_exists: str = "append") -> int:
    schema = get_schema_name("gold")
    full = f"{schema}.{table_name}"
    logger.info("Loading %s (append-only)...", table_name)

    if df.empty:
        logger.info("No data for %s.", table_name)
        return 0

    if table_name == "dim_cve":
        df = _prepare_dim_cve(df)
    df = _reindex_for_table(df, table_name)

    # PK detection
    pk_col = "cve_id" if table_name == "dim_cve" else f"{table_name.split('_')[1]}_id"
    if pk_col in df.columns:
        ids = df[pk_col].dropna().tolist()
        if table_name == "dim_cve":
            escaped = ["'" + str(v).replace("'", "''") + "'" for v in ids]
        else:
            escaped = [str(int(v)) for v in ids if pd.notna(v)]
        placeholders = ",".join(escaped) if escaped else "NULL"

        with engine.connect() as conn:
            existing = {
                row[0]
                for row in conn.execute(text(f"SELECT {pk_col} FROM {full} WHERE {pk_col} IN ({placeholders})"))
            }

        df = df[~df[pk_col].isin(existing)].copy()

        if df.empty:
            logger.info("All records already exist in %s.", table_name)
            return 0

    try:
        df.to_sql(name=table_name, con=engine, schema=schema, if_exists="append", index=False, method="multi", chunksize=1000)
        logger.info("%s: %s rows inserted.", table_name, len(df))
        return len(df)
    except Exception as e:
        logger.error("Load error for %s: %s", table_name, e, exc_info=True)
        return 0


# ------------------------- facts loaders -----------------------
def load_fact_cvss(df: pd.DataFrame, table_name: str, source_mapping: Dict[str, int], engine: Engine,
                   if_exists: str = "append") -> int:
    schema = get_schema_name("gold")
    full = f"{schema}.{table_name}"
    logger.info("Loading %s (append-only)...", table_name)

    if df.empty:
        logger.info("No data for %s.", table_name)
        return 0

    df = df.copy()
    if "cve_id" in df:
        df = df[df["cve_id"].notna()]
        df["cve_id"] = df["cve_id"].astype(str).str.slice(0, 20)
    if "cvss_vector" in df:
        df = df[df["cvss_vector"].astype(str).str.len() > 0]

    if "cvss_source" in df.columns:
        df["cvss_source"] = (
            df["cvss_source"].astype(str).str.replace("\xa0", " ", regex=False).str.strip().str[:100]
        )
        df["source_id"] = df["cvss_source"].map(source_mapping)
        df = df.drop(columns=["cvss_source"])
        df = df[df["source_id"].notna()]

    if df.empty:
        logger.info("No valid rows for %s after mapping.", table_name)
        return 0

    # dedupe by composite key
    df["_k"] = df["cve_id"].astype(str) + "|" + df["source_id"].astype(str) + "|" + df["cvss_vector"].astype(str)
    with engine.connect() as conn:
        existing = {r[0] for r in conn.execute(text(f"SELECT cve_id || '|' || source_id::TEXT || '|' || cvss_vector FROM {full}"))}
    df = df[~df["_k"].isin(existing)].drop(columns=["_k"])

    if df.empty:
        logger.info("All rows already exist in %s.", table_name)
        return 0

    try:
        df.to_sql(name=table_name, con=engine, schema=schema, if_exists="append", index=False, method="multi", chunksize=1000)
        logger.info("%s: %s rows inserted.", table_name, len(df))
        return len(df)
    except Exception as e:
        logger.error("Load error for %s: %s", table_name, e, exc_info=True)
        return 0


def load_bridge(df: pd.DataFrame, engine: Engine, if_exists: str = "append") -> int:
    schema = get_schema_name("gold")
    table = "bridge_cve_products"
    full = f"{schema}.{table}"
    logger.info("Loading %s (append-only)...", table)

    if df.empty:
        logger.info("No data for %s.", table)
        return 0

    df = df[["cve_id", "product_id"]].dropna().drop_duplicates()
    df["cve_id"] = df["cve_id"].astype(str).str.slice(0, 20)

    df["_k"] = df["cve_id"].astype(str) + "|" + df["product_id"].astype(str)
    with engine.connect() as conn:
        existing = {r[0] for r in conn.execute(text(f"SELECT cve_id || '|' || product_id::TEXT FROM {full}"))}
    df = df[~df["_k"].isin(existing)].drop(columns=["_k"])

    if df.empty:
        logger.info("All relationships already exist in %s.", table)
        return 0

    try:
        df.to_sql(name=table, con=engine, schema=schema, if_exists="append", index=False, method="multi", chunksize=1000)
        logger.info("%s: %s relationships inserted.", table, len(df))
        return len(df)
    except Exception as e:
        logger.error("Load error for %s: %s", table, e, exc_info=True)
        return 0


# -------------------------- main loader ------------------------
def load_gold_layer(tables: Dict[str, pd.DataFrame], engine: Optional[Engine] = None, if_exists: str = "append") -> bool:
    logger.info("=" * 72)
    logger.info("GOLD LAYER LOAD PIPELINE (APPEND-ONLY)")
    logger.info("=" * 72)

    required = ["dim_cve", "dim_vendor", "dim_products", "cvss_v2", "cvss_v3", "cvss_v4", "bridge_cve_products"]
    miss = [t for t in required if t not in tables]
    if miss:
        logger.error("Missing tables: %s", miss)
        return False

    try:
        if engine is None:
            engine = create_db_engine()
        if not verify_gold_schema(engine):
            return False

        start = datetime.now()

        # dim_cvss_source first (mapping)
        source_map = load_dim_cvss_source(tables["cvss_v2"], tables["cvss_v3"], tables["cvss_v4"], engine, "append")

        # dimensions
        n_dim_cve = load_dimension(tables["dim_cve"], "dim_cve", engine, "append")
        n_vendor = load_dimension(tables["dim_vendor"], "dim_vendor", engine, "append")
        n_products = load_dimension(tables["dim_products"], "dim_products", engine, "append")

        # facts
        n_v2 = load_fact_cvss(tables["cvss_v2"], "cvss_v2", source_map, engine, "append")
        n_v3 = load_fact_cvss(tables["cvss_v3"], "cvss_v3", source_map, engine, "append")
        n_v4 = load_fact_cvss(tables["cvss_v4"], "cvss_v4", source_map, engine, "append")

        # bridge
        n_bridge = load_bridge(tables["bridge_cve_products"], engine, "append")

        # analyze
        schema = get_schema_name("gold")
        with engine.begin() as conn:
            for t in [
                "dim_cve",
                "dim_cvss_source",
                "dim_vendor",
                "dim_products",
                "cvss_v2",
                "cvss_v3",
                "cvss_v4",
                "bridge_cve_products",
            ]:
                conn.execute(text(f"ANALYZE {schema}.{t};"))

        dur = (datetime.now() - start).total_seconds()
        logger.info("GOLD LOAD STATS — dim_cve=%s, vendor=%s, products=%s, v2=%s, v3=%s, v4=%s, bridge=%s, duration=%.2fs",
                    n_dim_cve, n_vendor, n_products, n_v2, n_v3, n_v4, n_bridge, dur)
        logger.info("GOLD LAYER LOAD COMPLETED (APPEND-ONLY)")
        return True

    except Exception as e:
        logger.error("Gold layer load failed: %s", e, exc_info=True)
        return False


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Load data to Gold layer (append-only)")
    p.add_argument("--test", action="store_true")
    args = p.parse_args()
    if args.test:
        logger.info("Test mode: import this module from the transformer runner.")
    else:
        logger.info("This module is intended to be imported by transformation_to_gold_m.py")
