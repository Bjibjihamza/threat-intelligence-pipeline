#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SILVER ➜ GOLD TRANSFORMATION (V3 — aligned with vulnarbilit)
- Star schema outputs
- Parses CVSS vectors
- Append-only downstream loaders
- Matches new gold.dim_cve schema (uses vulnarbilit; drops title/description/...)
"""

from pathlib import Path
import sys
sys.path.append(str(Path(__file__).resolve().parents[2]))

import argparse
import logging
from typing import Optional, Dict, Any, Tuple, List
import json
import pandas as pd
from sqlalchemy.engine import Engine

from database.connection import create_db_engine, get_schema_name
from src.stream.load.load_gold_layer import load_gold_layer
from utils.cvss_parser import CVSSVectorParser

LOGS_DIR = Path(__file__).resolve().parents[3] / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOGS_DIR / "transformation_to_gold.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(LOG_FILE, encoding="utf-8"), logging.StreamHandler()],
)
logger = logging.getLogger("transformation_to_gold")

pd.set_option("display.max_columns", None)
pd.set_option("display.float_format", "{:.2f}".format)


# --------------------------- helpers ---------------------------
def _safe_json_load(x):
    try:
        if isinstance(x, str):
            s = x.strip()
            if s and s.lower() not in ("null", "none", "nan"):
                return json.loads(s)
        elif isinstance(x, (list, dict)):
            return x
    except Exception:
        pass
    return None

def _is_empty_json_like(x) -> bool:
    if x is None:
        return True
    if isinstance(x, float) and pd.isna(x):
        return True
    if isinstance(x, str):
        s = x.strip().lower()
        return s in ("", "[]", "null", "none", "nan")
    if isinstance(x, (list, tuple, dict)):
        return len(x) == 0
    return False

def _norm_text(s, maxlen: Optional[int] = None) -> str:
    val = "" if pd.isna(s) else str(s).replace("\xa0", " ").strip()
    return val[:maxlen] if maxlen else val


# ------------------------ load silver -------------------------
def load_silver_data(engine: Engine, limit: Optional[int] = None) -> pd.DataFrame:
    logger.info("=" * 72)
    logger.info("LOADING SILVER DATA")
    logger.info("=" * 72)

    silver_schema = get_schema_name("silver")
    if limit:
        query = f"""
            SELECT *
            FROM {silver_schema}.cve_cleaned
            ORDER BY published_date DESC
            LIMIT {int(limit)}
        """
    else:
        query = f"SELECT * FROM {silver_schema}.cve_cleaned;"

    df = pd.read_sql(query, engine)
    logger.info("Loaded %s rows from silver layer", len(df))
    return df


# ---------------------- dim_cve (NEW SHAPE) --------------------
def create_dim_cve(df: pd.DataFrame) -> pd.DataFrame:
    """
    Build gold.dim_cve aligned to new schema:
      cve_id, vulnarbilit, published_date, last_modified, loaded_at,
      cve_year (generated in DB), remotely_exploit, source_identifier
    """
    logger.info("Building dimension: dim_cve...")

    needed = [
        "cve_id",
        "vulnarbilit",
        "published_date",
        "last_modified",
        "loaded_at",
        "remotely_exploit",
        "source_identifier",
    ]
    for col in needed:
        if col not in df.columns:
            df[col] = None

    dim = df[needed].copy()

    # normalize
    dim["cve_id"] = dim["cve_id"].astype(str).str.slice(0, 20)
    dim["vulnarbilit"] = dim["vulnarbilit"].fillna("uncategorized").astype(str).str.slice(0, 50)

    for c in ["published_date", "last_modified", "loaded_at"]:
        dim[c] = pd.to_datetime(dim[c], errors="coerce")
    now = pd.Timestamp.utcnow().tz_localize(None)
    dim["published_date"] = dim["published_date"].fillna(now)
    dim["last_modified"] = dim["last_modified"].fillna(dim["published_date"])
    dim["loaded_at"] = dim["loaded_at"].fillna(now)

    if "remotely_exploit" in dim.columns:
        dim["remotely_exploit"] = dim["remotely_exploit"].astype("boolean")

    if "source_identifier" in dim.columns:
        dim["source_identifier"] = (
            dim["source_identifier"].astype(str).str.replace("\xa0", " ", regex=False).str.strip()
        )

    # unique by cve_id
    dim = (
        dim.sort_values(["cve_id", "last_modified", "loaded_at"])
        .drop_duplicates(subset=["cve_id"], keep="last")
        .reset_index(drop=True)
    )

    logger.info("dim_cve: %s unique CVEs", len(dim))
    return dim


# --------------------- cvss version helper ---------------------
def get_version_info(version_str: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    if version_str == "CVSS 2.0":
        return "v2", "CVSS 2.0"
    if version_str == "CVSS 3.0":
        return "v3", "CVSS 3.0"
    if version_str == "CVSS 3.1":
        return "v3", "CVSS 3.1"
    if version_str == "CVSS 4.0":
        return "v4", "CVSS 4.0"
    return None, None


# ----------------------- cvss fact frames ----------------------
def create_cvss_facts(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    logger.info("Building CVSS facts with vector extraction...")

    rec_v2: List[Dict[str, Any]] = []
    rec_v3: List[Dict[str, Any]] = []
    rec_v4: List[Dict[str, Any]] = []

    for _, row in df.iterrows():
        cve_id = row.get("cve_id")
        if not cve_id:
            continue

        scores = _safe_json_load(row.get("cvss_scores"))
        if _is_empty_json_like(scores):
            continue
        if isinstance(scores, dict):
            scores = [scores]

        for score_entry in scores:
            if not isinstance(score_entry, dict):
                continue

            version = score_entry.get("version")
            vkey, vlabel = get_version_info(version)
            if not vkey:
                continue

            source = _norm_text(score_entry.get("source_identifier") or score_entry.get("source"), 100) or "unknown"
            vector = _norm_text(score_entry.get("vector"))
            if not vector:
                continue

            score = score_entry.get("score")
            severity = score_entry.get("severity")
            exploitability = score_entry.get("exploitability_score")
            impact = score_entry.get("impact_score")

            if vkey == "v2":
                metrics = CVSSVectorParser.parse_vector(vector, "v2") or {}
                rec_v2.append(
                    {
                        "cve_id": cve_id[:20],
                        "cvss_source": source,
                        "cvss_score": score,
                        "cvss_severity": severity,
                        "cvss_vector": vector,
                        "cvss_v2_av": metrics.get("cvss_v2_av"),
                        "cvss_v2_ac": metrics.get("cvss_v2_ac"),
                        "cvss_v2_au": metrics.get("cvss_v2_au"),
                        "cvss_v2_c": metrics.get("cvss_v2_c"),
                        "cvss_v2_i": metrics.get("cvss_v2_i"),
                        "cvss_v2_a": metrics.get("cvss_v2_a"),
                        "cvss_exploitability_score": exploitability,
                        "cvss_impact_score": impact,
                    }
                )
            elif vkey == "v3":
                metrics = CVSSVectorParser.parse_vector(vector, "v3") or {}
                rec_v3.append(
                    {
                        "cve_id": cve_id[:20],
                        "cvss_source": source,
                        "cvss_version": vlabel,
                        "cvss_score": score,
                        "cvss_severity": severity,
                        "cvss_vector": vector,
                        "cvss_v3_base_av": metrics.get("cvss_v3_base_av"),
                        "cvss_v3_base_ac": metrics.get("cvss_v3_base_ac"),
                        "cvss_v3_base_pr": metrics.get("cvss_v3_base_pr"),
                        "cvss_v3_base_ui": metrics.get("cvss_v3_base_ui"),
                        "cvss_v3_base_s": metrics.get("cvss_v3_base_s"),
                        "cvss_v3_base_c": metrics.get("cvss_v3_base_c"),
                        "cvss_v3_base_i": metrics.get("cvss_v3_base_i"),
                        "cvss_v3_base_a": metrics.get("cvss_v3_base_a"),
                        "cvss_exploitability_score": exploitability,
                        "cvss_impact_score": impact,
                    }
                )
            elif vkey == "v4":
                metrics = CVSSVectorParser.parse_vector(vector, "v4") or {}
                rec_v4.append(
                    {
                        "cve_id": cve_id[:20],
                        "cvss_source": source,
                        "cvss_score": score,
                        "cvss_severity": severity,
                        "cvss_vector": vector,
                        "cvss_v4_av": metrics.get("cvss_v4_av"),
                        "cvss_v4_at": metrics.get("cvss_v4_at"),
                        "cvss_v4_ac": metrics.get("cvss_v4_ac"),
                        "cvss_v4_vc": metrics.get("cvss_v4_vc"),
                        "cvss_v4_vi": metrics.get("cvss_v4_vi"),
                        "cvss_v4_va": metrics.get("cvss_v4_va"),
                        "cvss_v4_sc": metrics.get("cvss_v4_sc"),
                        "cvss_v4_si": metrics.get("cvss_v4_si"),
                        "cvss_v4_sa": metrics.get("cvss_v4_sa"),
                    }
                )

    cvss_v2 = pd.DataFrame(rec_v2)
    cvss_v3 = pd.DataFrame(rec_v3)
    cvss_v4 = pd.DataFrame(rec_v4)

    for d in (cvss_v2, cvss_v3, cvss_v4):
        if not d.empty and "cvss_score" in d:
            d["cvss_score"] = pd.to_numeric(d["cvss_score"], errors="coerce")
            for col in ["cvss_exploitability_score", "cvss_impact_score"]:
                if col in d.columns:
                    d[col] = pd.to_numeric(d[col], errors="coerce")

    logger.info("CVSS Facts: v2=%s, v3=%s, v4=%s", len(cvss_v2), len(cvss_v3), len(cvss_v4))
    return cvss_v2, cvss_v3, cvss_v4


# -------- dim_vendor + dim_products + bridge (unchanged logic) --------
def create_vendors_products_and_bridge(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    logger.info("Building dim_vendor + dim_products + bridge_cve_products...")

    vendors_dict: Dict[str, Dict[str, Any]] = {}
    products_dict: Dict[Tuple[str, str], Dict[str, Any]] = {}
    bridge_records: List[Dict[str, Any]] = []

    for _, row in df.iterrows():
        cve_id = row.get("cve_id")
        if not cve_id:
            continue
        published_date = pd.to_datetime(row.get("published_date"), errors="coerce")

        products = _safe_json_load(row.get("affected_products"))
        if _is_empty_json_like(products):
            continue
        if isinstance(products, dict):
            products = [products]

        for prod in products:
            if not isinstance(prod, dict):
                continue
            vendor = _norm_text(prod.get("vendor"))
            product = _norm_text(prod.get("product"))
            if not vendor or not product:
                continue

            vkey = vendor.lower()
            pkey = product.lower()

            v = vendors_dict.get(vkey)
            if v is None:
                vendors_dict[vkey] = v = {
                    "vendor_name": vendor,
                    "total_products": set([pkey]),
                    "total_cves": 1,
                    "first_cve_date": published_date,
                    "last_cve_date": published_date,
                }
            else:
                v["total_cves"] += 1
                v["total_products"].add(pkey)
                if pd.notna(published_date):
                    if v["first_cve_date"] is None or published_date < v["first_cve_date"]:
                        v["first_cve_date"] = published_date
                    if v["last_cve_date"] is None or published_date > v["last_cve_date"]:
                        v["last_cve_date"] = published_date

            key = (vkey, pkey)
            p = products_dict.get(key)
            if p is None:
                products_dict[key] = p = {
                    "vendor_lower": vkey,
                    "product_name": product,
                    "total_cves": 1,
                    "first_cve_date": published_date,
                    "last_cve_date": published_date,
                }
            else:
                p["total_cves"] += 1
                if pd.notna(published_date):
                    if p["first_cve_date"] is None or published_date < p["first_cve_date"]:
                        p["first_cve_date"] = published_date
                    if p["last_cve_date"] is None or published_date > p["last_cve_date"]:
                        p["last_cve_date"] = published_date

            bridge_records.append({"cve_id": cve_id[:20], "vendor_lower": vkey, "product_lower": pkey})

    if not vendors_dict:
        return (
            pd.DataFrame(columns=["vendor_id", "vendor_name", "total_products", "total_cves", "first_cve_date", "last_cve_date"]),
            pd.DataFrame(columns=["product_id", "vendor_id", "product_name", "total_cves", "first_cve_date", "last_cve_date"]),
            pd.DataFrame(columns=["cve_id", "product_id"]),
        )

    for v in vendors_dict.values():
        v["total_products"] = len(v["total_products"])

    dim_vendor = pd.DataFrame(
        [
            {
                "vendor_id": i,
                "vendor_name": d["vendor_name"],
                "total_products": d["total_products"],
                "total_cves": d["total_cves"],
                "first_cve_date": d["first_cve_date"],
                "last_cve_date": d["last_cve_date"],
            }
            for i, (_, d) in enumerate(vendors_dict.items(), start=1)
        ]
    )
    vendor_lookup = {row["vendor_name"].lower(): int(row["vendor_id"]) for _, row in dim_vendor.iterrows()}

    dim_products = pd.DataFrame(
        [
            {
                "product_id": i,
                "vendor_id": vendor_lookup.get(d["vendor_lower"]),
                "product_name": d["product_name"],
                "total_cves": d["total_cves"],
                "first_cve_date": d["first_cve_date"],
                "last_cve_date": d["last_cve_date"],
            }
            for i, (_, d) in enumerate(products_dict.items(), start=1)
        ]
    )

    product_lookup = {
        (r["vendor_id"], r["product_name"].lower()): int(r["product_id"])
        for _, r in dim_products.iterrows()
        if pd.notna(r["vendor_id"])
    }

    bridge_df = pd.DataFrame(bridge_records)
    bridge_df["vendor_id"] = bridge_df["vendor_lower"].map(lambda v: vendor_lookup.get(v))
    bridge_df["product_id"] = bridge_df.apply(lambda x: product_lookup.get((x["vendor_id"], x["product_lower"])), axis=1)
    bridge = bridge_df[["cve_id", "product_id"]].dropna().drop_duplicates().reset_index(drop=True)

    logger.info("dim_vendor: %s, dim_products: %s, bridge: %s", len(dim_vendor), len(dim_products), len(bridge))
    return dim_vendor, dim_products, bridge


# ---------------------- orchestrate outputs ---------------------
def transform_silver_to_gold(df_silver: pd.DataFrame) -> Dict[str, pd.DataFrame]:
    logger.info("=" * 72)
    logger.info("SILVER ➜ GOLD TRANSFORMATION (V3 / vulnarbilit)")
    logger.info("=" * 72)

    dim_cve = create_dim_cve(df_silver)
    dim_vendor, dim_products, bridge_cve_products = create_vendors_products_and_bridge(df_silver)
    cvss_v2, cvss_v3, cvss_v4 = create_cvss_facts(df_silver)

    gold_tables = {
        "dim_cve": dim_cve,
        "dim_vendor": dim_vendor,
        "dim_products": dim_products,
        "cvss_v2": cvss_v2,
        "cvss_v3": cvss_v3,
        "cvss_v4": cvss_v4,
        "bridge_cve_products": bridge_cve_products,
    }

    logger.info("Gold tables prepared: %s", ", ".join(gold_tables.keys()))
    return gold_tables


# ----------------------------- CLI -----------------------------
def run_silver_to_gold(limit: Optional[int] = None, if_exists: str = "append") -> bool:
    logger.info("=" * 72)
    logger.info("SILVER ➜ GOLD PIPELINE (APPEND-ONLY)")
    logger.info("=" * 72)

    if if_exists == "replace":
        logger.warning("if_exists='replace' is deprecated; using append-only.")

    try:
        engine = create_db_engine()
        df_silver = load_silver_data(engine, limit=limit)
        if df_silver.empty:
            logger.warning("No data in silver layer.")
            return False

        gold_tables = transform_silver_to_gold(df_silver)
        logger.info("Loading to Gold layer (append)...")
        return load_gold_layer(gold_tables, engine, if_exists="append")

    except Exception as e:
        logger.error("Pipeline failed: %s", e, exc_info=True)
        return False


def parse_args():
    p = argparse.ArgumentParser(description="Silver ➜ Gold: Star Schema Transformation (append-only)")
    p.add_argument("--limit", type=int, default=None, help="Limit rows (testing)")
    p.add_argument("--if-exists", choices=["append", "replace"], default="append")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    ok = run_silver_to_gold(limit=args.limit, if_exists=args.if_exists)
    sys.exit(0 if ok else 1)
