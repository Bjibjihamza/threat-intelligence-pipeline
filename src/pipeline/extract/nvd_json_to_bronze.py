# -*- coding: utf-8 -*-
# =============================================================================
# src/batch/extract/nvd_json_to_bronze.py
# NVD JSON 2.0 → Bronze → (auto) Silver → (auto) Gold
# =============================================================================
# UPDATED: Uses unified Bronze loader from src/pipeline/load/load_bronze_layer.py
# =============================================================================

from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import sys
SRC_PATH = Path(__file__).resolve().parents[2]  # .../src
if str(SRC_PATH) not in sys.path:
    sys.path.append(str(SRC_PATH))

# -----------------------------------------------------------------------------
# Imports projet
# -----------------------------------------------------------------------------
# 🔥 UNIFIED BRONZE LOADER
from pipeline.load.load_bronze_layer import load_bronze_layer

from database.connection import create_db_engine

# Pipelines suivants
from pipeline.transform.nvd_EDA_bronze_to_silver import run_eda_to_silver
from pipeline.transform.transformation_to_gold import run_silver_to_gold

import argparse
import logging

# -----------------------------------------------------------------------------
# CONFIG par défaut (surchargé par CLI)
# -----------------------------------------------------------------------------
DATA_DIR_DEFAULT = Path("../../../Data/Raw")
YEARS_DEFAULT = list(range(2002, 2026))  # 2002..2025 inclus
ZIP_PATTERN = "nvdcve-2.0-{}.json.zip"

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
LOGS_DIR = Path(__file__).resolve().parents[3] / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOGS_DIR / "nvd_bronze_full_pipeline.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(LOG_FILE, encoding="utf-8"), logging.StreamHandler()],
)
logger = logging.getLogger("nvd_bronze_full_pipeline")

# -----------------------------------------------------------------------------
# Regex CPE 2.3
# -----------------------------------------------------------------------------
CPE23_RE = re.compile(r"^cpe:2\.3:[aho]:([^:]+):([^:]+):([^:]*)", re.IGNORECASE)

# -----------------------------------------------------------------------------
# Helpers d'extraction
# -----------------------------------------------------------------------------
def first_cwe_raw(weaknesses: List[Dict[str, Any]]) -> str:
    """Extract first CWE-XXX from weaknesses list."""
    if not isinstance(weaknesses, list):
        return ""
    for w in weaknesses:
        for d in (w.get("description") or []):
            val = (d.get("value") or "").strip()
            if val.startswith("CWE-"):
                return val
    return ""

def collect_cvss(metrics: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Collect all CVSS scores (v4.0, v3.1, v3.0, v2.0) from metrics."""
    out: List[Dict[str, Any]] = []
    if not isinstance(metrics, dict):
        return out

    def add_many(items, version_key: str):
        for row in (items or []):
            d = row.get("cvssData", {}) or {}
            out.append({
                "version": version_key,
                "score": d.get("baseScore"),
                "severity": d.get("baseSeverity"),
                "vector": d.get("vectorString"),
                "exploitability_score": row.get("exploitabilityScore"),
                "impact_score": row.get("impactScore"),
                "source_identifier": row.get("source"),
                "type": row.get("type"),
            })

    add_many(metrics.get("cvssMetricV40"), "4.0")
    add_many(metrics.get("cvssMetricV31"), "3.1")
    add_many(metrics.get("cvssMetricV30"), "3.0")

    # CVSS v2.0
    for row in (metrics.get("cvssMetricV2") or []):
        d = row.get("cvssData", {}) or {}
        out.append({
            "version": "2.0",
            "score": d.get("baseScore"),
            "severity": row.get("baseSeverity") or d.get("baseSeverity"),
            "vector": d.get("vectorString"),
            "exploitability_score": row.get("exploitabilityScore"),
            "impact_score": row.get("impactScore"),
            "source_identifier": row.get("source"),
            "type": row.get("type"),
        })

    return [r for r in out if (r.get("version") or r.get("score") or r.get("vector"))]

def parse_cpe_vendor_product(cpe23uri: str) -> Tuple[str, str]:
    """Parse CPE 2.3 URI to extract vendor and product."""
    if not cpe23uri:
        return "", ""
    m = CPE23_RE.match(cpe23uri)
    if not m:
        return "", ""
    vendor = (m.group(1) or "").strip()
    product = (m.group(2) or "").strip()
    return vendor, product

def collect_products(configurations: Any) -> List[Dict[str, str]]:
    """
    Return distinct list of {"vendor","product"} from configurations.
    Handles dict/list root, cpeMatch/matches and criteria/cpe23Uri/cpe.
    """
    prods: List[Dict[str, str]] = []
    seen = set()

    def add_vendor_product(cpe_uri: Optional[str]):
        vendor, product = parse_cpe_vendor_product(cpe_uri or "")
        if vendor or product:
            key = f"{vendor}::{product}"
            if key not in seen:
                seen.add(key)
                prods.append({"vendor": vendor, "product": product})

    def walk_node(node: Dict[str, Any]):
        if not isinstance(node, dict):
            return
        for match in (node.get("cpeMatch") or node.get("matches") or []):
            if not isinstance(match, dict):
                continue
            cpe_uri = match.get("criteria") or match.get("cpe23Uri") or match.get("cpe")
            add_vendor_product(cpe_uri)
        for child in (node.get("children") or []):
            walk_node(child)

    if isinstance(configurations, dict):
        for n in (configurations.get("nodes") or []):
            walk_node(n)
    elif isinstance(configurations, list):
        for cfg in configurations:
            if isinstance(cfg, dict):
                for n in (cfg.get("nodes") or []):
                    walk_node(n)
    return prods

def load_year_file(zip_path: Path) -> List[Dict[str, Any]]:
    """
    Load nvdcve-2.0-YYYY.json.zip and return list of dicts conforming to Bronze schema.
    Dates = TEXT (no parsing).
    """
    with zipfile.ZipFile(zip_path, "r") as zf:
        members = [n for n in zf.namelist() if n.endswith(".json")]
        if not members:
            return []
        with zf.open(members[0], "r") as f:
            data = json.loads(f.read().decode("utf-8"))

    rows: List[Dict[str, Any]] = []
    for v in (data.get("vulnerabilities") or []):
        cve = v.get("cve", {}) or {}
        cve_id = cve.get("id") or ""
        if not cve_id.startswith("CVE-"):
            continue

        row = {
            "cve_id": cve_id,
            "published_date": cve.get("published") or None,   # TEXT
            "last_modified": cve.get("lastModified") or None, # TEXT
            "remotely_exploit": None,                         # Unknown from NVD
            "source_identifier": cve.get("sourceIdentifier") or None,
            "category": first_cwe_raw(cve.get("weaknesses", [])),
            "affected_products": collect_products(cve.get("configurations", {}) or {}),
            "cvss_scores": collect_cvss(cve.get("metrics", {}) or {}),
        }
        rows.append(row)

    return rows

# -----------------------------------------------------------------------------
# CLI & Run
# -----------------------------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser(
        description="NVD JSON → Bronze → (auto) Silver → (auto) Gold"
    )
    p.add_argument(
        "--data-dir", 
        type=Path, 
        default=DATA_DIR_DEFAULT,
        help="Folder containing nvdcve-2.0-*.json.zip files"
    )
    p.add_argument(
        "--start-year", 
        type=int, 
        default=min(YEARS_DEFAULT),
        help="Start year for processing"
    )
    p.add_argument(
        "--end-year", 
        type=int, 
        default=max(YEARS_DEFAULT),
        help="End year for processing (inclusive)"
    )
    p.add_argument(
        "--silver-mode", 
        choices=["append", "replace"], 
        default="replace",
        help="Loading mode for silver.cve_cleaned"
    )
    p.add_argument(
        "--gold-mode", 
        choices=["append", "replace"], 
        default="replace",
        help="Loading mode for gold.*"
    )
    p.add_argument(
        "--limit", 
        type=int, 
        default=None,
        help="Limit rows for EDA/Silver & Silver→Gold (debug)"
    )
    p.add_argument(
        "--skip-silver", 
        action="store_true", 
        help="Skip EDA→Silver step"
    )
    p.add_argument(
        "--skip-gold", 
        action="store_true", 
        help="Skip Silver→Gold step"
    )
    return p.parse_args()

def main():
    args = parse_args()
    years = list(range(args.start_year, args.end_year + 1))
    engine = create_db_engine()

    # ==========================================================================
    # STEP 1/3: Load Bronze from NVD zips (UNIFIED LOADER)
    # ==========================================================================
    total_parsed = 0
    total_inserted = 0
    
    logger.info("=" * 72)
    logger.info("🚀 STEP 1/3 — Loading Bronze from NVD zips (UNIFIED LOADER)")
    logger.info("=" * 72)

    for year in years:
        zp = args.data_dir / ZIP_PATTERN.format(year)
        if not zp.exists():
            logger.warning(f"[SKIP] {year} — {zp.name} not found")
            continue
        
        logger.info(f"[LOAD] {year} — {zp.name}")
        rows = load_year_file(zp)
        total_parsed += len(rows)
        
        # 🔥 Use unified loader
        stats = load_bronze_layer(rows, engine) or {}
        total_inserted += stats.get("inserted", 0)

    logger.info("-" * 72)
    logger.info(f"Bronze summary: parsed={total_parsed:,}  inserted={total_inserted:,}")

    # ==========================================================================
    # STEP 2/3: EDA + Silver load
    # ==========================================================================
    if not args.skip_silver:
        logger.info("=" * 72)
        logger.info(
            f"🚀 STEP 2/3 — EDA + Load to Silver "
            f"(mode={args.silver_mode}, limit={args.limit})"
        )
        logger.info("=" * 72)
        ok_silver = run_eda_to_silver(limit=args.limit, if_exists=args.silver_mode)
        if not ok_silver:
            logger.error("❌ EDA→Silver failed; stopping pipeline.")
            return 2
    else:
        logger.info("⏭️  Skipping EDA→Silver as requested.")

    # ==========================================================================
    # STEP 3/3: Silver → Gold transform + load
    # ==========================================================================
    if not args.skip_gold:
        logger.info("=" * 72)
        logger.info(
            f"🚀 STEP 3/3 — Transform & Load to Gold "
            f"(mode={args.gold_mode}, limit={args.limit})"
        )
        logger.info("=" * 72)
        ok_gold = run_silver_to_gold(limit=args.limit, if_exists=args.gold_mode)
        if not ok_gold:
            logger.error("❌ Silver→Gold failed.")
            return 3
    else:
        logger.info("⏭️  Skipping Silver→Gold as requested.")

    # ==========================================================================
    # DONE
    # ==========================================================================
    logger.info("=" * 72)
    logger.info("🎉 Full pipeline done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())