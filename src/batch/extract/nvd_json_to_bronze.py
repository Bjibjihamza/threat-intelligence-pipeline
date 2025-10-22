# -*- coding: utf-8 -*-
# nvd_json_to_bronze.py
# =============================================================================
# NVD JSON 2.0 → PostgreSQL (raw.cve_details), SANS SCRAPING
# - Lit nvdcve-2.0-YYYY.json.zip
# - Extrait cve_id, published/lastModified (TEXT brutes), CVSS v4/v3/v2,
#   CPE (vendor/product), premier CWE brut comme "category"
# - AUCUN title, description, url
# - Charge via batch.load.load_bronze_layer.load_bronze_layer(...)
# =============================================================================

from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# -----------------------------------------------------------------------------
# ❗ Patch PYTHONPATH pour que "batch" & "database" soient importables
# -----------------------------------------------------------------------------
import sys
SRC_PATH = Path(__file__).resolve().parents[2]  # .../src
if str(SRC_PATH) not in sys.path:
    sys.path.append(str(SRC_PATH))

# -----------------------------------------------------------------------------
# Imports du projet (après patch sys.path)
# -----------------------------------------------------------------------------
from batch.load.load_bronze_layer import load_bronze_layer  # noqa: E402
from database.connection import create_db_engine            # noqa: E402

# -----------------------------------------------------------------------------
# CONFIG
# -----------------------------------------------------------------------------
# Dossier contenant nvdcve-2.0-*.json.zip
DATA_DIR = Path("../../../Data/Raw")      # adapte si besoin
YEARS = list(range(2002, 2026))           # 2002..2025
ZIP_PATTERN = "nvdcve-2.0-{}.json.zip"

# Regex CPE 2.3 : cpe:2.3:[a|h|o]:vendor:product:version:...
CPE23_RE = re.compile(r"^cpe:2\.3:[aho]:([^:]+):([^:]+):([^:]*)", re.IGNORECASE)


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def first_cwe_raw(weaknesses: List[Dict[str, Any]]) -> str:
    """Retourne le premier identifiant CWE brut (ex: 'CWE-89'). Aucun mapping."""
    if not isinstance(weaknesses, list):
        return ""
    for w in weaknesses:
        for d in (w.get("description") or []):
            val = (d.get("value") or "").strip()
            if val.startswith("CWE-"):
                return val
    return ""


def collect_cvss(metrics: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Agrège CVSS v4.0 / v3.1 / v3.0 / v2.0 en une liste homogène.
    On conserve: version, score, severity, vector, exploitability_score, impact_score,
                 source_identifier, type.
    """
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

    # v2 a de légères différences (baseSeverity peut être au niveau parent)
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

    # Conserver les lignes non vides
    out = [r for r in out if (r.get("version") or r.get("score") or r.get("vector"))]
    return out


def parse_cpe_vendor_product(cpe23uri: str) -> Tuple[str, str]:
    """
    Extrait (vendor, product) depuis un CPE 2.3 (cpe:2.3:a:vendor:product:...).
    """
    if not cpe23uri:
        return "", ""
    m = CPE23_RE.match(cpe23uri)
    if not m:
        return "", ""
    vendor = (m.group(1) or "").strip()
    product = (m.group(2) or "").strip()
    return vendor, product


# remplace toute la fonction collect_products(...) par ceci

def collect_products(configurations: Any) -> List[Dict[str, str]]:
    """
    Retourne une liste distincte de {"vendor","product"} depuis configurations.
    Gère les deux formes NVD rencontrées:
      - dict avec "nodes": [...]
      - list de dicts, chacun éventuellement avec "nodes": [...]
    Gère aussi les variantes de clés: "cpeMatch" ou "matches",
    et "criteria" ou "cpe23Uri".
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

        # 1) lignes CPE (variantes: cpeMatch / matches)
        for match in (node.get("cpeMatch") or node.get("matches") or []):
            if not isinstance(match, dict):
                continue
            cpe_uri = match.get("criteria") or match.get("cpe23Uri") or match.get("cpe")
            add_vendor_product(cpe_uri)

        # 2) enfants
        for child in (node.get("children") or []):
            walk_node(child)

    # --- racine: dict ou list
    if isinstance(configurations, dict):
        for n in (configurations.get("nodes") or []):
            walk_node(n)
    elif isinstance(configurations, list):
        for cfg in configurations:
            if isinstance(cfg, dict):
                for n in (cfg.get("nodes") or []):
                    walk_node(n)
    else:
        # rien
        pass

    return prods



def load_year_file(zip_path: Path) -> List[Dict[str, Any]]:
    """
    Charge un nvdcve-2.0-YYYY.json.zip et renvoie une liste de dicts
    conformes au schéma Bronze sans title/description/url.
    - Dates gardées en TEXT (publié / modifié) exactement comme NVD les fournit.
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

        # ⚠️ Bronze: garder les dates en TEXT (aucun parsing → coller 1:1 au JSON NVD)
        published_text = cve.get("published") or None
        modified_text = cve.get("lastModified") or None

        category_raw = first_cwe_raw(cve.get("weaknesses", []))
        cvss = collect_cvss(cve.get("metrics", {}) or {})
        products = collect_products(cve.get("configurations", {}) or {})
        source_identifier = cve.get("sourceIdentifier") or None

        row = {
            "cve_id": cve_id,
            "published_date": published_text,   # TEXT
            "last_modified": modified_text,     # TEXT
            "remotely_exploit": None,           # NVD ne fournit pas un bool direct
            "source_identifier": source_identifier,
            "category": category_raw,           # ex: 'CWE-89'
            "affected_products": products,      # list[dict]
            "cvss_scores": cvss,                # list[dict]
        }
        rows.append(row)

    return rows


def main(engine=None):
    if engine is None:
        engine = create_db_engine()

    total_parsed = 0
    total_inserted = 0

    for year in YEARS:
        zp = DATA_DIR / ZIP_PATTERN.format(year)
        if not zp.exists():
            print(f"[SKIP] {year} — {zp.name} not found")
            continue

        print(f"[LOAD] {year} — {zp.name}")
        rows = load_year_file(zp)
        total_parsed += len(rows)

        # 🔗 Charge via le loader Bronze commun
        stats = load_bronze_layer(rows, engine)
        total_inserted += (stats or {}).get("inserted", 0)

    print("=" * 70)
    print(f"Done. Parsed total: {total_parsed:,} | Inserted total: {total_inserted:,}")


if __name__ == "__main__":
    main()
