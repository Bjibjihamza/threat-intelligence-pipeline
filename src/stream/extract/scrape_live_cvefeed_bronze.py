#!/usr/bin/env python3
# =============================================================================
# TELEGRAM → CVE DETAILS → COMPLETE ETL PIPELINE (Bronze → Silver → Gold)
# =============================================================================
# Description: Scrape CVEs from Telegram → Bronze → EDA → Silver → Gold
# Location: src/stream/extract/telegram_cve_complete_pipeline.py
# =============================================================================

from pathlib import Path
import sys
import re
import os
import time
import logging
import binascii
from typing import List, Dict, Any, Optional, Set
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import json
import requests
import pandas as pd
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from sqlalchemy import text
from sqlalchemy.engine import Engine

# Telethon
from telethon import TelegramClient
from telethon.errors import FloodWaitError, SessionPasswordNeededError
from telethon.tl.types import Message, PeerChannel

# ========================= Project Paths Setup ==========================
THIS_FILE = Path(__file__).resolve()
PROJECT_ROOT = THIS_FILE.parents[3]  # repo root
SRC_DIR = PROJECT_ROOT / "src"

for p in (str(PROJECT_ROOT), str(SRC_DIR)):
    if p not in sys.path:
        sys.path.append(p)

# ========================= Import Pipeline Modules ======================
from stream.load.load_bronze_layer import load_bronze_layer
from stream.load.load_silver_layer import load_silver_layer
from stream.load.load_gold_layer import load_gold_layer
from database.connection import create_db_engine, get_schema_name

# ⭐ IMPORTANT: Import EDA + Gold transformation
from stream.transform.EDA_bronze_to_silver_m import (
    perform_eda,
    clean_silver_data,
    create_silver_layer
)
from stream.transform.transformation_to_gold_m import transform_silver_to_gold

# =========================== Config / .env ==============================
load_dotenv(dotenv_path=PROJECT_ROOT / ".env")

LOGS_DIR = PROJECT_ROOT / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOGS_DIR / "telegram_cve_complete_pipeline.log"

RUNTIME_DIR = PROJECT_ROOT / ".runtime"
RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
SESSION_FILE = RUNTIME_DIR / "telegram.session"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(LOG_FILE, encoding="utf-8"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

# Telegram credentials
TELEGRAM_API_ID = int(os.getenv("TELEGRAM_API_ID", "0"))
TELEGRAM_API_HASH = os.getenv("TELEGRAM_API_HASH", "")
TELEGRAM_CHANNEL_ID = os.getenv("TELEGRAM_CHANNEL_ID", "-1002636168605")

# Time / window
TIMEZONE = os.getenv("TIMEZONE", "Africa/Casablanca")
CATCHUP_DAYS_AGO = int(os.getenv("CATCHUP_DAYS_AGO", "1"))

# cvefeed URL
CVEFEED_CVE_URL = "https://cvefeed.io/vuln/detail/{cve_id}"

# Optional year filter
_raw_years = os.getenv("TARGET_YEARS", "").strip()
TARGET_YEARS: Optional[List[int]] = (
    [int(y) for y in _raw_years.split(",") if y.strip().isdigit()] if _raw_years else None
)

DETAIL_DELAY_SEC = float(os.getenv("DETAIL_DELAY_SEC", "1.2"))

# ==================== Cloudflare Email Decoding =========================
def decode_cfemail(hex_str: str) -> str:
    try:
        data = bytearray(binascii.unhexlify(hex_str))
        if not data:
            return ""
        key = data[0]
        return ''.join(chr(b ^ key) for b in data[1:])
    except Exception:
        return ""

def extract_email_from_tag(tag) -> str:
    if not tag:
        return ""
    cf = tag.find(["a", "span"], class_=re.compile(r"__cf_email__"))
    if cf and cf.has_attr("data-cfemail"):
        decoded = decode_cfemail(cf["data-cfemail"])
        if decoded:
            return decoded.strip()
    link = tag.find("a", href=True)
    if link and isinstance(link["href"], str) and link["href"].lower().startswith("mailto:"):
        return link["href"].split("mailto:", 1)[-1].strip()
    return tag.get_text(" ", strip=True).strip()

# ===================== Telegram Authentication ==========================
async def telegram_authenticate(client: TelegramClient) -> bool:
    if not TELEGRAM_API_ID or not TELEGRAM_API_HASH:
        logger.error("❌ TELEGRAM_API_ID / TELEGRAM_API_HASH are missing in .env")
        return False

    try:
        await client.connect()
    except Exception as e:
        logger.error(f"Failed to connect to Telegram: {e}")
        return False

    if await client.is_user_authorized():
        logger.info("✅ Telegram: already authenticated")
        return True

    try:
        phone = input("Enter your phone number (e.g., +212...): ").strip()
        await client.send_code_request(phone)
        code = input("Enter the code you received: ").strip()
        try:
            await client.sign_in(phone, code)
            logger.info("✅ Telegram: signed in via phone")
            return True
        except SessionPasswordNeededError:
            pwd = input("Two-factor enabled. Enter your password: ")
            await client.sign_in(password=pwd)
            logger.info("✅ Telegram: signed in with 2FA password")
            return True
    except Exception as e:
        logger.error(f"Telegram auth failed: {e}")
        return False

    return False

# ===================== CVE ID Extraction ================================
def extract_cve_ids_from_text(text: Optional[str]) -> List[str]:
    if not text:
        return []
    pattern = re.compile(r"\bCVE-(\d{4})-(\d{4,})\b")
    seen: Set[str] = set()
    out: List[str] = []
    for m in pattern.finditer(text):
        year = int(m.group(1))
        cve = f"CVE-{m.group(1)}-{m.group(2)}"
        if TARGET_YEARS is not None and year not in TARGET_YEARS:
            continue
        if cve not in seen:
            seen.add(cve)
            out.append(cve)
    return out

# =================== Telegram CVE Collection ============================
async def collect_cve_ids_from_telegram_for_day(
    client: TelegramClient, channel_id: str, day_local: datetime, tz: ZoneInfo
) -> List[str]:
    """Return unique CVE IDs posted during [day 00:00, 24:00) local."""
    start_local = day_local.replace(hour=0, minute=0, second=0, microsecond=0)
    end_local = start_local + timedelta(days=1)
    start_utc = start_local.astimezone(timezone.utc)
    end_utc = end_local.astimezone(timezone.utc)

    logger.info(f"📅 Window local: {start_local} → {end_local} ({TIMEZONE})")
    logger.info(f"   Window UTC  : {start_utc} → {end_utc}")

    try:
        entity = await client.get_entity(PeerChannel(int(channel_id)))
    except Exception:
        entity = await client.get_entity(channel_id)

    cves: List[str] = []
    seen: Set[str] = set()
    scanned = 0

    try:
        async for msg in client.iter_messages(entity, offset_date=end_utc, reverse=False):
            if not isinstance(msg, Message) or not msg.date:
                continue
            if msg.date < start_utc:
                break
            if msg.date >= end_utc:
                continue

            scanned += 1
            found = extract_cve_ids_from_text(msg.message or "")
            for cv in found:
                if cv not in seen:
                    seen.add(cv)
                    cves.append(cv)

            if scanned and scanned % 200 == 0:
                logger.info(f"   … scanned {scanned} messages, collected {len(cves)} CVEs")

        logger.info(f"✅ Telegram scan complete: scanned {scanned}, unique CVEs {len(cves)}")
        return cves

    except FloodWaitError as e:
        logger.warning(f"⏳ Flood wait: sleeping {e.seconds}s…")
        time.sleep(e.seconds)
        return cves

# ======================= CVE Details Scraper ============================
class CVEDetailsScraper:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119 Safari/537.36"
            )
        })

    def scrape_cve_page(self, cve_id: str) -> Optional[Dict[str, Any]]:
        url = CVEFEED_CVE_URL.format(cve_id=cve_id)
        try:
            resp = self.session.get(url, timeout=25)
            resp.raise_for_status()
            soup = BeautifulSoup(resp.content, "html.parser")

            data = {
                "cve_id": cve_id,
                "title": "",
                "description": "",
                "published_date": "",
                "last_modified": "",
                "remotely_exploit": "",
                "source_identifier": "",
                "category": "",
                "affected_products": [],
                "cvss_scores": [],
                "url": url,
            }

            # ID
            h_id = soup.find("h5", class_="fs-36 mb-1")
            if h_id:
                page_id = h_id.get_text(strip=True)
                if page_id and page_id.startswith("CVE-"):
                    data["cve_id"] = page_id

            # Title
            h_title = soup.find("h5", class_="text mt-2")
            if h_title:
                data["title"] = h_title.get_text(strip=True)

            # Description
            for card in soup.find_all("div", class_="card-body"):
                p = card.find("p", class_="card-text")
                if p:
                    txt = p.get_text(strip=True)
                    if len(txt) > 50 and "vulnerab" in txt.lower():
                        data["description"] = txt
                        break

            # Info blocks
            for col in soup.find_all("div", class_="col-lg-3"):
                label = (col.find("p", class_="mb-1") or col.find("p", class_="mb-2"))
                if not label:
                    continue
                ltxt = label.get_text(strip=True)
                val = col.find("h6", class_="text-truncate")
                vtxt = val.get_text(strip=True) if val else ""
                if "Published" in ltxt or "Date" in ltxt:
                    data["published_date"] = vtxt
                elif "Modified" in ltxt:
                    data["last_modified"] = vtxt
                elif "Exploit" in ltxt or "Remote" in ltxt:
                    data["remotely_exploit"] = vtxt
                elif "Source" in ltxt:
                    data["source_identifier"] = extract_email_from_tag(col) or vtxt

            # CVSS scores
            self._extract_cvss_scores(soup, data)

            # Affected products
            self._extract_affected_products(soup, data)

            return data

        except Exception as e:
            logger.error(f"Error scraping {cve_id}: {e}")
            return None

    def _extract_cvss_scores(self, soup, data):
        cvss_tables = soup.find_all("table", class_="table-borderless")
        for table in cvss_tables:
            thead = table.find("thead")
            if not thead:
                continue
            headers = [th.get_text(strip=True) for th in thead.find_all("th")]
            if not ("Score" in headers and "Vector" in headers):
                continue

            body = table.find("tbody")
            rows = body.find_all("tr") if body else table.find_all("tr")[1:]
            for row in rows:
                tds = row.find_all("td")
                if len(tds) < 7:
                    continue
                entry = {}
                b0 = tds[0].find("b")
                entry["score"] = b0.get_text(strip=True) if b0 else ""
                entry["version"] = tds[1].get_text(strip=True)
                entry["severity"] = tds[2].get_text(strip=True)
                inp = tds[3].find("input")
                entry["vector"] = (inp.get("value", "").strip() if inp else tds[3].get_text(strip=True))
                b4 = tds[4].find("b")
                entry["exploitability_score"] = b4.get_text(strip=True) if b4 else ""
                b5 = tds[5].find("b")
                entry["impact_score"] = b5.get_text(strip=True) if b5 else ""
                entry["source_identifier"] = extract_email_from_tag(tds[6]) or tds[6].get_text(" ", strip=True)

                if entry.get("version") or entry.get("score") or entry.get("vector"):
                    data["cvss_scores"].append(entry)
            break

    def _extract_affected_products(self, soup, data):
        prod_block = None
        for h5 in soup.find_all("h5"):
            if "Affected Products" in h5.get_text():
                prod_block = h5.find_parent("div", class_="card-body")
                break
        if not prod_block:
            t = soup.find("table", class_="table-nowrap")
            if t:
                prod_block = t.find_parent("div", class_="card-body")

        if prod_block:
            t = prod_block.find("table", class_="table-nowrap")
            if t:
                tbody = t.find("tbody")
                if tbody:
                    for tr in tbody.find_all("tr"):
                        tds = tr.find_all("td")
                        if len(tds) >= 3:
                            pid = tds[0].get_text(strip=True)
                            vendor = tds[1].get_text(strip=True)
                            product = tds[2].get_text(strip=True)
                            if vendor or product:
                                data["affected_products"].append(
                                    {"id": pid, "vendor": vendor, "product": product}
                                )

# ============ Helper: Load Scraped CVE from Bronze =====================
def load_scraped_cve_from_bronze(cve_ids: List[str], engine: Engine) -> pd.DataFrame:
    """Charge UNIQUEMENT les CVE spécifiés depuis Bronze."""
    bronze_schema = get_schema_name("bronze")
    
    if not cve_ids:
        logger.warning("⚠️  No CVE IDs provided!")
        return pd.DataFrame()
    
    placeholders = ', '.join([f"'{cve_id}'" for cve_id in cve_ids])
    
    query = f"""
        SELECT *
        FROM {bronze_schema}.cve_details
        WHERE cve_id IN ({placeholders})
        ORDER BY published_date DESC NULLS LAST
    """
    
    logger.info(f"🔍 Loading {len(cve_ids)} scraped CVE(s) from bronze...")
    df = pd.read_sql(query, engine)
    logger.info(f"✅ Loaded {len(df)} row(s) from bronze")
    
    return df

# ================= COMPLETE PIPELINE (Telegram → Gold) ==================
async def run_complete_pipeline() -> Dict[str, Any]:
    """
    ⭐ COMPLETE ETL PIPELINE: Telegram → Bronze → EDA → Silver → Gold
    Traite UNIQUEMENT les CVE scrapés (pas toute la DB)
    Mode APPEND sur Silver et Gold (pas de TRUNCATE)
    """
    logger.info("=" * 72)
    logger.info("🚀 TELEGRAM → COMPLETE ETL PIPELINE (Bronze → Silver → Gold)")
    logger.info("=" * 72)

    pipeline_stats = {
        'timestamp': datetime.now().isoformat(),
        'total_found': 0,
        'already_in_db': 0,
        'to_scrape': 0,
        'scraped': 0,
        'bronze_inserted': 0,
        'bronze_skipped': 0,
        'silver_processed': 0,
        'gold_processed': 0,
        'failed': 0,
        'success': False
    }

    tz = ZoneInfo(TIMEZONE)
    today_local = datetime.now(tz)
    target_day_local = (today_local - timedelta(days=CATCHUP_DAYS_AGO)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    day_str = target_day_local.strftime("%Y-%m-%d")
    logger.info(f"🎯 Target local day: {day_str} ({TIMEZONE})")
    if TARGET_YEARS:
        logger.info(f"🎯 Filter years: {TARGET_YEARS}")

    client = TelegramClient(str(SESSION_FILE), TELEGRAM_API_ID, TELEGRAM_API_HASH)

    try:
        # ================= STEP 1: Telegram Authentication ==================
        authed = await telegram_authenticate(client)
        if not authed:
            logger.error("❌ Telegram authentication failed.")
            return pipeline_stats

        # ================= STEP 2: Collect CVE IDs ==========================
        logger.info("\n" + "=" * 72)
        logger.info("📥 STEP 2/8: COLLECTING CVE IDs FROM TELEGRAM")
        logger.info("=" * 72)
        
        cve_ids = await collect_cve_ids_from_telegram_for_day(
            client, TELEGRAM_CHANNEL_ID, target_day_local, tz
        )

        # Disconnect Telegram early
        try:
            await client.disconnect()
        except Exception:
            pass

        if not cve_ids:
            logger.info("ℹ️  No CVE IDs collected for this day.")
            pipeline_stats['success'] = True
            return pipeline_stats

        pipeline_stats['total_found'] = len(cve_ids)

        # ================= STEP 3: Check Existing CVEs ======================
        logger.info("\n" + "=" * 72)
        logger.info("🔎 STEP 3/8: CHECKING EXISTING CVEs IN BRONZE")
        logger.info("=" * 72)
        
        engine = create_db_engine()
        
        with engine.connect() as conn:
            result = conn.execute(text("SELECT cve_id FROM raw.cve_details"))
            scraped_cves = {row[0] for row in result.fetchall()}

        pipeline_stats['already_in_db'] = len([c for c in cve_ids if c in scraped_cves])
        to_scrape = [c for c in cve_ids if c not in scraped_cves]
        pipeline_stats['to_scrape'] = len(to_scrape)
        
        logger.info(f"📊 Total collected: {len(cve_ids)}")
        logger.info(f"📊 Already in DB: {pipeline_stats['already_in_db']}")
        logger.info(f"🎯 New to scrape: {len(to_scrape)}")

        if not to_scrape:
            logger.info("✅ All CVEs already exist. Pipeline complete.")
            pipeline_stats['success'] = True
            return pipeline_stats

        # ================= STEP 4: Scrape CVE Details =======================
        logger.info("\n" + "=" * 72)
        logger.info("📝 STEP 4/8: SCRAPING CVE DETAILS")
        logger.info("=" * 72)
        
        scraper = CVEDetailsScraper()
        details_rows: List[Dict[str, Any]] = []
        scraped_cve_ids: List[str] = []
        
        for i, cid in enumerate(to_scrape, 1):
            logger.info(f"[{i}/{len(to_scrape)}] Scraping {cid}...")
            data = scraper.scrape_cve_page(cid)
            if data:
                details_rows.append(data)
                scraped_cve_ids.append(cid)
                pipeline_stats['scraped'] += 1
            else:
                pipeline_stats['failed'] += 1
            if i < len(to_scrape):
                time.sleep(DETAIL_DELAY_SEC)

        if not details_rows:
            logger.info("ℹ️  No details scraped successfully.")
            return pipeline_stats

        # ================= STEP 5: Load to Bronze ===========================
        logger.info("\n" + "=" * 72)
        logger.info("📥 STEP 5/8: LOADING TO BRONZE LAYER")
        logger.info("=" * 72)
        
        bronze_stats = load_bronze_layer(details_rows, engine)
        pipeline_stats['bronze_inserted'] = bronze_stats.get('inserted', 0)
        pipeline_stats['bronze_skipped'] = bronze_stats.get('skipped', 0)

        # ================= STEP 6: EDA & Cleaning ===========================
        logger.info("\n" + "=" * 72)
        logger.info("🔍 STEP 6/8: EDA & CLEANING (SCRAPED CVEs ONLY)")
        logger.info("=" * 72)
        
        df_scraped = load_scraped_cve_from_bronze(scraped_cve_ids, engine)
        
        if df_scraped.empty:
            logger.error("❌ Could not load scraped CVEs from bronze!")
            return pipeline_stats
        
        logger.info(f"📊 Processing {len(df_scraped)} scraped CVE(s)")
        
        df_with_eda = perform_eda(df_scraped)
        df_cleaned = clean_silver_data(df_with_eda)
        
        if df_cleaned.empty:
            logger.error("❌ No valid data after cleaning!")
            return pipeline_stats
        
        silver_df = create_silver_layer(df_cleaned)
        pipeline_stats['silver_processed'] = len(silver_df)

        # ================= STEP 7: Load to Silver (APPEND) ==================
        logger.info("\n" + "=" * 72)
        logger.info("💾 STEP 7/8: LOADING TO SILVER LAYER (APPEND MODE)")
        logger.info("=" * 72)
        
        tables = {"cve_cleaned": silver_df}
        silver_success = load_silver_layer(tables, engine, if_exists='append')
        
        if not silver_success:
            logger.error("❌ Silver loading failed!")
            return pipeline_stats

        # ================= STEP 8: Transform & Load to Gold (APPEND) ========
        logger.info("\n" + "=" * 72)
        logger.info("🔄 STEP 8/8: TRANSFORMING & LOADING TO GOLD (APPEND MODE)")
        logger.info("=" * 72)
        
        gold_tables = transform_silver_to_gold(silver_df)
        pipeline_stats['gold_processed'] = len(gold_tables.get('dim_cve', pd.DataFrame()))
        
        gold_success = load_gold_layer(gold_tables, engine, if_exists='append')
        pipeline_stats['success'] = gold_success

        # ================= Final Summary ====================================
        logger.info("\n" + "=" * 72)
        logger.info("🎉 COMPLETE PIPELINE FINISHED (Telegram → Bronze → Silver → Gold)")
        logger.info("=" * 72)
        logger.info("📊 PIPELINE STATISTICS:")
        logger.info(f"   🔍 Total CVEs found:       {pipeline_stats['total_found']}")
        logger.info(f"   ✅ Already in DB:          {pipeline_stats['already_in_db']}")
        logger.info(f"   🎯 To scrape:              {pipeline_stats['to_scrape']}")
        logger.info(f"   📝 Successfully scraped:   {pipeline_stats['scraped']}")
        logger.info(f"   📥 Bronze inserted:        {pipeline_stats['bronze_inserted']}")
        logger.info(f"   💎 Silver processed:       {pipeline_stats['silver_processed']}")
        logger.info(f"   🌟 Gold processed:         {pipeline_stats['gold_processed']}")
        logger.info(f"   ❌ Failed:                 {pipeline_stats['failed']}")
        logger.info(f"   ✨ Success:                {pipeline_stats['success']}")
        logger.info("=" * 72)

        return pipeline_stats

    except Exception as e:
        logger.error(f"❌ Pipeline failed: {e}", exc_info=True)
        pipeline_stats['success'] = False
        return pipeline_stats

# ============================= MAIN =====================================
def main() -> int:
    logger.info(f"▶ Running {Path(__file__).name}")

    import asyncio
    stats = asyncio.run(run_complete_pipeline())
    
    return 0 if stats['success'] else 1

if __name__ == "__main__":
    sys.exit(main())