#!/usr/bin/env python3
# =============================================================================
# CVE SCRAPER WITH COMPLETE ETL PIPELINE (Bronze → Silver → Gold)
# =============================================================================
# Description: Scrape → Bronze → EDA → Silver → Gold (Star Schema)
# Location: src/batch/extract/stream/scrape_live_cvefeed_complete_pipeline.py
# Author: Data Engineering Team
# Date: 2025-10-18
# =============================================================================

from pathlib import Path
import sys
import os

# ---------------------------------------------------------------------------
# Import path setup
# ---------------------------------------------------------------------------
FILE_PATH = Path(__file__).resolve()

# APRÈS (adapté à src/stream/extract)
SRC_ROOT = FILE_PATH.parents[2]          # .../src
PROJECT_ROOT = FILE_PATH.parents[3]      # racine du projet


if str(SRC_ROOT) not in sys.path:
    sys.path.append(str(SRC_ROOT))

# Selenium + parsing
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options

from bs4 import BeautifulSoup
import requests
import csv
import json
import time
import logging
import re
import binascii
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

import pandas as pd
from sqlalchemy import text
from sqlalchemy.engine import Engine

# ============================================================================
# IMPORT PIPELINE MODULES (Bronze + Silver + Gold)
# ============================================================================
from stream.load.load_bronze_layer import load_bronze_layer
from stream.load.load_silver_layer_m import load_silver_layer
from stream.load.load_gold_layer_m import load_gold_layer
from database.connection import create_db_engine, get_schema_name

# ⭐ IMPORTANT: Import EDA + Gold transformation
from stream.transform.EDA_bronze_to_silver_m import (
    perform_eda,
    clean_silver_data,
    create_silver_layer
)
from stream.transform.transformation_to_gold_m import transform_silver_to_gold

# =============================================================================
# LOGGING
# =============================================================================
LOGS_DIR = (PROJECT_ROOT / "logs") if PROJECT_ROOT else (SRC_ROOT / "logs")
LOGS_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOGS_DIR / "cve_scraper_complete_pipeline.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()
    ],
)
logger = logging.getLogger(__name__)

# =============================================================================
# Cloudflare Email Decoder Helpers
# =============================================================================
def decode_cfemail(hex_str: str) -> str:
    """Decode Cloudflare-protected email from data-cfemail hex string."""
    try:
        data = bytearray(binascii.unhexlify(hex_str))
        if not data:
            return ""
        key = data[0]
        return ''.join(chr(b ^ key) for b in data[1:])
    except Exception:
        return ""


def extract_email_from_tag(tag) -> str:
    """Extract email from BeautifulSoup tag (Cloudflare-safe)."""
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

    txt = tag.get_text(" ", strip=True)
    return txt.strip()


# =============================================================================
# CVE LINK EXTRACTOR (Selenium)
# =============================================================================
class CVELinkExtractor:
    def __init__(self):
        self.options = Options()
        self.options.add_argument("--headless=new")
        self.options.add_argument("--no-sandbox")
        self.options.add_argument("--disable-dev-shm-usage")
        self.options.add_argument("--disable-blink-features=AutomationControlled")
        self.options.add_argument(
            "user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/119 Safari/537.36"
        )

    def extract_cve_links(self, search_url: str) -> List[Dict[str, str]]:
        """Extract CVE links from search page using Selenium."""
        logger.info("=" * 80)
        logger.info("🔍 STEP 1/8: EXTRACTING CVE LINKS")
        logger.info("=" * 80)
        logger.info(f"URL: {search_url}")

        driver = webdriver.Chrome(options=self.options)
        cve_links = []

        try:
            logger.info("🚀 Loading search page...")
            driver.get(search_url)

            wait = WebDriverWait(driver, 60)
            
            logger.info("⏳ Waiting for page to load (max 60s)...")
            try:
                wait.until(
                    EC.presence_of_element_located(
                        (By.CSS_SELECTOR, "#searchResults .row.align-items-start.mb-4")
                    )
                )
            except:
                logger.warning("⚠️  Timeout on main selector, trying fallback...")
                wait.until(
                    EC.presence_of_element_located((By.ID, "searchResults"))
                )
            
            time.sleep(3)

            html_content = driver.page_source
            soup = BeautifulSoup(html_content, "html.parser")

            search_results = soup.find("div", id="searchResults")
            if not search_results:
                logger.error("❌ No #searchResults div found!")
                logger.info("💾 Saving page source for debugging...")
                with open("debug_page.html", "w", encoding="utf-8") as f:
                    f.write(html_content)
                logger.info("   Saved to: debug_page.html")
                return []

            entries = search_results.find_all("div", class_="row align-items-start mb-4")
            
            if len(entries) == 0:
                no_results = soup.find(text=re.compile(r"No (results|CVEs) found", re.I))
                if no_results:
                    logger.warning("⚠️  No CVEs found for this date range")
                    return []
                else:
                    logger.error("❌ No CVE entries found but no 'No results' message either")
                    logger.info("💾 Saving page for debugging: debug_page.html")
                    with open("debug_page.html", "w", encoding="utf-8") as f:
                        f.write(html_content)
                    return []
            
            logger.info(f"📊 Found {len(entries)} CVE entries on the page")

            for i, entry in enumerate(entries, 1):
                try:
                    h5_tag = entry.find("h5")
                    if not h5_tag:
                        continue
                    a_tag = h5_tag.find("a")
                    if not a_tag:
                        continue

                    cve_id = a_tag.get_text(strip=True)
                    cve_href = a_tag.get("href", "")
                    cve_url = f"https://cvefeed.io{cve_href}" if cve_href else ""

                    if cve_id and cve_url:
                        cve_links.append({"cve_id": cve_id, "url": cve_url})
                        logger.info(f"  ✓ {i}. {cve_id}")
                except Exception as e:
                    logger.error(f"  ❌ Error parsing entry {i}: {e}")

            logger.info(f"✅ Successfully extracted {len(cve_links)} CVE links\n")
            return cve_links

        except Exception as e:
            logger.error(f"❌ Error extracting links: {e}")
            logger.info("💾 Attempting to save page source...")
            try:
                html_content = driver.page_source
                with open("debug_error_page.html", "w", encoding="utf-8") as f:
                    f.write(html_content)
                logger.info("   Saved to: debug_error_page.html")
            except:
                logger.warning("   Could not save page source")
            return []

        finally:
            driver.quit()
            logger.info("🔒 Browser closed\n")


# =============================================================================
# CVE DETAILS SCRAPER
# =============================================================================
class CVEDetailsScraper:
    def __init__(self):
        self.headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119 Safari/537.36"
            )
        }

    def scrape_cve_page(self, url: str) -> Optional[Dict[str, Any]]:
        """Scrape information from a single CVE detail page."""
        try:
            response = requests.get(url, headers=self.headers, timeout=20)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, "html.parser")

            cve_data = {
                "cve_id": "",
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

            cve_id_elem = soup.find("h5", class_="fs-36 mb-1")
            if cve_id_elem:
                cve_data["cve_id"] = cve_id_elem.get_text(strip=True)

            title_elem = soup.find("h5", class_="text mt-2")
            if title_elem:
                cve_data["title"] = title_elem.get_text(strip=True)

            self._extract_description(soup, cve_data)
            self._extract_info_section(soup, cve_data)

            category_alert = soup.find("div", class_="alert-dark")
            if category_alert:
                category_strong = category_alert.find("strong")
                if category_strong:
                    cve_data["category"] = category_strong.get_text(strip=True)

            self._extract_all_cvss_scores(soup, cve_data)
            self._extract_affected_products(soup, cve_data)

            return cve_data

        except Exception as e:
            logger.error(f"Error scraping {url}: {str(e)}")
            return None

    def _extract_description(self, soup, cve_data):
        desc_cards = soup.find_all("div", class_="card-body")
        for card in desc_cards:
            desc_p = card.find("p", class_="card-text")
            if desc_p:
                text = desc_p.get_text(strip=True)
                if len(text) > 50 and "vulnerability" in text.lower():
                    cve_data["description"] = text
                    return

    def _extract_info_section(self, soup, cve_data):
        info_cols = soup.find_all("div", class_="col-lg-3")
        for col in info_cols:
            label_elem = col.find("p", class_="mb-1") or col.find("p", class_="mb-2")
            if not label_elem:
                continue
            label_text = label_elem.get_text(strip=True)

            value_elem = col.find("h6", class_="text-truncate")
            value_text = value_elem.get_text(strip=True) if value_elem else ""

            if "Published" in label_text or "Date" in label_text:
                cve_data["published_date"] = value_text
            elif "Modified" in label_text:
                cve_data["last_modified"] = value_text
            elif "Exploit" in label_text or "Remote" in label_text:
                cve_data["remotely_exploit"] = value_text
            elif "Source" in label_text:
                cf_email = extract_email_from_tag(col)
                cve_data["source_identifier"] = cf_email or value_text

    def _extract_all_cvss_scores(self, soup, cve_data):
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
                cells = row.find_all("td")
                if len(cells) < 7:
                    continue

                entry = {}
                score_btn = cells[0].find("b")
                if score_btn:
                    entry["score"] = score_btn.get_text(strip=True)

                entry["version"] = cells[1].get_text(strip=True)
                entry["severity"] = cells[2].get_text(strip=True)

                vector_input = cells[3].find("input")
                if vector_input:
                    entry["vector"] = vector_input.get("value", "").strip()
                else:
                    entry["vector"] = cells[3].get_text(strip=True)

                exploit_btn = cells[4].find("b")
                if exploit_btn:
                    txt = exploit_btn.get_text(strip=True)
                    if txt:
                        entry["exploitability_score"] = txt

                impact_btn = cells[5].find("b")
                if impact_btn:
                    txt = impact_btn.get_text(strip=True)
                    if txt:
                        entry["impact_score"] = txt

                source_text = extract_email_from_tag(cells[6])
                if source_text:
                    entry["source_identifier"] = source_text

                if entry.get("version") or entry.get("score") or entry.get("vector"):
                    cve_data["cvss_scores"].append(entry)

            logger.info(f"    Found {len(cve_data['cvss_scores'])} CVSS score(s)")
            break

    def _extract_affected_products(self, soup, cve_data):
        affected_section = None
        for h5 in soup.find_all("h5"):
            if "Affected Products" in h5.get_text():
                affected_section = h5.find_parent("div", class_="card-body")
                break

        if not affected_section:
            product_table = soup.find("table", class_="table-nowrap")
            if product_table:
                affected_section = product_table.find_parent("div", class_="card-body")

        if not affected_section:
            return

        no_product_msg = affected_section.find("p", class_="text-warning")
        if no_product_msg and "No affected product" in no_product_msg.get_text():
            return

        product_table = affected_section.find("table", class_="table-nowrap")
        if not product_table:
            return

        tbody = product_table.find("tbody")
        if not tbody:
            return

        rows = tbody.find_all("tr")
        for row in rows:
            cells = row.find_all("td")
            if len(cells) >= 3:
                product_id = cells[0].get_text(strip=True)
                vendor = cells[1].get_text(strip=True)
                product = cells[2].get_text(strip=True)

                if vendor or product:
                    cve_data["affected_products"].append(
                        {"id": product_id, "vendor": vendor, "product": product}
                    )

        logger.info(f"    Found {len(cve_data['affected_products'])} affected product(s)")


# =============================================================================
# HELPER: Load scraped CVE from Bronze
# =============================================================================
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


# =============================================================================
# COMPLETE SCRAPER WITH FULL ETL PIPELINE (Bronze → Silver → Gold)
# =============================================================================
class CompleteCVEScraper:
    def __init__(self):
        self.link_extractor = CVELinkExtractor()
        self.details_scraper = CVEDetailsScraper()

    def scrape_and_load_with_pipeline(
        self,
        search_url: str,
        batch_size: int = 50,
        delay: int = 2,
        save_csv: bool = True,
        output_csv: str = "cve_data_backup.csv",
    ) -> Dict[str, Any]:
        """
        ⭐ COMPLETE ETL PIPELINE: Scrape → Bronze → EDA → Silver → Gold
        Traite UNIQUEMENT les CVE scrapés (pas toute la DB)
        Mode APPEND sur Silver et Gold (pas de TRUNCATE)
        """
        logger.info("=" * 80)
        logger.info("🚀 COMPLETE CVE SCRAPING & ETL PIPELINE (Bronze → Silver → Gold)")
        logger.info("=" * 80)
        logger.info(f"⏰ Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info("=" * 80 + "\n")

        pipeline_stats = {
            'timestamp': datetime.now().isoformat(),
            'search_url': search_url,
            'total_found': 0,
            'already_in_db': 0,
            'to_scrape': 0,
            'scraped': 0,
            'bronze_inserted': 0,
            'bronze_skipped': 0,
            'silver_processed': 0,
            'silver_inserted': 0,
            'silver_skipped': 0,
            'gold_processed': 0,
            'failed': 0,
            'success': False
        }

        try:
            engine = create_db_engine()

            # ================================================================
            # STEP 1: Extract CVE links
            # ================================================================
            cve_links = self.link_extractor.extract_cve_links(search_url)
            
            if not cve_links:
                logger.error("❌ No CVE links found!")
                return pipeline_stats
            
            pipeline_stats['total_found'] = len(cve_links)

            # ================================================================
            # STEP 2: Check existing CVEs
            # ================================================================
            logger.info("=" * 80)
            logger.info("🔎 STEP 2/8: CHECKING EXISTING CVEs")
            logger.info("=" * 80)
            
            with engine.connect() as conn:
                result = conn.execute(text("SELECT cve_id FROM raw.cve_details"))
                scraped_cves = {row[0] for row in result.fetchall()}

            pipeline_stats['already_in_db'] = len(scraped_cves)
            logger.info(f"📊 Already in database: {len(scraped_cves)} CVEs")

            to_scrape = [cve for cve in cve_links if cve["cve_id"] not in scraped_cves]
            pipeline_stats['to_scrape'] = len(to_scrape)
            logger.info(f"🎯 New CVEs to scrape: {len(to_scrape)}\n")

            if not to_scrape:
                logger.info("✅ All CVEs already exist. Pipeline complete.")
                pipeline_stats['success'] = True
                return pipeline_stats

            # ================================================================
            # STEP 3: Scrape CVE details
            # ================================================================
            logger.info("=" * 80)
            logger.info("📝 STEP 3/8: SCRAPING CVE DETAILS")
            logger.info("=" * 80)
            logger.info(f"Total CVEs to scrape: {len(to_scrape)}")
            logger.info(f"Delay: {delay}s")
            logger.info("=" * 80 + "\n")

            scraped_cve_data = []
            scraped_cve_ids = []

            for idx, cve_info in enumerate(to_scrape, 1):
                cve_id = cve_info["cve_id"]
                url = cve_info["url"]

                logger.info(f"[{idx}/{len(to_scrape)}] Scraping {cve_id}...")
                cve_data = self.details_scraper.scrape_cve_page(url)

                if cve_data:
                    scraped_cve_data.append(cve_data)
                    scraped_cve_ids.append(cve_id)
                    pipeline_stats['scraped'] += 1

                    scores_summary = ", ".join(
                        f"{s.get('version', 'N/A')}: {s.get('score', 'N/A')}"
                        for s in cve_data["cvss_scores"]
                    )
                    logger.info(f"    ✓ Scores: {scores_summary}")
                else:
                    pipeline_stats['failed'] += 1
                    logger.warning("    ✗ Failed to scrape")

                if idx < len(to_scrape):
                    time.sleep(delay)

            if not scraped_cve_data:
                logger.error("❌ No CVE data was successfully scraped!")
                return pipeline_stats

            # ================================================================
            # STEP 4: Load to Bronze
            # ================================================================
            logger.info("\n" + "=" * 80)
            logger.info("📥 STEP 4/8: LOADING TO BRONZE LAYER")
            logger.info("=" * 80)
            
            bronze_stats = load_bronze_layer(scraped_cve_data, engine)
            pipeline_stats['bronze_inserted'] = bronze_stats.get('inserted', 0)
            pipeline_stats['bronze_skipped'] = bronze_stats.get('skipped', 0)
            
            logger.info(f"✅ Bronze: {bronze_stats['inserted']} inserted, "
                       f"{bronze_stats['skipped']} skipped\n")

            # ================================================================
            # STEP 5: EDA & CLEANING (scraped CVEs only)
            # ================================================================
            logger.info("=" * 80)
            logger.info("🔍 STEP 5/8: EDA & CLEANING (SCRAPED CVEs ONLY)")
            logger.info("=" * 80)
            
            df_scraped = load_scraped_cve_from_bronze(scraped_cve_ids, engine)
            
            if df_scraped.empty:
                logger.error("❌ Could not load scraped CVEs from bronze!")
                return pipeline_stats
            
            logger.info(f"📊 Processing {len(df_scraped)} scraped CVE(s)\n")
            
            logger.info("🔬 Running EDA on scraped data...")
            df_with_eda = perform_eda(df_scraped)
            
            logger.info("\n🧹 Cleaning scraped data...")
            df_cleaned = clean_silver_data(df_with_eda)
            
            if df_cleaned.empty:
                logger.error("❌ No valid data after cleaning!")
                return pipeline_stats
            
            logger.info("\n🏗️  Creating silver format...")
            silver_df = create_silver_layer(df_cleaned)
            pipeline_stats['silver_processed'] = len(silver_df)

            # ================================================================
            # STEP 6: Load to Silver (APPEND mode)
            # ================================================================
            logger.info("\n" + "=" * 80)
            logger.info("💾 STEP 6/8: LOADING TO SILVER LAYER (APPEND MODE)")
            logger.info("=" * 80)
            
            tables = {"cve_cleaned": silver_df}
            silver_success = load_silver_layer(tables, engine, if_exists='append')
            
            if not silver_success:
                logger.error("❌ Silver loading failed!")
                return pipeline_stats

            # ================================================================
            # ⭐ STEP 7: Transform Silver → Gold (APPEND mode)
            # ================================================================
            logger.info("\n" + "=" * 80)
            logger.info("🔄 STEP 7/8: TRANSFORMING TO GOLD LAYER (APPEND MODE)")
            logger.info("=" * 80)
            
            logger.info("🔄 Transforming scraped CVEs to Gold format...")
            gold_tables = transform_silver_to_gold(silver_df)
            
            pipeline_stats['gold_processed'] = len(gold_tables.get('dim_cve', pd.DataFrame()))

            # ================================================================
            # ⭐ STEP 8: Load to Gold (APPEND mode)
            # ================================================================
            logger.info("\n" + "=" * 80)
            logger.info("💾 STEP 8/8: LOADING TO GOLD LAYER (APPEND MODE)")
            logger.info("=" * 80)
            
            gold_success = load_gold_layer(gold_tables, engine, if_exists='append')
            
            pipeline_stats['success'] = gold_success

            # ================================================================
            # CSV Backup (optional)
            # ================================================================
            if save_csv and scraped_cve_data:
                logger.info("\n" + "=" * 80)
                logger.info("💾 SAVING CSV BACKUP")
                logger.info("=" * 80)
                self.save_to_csv(scraped_cve_data, output_csv)

            # ================================================================
            # Final Summary
            # ================================================================
            logger.info("\n" + "=" * 80)
            logger.info("🎉 COMPLETE ETL PIPELINE FINISHED (Bronze → Silver → Gold)")
            logger.info("=" * 80)
            logger.info(f"⏰ End time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            logger.info("=" * 80)
            logger.info("📊 PIPELINE STATISTICS:")
            logger.info(f"   🔍 Total CVEs found:       {pipeline_stats['total_found']}")
            logger.info(f"   ✅ Already in DB:          {pipeline_stats['already_in_db']}")
            logger.info(f"   🎯 To scrape:              {pipeline_stats['to_scrape']}")
            logger.info(f"   📝 Successfully scraped:   {pipeline_stats['scraped']}")
            logger.info(f"   📥 Bronze inserted:        {pipeline_stats['bronze_inserted']}")
            logger.info(f"   ⭕ Bronze skipped:         {pipeline_stats['bronze_skipped']}")
            logger.info(f"   💎 Silver processed:       {pipeline_stats['silver_processed']}")
            logger.info(f"   🌟 Gold processed:         {pipeline_stats['gold_processed']}")
            logger.info(f"   ❌ Failed:                 {pipeline_stats['failed']}")
            logger.info(f"   ✨ Pipeline success:       {pipeline_stats['success']}")
            logger.info("=" * 80)

            return pipeline_stats

        except KeyboardInterrupt:
            logger.warning("\n⚠️  KeyboardInterrupt detected!")
            pipeline_stats['success'] = False
            return pipeline_stats

        except Exception as e:
            logger.error(f"\n❌ Pipeline failed: {e}", exc_info=True)
            pipeline_stats['success'] = False
            pipeline_stats['error'] = str(e)
            return pipeline_stats

    def save_to_csv(self, cve_data_list: List[Dict], filename: str):
        """Save CVE data to CSV backup."""
        if not cve_data_list:
            return

        fieldnames = [
            "cve_id", "title", "description", "published_date", "last_modified",
            "remotely_exploit", "source_identifier", "category",
            "affected_products", "cvss_scores", "url",
        ]

        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for cve in cve_data_list:
                row = cve.copy()
                row["affected_products"] = json.dumps(
                    row.get("affected_products", []), ensure_ascii=False
                )
                row["cvss_scores"] = json.dumps(
                    row.get("cvss_scores", []), ensure_ascii=False
                )
                writer.writerow(row)

        logger.info(f"✅ Saved {len(cve_data_list)} CVEs to {filename}")


# =============================================================================
# MAIN
# =============================================================================
def main():
    """Main entry point."""
    from datetime import datetime, timedelta
    
    # ⚠️ IMPORTANT: Choisir la date correcte
    today = datetime.now()
    today_str = today.strftime("%Y-%m-%d")
    
    yesterday = today - timedelta(days=1)
    yesterday_str = yesterday.strftime("%Y-%m-%d")
    
    # Option 3: Date fixe avec CVE connus
    fixed_date = "2025-10-16"
    
    # ⭐ Choisir la date à utiliser
    target_date = yesterday_str  # Changez selon vos besoins
    
    logger.info(f"🎯 Target date: {target_date}")
    
    SEARCH_URL = (
        f"https://cvefeed.io/search?"
        f"keyword=&"
        f"published_after={target_date}%2000:00:00&"
        f"published_before={target_date}%2023:59:59&"
        f"cvss_min=3.00&cvss_max=10.00&"
        f"order_by=-published"
    )
    
    logger.info(f"🔗 Search URL: {SEARCH_URL}")

    scraper = CompleteCVEScraper()
    stats = scraper.scrape_and_load_with_pipeline(
        search_url=SEARCH_URL,
        batch_size=50,
        delay=2,
        save_csv=True,
        output_csv="cve_data_backup.csv",
    )
    
    return 0 if stats['success'] else 1


if __name__ == "__main__":
    logger.info(f"▶ Running {Path(__file__).name}")
    exit_code = main()
    sys.exit(exit_code)