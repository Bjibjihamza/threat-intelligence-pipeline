# ============================================================================
# CVE SCRAPER - Integrated with Bronze Layer Loader (Cloudflare-safe emails)
# ============================================================================
# Description: Scrape CVE data and load directly to PostgreSQL bronze layer
# Author: Data Engineering Team
# Date: 2025-10-16
# ============================================================================

from pathlib import Path
import sys

# Add .../src to sys.path for absolute imports
sys.path.append(str(Path(__file__).resolve().parents[2]))

import requests
from bs4 import BeautifulSoup
import csv
import time
import logging
import json
import re
import binascii

from batch.load.load_bronze_layer import (
    load_bronze_layer,
    create_db_engine,
)

# ----------------------------------------------------------------------------
# Logging Configuration
# ----------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[3]
LOGS_DIR = PROJECT_ROOT / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOGS_DIR / "scraper.log"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------------
# Cloudflare email decoding helpers
# ----------------------------------------------------------------------------
def decode_cfemail(hex_str: str) -> str:
    """
    Decode Cloudflare-protected email from the 'data-cfemail' hex string.
    First byte = XOR key; each following byte XOR key => char.
    """
    try:
        data = bytearray(binascii.unhexlify(hex_str))
        if not data:
            return ""
        key = data[0]
        return ''.join(chr(b ^ key) for b in data[1:])
    except Exception:
        return ""

def extract_email_from_tag(tag) -> str:
    """
    Extract an email address from a BeautifulSoup tag with CF protection support.
      - Looks for <a|span class="__cf_email__" data-cfemail="...">
      - Falls back to mailto: links
      - Finally uses visible text
    """
    if not tag:
        return ""

    # Cloudflare wrapper
    cf = tag.find(["a", "span"], class_=re.compile(r"__cf_email__"))
    if cf and cf.has_attr("data-cfemail"):
        decoded = decode_cfemail(cf["data-cfemail"])
        if decoded:
            return decoded.strip()

    # Standard mailto link
    link = tag.find("a", href=True)
    if link and isinstance(link["href"], str) and link["href"].lower().startswith("mailto:"):
        return link["href"].split("mailto:", 1)[-1].strip()

    # Visible text fallback (may still be "[email protected]" placeholder)
    return tag.get_text(" ", strip=True).strip()

# ============================================================================
# CVE SCRAPER CLASS
# ============================================================================
class CVEScraper:
    def __init__(self):
        self.headers = {
            'User-Agent': (
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119 Safari/537.36'
            )
        }

    def scrape_cve_page(self, url):
        """Scrape information from a single CVE page"""
        try:
            response = requests.get(url, headers=self.headers, timeout=20)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, 'html.parser')

            cve_data = {
                'cve_id': '',
                'title': '',
                'description': '',
                'published_date': '',
                'last_modified': '',
                'remotely_exploit': '',
                'source_identifier': '',   # ← renamed
                'category': '',
                'affected_products': [],
                'cvss_scores': [],
                'url': url
            }

            # CVE ID
            cve_id_elem = soup.find('h5', class_='fs-36 mb-1')
            if cve_id_elem:
                cve_data['cve_id'] = cve_id_elem.get_text(strip=True)

            # Title
            title_elem = soup.find('h5', class_='text mt-2')
            if title_elem:
                cve_data['title'] = title_elem.get_text(strip=True)

            # Description
            self._extract_description(soup, cve_data)

            # INFO section (dates / remote / source_identifier via CF-safe)
            self._extract_info_section(soup, cve_data)

            # Category
            category_alert = soup.find('div', class_='alert-dark')
            if category_alert:
                category_strong = category_alert.find('strong')
                if category_strong:
                    cve_data['category'] = category_strong.get_text(strip=True)

            # All CVSS Scores (each row gets source_identifier)
            self._extract_all_cvss_scores(soup, cve_data)

            # Affected products
            self._extract_affected_products(soup, cve_data)

            return cve_data

        except Exception as e:
            logger.error(f"Error scraping {url}: {str(e)}")
            return None

    def _extract_description(self, soup, cve_data):
        """Extract description"""
        desc_cards = soup.find_all('div', class_='card-body')
        for card in desc_cards:
            desc_p = card.find('p', class_='card-text')
            if desc_p:
                text = desc_p.get_text(strip=True)
                if len(text) > 50 and 'vulnerability' in text.lower():
                    cve_data['description'] = text
                    return

    def _extract_info_section(self, soup, cve_data):
        """Extract Published Date, Last Modified, Remote Exploit, Source Identifier (Cloudflare-safe)"""
        info_cols = soup.find_all('div', class_='col-lg-3')

        for col in info_cols:
            label_elem = col.find('p', class_='mb-1') or col.find('p', class_='mb-2')
            if not label_elem:
                continue

            label_text = label_elem.get_text(strip=True)
            value_elem = col.find('h6', class_='text-truncate')
            value_text = value_elem.get_text(strip=True) if value_elem else ""

            if 'Published' in label_text or 'Date' in label_text:
                cve_data['published_date'] = value_text
            elif 'Modified' in label_text:
                cve_data['last_modified'] = value_text
            elif 'Exploit' in label_text or 'Remote' in label_text:
                cve_data['remotely_exploit'] = value_text
            elif 'Source' in label_text:
                cve_data['source_identifier'] = extract_email_from_tag(col) or value_text

    def _extract_all_cvss_scores(self, soup, cve_data):
        """Extract ALL CVSS scores from table (Cloudflare-safe for 'Source')"""
        cvss_tables = soup.find_all('table', class_='table-borderless')

        for table in cvss_tables:
            thead = table.find('thead')
            if not thead:
                continue

            headers = [th.get_text(strip=True) for th in thead.find_all('th')]
            if 'Score' not in headers or 'Vector' not in headers:
                continue

            tbody = table.find('tbody')
            rows = tbody.find_all('tr') if tbody else table.find_all('tr')[1:]

            for row in rows:
                cells = row.find_all('td')
                if len(cells) < 7:
                    continue

                cvss_entry = {}

                # Score
                score_btn = cells[0].find('b')
                if score_btn:
                    cvss_entry['score'] = score_btn.get_text(strip=True)

                # Version
                cvss_entry['version'] = cells[1].get_text(strip=True)

                # Severity
                cvss_entry['severity'] = cells[2].get_text(strip=True)

                # Vector (prefer input[value], fallback to text)
                vector_input = cells[3].find('input')
                if vector_input:
                    cvss_entry['vector'] = vector_input.get('value', '').strip()
                else:
                    cvss_entry['vector'] = cells[3].get_text(strip=True)

                # Exploitability Score
                exploit_btn = cells[4].find('b')
                if exploit_btn:
                    exploit_text = exploit_btn.get_text(strip=True)
                    if exploit_text:
                        cvss_entry['exploitability_score'] = exploit_text

                # Impact Score
                impact_btn = cells[5].find('b')
                if impact_btn:
                    impact_text = impact_btn.get_text(strip=True)
                    if impact_text:
                        cvss_entry['impact_score'] = impact_text

                # Source Identifier (Cloudflare-safe)
                source_text = extract_email_from_tag(cells[6])
                if source_text:
                    cvss_entry['source_identifier'] = source_text

                # Keep meaningful rows
                if cvss_entry.get('version') or cvss_entry.get('score') or cvss_entry.get('vector'):
                    cve_data['cvss_scores'].append(cvss_entry)

            logger.info(f"    Found {len(cve_data['cvss_scores'])} CVSS score(s)")
            break  # stop after the first valid CVSS table

    def _extract_affected_products(self, soup, cve_data):
        """Extract affected vendors and products"""
        affected_section = None
        for h5 in soup.find_all('h5'):
            if 'Affected Products' in h5.get_text():
                affected_section = h5.find_parent('div', class_='card-body')
                break

        if not affected_section:
            product_table = soup.find('table', class_='table-nowrap')
            if product_table:
                affected_section = product_table.find_parent('div', class_='card-body')

        if not affected_section:
            return

        no_product_msg = affected_section.find('p', class_='text-warning')
        if no_product_msg and 'No affected product' in no_product_msg.get_text():
            return

        product_table = affected_section.find('table', class_='table-nowrap')
        if not product_table:
            return

        tbody = product_table.find('tbody')
        if not tbody:
            return

        rows = tbody.find_all('tr')
        for row in rows:
            cells = row.find_all('td')
            if len(cells) >= 3:
                product_id = cells[0].get_text(strip=True)
                vendor = cells[1].get_text(strip=True)
                product = cells[2].get_text(strip=True)

                if vendor or product:
                    cve_data['affected_products'].append({
                        'id': product_id,
                        'vendor': vendor,
                        'product': product
                    })

        logger.info(f"    Found {len(cve_data['affected_products'])} affected product(s)")

    # ------------------------------------------------------------------------
    # Batch Orchestration
    # ------------------------------------------------------------------------
    def scrape_and_load_batch(self, cve_list, batch_size=100, delay=2, engine=None):
        """
        Scrape CVEs in batches and load directly to PostgreSQL

        Args:
            cve_list: List of (cve_id, url) tuples or URLs
            batch_size: Number of CVEs to scrape before loading to DB
            delay: Delay between requests (seconds)
            engine: Optional SQLAlchemy engine

        Returns:
            dict: Overall statistics
        """
        logger.info("="*70)
        logger.info("🚀 STARTING SCRAPE & LOAD PIPELINE")
        logger.info("="*70)
        logger.info(f"📋 Total CVEs to process: {len(cve_list):,}")
        logger.info(f"📦 Batch size: {batch_size}")
        logger.info(f"⏱️  Delay between requests: {delay}s")
        logger.info("="*70)

        # Create engine if not provided
        if engine is None:
            engine = create_db_engine()

        # Check which CVEs are already scraped
        from sqlalchemy import text
        with engine.connect() as conn:
            result = conn.execute(text("SELECT cve_id FROM raw.cve_details"))
            scraped_cves = {row[0] for row in result.fetchall()}

        logger.info(f"📊 Already in database: {len(scraped_cves):,} CVEs")

        # Filter out already scraped CVEs
        to_scrape = []
        for item in cve_list:
            if isinstance(item, tuple):
                cve_id, url = item
            else:
                url = item
                cve_id = url.rstrip('/').split('/')[-1]

            if cve_id not in scraped_cves:
                to_scrape.append((cve_id, url))

        logger.info(f"🎯 New CVEs to scrape: {len(to_scrape):,}")

        if not to_scrape:
            logger.info("✅ All CVEs already in database!")
            return {'total': 0, 'scraped': 0, 'inserted': 0, 'skipped': 0, 'failed': 0}

        # Scrape and load in batches
        overall_stats = {
            'total': len(to_scrape),
            'scraped': 0,
            'inserted': 0,
            'skipped': 0,
            'failed': 0
        }

        batch = []

        try:
            for idx, (cve_id, url) in enumerate(to_scrape, 1):
                logger.info(f"[{idx}/{len(to_scrape)}] Scraping {cve_id}...")

                data = self.scrape_cve_page(url)

                if data:
                    batch.append(data)
                    overall_stats['scraped'] += 1

                    # Log summary
                    scores_summary = ', '.join([
                        f"{s.get('version', 'N/A')}: {s.get('score', 'N/A')}"
                        for s in data['cvss_scores']
                    ])
                    logger.info(f"    ✓ Scores: {scores_summary}")
                else:
                    logger.warning(f"    ✗ Failed to scrape {cve_id}")
                    overall_stats['failed'] += 1

                # Load batch to database
                if len(batch) >= batch_size or idx == len(to_scrape):
                    if batch:
                        logger.info(f"\n{'='*70}")
                        logger.info(f"💾 Loading batch of {len(batch)} CVEs to database...")
                        logger.info(f"{'='*70}")

                        stats = load_bronze_layer(batch, engine)

                        if stats:
                            overall_stats['inserted'] += stats.get('inserted', 0)
                            overall_stats['skipped'] += stats.get('skipped', 0)

                        batch = []  # Reset batch

                # Delay before next request
                if idx < len(to_scrape):
                    time.sleep(delay)

        except KeyboardInterrupt:
            logger.warning("\n⚠️  KeyboardInterrupt detected!")
            if batch:
                logger.info("💾 Saving partial batch...")
                stats = load_bronze_layer(batch, engine)
                if stats:
                    overall_stats['inserted'] += stats.get('inserted', 0)
                    overall_stats['skipped'] += stats.get('skipped', 0)

        # Final summary
        logger.info("\n" + "="*70)
        logger.info("🎉 SCRAPE & LOAD PIPELINE COMPLETED")
        logger.info("="*70)
        logger.info(f"📊 Total CVEs attempted: {overall_stats['total']:,}")
        logger.info(f"✅ Successfully scraped:  {overall_stats['scraped']:,}")
        logger.info(f"💾 Inserted to DB:        {overall_stats['inserted']:,}")
        logger.info(f"⏭️  Skipped (duplicates):  {overall_stats['skipped']:,}")
        logger.info(f"❌ Failed:                {overall_stats['failed']:,}")
        logger.info("="*70)

        return overall_stats


# ============================================================================
# MAIN EXECUTION
# ============================================================================
def main():
    """Main execution function"""
    logger.info("🔧 Initializing CVE scraper...")
    scraper = CVEScraper()

    # Load CVE list from CSV
    cve_list_file = PROJECT_ROOT / "Data" / "cve_ids_all_years_2002_2025_from_zip.csv"
    logger.info(f"📂 Loading CVE list from: {cve_list_file}")

    cve_urls = []
    with open(cve_list_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            cve_urls.append((row['cve_id'], row['url']))

    logger.info(f"✅ Loaded {len(cve_urls):,} CVE URLs")

    # Scrape and load to database
    stats = scraper.scrape_and_load_batch(
        cve_urls,
        batch_size=100,  # Load to DB every 100 CVEs
        delay=2          # 2 seconds between requests
    )

    return stats


if __name__ == "__main__":
    print(f"▶ Running {Path(__file__).name}")
    main()
