# ============================================================================
# CVE SCRAPER - Extract Links + Scrape Details + Load to PostgreSQL
# ============================================================================
# Description: Complete pipeline from CVE search to database
# Location: src/batch/extract/stream/complete_cve_scraper.py
# ============================================================================

from pathlib import Path
import sys

# Add src directory to path for imports
sys.path.append(str(Path(__file__).resolve().parents[3]))

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

# Import bronze layer loader
from batch.load.load_bronze_layer import (
    load_bronze_layer,
    create_db_engine,
)

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================
PROJECT_ROOT = Path(__file__).resolve().parents[4]
LOGS_DIR = PROJECT_ROOT / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOGS_DIR / "cve_scraper.log"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ============================================================================
# CVE LINK EXTRACTOR (with Selenium)
# ============================================================================
class CVELinkExtractor:
    def __init__(self):
        self.options = Options()
        self.options.add_argument('--headless')
        self.options.add_argument('--no-sandbox')
        self.options.add_argument('--disable-dev-shm-usage')
        self.options.add_argument('--disable-blink-features=AutomationControlled')
        self.options.add_argument('user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
    
    def extract_cve_links(self, search_url):
        """Extract CVE links from search page using Selenium"""
        logger.info("="*80)
        logger.info("🔍 EXTRACTING CVE LINKS")
        logger.info("="*80)
        logger.info(f"URL: {search_url}")
        
        driver = webdriver.Chrome(options=self.options)
        cve_links = []
        
        try:
            logger.info("🚀 Loading search page...")
            driver.get(search_url)
            
            # Wait for results to load
            wait = WebDriverWait(driver, 20)
            wait.until(EC.presence_of_element_located(
                (By.CSS_SELECTOR, "#searchResults .row.align-items-start.mb-4")
            ))
            time.sleep(3)
            
            html_content = driver.page_source
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Find all CVE entries
            search_results = soup.find('div', id='searchResults')
            if not search_results:
                logger.error("❌ No searchResults div found!")
                return []
            
            entries = search_results.find_all('div', class_='row align-items-start mb-4')
            logger.info(f"📊 Found {len(entries)} CVE entries")
            
            for i, entry in enumerate(entries, 1):
                try:
                    h5_tag = entry.find('h5')
                    if not h5_tag:
                        continue
                    
                    a_tag = h5_tag.find('a')
                    if not a_tag:
                        continue
                    
                    cve_id = a_tag.get_text(strip=True)
                    cve_href = a_tag.get('href', '')
                    cve_url = f"https://cvefeed.io{cve_href}" if cve_href else ""
                    
                    if cve_url:
                        cve_links.append({
                            'cve_id': cve_id,
                            'url': cve_url
                        })
                        logger.info(f"  ✓ {i}. {cve_id}")
                
                except Exception as e:
                    logger.error(f"  ❌ Error parsing entry {i}: {e}")
            
            logger.info(f"✅ Successfully extracted {len(cve_links)} CVE links")
            return cve_links
        
        except Exception as e:
            logger.error(f"❌ Error extracting links: {e}")
            return []
        
        finally:
            driver.quit()
            logger.info("🔒 Browser closed\n")

# ============================================================================
# CVE DETAILS SCRAPER (Exact same as original)
# ============================================================================
class CVEDetailsScraper:
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
    
    def scrape_cve_page(self, url):
        """Scrape information from a single CVE page"""
        try:
            response = requests.get(url, headers=self.headers, timeout=15)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, 'html.parser')
            
            cve_data = {
                'cve_id': '',
                'title': '',
                'description': '',
                'published_date': '',
                'last_modified': '',
                'remotely_exploit': '',
                'source': '',
                'category': '',
                'affected_products': [],
                'cvss_scores': [],
                'url': url
            }
            
            # Extract CVE ID
            cve_id_elem = soup.find('h5', class_='fs-36 mb-1')
            if cve_id_elem:
                cve_data['cve_id'] = cve_id_elem.get_text(strip=True)
            
            # Extract Title
            title_elem = soup.find('h5', class_='text mt-2')
            if title_elem:
                cve_data['title'] = title_elem.get_text(strip=True)
            
            # Extract Description
            self._extract_description(soup, cve_data)
            
            # Extract INFO section
            self._extract_info_section(soup, cve_data)
            
            # Extract Category
            category_alert = soup.find('div', class_='alert-dark')
            if category_alert:
                category_strong = category_alert.find('strong')
                if category_strong:
                    cve_data['category'] = category_strong.get_text(strip=True)
            
            # Extract ALL CVSS Scores
            self._extract_all_cvss_scores(soup, cve_data)
            
            # Extract Affected Products
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
        """Extract Published Date, Last Modified, Remote Exploit, Source"""
        info_cols = soup.find_all('div', class_='col-lg-3')
        
        for col in info_cols:
            label_elem = col.find('p', class_='mb-1')
            if not label_elem:
                label_elem = col.find('p', class_='mb-2')
            
            if label_elem:
                label_text = label_elem.get_text(strip=True)
                value_elem = col.find('h6', class_='text-truncate')
                if value_elem:
                    value_text = value_elem.get_text(strip=True)
                    
                    if 'Published' in label_text or 'Date' in label_text:
                        cve_data['published_date'] = value_text
                    elif 'Modified' in label_text:
                        cve_data['last_modified'] = value_text
                    elif 'Exploit' in label_text or 'Remote' in label_text:
                        cve_data['remotely_exploit'] = value_text
                    elif 'Source' in label_text:
                        cve_data['source'] = value_text
    
    def _extract_all_cvss_scores(self, soup, cve_data):
        """Extract ALL CVSS scores from table"""
        cvss_tables = soup.find_all('table', class_='table-borderless')
        
        for table in cvss_tables:
            thead = table.find('thead')
            if thead:
                headers = [th.get_text(strip=True) for th in thead.find_all('th')]
                if 'Score' in headers and 'Vector' in headers:
                    rows = table.find('tbody').find_all('tr') if table.find('tbody') else table.find_all('tr')[1:]
                    
                    for row in rows:
                        cells = row.find_all('td')
                        if len(cells) >= 7:
                            cvss_entry = {}
                            
                            # Score
                            score_btn = cells[0].find('b')
                            if score_btn:
                                cvss_entry['score'] = score_btn.get_text(strip=True)
                            
                            # Version
                            cvss_entry['version'] = cells[1].get_text(strip=True)
                            
                            # Severity
                            cvss_entry['severity'] = cells[2].get_text(strip=True)
                            
                            # Vector
                            vector_input = cells[3].find('input')
                            if vector_input:
                                cvss_entry['vector'] = vector_input.get('value', '')
                            
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
                            
                            # Source
                            source_text = cells[6].get_text(strip=True)
                            if source_text:
                                cvss_entry['source'] = source_text
                            
                            if cvss_entry.get('vector'):
                                cve_data['cvss_scores'].append(cvss_entry)
                    
                    logger.info(f"    Found {len(cve_data['cvss_scores'])} CVSS score(s)")
                    break
    
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
        
        if affected_section:
            no_product_msg = affected_section.find('p', class_='text-warning')
            if no_product_msg and 'No affected product' in no_product_msg.get_text():
                return
            
            product_table = affected_section.find('table', class_='table-nowrap')
            
            if product_table:
                tbody = product_table.find('tbody')
                if tbody:
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

# ============================================================================
# COMPLETE SCRAPER WITH DATABASE LOADING
# ============================================================================
class CompleteCVEScraper:
    def __init__(self):
        self.link_extractor = CVELinkExtractor()
        self.details_scraper = CVEDetailsScraper()
    
    def scrape_and_load(self, search_url, batch_size=50, delay=2, 
                        save_csv=True, output_csv='cve_data_backup.csv'):
        """
        Complete pipeline: Extract links → Scrape details → Load to DB
        
        Args:
            search_url: CVEfeed.io search URL
            batch_size: Number of CVEs to scrape before loading to DB
            delay: Delay between detail scraping requests (seconds)
            save_csv: Also save to CSV as backup
            output_csv: CSV filename for backup
        """
        logger.info("="*80)
        logger.info("🚀 COMPLETE CVE SCRAPING & LOADING PIPELINE")
        logger.info("="*80)
        
        # Create database engine
        engine = create_db_engine()
        
        # Step 1: Extract CVE links
        cve_links = self.link_extractor.extract_cve_links(search_url)
        
        if not cve_links:
            logger.error("❌ No CVE links found!")
            return
        
        # Check which CVEs are already in database
        from sqlalchemy import text
        with engine.connect() as conn:
            result = conn.execute(text("SELECT cve_id FROM raw.cve_details"))
            scraped_cves = {row[0] for row in result.fetchall()}
        
        logger.info(f"📊 Already in database: {len(scraped_cves)} CVEs")
        
        # Filter out already scraped CVEs
        to_scrape = [
            cve for cve in cve_links 
            if cve['cve_id'] not in scraped_cves
        ]
        
        logger.info(f"🎯 New CVEs to scrape: {len(to_scrape)}")
        
        if not to_scrape:
            logger.info("✅ All CVEs already in database!")
            return
        
        # Step 2: Scrape details and load to database in batches
        logger.info("="*80)
        logger.info("📝 SCRAPING CVE DETAILS & LOADING TO DATABASE")
        logger.info("="*80)
        logger.info(f"Total CVEs to process: {len(to_scrape)}")
        logger.info(f"Batch size: {batch_size}")
        logger.info(f"Delay between requests: {delay}s")
        logger.info("="*80)
        
        overall_stats = {
            'total': len(to_scrape),
            'scraped': 0,
            'inserted': 0,
            'skipped': 0,
            'failed': 0
        }
        
        batch = []
        all_cve_data = []  # For CSV backup
        
        try:
            for idx, cve_info in enumerate(to_scrape, 1):
                cve_id = cve_info['cve_id']
                url = cve_info['url']
                
                logger.info(f"\n[{idx}/{len(to_scrape)}] Scraping {cve_id}...")
                
                cve_data = self.details_scraper.scrape_cve_page(url)
                
                if cve_data:
                    batch.append(cve_data)
                    all_cve_data.append(cve_data)
                    overall_stats['scraped'] += 1
                    
                    # Log summary
                    scores_summary = ', '.join([
                        f"{s.get('version', 'N/A')}: {s.get('score', 'N/A')}"
                        for s in cve_data['cvss_scores']
                    ])
                    logger.info(f"    ✓ Scores: {scores_summary}")
                else:
                    overall_stats['failed'] += 1
                    logger.warning(f"    ✗ Failed to scrape")
                
                # Load batch to database
                if len(batch) >= batch_size or idx == len(to_scrape):
                    if batch:
                        logger.info(f"\n{'='*80}")
                        logger.info(f"💾 Loading batch of {len(batch)} CVEs to database...")
                        logger.info(f"{'='*80}")
                        
                        stats = load_bronze_layer(batch, engine)
                        
                        if stats:
                            overall_stats['inserted'] += stats['inserted']
                            overall_stats['skipped'] += stats['skipped']
                        
                        batch = []  # Reset batch
                
                # Delay before next request
                if idx < len(to_scrape):
                    time.sleep(delay)
        
        except KeyboardInterrupt:
            logger.warning("\n⚠️  KeyboardInterrupt detected!")
            if batch:
                logger.info("💾 Saving partial batch to database...")
                stats = load_bronze_layer(batch, engine)
                if stats:
                    overall_stats['inserted'] += stats['inserted']
                    overall_stats['skipped'] += stats['skipped']
        
        # Step 3: Save CSV backup if requested
        if save_csv and all_cve_data:
            logger.info("\n" + "="*80)
            logger.info("💾 SAVING CSV BACKUP")
            logger.info("="*80)
            self.save_to_csv(all_cve_data, output_csv)
        
        # Final summary
        logger.info("\n" + "="*80)
        logger.info("🎉 SCRAPING & LOADING PIPELINE COMPLETED")
        logger.info("="*80)
        logger.info(f"📊 Total CVEs attempted:  {overall_stats['total']:,}")
        logger.info(f"✅ Successfully scraped:   {overall_stats['scraped']:,}")
        logger.info(f"💾 Inserted to DB:         {overall_stats['inserted']:,}")
        logger.info(f"⏭️  Skipped (duplicates):   {overall_stats['skipped']:,}")
        logger.info(f"❌ Failed:                 {overall_stats['failed']:,}")
        logger.info("="*80)
        
        return overall_stats
    
    def save_to_csv(self, cve_data_list, filename):
        """Save CVE data to CSV file (backup)"""
        if not cve_data_list:
            return
        
        fieldnames = [
            'cve_id', 'title', 'description', 'published_date', 'last_modified',
            'remotely_exploit', 'source', 'category', 'affected_products', 
            'cvss_scores', 'url'
        ]
        
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for cve in cve_data_list:
                row = cve.copy()
                row['affected_products'] = json.dumps(cve['affected_products'], ensure_ascii=False)
                row['cvss_scores'] = json.dumps(cve['cvss_scores'], ensure_ascii=False)
                writer.writerow(row)
        
        logger.info(f"✅ Saved {len(cve_data_list)} CVEs to {filename}")

# ============================================================================
# MAIN EXECUTION
# ============================================================================
def main():
    """Main execution function"""
    
    # Configuration
    SEARCH_URL = "https://cvefeed.io/search?keyword=&published_after=2025-10-16%2000:00:00&published_before=2025-10-16%2023:59:59&cvss_min=3.00&cvss_max=7.00&order_by=-published"
    BATCH_SIZE = 50        # Load to DB every 50 CVEs
    REQUEST_DELAY = 2      # 2 seconds between requests
    SAVE_CSV_BACKUP = True # Also save to CSV
    
    # Run scraper
    scraper = CompleteCVEScraper()
    stats = scraper.scrape_and_load(
        search_url=SEARCH_URL,
        batch_size=BATCH_SIZE,
        delay=REQUEST_DELAY,
        save_csv=SAVE_CSV_BACKUP
    )
    
    return stats

if __name__ == "__main__":
    logger.info(f"▶ Running {Path(__file__).name}")
    main()