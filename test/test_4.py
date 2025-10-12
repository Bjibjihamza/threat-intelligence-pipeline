import requests
from bs4 import BeautifulSoup
import csv
import time
import os
import logging
import json

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class CVEScraper:
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
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
                'affected_products': [],  # Liste de produits
                'cvss_scores': [],  # Liste de tous les scores CVSS
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
            
            # Extract ALL CVSS Scores from table
            self._extract_all_cvss_scores(soup, cve_data)
            
            # Extract Affected Products
            self._extract_affected_products(soup, cve_data)
            
            return cve_data
            
        except Exception as e:
            logging.error(f"Error scraping {url}: {str(e)}")
            import traceback
            traceback.print_exc()
            return None
    
    def _extract_description(self, soup, cve_data):
        """Extract description using multiple methods"""
        desc_cards = soup.find_all('div', class_='card-body')
        for card in desc_cards:
            desc_p = card.find('p', class_='card-text')
            if desc_p:
                text = desc_p.get_text(strip=True)
                if len(text) > 50 and 'vulnerability' in text.lower():
                    cve_data['description'] = text
                    return
        
        desc_section = soup.find('div', id='overview')
        if desc_section:
            desc_p = desc_section.find('p', class_='card-text')
            if desc_p:
                cve_data['description'] = desc_p.get_text(strip=True)
    
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
        """Extract ALL CVSS scores (multiple versions) from the scoring table"""
        # Chercher la table CVSS spécifiquement
        cvss_tables = soup.find_all('table', class_='table-borderless')
        
        for table in cvss_tables:
            # Vérifier que c'est bien la table CVSS (elle a des colonnes Score, Version, etc.)
            thead = table.find('thead')
            if thead:
                headers = [th.get_text(strip=True) for th in thead.find_all('th')]
                # Si on trouve "Score" et "Vector" dans les headers, c'est la bonne table
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
                            
                            # Vector (le plus important!)
                            vector_input = cells[3].find('input')
                            if vector_input:
                                cvss_entry['vector'] = vector_input.get('value', '')
                            
                            # Exploitability Score
                            exploit_btn = cells[4].find('b')
                            if exploit_btn:
                                exploit_text = exploit_btn.get_text(strip=True)
                                if exploit_text:  # Seulement si non vide
                                    cvss_entry['exploitability_score'] = exploit_text
                            
                            # Impact Score
                            impact_btn = cells[5].find('b')
                            if impact_btn:
                                impact_text = impact_btn.get_text(strip=True)
                                if impact_text:  # Seulement si non vide
                                    cvss_entry['impact_score'] = impact_text
                            
                            # Source
                            source_text = cells[6].get_text(strip=True)
                            if source_text:
                                cvss_entry['source'] = source_text
                            
                            # Ajouter cette entrée à la liste
                            if cvss_entry.get('vector'):  # Seulement si on a un vecteur
                                cve_data['cvss_scores'].append(cvss_entry)
                    
                    logging.info(f"    Found {len(cve_data['cvss_scores'])} CVSS score(s)")
                    break  # On a trouvé la bonne table, on arrête
    
    def _extract_affected_products(self, soup, cve_data):
        """Extract affected vendors and products"""
        # Chercher la section "Affected Products"
        affected_section = None
        for h5 in soup.find_all('h5'):
            if 'Affected Products' in h5.get_text():
                affected_section = h5.find_parent('div', class_='card-body')
                break
        
        if not affected_section:
            # Méthode 2: Chercher directement la table avec class table-nowrap
            product_table = soup.find('table', class_='table-nowrap')
            if product_table:
                affected_section = product_table.find_parent('div', class_='card-body')
        
        if affected_section:
            # Vérifier d'abord s'il y a le message "No affected product"
            no_product_msg = affected_section.find('p', class_='text-warning')
            if no_product_msg and 'No affected product' in no_product_msg.get_text():
                logging.info("    No affected products found")
                return
            
            # Chercher la table des produits
            product_table = affected_section.find('table', class_='table-nowrap')
            
            if product_table:
                tbody = product_table.find('tbody')
                if tbody:
                    rows = tbody.find_all('tr')
                    
                    for row in rows:
                        cells = row.find_all('td')
                        if len(cells) >= 3:
                            # ID est dans cells[0]
                            product_id = cells[0].get_text(strip=True)
                            # Vendor est dans cells[1]
                            vendor = cells[1].get_text(strip=True)
                            # Product est dans cells[2]
                            product = cells[2].get_text(strip=True)
                            
                            if vendor or product:
                                product_entry = {
                                    'id': product_id,
                                    'vendor': vendor,
                                    'product': product
                                }
                                cve_data['affected_products'].append(product_entry)
                    
                    logging.info(f"    Found {len(cve_data['affected_products'])} affected product(s)")
            else:
                logging.info("    No product table found")
        else:
            logging.info("    No affected products section found")
    
    def scrape_multiple_cves(self, cve_list, output_file='cve_data.csv', delay=1):
        """
        Scrape multiple CVE pages and save to CSV incrementally
        """
        results = []
        
        # Check existing CVEs in output file
        scraped_cves = set()
        if os.path.exists(output_file):
            with open(output_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    scraped_cves.add(row['cve_id'])
        
        try:
            for idx, item in enumerate(cve_list, 1):
                if isinstance(item, tuple):
                    cve_id, url = item
                else:
                    url = item
                    cve_id = url.split('/')[-1]
                
                if cve_id in scraped_cves:
                    logging.info(f"[{idx}/{len(cve_list)}] Skipping {cve_id} (already scraped)")
                    continue
                
                logging.info(f"[{idx}/{len(cve_list)}] Scraping {cve_id}...")
                
                data = self.scrape_cve_page(url)
                if data:
                    results.append(data)
                    
                    # Log summary
                    scores_summary = ', '.join([
                        f"{s.get('version', 'N/A')}: {s.get('score', 'N/A')}"
                        for s in data['cvss_scores']
                    ])
                    logging.info(f"    ✓ Scores: {scores_summary}")
                    logging.info(f"    ✓ Category: {data.get('category', 'N/A')}")
                    
                    # Save incrementally - ONE ROW PER CVE
                    self._save_to_csv(data, output_file)
                else:
                    logging.warning(f"    ✗ Failed to scrape {cve_id}")
                
                if idx < len(cve_list):
                    time.sleep(delay)
        
        except KeyboardInterrupt:
            logging.info("KeyboardInterrupt detected, saving partial results...")
        
        logging.info(f"\n{'='*60}")
        logging.info(f"Scraping completed! {len(results)}/{len(cve_list)} CVEs saved to {output_file}")
        logging.info(f"{'='*60}")
        
        return results
    
    def _save_to_csv(self, data, output_file):
        """Save CVE data to CSV - ONE ROW PER CVE with JSON fields"""
        os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', exist_ok=True)
        
        # Convertir les listes en JSON strings
        row = {
            'cve_id': data['cve_id'],
            'title': data['title'],
            'description': data['description'],
            'published_date': data['published_date'],
            'last_modified': data['last_modified'],
            'remotely_exploit': data['remotely_exploit'],
            'source': data['source'],
            'category': data['category'],
            # JSON fields
            'affected_products': json.dumps(data['affected_products'], ensure_ascii=False) if data['affected_products'] else '[]',
            'cvss_scores': json.dumps(data['cvss_scores'], ensure_ascii=False) if data['cvss_scores'] else '[]',
            'url': data['url']
        }
        
        self._write_csv_row(output_file, row)
    
    def _write_csv_row(self, output_file, row):
        """Write a single row to CSV"""
        fieldnames = [
            'cve_id', 'title', 'description',
            'published_date', 'last_modified', 'remotely_exploit',
            'source', 'category',
            'affected_products',  # JSON
            'cvss_scores',  # JSON
            'url'
        ]
        
        file_exists = os.path.exists(output_file)
        mode = 'a' if file_exists else 'w'
        
        with open(output_file, mode, newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            if not file_exists:
                writer.writeheader()
            writer.writerow(row)

if __name__ == "__main__":
    scraper = CVEScraper()
    
    cve_urls = []
    with open('partition4.csv', 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            cve_urls.append((row['cve_id'], row['url']))
    
    results = scraper.scrape_multiple_cves(
        cve_urls, 
        output_file='cve_detailed_raw.csv',
        delay=2
    )
    
    if results:
        logging.info("\n" + "="*60)
        logging.info("SAMPLE DETAILED RESULT:")
        logging.info("="*60)
        sample = results[0]
        logging.info(f"CVE ID: {sample['cve_id']}")
        logging.info(f"Title: {sample['title']}")
        logging.info(f"Category: {sample['category']}")
        logging.info(f"CVSS Scores ({len(sample['cvss_scores'])} versions):")
        for cvss in sample['cvss_scores']:
            logging.info(f"  - {cvss.get('version')}: {cvss.get('score')} ({cvss.get('severity')})")
            logging.info(f"    Vector: {cvss.get('vector')}")
        logging.info(f"Affected Products ({len(sample['affected_products'])} items):")
        for prod in sample['affected_products']:
            logging.info(f"  - {prod.get('vendor')} / {prod.get('product')}")