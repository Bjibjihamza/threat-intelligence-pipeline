import requests
from bs4 import BeautifulSoup
import csv
import time
import re
import os
import logging

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
                'cvss_score': '',
                'cvss_severity': '',
                'cvss_version': '',
                'cvss_vector': '',
                'exploitability_score': '',
                'impact_score': '',
                'published_date': '',
                'last_modified': '',
                'remotely_exploit': '',
                'source': '',
                'source_from_table': '',
                'category': '',
                'affected_vendors': '',
                'affected_products': '',
                'attack_vector': '',
                'attack_complexity': '',
                'privileges_required': '',
                'user_interaction': '',
                'scope': '',
                'confidentiality_impact': '',
                'integrity_impact': '',
                'availability_impact': '',
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
            
            # Extract CVSS Score
            cvss_score_div = soup.find('div', class_='fs-36 mt-1 mb-1')
            if cvss_score_div:
                score_b = cvss_score_div.find('b')
                if score_b:
                    cve_data['cvss_score'] = score_b.get_text(strip=True)
            
            # Extract CVSS Severity and Version
            severity_container = soup.find('div', class_='rounded-0 btn btn-severity-high')
            if not severity_container:
                severity_container = soup.find('div', class_='btn', attrs={'class': lambda x: x and 'btn-severity' in x})
            
            if severity_container:
                smalls = severity_container.find_all('small')
                if len(smalls) >= 1:
                    cve_data['cvss_severity'] = smalls[0].get_text(strip=True)
                if len(smalls) >= 2:
                    cve_data['cvss_version'] = smalls[1].get_text(strip=True)
            
            # Extract INFO section
            self._extract_info_section(soup, cve_data)
            
            # Extract Category (Update this based on actual HTML)
            category_alert = soup.find('div', class_='alert-dark')
            if category_alert:
                category_strong = category_alert.find('strong')
                if category_strong:
                    cve_data['category'] = category_strong.get_text(strip=True)
                else:
                    logging.warning(f"No strong tag found in alert-dark for {url}")
            
            # Extract CVSS Details
            self._extract_cvss_table(soup, cve_data)
            
            # Extract Affected Products
            self._extract_affected_products(soup, cve_data)
            
            # Extract CVSS Metrics
            self._extract_cvss_metrics(soup, cve_data)
            
            # Parse CVSS Vector
            if not cve_data['attack_vector'] and cve_data['cvss_vector']:
                self._parse_cvss_vector(cve_data)
            
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
    
    def _extract_cvss_table(self, soup, cve_data):
        """Extract CVSS details from the scoring table"""
        cvss_table = soup.find('table', class_='table-borderless')
        if not cvss_table:
            cvss_table = soup.find('table', class_='table-centered')
        
        if cvss_table:
            rows = cvss_table.find_all('tr')
            for row in rows[1:]:
                cells = row.find_all('td')
                if len(cells) >= 7:
                    score_btn = cells[0].find('b')
                    if score_btn and not cve_data['cvss_score']:
                        cve_data['cvss_score'] = score_btn.get_text(strip=True)
                    
                    if cells[1] and not cve_data['cvss_version']:
                        cve_data['cvss_version'] = cells[1].get_text(strip=True)
                    
                    if cells[2] and not cve_data['cvss_severity']:
                        cve_data['cvss_severity'] = cells[2].get_text(strip=True)
                    
                    vector_input = cells[3].find('input', class_='apikey-value')
                    if not vector_input:
                        vector_input = cells[3].find('input')
                    if vector_input:
                        vector_value = vector_input.get('value', '')
                        if vector_value:
                            cve_data['cvss_vector'] = vector_value
                    
                    exploit_btn = cells[4].find('b')
                    if exploit_btn:
                        cve_data['exploitability_score'] = exploit_btn.get_text(strip=True)
                    
                    impact_btn = cells[5].find('b')
                    if impact_btn:
                        cve_data['impact_score'] = impact_btn.get_text(strip=True)
                    
                    if cells[6]:
                        source_text = cells[6].get_text(strip=True)
                        if source_text:
                            cve_data['source_from_table'] = source_text
                            if not cve_data['source']:
                                cve_data['source'] = source_text
    
    def _extract_affected_products(self, soup, cve_data):
        """Extract affected vendors and products"""
        product_table = soup.find('table', class_='table-nowrap')
        
        if product_table:
            vendors = []
            products = []
            rows = product_table.find_all('tr')[1:]
            
            for row in rows:
                cells = row.find_all('td')
                if len(cells) >= 3:
                    vendor = cells[1].get_text(strip=True)
                    product = cells[2].get_text(strip=True)
                    
                    if vendor:
                        vendors.append(vendor)
                    if product:
                        products.append(product)
            
            if vendors:
                cve_data['affected_vendors'] = '; '.join(vendors)
            if products:
                cve_data['affected_products'] = '; '.join(products)
    
    def _extract_cvss_metrics(self, soup, cve_data):
        """Extract detailed CVSS metrics from radio buttons and labels"""
        metrics_mapping = {
            'metric-AV': ('attack_vector', {
                'N': 'Network',
                'A': 'Adjacent',
                'L': 'Local',
                'P': 'Physical'
            }),
            'metric-AC': ('attack_complexity', {
                'L': 'Low',
                'H': 'High'
            }),
            'metric-PR': ('privileges_required', {
                'N': 'None',
                'L': 'Low',
                'H': 'High'
            }),
            'metric-UI': ('user_interaction', {
                'N': 'None',
                'R': 'Required'
            }),
            'metric-S': ('scope', {
                'C': 'Changed',
                'U': 'Unchanged'
            }),
            'metric-C': ('confidentiality_impact', {
                'H': 'High',
                'L': 'Low',
                'N': 'None'
            }),
            'metric-I': ('integrity_impact', {
                'H': 'High',
                'L': 'Low',
                'N': 'None'
            }),
            'metric-A': ('availability_impact', {
                'H': 'High',
                'L': 'Low',
                'N': 'None'
            })
        }
        
        for metric_prefix, (data_key, value_map) in metrics_mapping.items():
            checked_input = soup.find('input', {
                'name': metric_prefix,
                'checked': True
            })
            
            if checked_input:
                value = checked_input.get('value', '')
                cve_data[data_key] = value_map.get(value, value)
            
            if not cve_data[data_key]:
                all_inputs = soup.find_all('input', {'name': metric_prefix})
                for inp in all_inputs:
                    if inp.has_attr('checked'):
                        value = inp.get('value', '')
                        cve_data[data_key] = value_map.get(value, value)
                        break
    
    def _parse_cvss_vector(self, cve_data):
        """Parse CVSS vector string to extract metrics"""
        vector = cve_data.get('cvss_vector', '')
        if not vector:
            return
        
        is_v2 = 'AV:' in vector and 'AC:' in vector and 'Au:' in vector
        
        if is_v2:
            vector_mapping = {
                'AV': ('attack_vector', {'N': 'Network', 'A': 'Adjacent', 'L': 'Local'}),
                'AC': ('attack_complexity', {'L': 'Low', 'M': 'Medium', 'H': 'High'}),
                'Au': ('privileges_required', {'N': 'None', 'S': 'Single', 'M': 'Multiple'}),
                'C': ('confidentiality_impact', {'C': 'Complete', 'P': 'Partial', 'N': 'None'}),
                'I': ('integrity_impact', {'C': 'Complete', 'P': 'Partial', 'N': 'None'}),
                'A': ('availability_impact', {'C': 'Complete', 'P': 'Partial', 'N': 'None'})
            }
        else:
            vector_mapping = {
                'AV': ('attack_vector', {'N': 'Network', 'A': 'Adjacent', 'L': 'Local', 'P': 'Physical'}),
                'AC': ('attack_complexity', {'L': 'Low', 'H': 'High'}),
                'PR': ('privileges_required', {'N': 'None', 'L': 'Low', 'H': 'High'}),
                'UI': ('user_interaction', {'N': 'None', 'R': 'Required'}),
                'S': ('scope', {'C': 'Changed', 'U': 'Unchanged'}),
                'C': ('confidentiality_impact', {'H': 'High', 'L': 'Low', 'N': 'None'}),
                'I': ('integrity_impact', {'H': 'High', 'L': 'Low', 'N': 'None'}),
                'A': ('availability_impact', {'H': 'High', 'L': 'Low', 'N': 'None'})
            }
        
        parts = vector.split('/')
        for part in parts:
            if ':' in part:
                key, value = part.split(':', 1)
                if key in vector_mapping:
                    data_key, value_map = vector_mapping[key]
                    if not cve_data.get(data_key):
                        cve_data[data_key] = value_map.get(value, value)
    
    def scrape_multiple_cves(self, cve_list, output_file='cve_data.csv', delay=1):
        """
        Scrape multiple CVE pages and save to CSV incrementally
        """
        results = []
        fieldnames = [
            'cve_id', 'title', 'description', 
            'cvss_score', 'cvss_severity', 'cvss_version', 'cvss_vector', 
            'exploitability_score', 'impact_score',
            'published_date', 'last_modified', 'remotely_exploit', 
            'source', 'source_from_table', 'category', 
            'affected_vendors', 'affected_products',
            'attack_vector', 'attack_complexity', 'privileges_required',
            'user_interaction', 'scope', 'confidentiality_impact',
            'integrity_impact', 'availability_impact',
            'url'
        ]
        
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
                    logging.info(f"    ✓ Score: {data['cvss_score']} | Severity: {data['cvss_severity']} | Category: {data['category']}")
                    # Save incrementally
                    mode = 'a' if os.path.exists(output_file) else 'w'
                    os.makedirs(os.path.dirname(output_file), exist_ok=True)
                    with open(output_file, mode, newline='', encoding='utf-8') as csvfile:
                        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                        if mode == 'w':
                            writer.writeheader()
                        writer.writerow(data)
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

if __name__ == "__main__":
    scraper = CVEScraper()
    
    cve_urls = []
    with open('data/test_to_scrap.csv', 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            cve_urls.append((row['cve_id'], row['url']))
    
    results = scraper.scrape_multiple_cves(
        cve_urls, 
        output_file='output/cve_detailed_data2.csv',
        delay=2
    )
    
    if results:
        logging.info("\n" + "="*60)
        logging.info("SAMPLE DETAILED RESULT:")
        logging.info("="*60)
        sample = results[0]
        for key, value in sample.items():
            if value:
                logging.info(f"{key:25s}: {value}")