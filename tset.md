(cenv) PS C:\Users\hamza\OneDrive\Desktop\Projects\threat-intelligence-pipeline\src\batch\extract\stream> python scrape_live_cvefeed_bronze_m.py
2025-10-18 00:54:55,805 - INFO - ▶ Running scrape_live_cvefeed_bronze_m.py
2025-10-18 00:54:55,805 - INFO - 🎯 Target date: 2025-10-16
2025-10-18 00:54:55,806 - INFO - 🔗 Search URL: https://cvefeed.io/search?keyword=&published_after=2025-10-16%2000:00:00&published_before=2025-10-16%2023:59:59&cvss_min=3.00&cvss_max=10.00&order_by=-published
2025-10-18 00:54:55,806 - INFO - ================================================================================
2025-10-18 00:54:55,806 - INFO - 🚀 COMPLETE CVE SCRAPING & ETL PIPELINE
2025-10-18 00:54:55,806 - INFO - ================================================================================
2025-10-18 00:54:55,806 - INFO - ⏰ Start time: 2025-10-18 00:54:55
2025-10-18 00:54:55,806 - INFO - ================================================================================

2025-10-18 00:54:55,861 - INFO - ✅ Connected to PostgreSQL at localhost:5432/tip
2025-10-18 00:54:55,861 - INFO - ================================================================================
2025-10-18 00:54:55,862 - INFO - 🔍 STEP 1/6: EXTRACTING CVE LINKS
2025-10-18 00:54:55,862 - INFO - ================================================================================
2025-10-18 00:54:55,862 - INFO - URL: https://cvefeed.io/search?keyword=&published_after=2025-10-16%2000:00:00&published_before=2025-10-16%2023:59:59&cvss_min=3.00&cvss_max=10.00&order_by=-published
2025-10-18 00:54:57,020 - INFO - 🚀 Loading search page...
2025-10-18 00:54:58,425 - INFO - ⏳ Waiting for page to load (max 60s)...
2025-10-18 00:55:02,027 - INFO - 📊 Found 10 CVE entries on the page
2025-10-18 00:55:02,027 - INFO -   ✓ 1. CVE-2025-62506
2025-10-18 00:55:02,028 - INFO -   ✓ 2. CVE-2025-62504
2025-10-18 00:55:02,028 - INFO -   ✓ 3. CVE-2025-11864
2025-10-18 00:55:02,028 - INFO -   ✓ 4. CVE-2024-42192
2025-10-18 00:55:02,028 - INFO -   ✓ 5. CVE-2025-61554
2025-10-18 00:55:02,029 - INFO -   ✓ 6. CVE-2025-60358
2025-10-18 00:55:02,029 - INFO -   ✓ 7. CVE-2025-62428
2025-10-18 00:55:02,029 - INFO -   ✓ 8. CVE-2025-62427
2025-10-18 00:55:02,029 - INFO -   ✓ 9. CVE-2025-62425
2025-10-18 00:55:02,029 - INFO -   ✓ 10. CVE-2025-62423
2025-10-18 00:55:02,029 - INFO - ✅ Successfully extracted 10 CVE links

2025-10-18 00:55:04,160 - INFO - 🔒 Browser closed

2025-10-18 00:55:04,160 - INFO - ================================================================================
2025-10-18 00:55:04,160 - INFO - 🔎 STEP 2/6: CHECKING EXISTING CVEs
2025-10-18 00:55:04,160 - INFO - ================================================================================
2025-10-18 00:55:04,331 - INFO - 📊 Already in database: 90766 CVEs
2025-10-18 00:55:04,332 - INFO - 🎯 New CVEs to scrape: 4

2025-10-18 00:55:04,332 - INFO - ================================================================================
2025-10-18 00:55:04,332 - INFO - 📝 STEP 3/6: SCRAPING CVE DETAILS
2025-10-18 00:55:04,332 - INFO - ================================================================================
2025-10-18 00:55:04,332 - INFO - Total CVEs to scrape: 4
2025-10-18 00:55:04,332 - INFO - Delay: 2s
2025-10-18 00:55:04,333 - INFO - ================================================================================

2025-10-18 00:55:04,333 - INFO - [1/4] Scraping CVE-2025-62506...
2025-10-18 00:55:04,830 - INFO -     Found 1 CVSS score(s)
2025-10-18 00:55:04,831 - INFO -     Found 1 affected product(s)
2025-10-18 00:55:04,832 - INFO -     ✓ Scores: CVSS 3.1: 8.1
2025-10-18 00:55:06,833 - INFO - [2/4] Scraping CVE-2025-62504...
2025-10-18 00:55:07,398 - INFO -     Found 1 CVSS score(s)
2025-10-18 00:55:07,400 - INFO -     Found 1 affected product(s)
2025-10-18 00:55:07,401 - INFO -     ✓ Scores: CVSS 3.1: 6.5
2025-10-18 00:55:09,402 - INFO - [3/4] Scraping CVE-2025-11864...
2025-10-18 00:55:09,911 - INFO -     Found 3 CVSS score(s)
2025-10-18 00:55:09,913 - INFO -     ✓ Scores: CVSS 2.0: 7.5, CVSS 3.1: 7.3, CVSS 4.0: 6.9
2025-10-18 00:55:11,914 - INFO - [4/4] Scraping CVE-2024-42192...
2025-10-18 00:55:12,464 - INFO -     Found 2 CVSS score(s)
2025-10-18 00:55:12,466 - INFO -     ✓ Scores: CVSS 3.1: 5.5, CVSS 3.1: 5.5
2025-10-18 00:55:12,467 - INFO -
================================================================================
2025-10-18 00:55:12,467 - INFO - 📥 STEP 4/6: LOADING TO BRONZE LAYER
2025-10-18 00:55:12,467 - INFO - ================================================================================
2025-10-18 00:55:12,467 - INFO - ======================================================================
2025-10-18 00:55:12,467 - INFO - 🎯 BRONZE LAYER LOAD PIPELINE
2025-10-18 00:55:12,467 - INFO - ======================================================================
2025-10-18 00:55:12,468 - INFO - 🔎 Verifying bronze schema 'raw' and table 'raw.cve_details'...
2025-10-18 00:55:12,473 - INFO - ✅ Bronze schema validated
2025-10-18 00:55:12,473 - INFO - 🛠️ Preparing data for database insertion...
2025-10-18 00:55:12,477 - INFO - ✅ Prepared 4 rows for insertion
2025-10-18 00:55:12,477 - INFO - ======================================================================
2025-10-18 00:55:12,477 - INFO - 🚀 LOADING TO BRONZE LAYER (raw.cve_details)
2025-10-18 00:55:12,478 - INFO - ======================================================================
2025-10-18 00:55:12,509 - INFO - ======================================================================
2025-10-18 00:55:12,509 - INFO - 📊 LOAD STATISTICS
2025-10-18 00:55:12,509 - INFO - ======================================================================
2025-10-18 00:55:12,509 - INFO - ✅ Inserted:  4 new CVEs
2025-10-18 00:55:12,509 - INFO - ⭕ Skipped:   0 duplicates
2025-10-18 00:55:12,510 - INFO - ⏱️ Duration:  0.03s
2025-10-18 00:55:12,510 - INFO - 🧮 Total CVEs in database: 90,770
2025-10-18 00:55:12,510 - INFO - ======================================================================
2025-10-18 00:55:12,510 - INFO -
======================================================================
2025-10-18 00:55:12,510 - INFO - 🎉 BRONZE LAYER LOAD COMPLETED
2025-10-18 00:55:12,510 - INFO - ======================================================================
2025-10-18 00:55:12,511 - INFO - ✅ Bronze: 4 inserted, 0 skipped

2025-10-18 00:55:12,511 - INFO - ================================================================================
2025-10-18 00:55:12,511 - INFO - 🔍 STEP 5/6: EDA & CLEANING (SCRAPED CVEs ONLY)
2025-10-18 00:55:12,511 - INFO - ================================================================================
2025-10-18 00:55:12,511 - INFO - 🔍 Loading 4 scraped CVE(s) from bronze...
2025-10-18 00:55:12,524 - INFO - ✅ Loaded 4 row(s) from bronze
2025-10-18 00:55:12,524 - INFO - 📊 Processing 4 scraped CVE(s)

2025-10-18 00:55:12,524 - INFO - 🔬 Running EDA on scraped data...
2025-10-18 00:55:12,524 - INFO - ========================================================================
2025-10-18 00:55:12,526 - INFO - 🔍 EXPLORATORY DATA ANALYSIS
2025-10-18 00:55:12,526 - INFO - ========================================================================
2025-10-18 00:55:12,526 - INFO -
📊 OVERVIEW:
2025-10-18 00:55:12,526 - INFO -    Total rows: 4
2025-10-18 00:55:12,526 - INFO -    Total columns: 12
2025-10-18 00:55:12,528 - INFO -    Memory usage: 0.01 MB
2025-10-18 00:55:12,528 - INFO -
🔎 MISSING VALUES ANALYSIS:
2025-10-18 00:55:12,529 - INFO -    remotely_exploit: 3.0 (75.00%)
2025-10-18 00:55:12,531 - INFO -
🔄 DUPLICATES ANALYSIS:
2025-10-18 00:55:12,531 - INFO -    Duplicate CVE IDs: 0
2025-10-18 00:55:12,532 - INFO -
📅 DATE ANALYSIS:
2025-10-18 00:55:12,534 - INFO -    Valid published dates: 4 / 4
2025-10-18 00:55:12,534 - INFO -    Date range: 2025-10-16 21:15:00 to 2025-10-16 22:15:00
2025-10-18 00:55:12,534 - INFO -
🎯 CVSS SCORES ANALYSIS:
2025-10-18 00:55:12,534 - INFO -    CVEs with CVSS: 4 (100.00%)
2025-10-18 00:55:12,534 - INFO -
📑 CATEGORY ANALYSIS:
2025-10-18 00:55:12,535 - INFO -    Total categories: 4
2025-10-18 00:55:12,535 - INFO -    Top categories:
2025-10-18 00:55:12,535 - INFO -       - Information Disclosure: 1
2025-10-18 00:55:12,535 - INFO -       - Server-Side Request Forgery: 1
2025-10-18 00:55:12,536 - INFO -       - Memory Corruption: 1
2025-10-18 00:55:12,536 - INFO -       - Authorization: 1
2025-10-18 00:55:12,536 - INFO -
========================================================================
2025-10-18 00:55:12,536 - INFO -
🧹 Cleaning scraped data...
2025-10-18 00:55:12,536 - INFO - ========================================================================
2025-10-18 00:55:12,537 - INFO - 🧹 DATA CLEANING
2025-10-18 00:55:12,537 - INFO - ========================================================================
2025-10-18 00:55:12,537 - INFO -
🔄 Removing duplicates...
2025-10-18 00:55:12,537 - INFO - 
📅 Cleaning dates...
2025-10-18 00:55:12,544 - INFO -
🎯 Filtering CVEs without CVSS scores...
2025-10-18 00:55:12,546 - INFO -
🤖 ADDING PREDICTED CATEGORY COLUMN...
2025-10-18 00:55:12,547 - INFO -    ✅ Predictions: 0 / 4
2025-10-18 00:55:12,547 - INFO -
✅ CLEANING SUMMARY:
2025-10-18 00:55:12,547 - INFO -    Initial rows: 4
2025-10-18 00:55:12,547 - INFO -    Final rows: 4
2025-10-18 00:55:12,547 - INFO -    Removed: 0
2025-10-18 00:55:12,548 - INFO -    Quality: 100.00%
2025-10-18 00:55:12,548 - INFO -
========================================================================
2025-10-18 00:55:12,548 - INFO -
🏗️  Creating silver format...
2025-10-18 00:55:12,548 - INFO - ========================================================================
2025-10-18 00:55:12,548 - INFO - 🏗️  CREATING SILVER LAYER
2025-10-18 00:55:12,548 - INFO - ========================================================================
2025-10-18 00:55:12,550 - INFO - ✅ Silver layer: 4 rows
2025-10-18 00:55:12,550 - INFO - 📊 Columns: ['cve_id', 'title', 'description', 'category', 'predicted_category', 'published_date', 'last_modified', 'loaded_at', 'remotely_exploit', 'source_identifier', 'affected_products', 'cvss_scores', 'url']
2025-10-18 00:55:12,550 - INFO -
================================================================================
2025-10-18 00:55:12,550 - INFO - 💾 STEP 6/6: LOADING TO SILVER LAYER (APPEND)
2025-10-18 00:55:12,550 - INFO - ================================================================================
2025-10-18 00:55:12,551 - INFO - ========================================================================
2025-10-18 00:55:12,551 - INFO - 🚀 SILVER LAYER LOAD PIPELINE
2025-10-18 00:55:12,551 - INFO - ========================================================================
2025-10-18 00:55:12,551 - INFO - 🔎 Verifying silver schema 'silver' and table 'cve_cleaned'...
2025-10-18 00:55:12,563 - INFO - ✅ Silver schema validated
2025-10-18 00:55:12,563 - INFO - ========================================================================
2025-10-18 00:55:12,564 - INFO - 💾 LOADING TO SILVER: silver.cve_cleaned
2025-10-18 00:55:12,564 - INFO -    Mode: append
2025-10-18 00:55:12,564 - INFO - ========================================================================
2025-10-18 00:55:12,564 - INFO - 🛠️ Preparing dataframe for silver layer...
2025-10-18 00:55:12,570 - INFO - 🤖 Prediction stats: 0/4 (0.0%) with predictions
2025-10-18 00:55:12,570 - INFO - ✅ Prepared 4 rows for silver layer
2025-10-18 00:55:12,570 - INFO - 📋 Columns: ['cve_id', 'title', 'description', 'category', 'predicted_category', 'published_date', 'last_modified', 'loaded_at', 'remotely_exploit', 'source_identifier', 'affected_products', 'cvss_scores', 'url']
2025-10-18 00:55:12,572 - INFO - 📊 DataFrame shape: (4, 13)
2025-10-18 00:55:12,572 - INFO - 📋 Columns to insert: ['cve_id', 'title', 'description', 'category', 'predicted_category', 'published_date', 'last_modified', 'loaded_at', 'remotely_exploit', 'source_identifier', 'affected_products', 'cvss_scores', 'url']
2025-10-18 00:55:12,572 - INFO - 📤 Inserting 4 rows...
2025-10-18 00:55:12,586 - ERROR - ❌ Database error: (psycopg2.errors.UniqueViolation) duplicate key value violates unique constraint "cve_cleaned_pkey"
DETAIL:  Key (cve_id)=(CVE-2024-42192) already exists.

[SQL: INSERT INTO silver.cve_cleaned (cve_id, title, description, category, predicted_category, published_date, last_modified, loaded_at, remotely_exploit, source_identifier, affected_products, cvss_scores, url) VALUES (%(cve_id_m0)s, %(title_m0)s, %(description_m0)s, %(category_m0)s, %(predicted_category_m0)s, %(published_date_m0)s, %(last_modified_m0)s, %(loaded_at_m0)s, %(remotely_exploit_m0)s, %(source_identifier_m0)s, %(affected_products_m0)s, %(cvss_scores_m0)s, %(url_m0)s), (%(cve_id_m1)s, %(title_m1)s, %(description_m1)s, %(category_m1)s, %(predicted_category_m1)s, %(published_date_m1)s, %(last_modified_m1)s, %(loaded_at_m1)s, %(remotely_exploit_m1)s, %(source_identifier_m1)s, %(affected_products_m1)s, %(cvss_scores_m1)s, %(url_m1)s), (%(cve_id_m2)s, %(title_m2)s, %(description_m2)s, %(category_m2)s, %(predicted_category_m2)s, %(published_date_m2)s, %(last_modified_m2)s, %(loaded_at_m2)s, %(remotely_exploit_m2)s, %(source_identifier_m2)s, %(affected_products_m2)s, %(cvss_scores_m2)s, %(url_m2)s), (%(cve_id_m3)s, %(title_m3)s, %(description_m3)s, %(category_m3)s, %(predicted_category_m3)s, %(published_date_m3)s, %(last_modified_m3)s, %(loaded_at_m3)s, %(remotely_exploit_m3)s, %(source_identifier_m3)s, %(affected_products_m3)s, %(cvss_scores_m3)s, %(url_m3)s)]
[parameters: {'cve_id_m0': 'CVE-2024-42192', 'title_m0': 'HCL Traveler for Microsoft Outlook (HTMO) is susceptible to a credential leakage', 'description_m0': 'The following products are affected byCVE-2024-42192vulnerability.\n                                            Even ifcvefeed.iois aware of the exac ... (131 characters truncated) ...                                     are\n                                            affected, the information is not represented in the table below.', 'category_m0': 'Information Disclosure', 'predicted_category_m0': None, 'published_date_m0': datetime.datetime(2025, 10, 16, 21, 15), 'last_modified_m0': datetime.datetime(2025, 10, 16, 21, 15), 'loaded_at_m0': datetime.datetime(2025, 10, 17, 23, 55, 12, 483835), 'remotely_exploit_m0': False, 'source_identifier_m0': 'psirt@hcl.com', 'affected_products_m0': None, 'cvss_scores_m0': '[{"score": "5.5", "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "version": "CVSS 3.1", "severity": "MEDIUM", "source_identifier": "1e47fe ... (97 characters truncated) ... H/I:N/A:N", "version": "CVSS 3.1", "severity": "MEDIUM", "impact_score": "3.6", "source_identifier": "psirt@hcl.com", "exploitability_score": "1.8"}]', 'url_m0': 'https://cvefeed.io/vuln/detail/CVE-2024-42192', 'cve_id_m1': 'CVE-2025-11864', 'title_m1': 'NucleoidAI Nucleoid Outbound Request cluster.ts extension.apply server-side request forgery', 'description_m1': 'A vulnerability was identified in NucleoidAI Nucleoid up to 0.7.10. The impacted element is the function extension.apply of the file /src/cluster.ts  ... (33 characters truncated) ...  Handler. Such manipulation of the argument https/ip/port/path/headers leads to server-side request forgery. The attack may be performed from remote.', 'category_m1': 'Server-Side Request Forgery', 'predicted_category_m1': None, 'published_date_m1': datetime.datetime(2025, 10, 16, 21, 15), 'last_modified_m1': datetime.datetime(2025, 10, 16, 21, 15), 'loaded_at_m1': datetime.datetime(2025, 10, 17, 23, 55, 12, 483835), 'remotely_exploit_m1': None, 'source_identifier_m1': 'cna@vuldb.com', 'affected_products_m1': None, 'cvss_scores_m1': '[{"score": "7.5", "vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P", "version": "CVSS 2.0", "severity": "HIGH", "impact_score": "6.4", "source_identifier": "cna ... (396 characters truncated) ... X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X", "version": "CVSS 4.0", "severity": "MEDIUM", "source_identifier": "cna@vuldb.com"}]', 'url_m1': 'https://cvefeed.io/vuln/detail/CVE-2025-11864', 'cve_id_m2': 'CVE-2025-62504', 'title_m2': 'Envoy Lua filter use-after-free when oversized rewritten response body causes crash', 'description_m2': 'Envoy is an open source edge and service proxy. Envoy versions earlier than 1.36.2, 1.35.6, 1.34.10, and 1.33.12 contain a use-after-free vulnerabili ... (554 characters truncated) ... limit_bytes / request_body_buffer_limit can reduce the likelihood of triggering the condition but does not correct the underlying memory safety flaw.', 'category_m2': 'Memory Corruption', 'predicted_category_m2': None, 'published_date_m2': datetime.datetime(2025, 10, 16, 22, 15), 'last_modified_m2': datetime.datetime(2025, 10, 16, 22, 15), 'loaded_at_m2': datetime.datetime(2025, 10, 17, 23, 55, 12, 483835), 'remotely_exploit_m2': None, 'source_identifier_m2': 'security-advisories@github.com', 'affected_products_m2': '[{"id": "1", "vendor": "Envoyproxy", "product": "envoy"}]', 'cvss_scores_m2': '[{"score": "6.5", "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", "version": "CVSS 3.1", "severity": "MEDIUM", "impact_score": "3.6", "source_identifier": "security-advisories@github.com", "exploitability_score": "2.8"}]', 'url_m2': 'https://cvefeed.io/vuln/detail/CVE-2025-62504', 'cve_id_m3': 'CVE-2025-62506', 'title_m3': 'MinIO vulnerable to privilege escalation via session policy bypass in service accounts and STS', 'description_m3': 'MinIO is a high-performance object storage system. In all versions prior to RELEASE.2025-10-15T17-29-55Z, a privilege escalation vulnerability allows ... (911 characters truncated) ... estrictions and modify, delete, or create objects outside their authorized scope. The vulnerability is fixed in version RELEASE.2025-10-15T17-29-55Z.', 'category_m3': 'Authorization', 'predicted_category_m3': None, 'published_date_m3': datetime.datetime(2025, 10, 16, 22, 15), 'last_modified_m3': datetime.datetime(2025, 10, 16, 22, 15), 'loaded_at_m3': datetime.datetime(2025, 10, 17, 23, 55, 12, 483835), 'remotely_exploit_m3': None, 'source_identifier_m3': 'security-advisories@github.com', 'affected_products_m3': '[{"id": "1", "vendor": "Minio", "product": "minio"}]', 'cvss_scores_m3': '[{"score": "8.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "version": "CVSS 3.1", "severity": "HIGH", "impact_score": "5.2", "source_identifier": "security-advisories@github.com", "exploitability_score": "2.8"}]', 'url_m3': 'https://cvefeed.io/vuln/detail/CVE-2025-62506'}]
(Background on this error at: https://sqlalche.me/e/20/gkpj)
2025-10-18 00:55:12,588 - ERROR - ❌ Silver layer load failed: (psycopg2.errors.UniqueViolation) duplicate key value violates unique constraint "cve_cleaned_pkey"   
DETAIL:  Key (cve_id)=(CVE-2024-42192) already exists.

[SQL: INSERT INTO silver.cve_cleaned (cve_id, title, description, category, predicted_category, published_date, last_modified, loaded_at, remotely_exploit, source_identifier, affected_products, cvss_scores, url) VALUES (%(cve_id_m0)s, %(title_m0)s, %(description_m0)s, %(category_m0)s, %(predicted_category_m0)s, %(published_date_m0)s, %(last_modified_m0)s, %(loaded_at_m0)s, %(remotely_exploit_m0)s, %(source_identifier_m0)s, %(affected_products_m0)s, %(cvss_scores_m0)s, %(url_m0)s).....d_category_m3': None, 'published_date_m3': datetime.datetime(2025, 10, 16, 22, 15), 'last_modified_m3': datetime.datetime(2025, 10, 16, 22, 15), 'loaded_at_m3': datetime.datetime(2025, 10, 17, 23, 55, 12, 483835), 'remotely_exploit_m3': None, 'source_identifier_m3': 'security-advisories@github.com', 'affected_products_m3': '[{"id": "1", "vendor": "Minio", "product": "minio"}]', 'cvss_scores_m3': '[{"score": "8.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "version": "CVSS 3.1", "severity": "HIGH", "impact_score": "5.2", "source_identifier": "security-advisories@github.com", "exploitability_score": "2.8"}]', 'url_m3': 'https://cvefeed.io/vuln/detail/CVE-2025-62506'}]
(Background on this error at: https://sqlalche.me/e/20/gkpj)
Traceback (most recent call last):
  File "C:\Users\hamza\miniconda3\envs\cenv\Lib\site-packages\sqlalchemy\engine\base.py", line 1967, in _exec_single_context
    self.dialect.do_execute(
  File "C:\Users\hamza\miniconda3\envs\cenv\Lib\site-packages\sqlalchemy\engine\default.py", line 951, in do_execute
    cursor.execute(statement, parameters)
psycopg2.errors.UniqueViolation: duplicate key value violates unique constraint "cve_cleaned_pkey"
DETAIL:  Key (cve_id)=(CVE-2024-42192) already exists.


The above exception was the direct cause of the following exception:

Traceback (most recent call last):
  File "C:\Users\hamza\OneDrive\Desktop\Projects\threat-intelligence-pipeline\src\batch\load\load_silver_layer.py", line 374, in load_silver_layer
    stats = load_to_silver_table(df_cleaned, engine, if_exists=if_exists)
            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\hamza\OneDrive\Desktop\Projects\threat-intelligence-pipeline\src\batch\load\load_silver_layer.py", line 283, in load_to_silver_table
    rows_inserted = df_prepared.to_sql(
                    ^^^^^^^^^^^^^^^^^^^
  File "C:\Users\hamza\miniconda3\envs\cenv\Lib\site-packages\pandas\util\_decorators.py", line 333, in wrapper
    return func(*args, **kwargs)
           ^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\hamza\miniconda3\envs\cenv\Lib\site-packages\pandas\core\generic.py", line 3109, in to_sql
    return sql.to_sql(
           ^^^^^^^^^^^
  File "C:\Users\hamza\miniconda3\envs\cenv\Lib\site-packages\pandas\io\sql.py", line 844, in to_sql
    return pandas_sql.to_sql(
           ^^^^^^^^^^^^^^^^^^
  File "C:\Users\hamza\miniconda3\envs\cenv\Lib\site-packages\pandas\io\sql.py", line 2030, in to_sql
    total_inserted = sql_engine.insert_records(
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\hamza\miniconda3\envs\cenv\Lib\site-packages\pandas\io\sql.py", line 1579, in insert_records
    raise err
  File "C:\Users\hamza\miniconda3\envs\cenv\Lib\site-packages\pandas\io\sql.py", line 1570, in insert_records
    return table.insert(chunksize=chunksize, method=method)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\hamza\miniconda3\envs\cenv\Lib\site-packages\pandas\io\sql.py", line 1121, in insert
    num_inserted = exec_insert(conn, keys, chunk_iter)
                   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\hamza\miniconda3\envs\cenv\Lib\site-packages\pandas\io\sql.py", line 1029, in _execute_insert_multi
    result = conn.execute(stmt)
             ^^^^^^^^^^^^^^^^^^
  File "C:\Users\hamza\miniconda3\envs\cenv\Lib\site-packages\sqlalchemy\engine\base.py", line 1419, in execute
    return meth(
           ^^^^^
  File "C:\Users\hamza\miniconda3\envs\cenv\Lib\site-packages\sqlalchemy\sql\elements.py", line 526, in _execute_on_connection
    return connection._execute_clauseelement(
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\hamza\miniconda3\envs\cenv\Lib\site-packages\sqlalchemy\engine\base.py", line 1641, in _execute_clauseelement
    ret = self._execute_context(
          ^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\hamza\miniconda3\envs\cenv\Lib\site-packages\sqlalchemy\engine\base.py", line 1846, in _execute_context
    return self._exec_single_context(
           ^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\hamza\miniconda3\envs\cenv\Lib\site-packages\sqlalchemy\engine\base.py", line 1986, in _exec_single_context
    self._handle_dbapi_exception(
  File "C:\Users\hamza\miniconda3\envs\cenv\Lib\site-packages\sqlalchemy\engine\base.py", line 2355, in _handle_dbapi_exception
    raise sqlalchemy_exception.with_traceback(exc_info[2]) from e
  File "C:\Users\hamza\miniconda3\envs\cenv\Lib\site-packages\sqlalchemy\engine\base.py", line 1967, in _exec_single_context
    self.dialect.do_execute(
  File "C:\Users\hamza\miniconda3\envs\cenv\Lib\site-packages\sqlalchemy\engine\default.py", line 951, in do_execute
    cursor.execute(statement, parameters)
sqlalchemy.exc.IntegrityError: (psycopg2.errors.UniqueViolation) duplicate key value violates unique constraint "cve_cleaned_pkey"
DETAIL:  Key (cve_id)=(CVE-2024-42192) already exists.

[SQL: INSERT INTO silver.cve_cleaned (cve_id, title, description, category, predicted_category, published_date, last_modified, loaded_at, remotely_exploit, source_identifier, affected_products, cvss_scores, url) VALUES (%(cve_id_m0)s, %(title_m0)s, %(description_m0)s, %(category_m0)s, %(predicted_category_m0)s, %(published_date_m0)s, %(last_modified_m0)s, %(loaded_at_m0)s, %(remotely_exploit_m0)s, %(source_identifier_m0)s, %(affected_products_m0)s, %(cvss_scores_m0)s, %(url_m0)s), (%(cve_id......product": "minio"}]', 'cvss_scores_m3': '[{"score": "8.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "version": "CVSS 3.1", "severity": "HIGH", "impact_score": "5.2", "source_identifier": "security-advisories@github.com", "exploitability_score": "2.8"}]', 'url_m3': 'https://cvefeed.io/vuln/detail/CVE-2025-62506'}]
(Background on this error at: https://sqlalche.me/e/20/gkpj)
2025-10-18 00:55:12,597 - INFO -
================================================================================
2025-10-18 00:55:12,598 - INFO - 💾 SAVING CSV BACKUP
2025-10-18 00:55:12,598 - INFO - ================================================================================
2025-10-18 00:55:12,600 - INFO - ✅ Saved 4 CVEs to cve_data_backup.csv
2025-10-18 00:55:12,601 - INFO -
================================================================================
2025-10-18 00:55:12,601 - INFO - 🎉 COMPLETE ETL PIPELINE FINISHED
2025-10-18 00:55:12,601 - INFO - ================================================================================
2025-10-18 00:55:12,601 - INFO - ⏰ End time: 2025-10-18 00:55:12
2025-10-18 00:55:12,601 - INFO - ================================================================================
2025-10-18 00:55:12,601 - INFO - 📊 PIPELINE STATISTICS:
2025-10-18 00:55:12,603 - INFO -    🔍 Total CVEs found:       10
2025-10-18 00:55:12,603 - INFO -    ✅ Already in DB:          90766
2025-10-18 00:55:12,603 - INFO -    🎯 To scrape:              4
2025-10-18 00:55:12,603 - INFO -    📝 Successfully scraped:   4
2025-10-18 00:55:12,603 - INFO -    📥 Bronze inserted:        4
2025-10-18 00:55:12,603 - INFO -    ⭕ Bronze skipped:         0
2025-10-18 00:55:12,604 - INFO -    💎 Silver processed:       4
2025-10-18 00:55:12,604 - INFO -    ❌ Failed:                 0
2025-10-18 00:55:12,604 - INFO -    ✨ Pipeline success:       False
2025-10-18 00:55:12,604 - INFO - ================================================================================
(cenv) PS C:\Users\hamza\OneDrive\Desktop\Projects\threat-intelligence-pipeline\src\batch\extract\stream> 