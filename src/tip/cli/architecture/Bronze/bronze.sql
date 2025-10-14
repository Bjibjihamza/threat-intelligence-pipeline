-- ============================================================================
-- BRONZE LAYER SCHEMA - Raw CVE Data Storage
-- ============================================================================
-- Description: PostgreSQL schema for storing raw CVE data from web scraping
-- Author: Data Engineering Team
-- Date: 2025-10-14
-- Database: tip
-- Schema: raw (Bronze Layer)
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. CREATE SCHEMA
-- ----------------------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS raw;

COMMENT ON SCHEMA raw IS 'Bronze Layer: Raw, unprocessed CVE data from web scraping';

-- ----------------------------------------------------------------------------
-- 2. DROP EXISTING OBJECTS (for clean setup)
-- ----------------------------------------------------------------------------
DROP TABLE IF EXISTS raw.cve_details CASCADE;
DROP TABLE IF EXISTS raw.load_metadata CASCADE;

-- ----------------------------------------------------------------------------
-- 3. MAIN TABLE: cve_details
-- ----------------------------------------------------------------------------
CREATE TABLE raw.cve_details (
    -- Primary Key
    cve_id VARCHAR(50) PRIMARY KEY,
    
    -- Basic Information
    title TEXT,
    description TEXT,
    
    -- Dates
    published_date VARCHAR(50),
    last_modified VARCHAR(50),
    
    -- Classification
    remotely_exploit VARCHAR(50),
    source VARCHAR(100),
    category VARCHAR(200),
    
    -- Complex Data (stored as JSON text)
    affected_products TEXT,  -- JSON array of {id, vendor, product}
    cvss_scores TEXT,        -- JSON array of {score, version, severity, vector, etc.}
    
    -- Source URL
    url TEXT NOT NULL,
    
    -- Metadata
    loaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_cve_details_published_date ON raw.cve_details(published_date);
CREATE INDEX idx_cve_details_category ON raw.cve_details(category);
CREATE INDEX idx_cve_details_source ON raw.cve_details(source);
CREATE INDEX idx_cve_details_loaded_at ON raw.cve_details(loaded_at);

-- Full-text search on description
CREATE INDEX idx_cve_details_description_fts ON raw.cve_details USING gin(to_tsvector('english', description));

COMMENT ON TABLE raw.cve_details IS 'Raw CVE vulnerability data scraped from CVE databases';
COMMENT ON COLUMN raw.cve_details.cve_id IS 'Unique CVE identifier (e.g., CVE-2024-1234)';
COMMENT ON COLUMN raw.cve_details.title IS 'Brief title/summary of the vulnerability';
COMMENT ON COLUMN raw.cve_details.description IS 'Detailed description of the vulnerability';
COMMENT ON COLUMN raw.cve_details.published_date IS 'Initial publication date (as text from source)';
COMMENT ON COLUMN raw.cve_details.last_modified IS 'Last modification date (as text from source)';
COMMENT ON COLUMN raw.cve_details.remotely_exploit IS 'Whether vulnerability can be exploited remotely';
COMMENT ON COLUMN raw.cve_details.source IS 'Data source (e.g., NVD, MITRE)';
COMMENT ON COLUMN raw.cve_details.category IS 'Vulnerability category/type';
COMMENT ON COLUMN raw.cve_details.affected_products IS 'JSON array of affected vendors/products';
COMMENT ON COLUMN raw.cve_details.cvss_scores IS 'JSON array of CVSS scoring details (all versions)';
COMMENT ON COLUMN raw.cve_details.url IS 'Source URL where data was scraped';
COMMENT ON COLUMN raw.cve_details.loaded_at IS 'Timestamp when record was loaded to database';

-- ----------------------------------------------------------------------------
-- 4. LOAD METADATA TABLE
-- ----------------------------------------------------------------------------
CREATE TABLE raw.load_metadata (
    load_id SERIAL PRIMARY KEY,
    load_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Load Statistics
    total_attempted INTEGER,
    total_scraped INTEGER,
    total_inserted INTEGER,
    total_skipped INTEGER,
    total_failed INTEGER,
    
    -- Load Configuration
    batch_size INTEGER,
    delay_seconds NUMERIC(5,2),
    
    -- Source Information
    source_file TEXT,
    
    -- Duration
    duration_seconds NUMERIC(10,2),
    
    -- Status
    status VARCHAR(20) CHECK (status IN ('RUNNING', 'COMPLETED', 'FAILED', 'INTERRUPTED')),
    
    -- Notes
    notes TEXT
);

CREATE INDEX idx_load_metadata_timestamp ON raw.load_metadata(load_timestamp);
CREATE INDEX idx_load_metadata_status ON raw.load_metadata(status);

COMMENT ON TABLE raw.load_metadata IS 'Metadata tracking for each scrape & load operation';
COMMENT ON COLUMN raw.load_metadata.load_id IS 'Unique identifier for each load operation';
COMMENT ON COLUMN raw.load_metadata.total_attempted IS 'Total CVEs attempted to scrape';
COMMENT ON COLUMN raw.load_metadata.total_scraped IS 'Successfully scraped CVEs';
COMMENT ON COLUMN raw.load_metadata.total_inserted IS 'New records inserted to database';
COMMENT ON COLUMN raw.load_metadata.total_skipped IS 'Duplicate records skipped';
COMMENT ON COLUMN raw.load_metadata.total_failed IS 'Failed scraping attempts';

-- ----------------------------------------------------------------------------
-- 5. HELPER VIEWS
-- ----------------------------------------------------------------------------

-- View: Recent CVEs (last 30 days)
CREATE OR REPLACE VIEW raw.v_recent_cves AS
SELECT 
    cve_id,
    title,
    published_date,
    category,
    source,
    loaded_at
FROM raw.cve_details
WHERE loaded_at >= NOW() - INTERVAL '30 days'
ORDER BY loaded_at DESC;

COMMENT ON VIEW raw.v_recent_cves IS 'CVEs loaded in the last 30 days';

-- View: Load Statistics Summary
CREATE OR REPLACE VIEW raw.v_load_summary AS
SELECT 
    DATE(load_timestamp) as load_date,
    COUNT(*) as load_count,
    SUM(total_inserted) as total_inserted,
    SUM(total_skipped) as total_skipped,
    SUM(total_failed) as total_failed,
    AVG(duration_seconds) as avg_duration_seconds
FROM raw.load_metadata
WHERE status = 'COMPLETED'
GROUP BY DATE(load_timestamp)
ORDER BY load_date DESC;

COMMENT ON VIEW raw.v_load_summary IS 'Daily summary of load operations';

-- View: CVE Count by Category
CREATE OR REPLACE VIEW raw.v_cve_by_category AS
SELECT 
    category,
    COUNT(*) as cve_count,
    MAX(loaded_at) as last_loaded
FROM raw.cve_details
WHERE category IS NOT NULL AND category != ''
GROUP BY category
ORDER BY cve_count DESC;

COMMENT ON VIEW raw.v_cve_by_category IS 'CVE count grouped by category';

-- ----------------------------------------------------------------------------
-- 6. UTILITY FUNCTIONS
-- ----------------------------------------------------------------------------

-- Function: Get total CVE count
CREATE OR REPLACE FUNCTION raw.get_cve_count()
RETURNS INTEGER AS $$
BEGIN
    RETURN (SELECT COUNT(*) FROM raw.cve_details);
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION raw.get_cve_count() IS 'Returns total number of CVEs in bronze layer';

-- Function: Get CVE count by year
CREATE OR REPLACE FUNCTION raw.get_cve_count_by_year(year_param INTEGER)
RETURNS INTEGER AS $$
BEGIN
    RETURN (
        SELECT COUNT(*) 
        FROM raw.cve_details 
        WHERE cve_id LIKE 'CVE-' || year_param || '-%'
    );
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION raw.get_cve_count_by_year(INTEGER) IS 'Returns CVE count for a specific year';

-- Function: Parse affected products from JSON
CREATE OR REPLACE FUNCTION raw.parse_affected_products(cve_id_param VARCHAR)
RETURNS TABLE(
    product_id VARCHAR,
    vendor VARCHAR,
    product VARCHAR
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        (elem->>'id')::VARCHAR as product_id,
        (elem->>'vendor')::VARCHAR as vendor,
        (elem->>'product')::VARCHAR as product
    FROM raw.cve_details,
         jsonb_array_elements(affected_products::jsonb) as elem
    WHERE cve_id = cve_id_param;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION raw.parse_affected_products(VARCHAR) IS 'Parses affected products JSON for a given CVE';

-- Function: Parse CVSS scores from JSON
CREATE OR REPLACE FUNCTION raw.parse_cvss_scores(cve_id_param VARCHAR)
RETURNS TABLE(
    score VARCHAR,
    version VARCHAR,
    severity VARCHAR,
    vector VARCHAR,
    exploitability_score VARCHAR,
    impact_score VARCHAR,
    source VARCHAR
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        (elem->>'score')::VARCHAR,
        (elem->>'version')::VARCHAR,
        (elem->>'severity')::VARCHAR,
        (elem->>'vector')::VARCHAR,
        (elem->>'exploitability_score')::VARCHAR,
        (elem->>'impact_score')::VARCHAR,
        (elem->>'source')::VARCHAR
    FROM raw.cve_details,
         jsonb_array_elements(cvss_scores::jsonb) as elem
    WHERE cve_id = cve_id_param;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION raw.parse_cvss_scores(VARCHAR) IS 'Parses CVSS scores JSON for a given CVE';

-- ----------------------------------------------------------------------------
-- 7. QUALITY CHECK QUERIES
-- ----------------------------------------------------------------------------

-- Check for records with missing critical fields
CREATE OR REPLACE VIEW raw.v_data_quality_issues AS
SELECT 
    cve_id,
    CASE 
        WHEN title IS NULL OR title = '' THEN 'Missing Title'
        WHEN description IS NULL OR description = '' THEN 'Missing Description'
        WHEN published_date IS NULL OR published_date = '' THEN 'Missing Published Date'
        WHEN cvss_scores IS NULL OR cvss_scores = '[]' THEN 'Missing CVSS Scores'
        ELSE 'Unknown Issue'
    END as issue_type,
    loaded_at
FROM raw.cve_details
WHERE 
    title IS NULL OR title = '' OR
    description IS NULL OR description = '' OR
    published_date IS NULL OR published_date = '' OR
    cvss_scores IS NULL OR cvss_scores = '[]'
ORDER BY loaded_at DESC;

COMMENT ON VIEW raw.v_data_quality_issues IS 'CVEs with missing critical fields';

-- ----------------------------------------------------------------------------
-- 8. SAMPLE DATA VALIDATION QUERIES
-- ----------------------------------------------------------------------------

-- Test query: Show sample CVE with all fields
COMMENT ON DATABASE tip IS 'Threat Intelligence Platform - CVE Data Warehouse';

-- ----------------------------------------------------------------------------
-- 9. GRANTS (adjust based on your security model)
-- ----------------------------------------------------------------------------

-- Grant permissions to application user (if needed)
-- GRANT USAGE ON SCHEMA raw TO tip_app_user;
-- GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA raw TO tip_app_user;
-- GRANT SELECT ON ALL VIEWS IN SCHEMA raw TO tip_app_user;
-- GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA raw TO tip_app_user;

-- ----------------------------------------------------------------------------
-- 10. VERIFICATION QUERIES
-- ----------------------------------------------------------------------------

-- Run these after setup to verify:
/*
-- Check schema exists
SELECT schema_name FROM information_schema.schemata WHERE schema_name = 'raw';

-- Check table structure
SELECT column_name, data_type, is_nullable 
FROM information_schema.columns 
WHERE table_schema = 'raw' AND table_name = 'cve_details'
ORDER BY ordinal_position;

-- Check indexes
SELECT indexname, indexdef 
FROM pg_indexes 
WHERE schemaname = 'raw' AND tablename = 'cve_details';

-- Check views
SELECT table_name 
FROM information_schema.views 
WHERE table_schema = 'raw';

-- Check functions
SELECT routine_name, routine_type 
FROM information_schema.routines 
WHERE routine_schema = 'raw';
*/

-- ============================================================================
-- END OF BRONZE LAYER SCHEMA
-- ============================================================================

VACUUM ANALYZE raw.cve_details;
VACUUM ANALYZE raw.load_metadata;