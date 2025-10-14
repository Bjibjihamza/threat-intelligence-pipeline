-- ============================================================================
-- SILVER LAYER SCHEMA - CVE DATA WAREHOUSE
-- ============================================================================
-- Architecture: Star Schema with 4 normalized tables
-- Purpose: Optimized for analytics and querying
-- Author: Data Engineering Team
-- Date: 2025-10-14
-- ============================================================================

-- Drop existing schema if needed (CAUTION: This will delete all data!)
-- DROP SCHEMA IF EXISTS silver CASCADE;

-- Create Silver schema
CREATE SCHEMA IF NOT EXISTS silver;

-- Set search path for convenience
SET search_path TO silver, public;

-- ============================================================================
-- TABLE 1: DIM_CVE (Dimension - CVE Master Table)
-- ============================================================================
-- Purpose: One row per unique CVE, contains all CVE-level attributes
-- Grain: 1 row per CVE ID
-- ============================================================================

DROP TABLE IF EXISTS silver.dim_cve CASCADE;

CREATE TABLE silver.dim_cve (
    -- Primary Key
    cve_id VARCHAR(20) PRIMARY KEY,
    
    -- CVE Metadata
    title TEXT NOT NULL,
    description TEXT,
    category VARCHAR(50) DEFAULT 'undefined',
    
    -- Dates
    published_date TIMESTAMP NOT NULL,
    last_modified TIMESTAMP NOT NULL,
    loaded_at TIMESTAMP NOT NULL,
    cve_year INTEGER GENERATED ALWAYS AS (EXTRACT(YEAR FROM published_date)) STORED,
    
    -- Security Flags
    remotely_exploit BOOLEAN DEFAULT FALSE,
    
    -- Audit
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for dim_cve
CREATE INDEX idx_dim_cve_published_date ON silver.dim_cve(published_date);
CREATE INDEX idx_dim_cve_cve_year ON silver.dim_cve(cve_year);
CREATE INDEX idx_dim_cve_category ON silver.dim_cve(category);
CREATE INDEX idx_dim_cve_remotely_exploit ON silver.dim_cve(remotely_exploit);
CREATE INDEX idx_dim_cve_last_modified ON silver.dim_cve(last_modified);

-- Comments
COMMENT ON TABLE silver.dim_cve IS 'CVE dimension table - One row per unique CVE identifier';
COMMENT ON COLUMN silver.dim_cve.cve_id IS 'Unique CVE identifier (e.g., CVE-2024-1234)';
COMMENT ON COLUMN silver.dim_cve.cve_year IS 'Year extracted from CVE ID for partitioning/filtering';
COMMENT ON COLUMN silver.dim_cve.remotely_exploit IS 'Whether the vulnerability can be exploited remotely';

-- ============================================================================
-- TABLE 2: FACT_CVSS_SCORES (Fact Table - CVSS Scoring)
-- ============================================================================
-- Purpose: One row per CVE × CVSS version combination
-- Grain: 1 row per (CVE_ID, CVSS_VERSION)
-- ============================================================================

DROP TABLE IF EXISTS silver.fact_cvss_scores CASCADE;

CREATE TABLE silver.fact_cvss_scores (
    -- Composite Primary Key
    cvss_score_id SERIAL PRIMARY KEY,
    cve_id VARCHAR(20) NOT NULL,
    cvss_version VARCHAR(10) NOT NULL,
    
    -- CVSS Base Metrics
    cvss_score NUMERIC(3,1) CHECK (cvss_score >= 0 AND cvss_score <= 10),
    cvss_severity VARCHAR(10) CHECK (cvss_severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'NONE')),
    cvss_vector TEXT,
    cvss_exploitability_score NUMERIC(3,1),
    cvss_impact_score NUMERIC(3,1),
    
    -- CVSS Metrics (Common across versions)
    cvss_av VARCHAR(20),  -- Attack Vector
    cvss_ac VARCHAR(20),  -- Attack Complexity
    cvss_c VARCHAR(20),   -- Confidentiality Impact
    cvss_i VARCHAR(20),   -- Integrity Impact
    cvss_a VARCHAR(20),   -- Availability Impact
    
    -- CVSS v2 Specific
    cvss_au VARCHAR(20),  -- Authentication (v2 only)
    
    -- CVSS v3/v4 Specific
    cvss_pr VARCHAR(20),  -- Privileges Required
    cvss_ui VARCHAR(20),  -- User Interaction
    cvss_s VARCHAR(20),   -- Scope
    
    -- CVSS v4 Specific
    cvss_at VARCHAR(20),  -- Attack Requirements (v4)
    cvss_vc VARCHAR(20),  -- Vulnerable System Confidentiality (v4)
    cvss_vi VARCHAR(20),  -- Vulnerable System Integrity (v4)
    cvss_va VARCHAR(20),  -- Vulnerable System Availability (v4)
    cvss_sc VARCHAR(20),  -- Subsequent System Confidentiality (v4)
    cvss_si VARCHAR(20),  -- Subsequent System Integrity (v4)
    cvss_sa VARCHAR(20),  -- Subsequent System Availability (v4)
    
    -- Audit
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Foreign Key
    CONSTRAINT fk_fact_cvss_cve 
        FOREIGN KEY (cve_id) 
        REFERENCES silver.dim_cve(cve_id) 
        ON DELETE CASCADE,
    
    -- Unique constraint: One score per CVE per version
    CONSTRAINT uk_fact_cvss_cve_version UNIQUE (cve_id, cvss_version)
);

-- Indexes for fact_cvss_scores
CREATE INDEX idx_fact_cvss_cve_id ON silver.fact_cvss_scores(cve_id);
CREATE INDEX idx_fact_cvss_version ON silver.fact_cvss_scores(cvss_version);
CREATE INDEX idx_fact_cvss_score ON silver.fact_cvss_scores(cvss_score);
CREATE INDEX idx_fact_cvss_severity ON silver.fact_cvss_scores(cvss_severity);
CREATE INDEX idx_fact_cvss_av ON silver.fact_cvss_scores(cvss_av);
CREATE INDEX idx_fact_cvss_score_range ON silver.fact_cvss_scores(cvss_score) 
    WHERE cvss_score >= 7.0; -- Critical/High vulnerabilities

-- Comments
COMMENT ON TABLE silver.fact_cvss_scores IS 'CVSS scores fact table - One row per CVE × CVSS version';
COMMENT ON COLUMN silver.fact_cvss_scores.cvss_version IS 'CVSS version (e.g., CVSS 2.0, CVSS 3.1, CVSS 4.0)';
COMMENT ON COLUMN silver.fact_cvss_scores.cvss_score IS 'Base CVSS score (0.0 to 10.0)';
COMMENT ON COLUMN silver.fact_cvss_scores.cvss_av IS 'Attack Vector: Network, Adjacent, Local, Physical';

-- ============================================================================
-- TABLE 3: DIM_PRODUCTS (Dimension - Affected Products)
-- ============================================================================
-- Purpose: Master list of all products affected by CVEs
-- Grain: 1 row per unique (vendor, product_name) combination
-- ============================================================================

DROP TABLE IF EXISTS silver.dim_products CASCADE;

CREATE TABLE silver.dim_products (
    -- Primary Key
    product_id SERIAL PRIMARY KEY,
    
    -- Product Information
    vendor VARCHAR(255) NOT NULL,
    product_name VARCHAR(255) NOT NULL,
    
    -- Aggregated Statistics
    total_cves INTEGER DEFAULT 0,
    first_cve_date TIMESTAMP,
    last_cve_date TIMESTAMP,
    
    -- Computed Fields
    product_lifespan_days INTEGER GENERATED ALWAYS AS 
        (EXTRACT(DAY FROM (last_cve_date - first_cve_date))) STORED,
    
    -- Audit
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Unique constraint
    CONSTRAINT uk_dim_products_vendor_product UNIQUE (vendor, product_name)
);

-- Indexes for dim_products
CREATE INDEX idx_dim_products_vendor ON silver.dim_products(vendor);
CREATE INDEX idx_dim_products_product_name ON silver.dim_products(product_name);
CREATE INDEX idx_dim_products_total_cves ON silver.dim_products(total_cves DESC);
CREATE INDEX idx_dim_products_vendor_lower ON silver.dim_products(LOWER(vendor));
CREATE INDEX idx_dim_products_product_lower ON silver.dim_products(LOWER(product_name));

-- Full-text search index
CREATE INDEX idx_dim_products_search ON silver.dim_products 
    USING gin(to_tsvector('english', vendor || ' ' || product_name));

-- Comments
COMMENT ON TABLE silver.dim_products IS 'Products dimension - Unique vendor/product combinations';
COMMENT ON COLUMN silver.dim_products.total_cves IS 'Total number of CVEs affecting this product';
COMMENT ON COLUMN silver.dim_products.product_lifespan_days IS 'Days between first and last CVE';

-- ============================================================================
-- TABLE 4: BRIDGE_CVE_PRODUCTS (Many-to-Many Bridge Table)
-- ============================================================================
-- Purpose: Links CVEs to affected products (Many-to-Many relationship)
-- Grain: 1 row per (CVE_ID, PRODUCT_ID) combination
-- ============================================================================

DROP TABLE IF EXISTS silver.bridge_cve_products CASCADE;

CREATE TABLE silver.bridge_cve_products (
    -- Composite Primary Key
    bridge_id SERIAL PRIMARY KEY,
    cve_id VARCHAR(20) NOT NULL,
    product_id INTEGER NOT NULL,
    
    -- Audit
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Foreign Keys
    CONSTRAINT fk_bridge_cve 
        FOREIGN KEY (cve_id) 
        REFERENCES silver.dim_cve(cve_id) 
        ON DELETE CASCADE,
    
    CONSTRAINT fk_bridge_product 
        FOREIGN KEY (product_id) 
        REFERENCES silver.dim_products(product_id) 
        ON DELETE CASCADE,
    
    -- Unique constraint: One relationship per CVE-Product pair
    CONSTRAINT uk_bridge_cve_product UNIQUE (cve_id, product_id)
);

-- Indexes for bridge_cve_products
CREATE INDEX idx_bridge_cve_id ON silver.bridge_cve_products(cve_id);
CREATE INDEX idx_bridge_product_id ON silver.bridge_cve_products(product_id);
CREATE INDEX idx_bridge_composite ON silver.bridge_cve_products(cve_id, product_id);

-- Comments
COMMENT ON TABLE silver.bridge_cve_products IS 'Bridge table linking CVEs to affected products (M:N)';
COMMENT ON COLUMN silver.bridge_cve_products.cve_id IS 'Reference to CVE in dim_cve';
COMMENT ON COLUMN silver.bridge_cve_products.product_id IS 'Reference to product in dim_products';

-- ============================================================================
-- MATERIALIZED VIEWS (Optional - for performance)
-- ============================================================================

-- View: CVE with CVSS 3.1 scores (most common version)
DROP MATERIALIZED VIEW IF EXISTS silver.mv_cve_cvss3 CASCADE;

CREATE MATERIALIZED VIEW silver.mv_cve_cvss3 AS
SELECT 
    c.cve_id,
    c.title,
    c.description,
    c.published_date,
    c.cve_year,
    c.category,
    c.remotely_exploit,
    f.cvss_score,
    f.cvss_severity,
    f.cvss_vector,
    f.cvss_av,
    f.cvss_ac,
    f.cvss_pr,
    f.cvss_ui,
    f.cvss_s,
    f.cvss_c,
    f.cvss_i,
    f.cvss_a
FROM silver.dim_cve c
INNER JOIN silver.fact_cvss_scores f ON c.cve_id = f.cve_id
WHERE f.cvss_version = 'CVSS 3.1';

CREATE UNIQUE INDEX idx_mv_cve_cvss3_cve_id ON silver.mv_cve_cvss3(cve_id);
CREATE INDEX idx_mv_cve_cvss3_score ON silver.mv_cve_cvss3(cvss_score);
CREATE INDEX idx_mv_cve_cvss3_year ON silver.mv_cve_cvss3(cve_year);

COMMENT ON MATERIALIZED VIEW silver.mv_cve_cvss3 IS 'Precomputed view: CVEs with CVSS 3.1 scores';

-- View: Top vulnerable products
DROP MATERIALIZED VIEW IF EXISTS silver.mv_top_products CASCADE;

CREATE MATERIALIZED VIEW silver.mv_top_products AS
SELECT 
    p.product_id,
    p.vendor,
    p.product_name,
    p.total_cves,
    COUNT(DISTINCT b.cve_id) as cve_count_verified,
    AVG(f.cvss_score) as avg_cvss_score,
    MAX(f.cvss_score) as max_cvss_score,
    COUNT(CASE WHEN f.cvss_severity = 'CRITICAL' THEN 1 END) as critical_count,
    COUNT(CASE WHEN f.cvss_severity = 'HIGH' THEN 1 END) as high_count,
    p.first_cve_date,
    p.last_cve_date
FROM silver.dim_products p
LEFT JOIN silver.bridge_cve_products b ON p.product_id = b.product_id
LEFT JOIN silver.fact_cvss_scores f ON b.cve_id = f.cve_id AND f.cvss_version = 'CVSS 3.1'
GROUP BY p.product_id, p.vendor, p.product_name, p.total_cves, p.first_cve_date, p.last_cve_date
HAVING COUNT(DISTINCT b.cve_id) > 0
ORDER BY p.total_cves DESC;

CREATE INDEX idx_mv_top_products_vendor ON silver.mv_top_products(vendor);
CREATE INDEX idx_mv_top_products_total_cves ON silver.mv_top_products(total_cves DESC);

COMMENT ON MATERIALIZED VIEW silver.mv_top_products IS 'Precomputed view: Products ranked by vulnerability count';

-- ============================================================================
-- HELPER FUNCTIONS
-- ============================================================================

-- Function to refresh all materialized views
CREATE OR REPLACE FUNCTION silver.refresh_all_mv()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY silver.mv_cve_cvss3;
    REFRESH MATERIALIZED VIEW CONCURRENTLY silver.mv_top_products;
    RAISE NOTICE 'All materialized views refreshed successfully';
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION silver.refresh_all_mv() IS 'Refresh all materialized views in silver schema';

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION silver.update_modified_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Triggers for updated_at
CREATE TRIGGER trg_dim_cve_updated
    BEFORE UPDATE ON silver.dim_cve
    FOR EACH ROW
    EXECUTE FUNCTION silver.update_modified_column();

CREATE TRIGGER trg_dim_products_updated
    BEFORE UPDATE ON silver.dim_products
    FOR EACH ROW
    EXECUTE FUNCTION silver.update_modified_column();

-- ============================================================================
-- GRANTS (Adjust based on your security requirements)
-- ============================================================================

-- Grant usage on schema
-- GRANT USAGE ON SCHEMA silver TO your_application_user;
-- GRANT SELECT ON ALL TABLES IN SCHEMA silver TO your_application_user;
-- GRANT SELECT ON ALL SEQUENCES IN SCHEMA silver TO your_application_user;

-- ============================================================================
-- VERIFICATION QUERIES
-- ============================================================================

-- Verify schema creation
DO $$
BEGIN
    RAISE NOTICE '========================================';
    RAISE NOTICE 'Silver Schema Created Successfully!';
    RAISE NOTICE '========================================';
    RAISE NOTICE 'Tables created:';
    RAISE NOTICE '  ✓ dim_cve';
    RAISE NOTICE '  ✓ fact_cvss_scores';
    RAISE NOTICE '  ✓ dim_products';
    RAISE NOTICE '  ✓ bridge_cve_products';
    RAISE NOTICE '';
    RAISE NOTICE 'Materialized Views:';
    RAISE NOTICE '  ✓ mv_cve_cvss3';
    RAISE NOTICE '  ✓ mv_top_products';
    RAISE NOTICE '========================================';
END $$;

-- Quick stats query (run after loading data)
/*
SELECT 
    'dim_cve' as table_name,
    COUNT(*) as row_count,
    pg_size_pretty(pg_total_relation_size('silver.dim_cve')) as size
FROM silver.dim_cve
UNION ALL
SELECT 
    'fact_cvss_scores',
    COUNT(*),
    pg_size_pretty(pg_total_relation_size('silver.fact_cvss_scores'))
FROM silver.fact_cvss_scores
UNION ALL
SELECT 
    'dim_products',
    COUNT(*),
    pg_size_pretty(pg_total_relation_size('silver.dim_products'))
FROM silver.dim_products
UNION ALL
SELECT 
    'bridge_cve_products',
    COUNT(*),
    pg_size_pretty(pg_total_relation_size('silver.bridge_cve_products'))
FROM silver.bridge_cve_products;
*/