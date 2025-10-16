-- ============================================================================
-- SILVER LAYER SCHEMA V2.1 - CVE DATA WAREHOUSE (WITH SOURCE TRACKING)
-- - dim_cve includes source_identifier (top-level CVE origin)
-- - fact_cvss_scores uses dim_cvss_source for CVSS row sources
-- ============================================================================

CREATE SCHEMA IF NOT EXISTS silver;
SET search_path TO silver, public;

-- DIM_CVE
DROP TABLE IF EXISTS silver.dim_cve CASCADE;

CREATE TABLE silver.dim_cve (
    cve_id VARCHAR(20) PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    category VARCHAR(50) DEFAULT 'undefined',
    published_date TIMESTAMP NOT NULL,
    last_modified TIMESTAMP NOT NULL,
    loaded_at TIMESTAMP NOT NULL,
    cve_year INTEGER GENERATED ALWAYS AS (EXTRACT(YEAR FROM published_date)) STORED,
    remotely_exploit BOOLEAN,
    source_identifier TEXT,               -- ← NEW: keep origin (NVD/MITRE/email)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_dim_cve_published_date ON silver.dim_cve(published_date);
CREATE INDEX idx_dim_cve_cve_year ON silver.dim_cve(cve_year);
CREATE INDEX idx_dim_cve_category ON silver.dim_cve(category);
CREATE INDEX idx_dim_cve_remotely_exploit ON silver.dim_cve(remotely_exploit);
CREATE INDEX idx_dim_cve_source_identifier ON silver.dim_cve(source_identifier);

COMMENT ON COLUMN silver.dim_cve.source_identifier IS 'Top-level CVE source identifier (e.g., NVD, MITRE, email).';

-- DIM_CVSS_SOURCE
DROP TABLE IF EXISTS silver.dim_cvss_source CASCADE;

CREATE TABLE silver.dim_cvss_source (
    source_id SERIAL PRIMARY KEY,
    source_name VARCHAR(100) UNIQUE NOT NULL,  -- e.g., 'nvd@nist.gov'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_dim_cvss_source_name ON silver.dim_cvss_source(source_name);

-- FACT_CVSS_SCORES
DROP TABLE IF EXISTS silver.fact_cvss_scores CASCADE;

CREATE TABLE silver.fact_cvss_scores (
    cvss_score_id SERIAL PRIMARY KEY,
    cve_id VARCHAR(20) NOT NULL,
    source_id INTEGER,  -- FK to dim_cvss_source
    cvss_version VARCHAR(10) NOT NULL,
    cvss_score NUMERIC(3,1) CHECK (cvss_score >= 0 AND cvss_score <= 10),
    cvss_severity VARCHAR(10),
    cvss_vector TEXT,
    cvss_exploitability_score NUMERIC(3,1),
    cvss_impact_score NUMERIC(3,1),
    -- v2/v3/v4 metrics
    cvss_av VARCHAR(20), cvss_ac VARCHAR(20), cvss_c VARCHAR(20), cvss_i VARCHAR(20), cvss_a VARCHAR(20),
    cvss_au VARCHAR(20), cvss_pr VARCHAR(20), cvss_ui VARCHAR(20), cvss_s VARCHAR(20),
    cvss_at VARCHAR(20), cvss_vc VARCHAR(20), cvss_vi VARCHAR(20), cvss_va VARCHAR(20),
    cvss_sc VARCHAR(20), cvss_si VARCHAR(20), cvss_sa VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_fact_cvss_cve    FOREIGN KEY (cve_id)   REFERENCES silver.dim_cve(cve_id) ON DELETE CASCADE,
    CONSTRAINT fk_fact_cvss_source FOREIGN KEY (source_id) REFERENCES silver.dim_cvss_source(source_id) ON DELETE SET NULL
);

CREATE INDEX idx_fact_cvss_cve_id     ON silver.fact_cvss_scores(cve_id);
CREATE INDEX idx_fact_cvss_source_id  ON silver.fact_cvss_scores(source_id);
CREATE INDEX idx_fact_cvss_version    ON silver.fact_cvss_scores(cvss_version);
CREATE INDEX idx_fact_cvss_score      ON silver.fact_cvss_scores(cvss_score);
CREATE INDEX idx_fact_cvss_severity   ON silver.fact_cvss_scores(cvss_severity);
CREATE INDEX idx_fact_cvss_cve_source ON silver.fact_cvss_scores(cve_id, source_id);

-- DIM_PRODUCTS (unchanged)
DROP TABLE IF EXISTS silver.dim_products CASCADE;

CREATE TABLE silver.dim_products (
    product_id SERIAL PRIMARY KEY,
    vendor VARCHAR(255) NOT NULL,
    product_name VARCHAR(255) NOT NULL,
    total_cves INTEGER DEFAULT 0,
    first_cve_date TIMESTAMP,
    last_cve_date TIMESTAMP,
    product_lifespan_days INTEGER GENERATED ALWAYS AS (EXTRACT(DAY FROM (last_cve_date - first_cve_date))) STORED,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uk_dim_products_vendor_product UNIQUE (vendor, product_name)
);

CREATE INDEX idx_dim_products_vendor ON silver.dim_products(vendor);
CREATE INDEX idx_dim_products_product_name ON silver.dim_products(product_name);
CREATE INDEX idx_dim_products_total_cves ON silver.dim_products(total_cves DESC);

-- BRIDGE_CVE_PRODUCTS (unchanged)
DROP TABLE IF EXISTS silver.bridge_cve_products CASCADE;

CREATE TABLE silver.bridge_cve_products (
    bridge_id SERIAL PRIMARY KEY,
    cve_id VARCHAR(20) NOT NULL,
    product_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_bridge_cve     FOREIGN KEY (cve_id)    REFERENCES silver.dim_cve(cve_id)     ON DELETE CASCADE,
    CONSTRAINT fk_bridge_product FOREIGN KEY (product_id) REFERENCES silver.dim_products(product_id) ON DELETE CASCADE,
    CONSTRAINT uk_bridge_cve_product UNIQUE (cve_id, product_id)
);

CREATE INDEX idx_bridge_cve_id     ON silver.bridge_cve_products(cve_id);
CREATE INDEX idx_bridge_product_id ON silver.bridge_cve_products(product_id);

-- MATERIALIZED VIEWS (include dim_cve.source_identifier in outputs)
DROP MATERIALIZED VIEW IF EXISTS silver.mv_cve_all_cvss CASCADE;

CREATE MATERIALIZED VIEW silver.mv_cve_all_cvss AS
SELECT 
    c.cve_id,
    c.title,
    c.description,
    c.published_date,
    c.cve_year,
    c.category,
    c.remotely_exploit,
    c.source_identifier,                 -- ← added
    s.source_name,
    f.cvss_version,
    f.cvss_score,
    f.cvss_severity,
    f.cvss_vector,
    f.cvss_av, f.cvss_ac, f.cvss_pr, f.cvss_ui, f.cvss_s,
    f.cvss_c, f.cvss_i, f.cvss_a
FROM silver.dim_cve c
JOIN silver.fact_cvss_scores f ON c.cve_id = f.cve_id
LEFT JOIN silver.dim_cvss_source s ON f.source_id = s.source_id
ORDER BY c.cve_id, f.cvss_version, s.source_name;

CREATE INDEX idx_mv_cve_all_cvss_cve_id   ON silver.mv_cve_all_cvss(cve_id);
CREATE INDEX idx_mv_cve_all_cvss_version  ON silver.mv_cve_all_cvss(cvss_version);
CREATE INDEX idx_mv_cve_all_cvss_source   ON silver.mv_cve_all_cvss(source_name);

DROP MATERIALIZED VIEW IF EXISTS silver.mv_cvss_source_comparison CASCADE;

CREATE MATERIALIZED VIEW silver.mv_cvss_source_comparison AS
SELECT 
    c.cve_id,
    c.title,
    c.source_identifier,                 -- ← added
    f.cvss_version,
    s.source_name,
    f.cvss_score,
    f.cvss_severity,
    COUNT(*) OVER (PARTITION BY c.cve_id, f.cvss_version) AS source_count_for_version,
    MAX(f.cvss_score) OVER (PARTITION BY c.cve_id, f.cvss_version) AS max_score_for_version,
    MIN(f.cvss_score) OVER (PARTITION BY c.cve_id, f.cvss_version) AS min_score_for_version,
    ABS(f.cvss_score - AVG(f.cvss_score) OVER (PARTITION BY c.cve_id, f.cvss_version)) AS score_deviation
FROM silver.dim_cve c
JOIN silver.fact_cvss_scores f ON c.cve_id = f.cve_id
LEFT JOIN silver.dim_cvss_source s ON f.source_id = s.source_id
ORDER BY c.cve_id, f.cvss_version, score_deviation DESC;

DROP MATERIALIZED VIEW IF EXISTS silver.mv_top_products CASCADE;

CREATE MATERIALIZED VIEW silver.mv_top_products AS
SELECT 
    p.product_id,
    p.vendor,
    p.product_name,
    p.total_cves,
    COUNT(DISTINCT b.cve_id) AS cve_count_verified,
    AVG(f.cvss_score) AS avg_cvss_score,
    MAX(f.cvss_score) AS max_cvss_score,
    COUNT(CASE WHEN f.cvss_severity = 'CRITICAL' THEN 1 END) AS critical_count,
    COUNT(CASE WHEN f.cvss_severity = 'HIGH' THEN 1 END) AS high_count,
    COUNT(DISTINCT f.source_id) AS source_count,
    p.first_cve_date,
    p.last_cve_date
FROM silver.dim_products p
LEFT JOIN silver.bridge_cve_products b ON p.product_id = b.product_id
LEFT JOIN silver.fact_cvss_scores f ON b.cve_id = f.cve_id
GROUP BY p.product_id, p.vendor, p.product_name, p.total_cves, p.first_cve_date, p.last_cve_date
HAVING COUNT(DISTINCT b.cve_id) > 0
ORDER BY p.total_cves DESC;

-- FUNCTIONS
CREATE OR REPLACE FUNCTION silver.refresh_all_mv()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY silver.mv_cve_all_cvss;
    REFRESH MATERIALIZED VIEW CONCURRENTLY silver.mv_cvss_source_comparison;
    REFRESH MATERIALIZED VIEW CONCURRENTLY silver.mv_top_products;
    RAISE NOTICE 'All materialized views refreshed successfully';
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION silver.update_modified_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_dim_cve_updated
    BEFORE UPDATE ON silver.dim_cve
    FOR EACH ROW
    EXECUTE FUNCTION silver.update_modified_column();

CREATE TRIGGER trg_dim_products_updated
    BEFORE UPDATE ON silver.dim_products
    FOR EACH ROW
    EXECUTE FUNCTION silver.update_modified_column();
