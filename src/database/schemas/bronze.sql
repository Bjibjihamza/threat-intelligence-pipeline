-- =====================================================================
-- BRONZE LAYER (RAW) - CVE DATA STORAGE (Clean Version)
-- =====================================================================
-- Database: tip
-- Schema  : raw
-- Date    : 2025-10-16
-- =====================================================================

CREATE SCHEMA IF NOT EXISTS raw;
COMMENT ON SCHEMA raw IS 'Bronze Layer: Unprocessed CVE data from scraping / ingestion.';


CREATE TABLE raw.cve_details (
    -- Primary Key
    cve_id VARCHAR(50) PRIMARY KEY,

    -- Basic Information
    title TEXT,
    description TEXT,

    -- Dates (kept as TEXT in Bronze)
    published_date TEXT,
    last_modified TEXT,

    -- Classification & Metadata
    remotely_exploit BOOLEAN,
    source_identifier VARCHAR(100),   -- ← renamed
    category VARCHAR(200),

    -- JSON fields
    affected_products JSONB,  -- Array of {id, vendor, product}
    cvss_scores JSONB,        -- Array of {score, version, severity, vector, exploitability_score, impact_score, source_identifier}

    -- Source URL
    url TEXT,

    -- Metadata
    loaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_raw_cve_details_published_date ON raw.cve_details((published_date::text));
CREATE INDEX IF NOT EXISTS idx_raw_cve_details_category ON raw.cve_details(category);
CREATE INDEX IF NOT EXISTS idx_raw_cve_details_source_identifier ON raw.cve_details(source_identifier);
CREATE INDEX IF NOT EXISTS idx_raw_cve_details_loaded_at ON raw.cve_details(loaded_at);

-- Full-text index for search
CREATE INDEX IF NOT EXISTS idx_raw_cve_details_desc_fts 
  ON raw.cve_details USING gin(to_tsvector('english', description));

-- Comments
COMMENT ON TABLE  raw.cve_details IS 'Raw CVE vulnerability data collected before cleaning (Bronze layer).';
COMMENT ON COLUMN raw.cve_details.cve_id             IS 'Unique CVE identifier (e.g., CVE-2025-12345).';
COMMENT ON COLUMN raw.cve_details.title              IS 'Short summary of the CVE.';
COMMENT ON COLUMN raw.cve_details.description        IS 'Full vulnerability description.';
COMMENT ON COLUMN raw.cve_details.published_date     IS 'Original publication date (string).';
COMMENT ON COLUMN raw.cve_details.last_modified      IS 'Last modification date (string).';
COMMENT ON COLUMN raw.cve_details.remotely_exploit   IS 'True if remotely exploitable.';
COMMENT ON COLUMN raw.cve_details.source_identifier  IS 'Source identifier for the CVE (e.g., NVD, MITRE, email, CVEFeed).';
COMMENT ON COLUMN raw.cve_details.category           IS 'Type/category of vulnerability.';
COMMENT ON COLUMN raw.cve_details.affected_products  IS 'JSONB list of affected products ({vendor, product, id}).';
COMMENT ON COLUMN raw.cve_details.cvss_scores        IS 'JSONB list of CVSS metrics (v2/v3/v4). Each row may carry source_identifier.';
COMMENT ON COLUMN raw.cve_details.url                IS 'Original URL of the CVE.';
COMMENT ON COLUMN raw.cve_details.loaded_at          IS 'Timestamp of ingestion into raw layer.';

VACUUM ANALYZE raw.cve_details;
