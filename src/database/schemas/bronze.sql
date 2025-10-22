-- =====================================================================
-- BRONZE LAYER (RAW) - CVE DATA STORAGE (No title/description/url)
-- =====================================================================
-- Database: tip
-- Schema  : raw
-- Date    : 2025-10-22
-- Notes   : Conçu pour ingestion directe NVD JSON v2.0
--           Champs supprimés: title, description, url
-- =====================================================================

BEGIN;

-- 0) Schéma
CREATE SCHEMA IF NOT EXISTS raw;
COMMENT ON SCHEMA raw IS 'Bronze Layer: Unprocessed CVE data from official NVD JSON feeds.';

-- 1) Drop & recreate
DROP TABLE IF EXISTS raw.cve_details CASCADE;

CREATE TABLE raw.cve_details (
    -- Primary Key
    cve_id              VARCHAR(50) PRIMARY KEY,

    -- Dates (conservées en TEXT en Bronze, telles que fournies par la source)
    published_date      TEXT,
    last_modified       TEXT,

    -- Classification & Metadata (brut NVD)
    remotely_exploit    BOOLEAN,                -- NVD ne l’expose pas: peut rester NULL
    source_identifier   VARCHAR(100),           -- cve.sourceIdentifier NVD (ex: nvd@nist.gov, cna@...)
    category            VARCHAR(200),           -- premier identifiant CWE brut (ex: 'CWE-89')

    -- JSONB (brut)
    affected_products   JSONB,                  -- [{ "vendor": "...", "product": "..." }]
    cvss_scores         JSONB,                  -- [{ "version": "4.0|3.1|3.0|2.0", "score": ..., "severity": ..., "vector": ..., "exploitability_score": ..., "impact_score": ..., "source_identifier": ..., "type": ... }]

    -- Métadonnées d’ingestion
    loaded_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2) Indexation utile
CREATE INDEX IF NOT EXISTS idx_raw_cve_details_published_date   ON raw.cve_details(published_date);
CREATE INDEX IF NOT EXISTS idx_raw_cve_details_last_modified    ON raw.cve_details(last_modified);
CREATE INDEX IF NOT EXISTS idx_raw_cve_details_category         ON raw.cve_details(category);
CREATE INDEX IF NOT EXISTS idx_raw_cve_details_source_identifier ON raw.cve_details(source_identifier);
CREATE INDEX IF NOT EXISTS idx_raw_cve_details_loaded_at        ON raw.cve_details(loaded_at);

-- (Optionnel) Index GIN pour requêtes sur JSONB
-- CREATE INDEX IF NOT EXISTS idx_raw_cve_details_products_gin ON raw.cve_details USING gin (affected_products);
-- CREATE INDEX IF NOT EXISTS idx_raw_cve_details_cvss_gin     ON raw.cve_details USING gin (cvss_scores);

-- 3) Documentation
COMMENT ON TABLE  raw.cve_details IS 'Raw CVE data from NVD JSON 2.0 (Bronze). No title/description/url stored.';
COMMENT ON COLUMN raw.cve_details.cve_id            IS 'Unique CVE identifier (e.g., CVE-2025-12345).';
COMMENT ON COLUMN raw.cve_details.published_date    IS 'Original publication date string from NVD JSON.';
COMMENT ON COLUMN raw.cve_details.last_modified     IS 'Last modification date string from NVD JSON.';
COMMENT ON COLUMN raw.cve_details.remotely_exploit  IS 'Whether remotely exploitable (left NULL when unknown).';
COMMENT ON COLUMN raw.cve_details.source_identifier IS 'NVD sourceIdentifier (e.g., nvd@nist.gov, CNA emails).';
COMMENT ON COLUMN raw.cve_details.category          IS 'First raw CWE id encountered (e.g., CWE-89).';
COMMENT ON COLUMN raw.cve_details.affected_products IS 'JSONB list of affected vendor/product extracted from CPE.';
COMMENT ON COLUMN raw.cve_details.cvss_scores       IS 'JSONB list of CVSS metrics (v2/v3/v4) as provided by NVD.';
COMMENT ON COLUMN raw.cve_details.loaded_at         IS 'Ingestion timestamp (UTC).';

COMMIT;

-- 4) Stats
VACUUM ANALYZE raw.cve_details;
