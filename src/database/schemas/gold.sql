-- ================================================================
-- GOLD LAYER SCHEMA (STAR SCHEMA / MODÈLE EN ÉTOILE) - VERSION 2 (NO MV)
-- Modélisation dimensionnelle pour analytics et BI
-- ================================================================

CREATE SCHEMA IF NOT EXISTS gold;
SET search_path TO gold, public;

-- ================================================================
-- NETTOYAGE DES TABLES EXISTANTES
-- ================================================================
DROP TABLE IF EXISTS gold.bridge_vendor_products CASCADE;
DROP TABLE IF EXISTS gold.bridge_cve_products CASCADE;
DROP TABLE IF EXISTS gold.cvss_v4 CASCADE;
DROP TABLE IF EXISTS gold.cvss_v3 CASCADE;
DROP TABLE IF EXISTS gold.cvss_v2 CASCADE;
DROP TABLE IF EXISTS gold.dim_products CASCADE;
DROP TABLE IF EXISTS gold.dim_vendor CASCADE;
DROP TABLE IF EXISTS gold.dim_cvss_source CASCADE;
DROP TABLE IF EXISTS gold.dim_cve CASCADE;

-- ================================================================
-- DIMENSION: DIM_CVE
-- ================================================================
CREATE TABLE gold.dim_cve (
    cve_id VARCHAR(20) PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    category VARCHAR(50) DEFAULT 'undefined',
    predicted_category VARCHAR(50),
    published_date TIMESTAMP NOT NULL,
    last_modified TIMESTAMP NOT NULL,
    loaded_at TIMESTAMP NOT NULL,
    cve_year INTEGER GENERATED ALWAYS AS (EXTRACT(YEAR FROM published_date)) STORED,
    remotely_exploit BOOLEAN,
    source_identifier TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_gold_dim_cve_published ON gold.dim_cve(published_date);
CREATE INDEX idx_gold_dim_cve_year ON gold.dim_cve(cve_year);
CREATE INDEX idx_gold_dim_cve_category ON gold.dim_cve(category);
CREATE INDEX idx_gold_dim_cve_predicted_cat ON gold.dim_cve(predicted_category);
CREATE INDEX idx_gold_dim_cve_source ON gold.dim_cve(source_identifier);

-- ================================================================
-- DIMENSION: DIM_CVSS_SOURCE
-- ================================================================
CREATE TABLE gold.dim_cvss_source (
    source_id SERIAL PRIMARY KEY,
    source_name VARCHAR(100) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX idx_gold_dim_source_name ON gold.dim_cvss_source(source_name);

-- ================================================================
-- DIMENSION: DIM_VENDOR
-- ================================================================
CREATE TABLE gold.dim_vendor (
    vendor_id SERIAL PRIMARY KEY,
    vendor_name VARCHAR(255) NOT NULL UNIQUE,
    total_products INTEGER DEFAULT 0,
    total_cves INTEGER DEFAULT 0,
    first_cve_date TIMESTAMP,
    last_cve_date TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX idx_gold_dim_vendor_name ON gold.dim_vendor(vendor_name);
CREATE INDEX idx_gold_dim_vendor_cves ON gold.dim_vendor(total_cves);

-- ================================================================
-- DIMENSION: DIM_PRODUCTS
-- ================================================================
CREATE TABLE gold.dim_products (
    product_id SERIAL PRIMARY KEY,
    vendor_id INTEGER NOT NULL REFERENCES gold.dim_vendor(vendor_id) ON DELETE CASCADE,
    product_name VARCHAR(255) NOT NULL,
    total_cves INTEGER DEFAULT 0,
    first_cve_date TIMESTAMP,
    last_cve_date TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uk_gold_products_vendor_product UNIQUE (vendor_id, product_name)
);
CREATE INDEX idx_gold_dim_products_vendor ON gold.dim_products(vendor_id);
CREATE INDEX idx_gold_dim_products_name ON gold.dim_products(product_name);
CREATE INDEX idx_gold_dim_products_cves ON gold.dim_products(total_cves);

-- ================================================================
-- FAIT: CVSS_V2
-- ================================================================
CREATE TABLE gold.cvss_v2 (
    cvss_v2_id SERIAL PRIMARY KEY,
    cve_id VARCHAR(20) NOT NULL REFERENCES gold.dim_cve(cve_id) ON DELETE CASCADE,
    source_id INTEGER NOT NULL REFERENCES gold.dim_cvss_source(source_id) ON DELETE CASCADE,
    cvss_score NUMERIC(3,1) CHECK (cvss_score >= 0 AND cvss_score <= 10),
    cvss_severity VARCHAR(10),
    cvss_vector TEXT NOT NULL,
    cvss_v2_av VARCHAR(1),
    cvss_v2_ac VARCHAR(1),
    cvss_v2_au VARCHAR(1),
    cvss_v2_c  VARCHAR(1),
    cvss_v2_i  VARCHAR(1),
    cvss_v2_a  VARCHAR(1),
    cvss_exploitability_score NUMERIC(3,1),
    cvss_impact_score NUMERIC(3,1),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_gold_cvss_v2_cve ON gold.cvss_v2(cve_id);
CREATE INDEX idx_gold_cvss_v2_source ON gold.cvss_v2(source_id);
CREATE INDEX idx_gold_cvss_v2_score ON gold.cvss_v2(cvss_score);
CREATE INDEX idx_gold_cvss_v2_severity ON gold.cvss_v2(cvss_severity);

-- ================================================================
-- FAIT: CVSS_V3
-- ================================================================
CREATE TABLE gold.cvss_v3 (
    cvss_v3_id SERIAL PRIMARY KEY,
    cve_id VARCHAR(20) NOT NULL REFERENCES gold.dim_cve(cve_id) ON DELETE CASCADE,
    source_id INTEGER NOT NULL REFERENCES gold.dim_cvss_source(source_id) ON DELETE CASCADE,
    cvss_version VARCHAR(10) NOT NULL CHECK (cvss_version IN ('CVSS 3.0', 'CVSS 3.1')),
    cvss_score NUMERIC(3,1) CHECK (cvss_score >= 0 AND cvss_score <= 10),
    cvss_severity VARCHAR(10),
    cvss_vector TEXT NOT NULL,
    cvss_v3_base_av VARCHAR(1),
    cvss_v3_base_ac VARCHAR(1),
    cvss_v3_base_pr VARCHAR(1),
    cvss_v3_base_ui VARCHAR(1),
    cvss_v3_base_s  VARCHAR(1),
    cvss_v3_base_c  VARCHAR(1),
    cvss_v3_base_i  VARCHAR(1),
    cvss_v3_base_a  VARCHAR(1),
    cvss_exploitability_score NUMERIC(3,1),
    cvss_impact_score NUMERIC(3,1),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_gold_cvss_v3_cve ON gold.cvss_v3(cve_id);
CREATE INDEX idx_gold_cvss_v3_source ON gold.cvss_v3(source_id);
CREATE INDEX idx_gold_cvss_v3_version ON gold.cvss_v3(cvss_version);
CREATE INDEX idx_gold_cvss_v3_score ON gold.cvss_v3(cvss_score);
CREATE INDEX idx_gold_cvss_v3_severity ON gold.cvss_v3(cvss_severity);

-- ================================================================
-- FAIT: CVSS_V4
-- ================================================================
CREATE TABLE gold.cvss_v4 (
    cvss_v4_id SERIAL PRIMARY KEY,
    cve_id VARCHAR(20) NOT NULL REFERENCES gold.dim_cve(cve_id) ON DELETE CASCADE,
    source_id INTEGER NOT NULL REFERENCES gold.dim_cvss_source(source_id) ON DELETE CASCADE,
    cvss_score NUMERIC(3,1) CHECK (cvss_score >= 0 AND cvss_score <= 10),
    cvss_severity VARCHAR(10),
    cvss_vector TEXT NOT NULL,
    cvss_v4_av VARCHAR(1),
    cvss_v4_at VARCHAR(1),
    cvss_v4_ac VARCHAR(2),
    cvss_v4_vc VARCHAR(1),
    cvss_v4_vi VARCHAR(1),
    cvss_v4_va VARCHAR(1),
    cvss_v4_sc VARCHAR(1),
    cvss_v4_si VARCHAR(1),
    cvss_v4_sa VARCHAR(1),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_gold_cvss_v4_cve ON gold.cvss_v4(cve_id);
CREATE INDEX idx_gold_cvss_v4_source ON gold.cvss_v4(source_id);
CREATE INDEX idx_gold_cvss_v4_score ON gold.cvss_v4(cvss_score);
CREATE INDEX idx_gold_cvss_v4_severity ON gold.cvss_v4(cvss_severity);

-- ================================================================
-- BRIDGE TABLE: BRIDGE_CVE_PRODUCTS
-- ================================================================
CREATE TABLE gold.bridge_cve_products (
    bridge_id SERIAL PRIMARY KEY,
    cve_id VARCHAR(20) NOT NULL REFERENCES gold.dim_cve(cve_id) ON DELETE CASCADE,
    product_id INTEGER NOT NULL REFERENCES gold.dim_products(product_id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uk_gold_bridge_cve_product UNIQUE (cve_id, product_id)
);
CREATE INDEX idx_gold_bridge_cve ON gold.bridge_cve_products(cve_id);
CREATE INDEX idx_gold_bridge_product ON gold.bridge_cve_products(product_id);

-- ================================================================
-- FONCTIONS UTILITAIRES (empty stub)
-- ================================================================
CREATE OR REPLACE FUNCTION gold.refresh_all_mv()
RETURNS void AS $$
BEGIN
    RAISE NOTICE 'No materialized views to refresh (mv_cve_all_cvss removed).';
END;
$$ LANGUAGE plpgsql;

-- ================================================================
-- COMMENTAIRES POUR DOCUMENTATION
-- ================================================================
COMMENT ON SCHEMA gold IS 'Gold Layer: Modèle en étoile (Star Schema) pour analytics et BI';
COMMENT ON TABLE gold.dim_cve IS 'Dimension centrale: CVE avec attributs descriptifs et catégorie prédite';
COMMENT ON TABLE gold.dim_cvss_source IS 'Dimension: Sources des scores CVSS';
COMMENT ON TABLE gold.dim_vendor IS 'Dimension: Vendors/éditeurs de logiciels';
COMMENT ON TABLE gold.dim_products IS 'Dimension: Produits et logiciels affectés';
COMMENT ON TABLE gold.cvss_v2 IS 'Fait: Scores CVSS version 2.0 avec 6 métriques de base';
COMMENT ON TABLE gold.cvss_v3 IS 'Fait: Scores CVSS version 3.0/3.1 avec 8 métriques de base';
COMMENT ON TABLE gold.cvss_v4 IS 'Fait: Scores CVSS version 4.0 avec 9 métriques de base';
COMMENT ON TABLE gold.bridge_cve_products IS 'Bridge: Relation many-to-many CVE <-> Products';

-- ================================================================
-- STATISTIQUES INITIALES
-- ================================================================
ANALYZE gold.dim_cve;
ANALYZE gold.dim_cvss_source;
ANALYZE gold.dim_vendor;
ANALYZE gold.dim_products;
ANALYZE gold.cvss_v2;
ANALYZE gold.cvss_v3;
ANALYZE gold.cvss_v4;
ANALYZE gold.bridge_cve_products;

-- ================================================================
-- RAPPORT FINAL
-- ================================================================
DO $$
BEGIN
    RAISE NOTICE '================================================================';
    RAISE NOTICE 'GOLD LAYER SCHEMA CREATED SUCCESSFULLY (VERSION 2 - NO MV)';
    RAISE NOTICE '================================================================';
    RAISE NOTICE 'Schema: gold (Star Schema / Modèle en étoile)';
    RAISE NOTICE '';
    RAISE NOTICE 'DIMENSIONS: dim_cve, dim_cvss_source, dim_vendor, dim_products';
    RAISE NOTICE 'FACTS: cvss_v2, cvss_v3, cvss_v4';
    RAISE NOTICE 'BRIDGES: bridge_cve_products';
    RAISE NOTICE '';
    RAISE NOTICE 'No materialized views included in this version.';
    RAISE NOTICE '================================================================';
END $$;
