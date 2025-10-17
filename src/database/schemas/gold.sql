-- ================================================================
-- GOLD LAYER SCHEMA (STAR SCHEMA / MODÈLE EN ÉTOILE)
-- Modélisation dimensionnelle pour analytics et BI
-- ================================================================

CREATE SCHEMA IF NOT EXISTS gold;
SET search_path TO gold, public;

-- ================================================================
-- NETTOYAGE DES TABLES EXISTANTES
-- ================================================================
DROP MATERIALIZED VIEW IF EXISTS gold.mv_cve_all_cvss CASCADE;
DROP TABLE IF EXISTS gold.bridge_cve_products CASCADE;
DROP TABLE IF EXISTS gold.cvss_v4 CASCADE;
DROP TABLE IF EXISTS gold.cvss_v3 CASCADE;
DROP TABLE IF EXISTS gold.cvss_v2 CASCADE;
DROP TABLE IF EXISTS gold.dim_products CASCADE;
DROP TABLE IF EXISTS gold.dim_cvss_source CASCADE;
DROP TABLE IF EXISTS gold.dim_cve CASCADE;

-- ================================================================
-- DIMENSION: DIM_CVE
-- Description: Dimension principale des CVE (centre de l'étoile)
-- ================================================================
CREATE TABLE gold.dim_cve (
    -- Clé primaire
    cve_id VARCHAR(20) PRIMARY KEY,
    
    -- Attributs descriptifs
    title TEXT NOT NULL,
    description TEXT,
    category VARCHAR(50) DEFAULT 'undefined',
    
    -- Dates (SCD Type 1)
    published_date TIMESTAMP NOT NULL,
    last_modified TIMESTAMP NOT NULL,
    loaded_at TIMESTAMP NOT NULL,
    
    -- Colonne calculée: année de publication
    cve_year INTEGER GENERATED ALWAYS AS (EXTRACT(YEAR FROM published_date)) STORED,
    
    -- Attributs métier
    remotely_exploit BOOLEAN,
    source_identifier TEXT,
    
    -- Audit
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes pour performance
CREATE INDEX idx_gold_dim_cve_published ON gold.dim_cve(published_date);
CREATE INDEX idx_gold_dim_cve_year ON gold.dim_cve(cve_year);
CREATE INDEX idx_gold_dim_cve_category ON gold.dim_cve(category);
CREATE INDEX idx_gold_dim_cve_source ON gold.dim_cve(source_identifier);

-- ================================================================
-- DIMENSION: DIM_CVSS_SOURCE
-- Description: Sources des scores CVSS (NVD, vendors, etc.)
-- ================================================================
CREATE TABLE gold.dim_cvss_source (
    source_id SERIAL PRIMARY KEY,
    source_name VARCHAR(100) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Index unique sur source_name
CREATE UNIQUE INDEX idx_gold_dim_source_name ON gold.dim_cvss_source(source_name);

-- ================================================================
-- FAIT: CVSS_V2
-- Description: Scores et métriques CVSS version 2.0
-- ================================================================
CREATE TABLE gold.cvss_v2 (
    cvss_v2_id SERIAL PRIMARY KEY,
    
    -- Clés étrangères
    cve_id VARCHAR(20) NOT NULL REFERENCES gold.dim_cve(cve_id) ON DELETE CASCADE,
    source_id INTEGER NOT NULL REFERENCES gold.dim_cvss_source(source_id) ON DELETE CASCADE,
    
    -- Métriques principales
    cvss_score NUMERIC(3,1) CHECK (cvss_score >= 0 AND cvss_score <= 10),
    cvss_severity VARCHAR(10),
    cvss_vector TEXT NOT NULL,
    
    -- Métriques CVSS v2 (6 métriques de base)
    cvss_v2_av VARCHAR(1),  -- Access Vector: L/A/N
    cvss_v2_ac VARCHAR(1),  -- Access Complexity: H/M/L
    cvss_v2_au VARCHAR(1),  -- Authentication: M/S/N
    cvss_v2_c  VARCHAR(1),  -- Confidentiality: N/P/C
    cvss_v2_i  VARCHAR(1),  -- Integrity: N/P/C
    cvss_v2_a  VARCHAR(1),  -- Availability: N/P/C
    
    -- Scores complémentaires
    cvss_exploitability_score NUMERIC(3,1),
    cvss_impact_score NUMERIC(3,1),
    
    -- Audit
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes pour performance
CREATE INDEX idx_gold_cvss_v2_cve ON gold.cvss_v2(cve_id);
CREATE INDEX idx_gold_cvss_v2_source ON gold.cvss_v2(source_id);
CREATE INDEX idx_gold_cvss_v2_score ON gold.cvss_v2(cvss_score);
CREATE INDEX idx_gold_cvss_v2_severity ON gold.cvss_v2(cvss_severity);

-- ================================================================
-- FAIT: CVSS_V3
-- Description: Scores et métriques CVSS version 3.0/3.1 (base only)
-- ================================================================
CREATE TABLE gold.cvss_v3 (
    cvss_v3_id SERIAL PRIMARY KEY,
    
    -- Clés étrangères
    cve_id VARCHAR(20) NOT NULL REFERENCES gold.dim_cve(cve_id) ON DELETE CASCADE,
    source_id INTEGER NOT NULL REFERENCES gold.dim_cvss_source(source_id) ON DELETE CASCADE,
    
    -- Version spécifique
    cvss_version VARCHAR(10) NOT NULL CHECK (cvss_version IN ('CVSS 3.0', 'CVSS 3.1')),
    
    -- Métriques principales
    cvss_score NUMERIC(3,1) CHECK (cvss_score >= 0 AND cvss_score <= 10),
    cvss_severity VARCHAR(10),
    cvss_vector TEXT NOT NULL,
    
    -- Métriques CVSS v3 base (8 métriques)
    cvss_v3_base_av VARCHAR(1),  -- Attack Vector: N/A/L/P
    cvss_v3_base_ac VARCHAR(1),  -- Attack Complexity: L/H
    cvss_v3_base_pr VARCHAR(1),  -- Privileges Required: N/L/H
    cvss_v3_base_ui VARCHAR(1),  -- User Interaction: N/R
    cvss_v3_base_s  VARCHAR(1),  -- Scope: U/C
    cvss_v3_base_c  VARCHAR(1),  -- Confidentiality: N/L/H
    cvss_v3_base_i  VARCHAR(1),  -- Integrity: N/L/H
    cvss_v3_base_a  VARCHAR(1),  -- Availability: N/L/H
    
    -- Scores complémentaires
    cvss_exploitability_score NUMERIC(3,1),
    cvss_impact_score NUMERIC(3,1),
    
    -- Audit
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes pour performance
CREATE INDEX idx_gold_cvss_v3_cve ON gold.cvss_v3(cve_id);
CREATE INDEX idx_gold_cvss_v3_source ON gold.cvss_v3(source_id);
CREATE INDEX idx_gold_cvss_v3_version ON gold.cvss_v3(cvss_version);
CREATE INDEX idx_gold_cvss_v3_score ON gold.cvss_v3(cvss_score);
CREATE INDEX idx_gold_cvss_v3_severity ON gold.cvss_v3(cvss_severity);

-- ================================================================
-- FAIT: CVSS_V4
-- Description: Scores et métriques CVSS version 4.0
-- ================================================================
CREATE TABLE gold.cvss_v4 (
    cvss_v4_id SERIAL PRIMARY KEY,
    
    -- Clés étrangères
    cve_id VARCHAR(20) NOT NULL REFERENCES gold.dim_cve(cve_id) ON DELETE CASCADE,
    source_id INTEGER NOT NULL REFERENCES gold.dim_cvss_source(source_id) ON DELETE CASCADE,
    
    -- Métriques principales
    cvss_score NUMERIC(3,1) CHECK (cvss_score >= 0 AND cvss_score <= 10),
    cvss_severity VARCHAR(10),
    cvss_vector TEXT NOT NULL,
    
    -- Métriques CVSS v4 (9 métriques de base)
    cvss_v4_av VARCHAR(1),   -- Attack Vector: N/A/L/P
    cvss_v4_at VARCHAR(1),   -- Attack Requirements: N/P
    cvss_v4_ac VARCHAR(2),   -- Attack Complexity: L/H
    cvss_v4_vc VARCHAR(1),   -- Vulnerable System Confidentiality: H/L/N
    cvss_v4_vi VARCHAR(1),   -- Vulnerable System Integrity: H/L/N
    cvss_v4_va VARCHAR(1),   -- Vulnerable System Availability: H/L/N
    cvss_v4_sc VARCHAR(1),   -- Subsequent System Confidentiality: H/L/N
    cvss_v4_si VARCHAR(1),   -- Subsequent System Integrity: H/L/N
    cvss_v4_sa VARCHAR(1),   -- Subsequent System Availability: H/L/N
    
    -- Note: CVSS v4 n'a pas exploitability/impact scores
    
    -- Audit
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes pour performance
CREATE INDEX idx_gold_cvss_v4_cve ON gold.cvss_v4(cve_id);
CREATE INDEX idx_gold_cvss_v4_source ON gold.cvss_v4(source_id);
CREATE INDEX idx_gold_cvss_v4_score ON gold.cvss_v4(cvss_score);
CREATE INDEX idx_gold_cvss_v4_severity ON gold.cvss_v4(cvss_severity);

-- ================================================================
-- DIMENSION: DIM_PRODUCTS
-- Description: Produits/logiciels affectés par les CVE
-- ================================================================
CREATE TABLE gold.dim_products (
    product_id SERIAL PRIMARY KEY,
    
    -- Attributs descriptifs
    vendor VARCHAR(255) NOT NULL,
    product_name VARCHAR(255) NOT NULL,
    
    -- Métriques agrégées
    total_cves INTEGER DEFAULT 0,
    first_cve_date TIMESTAMP,
    last_cve_date TIMESTAMP,
    
    -- Colonne calculée: durée de vie (jours)
    product_lifespan_days INTEGER GENERATED ALWAYS AS (
        EXTRACT(DAY FROM (last_cve_date - first_cve_date))
    ) STORED,
    
    -- Audit
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Contrainte d'unicité
    CONSTRAINT uk_gold_products_vendor_product UNIQUE (vendor, product_name)
);

-- Indexes pour performance
CREATE INDEX idx_gold_dim_products_vendor ON gold.dim_products(vendor);
CREATE INDEX idx_gold_dim_products_name ON gold.dim_products(product_name);
CREATE INDEX idx_gold_dim_products_cves ON gold.dim_products(total_cves);

-- ================================================================
-- BRIDGE TABLE: BRIDGE_CVE_PRODUCTS
-- Description: Relation many-to-many entre CVE et Products
-- ================================================================
CREATE TABLE gold.bridge_cve_products (
    bridge_id SERIAL PRIMARY KEY,
    
    -- Clés étrangères
    cve_id VARCHAR(20) NOT NULL REFERENCES gold.dim_cve(cve_id) ON DELETE CASCADE,
    product_id INTEGER NOT NULL REFERENCES gold.dim_products(product_id) ON DELETE CASCADE,
    
    -- Audit
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Contrainte d'unicité
    CONSTRAINT uk_gold_bridge_cve_product UNIQUE (cve_id, product_id)
);

-- Indexes pour performance
CREATE INDEX idx_gold_bridge_cve ON gold.bridge_cve_products(cve_id);
CREATE INDEX idx_gold_bridge_product ON gold.bridge_cve_products(product_id);

-- ================================================================
-- MATERIALIZED VIEW: MV_CVE_ALL_CVSS
-- Description: Vue unifiée de tous les scores CVSS (v2/v3/v4)
-- ================================================================
CREATE MATERIALIZED VIEW gold.mv_cve_all_cvss AS
-- CVSS v2
SELECT 
    c.cve_id,
    c.title,
    c.published_date,
    c.cve_year,
    c.category,
    c.source_identifier,
    s.source_name AS cvss_source,
    'CVSS 2.0' AS cvss_version,
    v2.cvss_score,
    v2.cvss_severity,
    v2.cvss_vector,
    v2.cvss_exploitability_score,
    v2.cvss_impact_score,
    v2.cvss_v2_av AS av,
    v2.cvss_v2_ac AS ac,
    NULL::VARCHAR AS pr,
    NULL::VARCHAR AS ui,
    NULL::VARCHAR AS s,
    v2.cvss_v2_c AS c,
    v2.cvss_v2_i AS i,
    v2.cvss_v2_a AS a
FROM gold.cvss_v2 v2
JOIN gold.dim_cve c ON c.cve_id = v2.cve_id
JOIN gold.dim_cvss_source s ON s.source_id = v2.source_id

UNION ALL

-- CVSS v3
SELECT 
    c.cve_id,
    c.title,
    c.published_date,
    c.cve_year,
    c.category,
    c.source_identifier,
    s.source_name AS cvss_source,
    v3.cvss_version,
    v3.cvss_score,
    v3.cvss_severity,
    v3.cvss_vector,
    v3.cvss_exploitability_score,
    v3.cvss_impact_score,
    v3.cvss_v3_base_av AS av,
    v3.cvss_v3_base_ac AS ac,
    v3.cvss_v3_base_pr AS pr,
    v3.cvss_v3_base_ui AS ui,
    v3.cvss_v3_base_s AS s,
    v3.cvss_v3_base_c AS c,
    v3.cvss_v3_base_i AS i,
    v3.cvss_v3_base_a AS a
FROM gold.cvss_v3 v3
JOIN gold.dim_cve c ON c.cve_id = v3.cve_id
JOIN gold.dim_cvss_source s ON s.source_id = v3.source_id

UNION ALL

-- CVSS v4
SELECT 
    c.cve_id,
    c.title,
    c.published_date,
    c.cve_year,
    c.category,
    c.source_identifier,
    s.source_name AS cvss_source,
    'CVSS 4.0' AS cvss_version,
    v4.cvss_score,
    v4.cvss_severity,
    v4.cvss_vector,
    NULL::NUMERIC(3,1) AS cvss_exploitability_score,
    NULL::NUMERIC(3,1) AS cvss_impact_score,
    v4.cvss_v4_av AS av,
    v4.cvss_v4_ac AS ac,
    NULL::VARCHAR AS pr,
    NULL::VARCHAR AS ui,
    NULL::VARCHAR AS s,
    v4.cvss_v4_vc AS c,
    v4.cvss_v4_vi AS i,
    v4.cvss_v4_va AS a
FROM gold.cvss_v4 v4
JOIN gold.dim_cve c ON c.cve_id = v4.cve_id
JOIN gold.dim_cvss_source s ON s.source_id = v4.source_id

ORDER BY cve_id, cvss_version;

-- Indexes sur la vue matérialisée
CREATE INDEX idx_gold_mv_cvss_cve ON gold.mv_cve_all_cvss(cve_id);
CREATE INDEX idx_gold_mv_cvss_version ON gold.mv_cve_all_cvss(cvss_version);
CREATE INDEX idx_gold_mv_cvss_year ON gold.mv_cve_all_cvss(cve_year);
CREATE INDEX idx_gold_mv_cvss_score ON gold.mv_cve_all_cvss(cvss_score);

-- ================================================================
-- FONCTIONS UTILITAIRES
-- ================================================================

-- Fonction: Rafraîchir toutes les vues matérialisées
CREATE OR REPLACE FUNCTION gold.refresh_all_mv()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY gold.mv_cve_all_cvss;
    RAISE NOTICE 'All materialized views refreshed successfully';
END;
$$ LANGUAGE plpgsql;

-- Fonction: Auto-update timestamp
CREATE OR REPLACE FUNCTION gold.update_modified_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Triggers pour auto-update
CREATE TRIGGER trigger_update_dim_cve_modtime
    BEFORE UPDATE ON gold.dim_cve
    FOR EACH ROW
    EXECUTE FUNCTION gold.update_modified_column();

CREATE TRIGGER trigger_update_dim_products_modtime
    BEFORE UPDATE ON gold.dim_products
    FOR EACH ROW
    EXECUTE FUNCTION gold.update_modified_column();

-- ================================================================
-- COMMENTAIRES POUR DOCUMENTATION
-- ================================================================

COMMENT ON SCHEMA gold IS 'Gold Layer: Modèle en étoile (Star Schema) pour analytics et BI';
COMMENT ON TABLE gold.dim_cve IS 'Dimension centrale: CVE avec attributs descriptifs';
COMMENT ON TABLE gold.dim_cvss_source IS 'Dimension: Sources des scores CVSS';
COMMENT ON TABLE gold.cvss_v2 IS 'Fait: Scores CVSS version 2.0 avec 6 métriques de base';
COMMENT ON TABLE gold.cvss_v3 IS 'Fait: Scores CVSS version 3.0/3.1 avec 8 métriques de base';
COMMENT ON TABLE gold.cvss_v4 IS 'Fait: Scores CVSS version 4.0 avec 9 métriques de base';
COMMENT ON TABLE gold.dim_products IS 'Dimension: Produits et vendors affectés';
COMMENT ON TABLE gold.bridge_cve_products IS 'Bridge: Relation many-to-many CVE <-> Products';
COMMENT ON MATERIALIZED VIEW gold.mv_cve_all_cvss IS 'Vue unifiée de tous les scores CVSS pour reporting';

-- ================================================================
-- STATISTIQUES INITIALES
-- ================================================================

ANALYZE gold.dim_cve;
ANALYZE gold.dim_cvss_source;
ANALYZE gold.cvss_v2;
ANALYZE gold.cvss_v3;
ANALYZE gold.cvss_v4;
ANALYZE gold.dim_products;
ANALYZE gold.bridge_cve_products;

-- ================================================================
-- RAPPORT FINAL
-- ================================================================

DO $
BEGIN
    RAISE NOTICE '================================================================';
    RAISE NOTICE 'GOLD LAYER SCHEMA CREATED SUCCESSFULLY';
    RAISE NOTICE '================================================================';
    RAISE NOTICE 'Schema: gold (Star Schema / Modèle en étoile)';
    RAISE NOTICE '';
    RAISE NOTICE 'DIMENSIONS:';
    RAISE NOTICE '  - dim_cve (CVE principale)';
    RAISE NOTICE '  - dim_cvss_source (Sources CVSS)';
    RAISE NOTICE '  - dim_products (Produits affectés)';
    RAISE NOTICE '';
    RAISE NOTICE 'FACTS:';
    RAISE NOTICE '  - cvss_v2 (Scores CVSS 2.0)';
    RAISE NOTICE '  - cvss_v3 (Scores CVSS 3.0/3.1)';
    RAISE NOTICE '  - cvss_v4 (Scores CVSS 4.0)';
    RAISE NOTICE '';
    RAISE NOTICE 'BRIDGES:';
    RAISE NOTICE '  - bridge_cve_products (CVE <-> Products)';
    RAISE NOTICE '';
    RAISE NOTICE 'MATERIALIZED VIEWS:';
    RAISE NOTICE '  - mv_cve_all_cvss (Vue unifiée)';
    RAISE NOTICE '';
    RAISE NOTICE 'INDEXES: 25+ (optimisation performance)';
    RAISE NOTICE '================================================================';
END $;