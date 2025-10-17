-- ================================================================
-- SILVER LAYER SCHEMA (EDA + Cleaned Data)
-- Table unique: cve_cleaned (données nettoyées et standardisées)
-- ================================================================

CREATE SCHEMA IF NOT EXISTS silver;
SET search_path TO silver, public;

-- ================================================================
-- NETTOYAGE
-- ================================================================
DROP TABLE IF EXISTS silver.cve_cleaned CASCADE;

-- ================================================================
-- TABLE: CVE_CLEANED
-- Description: Données CVE nettoyées issues de la couche Bronze
--              - Pas de modélisation en étoile
--              - Données standardisées et validées
--              - Prête pour transformation en Gold
-- ================================================================
CREATE TABLE silver.cve_cleaned (
    -- Identifiants
    cve_id VARCHAR(20) PRIMARY KEY,
    
    -- Informations principales
    title TEXT,
    description TEXT,
    category VARCHAR(50) DEFAULT 'undefined',
    
    -- Dates
    published_date TIMESTAMP,
    last_modified TIMESTAMP,
    loaded_at TIMESTAMP,
    
    -- Métadonnées
    remotely_exploit BOOLEAN,
    source_identifier TEXT,
    
    -- Données structurées (TEXT pour compatibilité avec pandas)
    -- Seront converties en JSONB après insertion si nécessaire
    affected_products TEXT,
    cvss_scores TEXT,
    
    -- Référence source
    url TEXT,
    
    -- Audit
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Fonction pour convertir TEXT en JSONB (optionnel)
CREATE OR REPLACE FUNCTION silver.convert_json_columns()
RETURNS void AS $
BEGIN
    -- Convertir affected_products en JSONB
    ALTER TABLE silver.cve_cleaned 
        ALTER COLUMN affected_products TYPE JSONB USING affected_products::jsonb;
    
    -- Convertir cvss_scores en JSONB
    ALTER TABLE silver.cve_cleaned 
        ALTER COLUMN cvss_scores TYPE JSONB USING cvss_scores::jsonb;
    
    RAISE NOTICE 'JSON columns converted to JSONB';
END;
$ LANGUAGE plpgsql;

-- ================================================================
-- INDEXES POUR PERFORMANCE
-- ================================================================

-- Index sur les dates (pour filtrage temporel)
CREATE INDEX idx_silver_cve_published ON silver.cve_cleaned(published_date);
CREATE INDEX idx_silver_cve_modified ON silver.cve_cleaned(last_modified);

-- Index sur category (pour groupement)
CREATE INDEX idx_silver_cve_category ON silver.cve_cleaned(category);

-- Index GIN sur JSONB pour recherche efficace
CREATE INDEX idx_silver_cve_products_gin ON silver.cve_cleaned USING GIN(affected_products);
CREATE INDEX idx_silver_cve_scores_gin ON silver.cve_cleaned USING GIN(cvss_scores);

-- Index sur source_identifier (pour traçabilité)
CREATE INDEX idx_silver_cve_source ON silver.cve_cleaned(source_identifier);

-- ================================================================
-- VUES POUR ANALYSE RAPIDE
-- ================================================================

-- Vue: Statistiques globales par année
CREATE OR REPLACE VIEW silver.vw_cve_stats_by_year AS
SELECT 
    EXTRACT(YEAR FROM published_date) AS year,
    COUNT(*) AS total_cves,
    COUNT(CASE WHEN remotely_exploit = TRUE THEN 1 END) AS remotely_exploitable,
    COUNT(CASE WHEN cvss_scores IS NOT NULL AND jsonb_array_length(cvss_scores) > 0 THEN 1 END) AS with_cvss,
    COUNT(CASE WHEN affected_products IS NOT NULL AND jsonb_array_length(affected_products) > 0 THEN 1 END) AS with_products
FROM silver.cve_cleaned
GROUP BY EXTRACT(YEAR FROM published_date)
ORDER BY year DESC;

-- Vue: CVEs sans données CVSS (pour validation qualité)
CREATE OR REPLACE VIEW silver.vw_cve_missing_cvss AS
SELECT 
    cve_id,
    title,
    published_date,
    category,
    source_identifier
FROM silver.cve_cleaned
WHERE cvss_scores IS NULL 
   OR jsonb_array_length(cvss_scores) = 0;

-- Vue: CVEs sans produits affectés (pour validation qualité)
CREATE OR REPLACE VIEW silver.vw_cve_missing_products AS
SELECT 
    cve_id,
    title,
    published_date,
    category,
    source_identifier
FROM silver.cve_cleaned
WHERE affected_products IS NULL 
   OR jsonb_array_length(affected_products) = 0;

-- Vue: Statistiques par catégorie
CREATE OR REPLACE VIEW silver.vw_cve_stats_by_category AS
SELECT 
    category,
    COUNT(*) AS total_cves,
    MIN(published_date) AS first_cve_date,
    MAX(published_date) AS last_cve_date,
    COUNT(CASE WHEN remotely_exploit = TRUE THEN 1 END) AS remotely_exploitable
FROM silver.cve_cleaned
GROUP BY category
ORDER BY total_cves DESC;

-- ================================================================
-- FONCTIONS UTILITAIRES
-- ================================================================

-- Fonction: Rafraîchir les timestamps updated_at
CREATE OR REPLACE FUNCTION silver.update_modified_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger: Auto-update de updated_at
CREATE TRIGGER trigger_update_cve_cleaned_modtime
    BEFORE UPDATE ON silver.cve_cleaned
    FOR EACH ROW
    EXECUTE FUNCTION silver.update_modified_column();

-- ================================================================
-- COMMENTAIRES POUR DOCUMENTATION
-- ================================================================

COMMENT ON SCHEMA silver IS 'Silver Layer: Données nettoyées et standardisées issues de la couche Bronze';
COMMENT ON TABLE silver.cve_cleaned IS 'CVEs nettoyées avec données validées et standardisées, prêtes pour transformation en Gold';
COMMENT ON COLUMN silver.cve_cleaned.cve_id IS 'Identifiant unique CVE (format: CVE-YYYY-NNNNN)';
COMMENT ON COLUMN silver.cve_cleaned.remotely_exploit IS 'Indique si la vulnérabilité est exploitable à distance';
COMMENT ON COLUMN silver.cve_cleaned.affected_products IS 'Liste des produits affectés (format JSONB)';
COMMENT ON COLUMN silver.cve_cleaned.cvss_scores IS 'Scores CVSS (v2/v3/v4) avec métriques (format JSONB)';

-- ================================================================
-- STATISTIQUES INITIALES
-- ================================================================

-- Analyser la table pour optimiser les requêtes
ANALYZE silver.cve_cleaned;

-- Afficher les statistiques
DO $$
BEGIN
    RAISE NOTICE '================================================================';
    RAISE NOTICE 'SILVER LAYER SCHEMA CREATED SUCCESSFULLY';
    RAISE NOTICE '================================================================';
    RAISE NOTICE 'Schema: silver';
    RAISE NOTICE 'Tables: 1 (cve_cleaned)';
    RAISE NOTICE 'Views: 4 (stats & quality checks)';
    RAISE NOTICE 'Indexes: 6 (performance optimization)';
    RAISE NOTICE '================================================================';
END $$;