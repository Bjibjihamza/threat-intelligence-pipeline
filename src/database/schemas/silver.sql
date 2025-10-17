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
--              - Inclut predicted_category (ML)
-- ================================================================
CREATE TABLE silver.cve_cleaned (
    -- Identifiants
    cve_id VARCHAR(20) PRIMARY KEY,
    
    -- Informations principales
    title TEXT,
    description TEXT,
    category VARCHAR(50) DEFAULT 'undefined',
    predicted_category VARCHAR(50),  -- ✨ NOUVEAU: Catégorie prédite par ML
    
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
RETURNS void AS $$
BEGIN
    -- Convertir affected_products en JSONB
    ALTER TABLE silver.cve_cleaned 
        ALTER COLUMN affected_products TYPE JSONB USING affected_products::jsonb;
    
    -- Convertir cvss_scores en JSONB
    ALTER TABLE silver.cve_cleaned 
        ALTER COLUMN cvss_scores TYPE JSONB USING cvss_scores::jsonb;
    
    RAISE NOTICE 'JSON columns converted to JSONB';
END;
$$ LANGUAGE plpgsql;

-- ================================================================
-- INDEXES POUR PERFORMANCE
-- ================================================================

-- Index sur les dates (pour filtrage temporel)
CREATE INDEX idx_silver_cve_published ON silver.cve_cleaned(published_date);
CREATE INDEX idx_silver_cve_modified ON silver.cve_cleaned(last_modified);

-- Index sur category (pour groupement)
CREATE INDEX idx_silver_cve_category ON silver.cve_cleaned(category);

-- ✨ NOUVEAU: Index sur predicted_category (pour analyse ML)
CREATE INDEX idx_silver_cve_predicted_category ON silver.cve_cleaned(predicted_category);

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
    COUNT(CASE WHEN affected_products IS NOT NULL AND jsonb_array_length(affected_products) > 0 THEN 1 END) AS with_products,
    COUNT(CASE WHEN predicted_category IS NOT NULL THEN 1 END) AS with_prediction
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
    predicted_category,
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
    predicted_category,
    source_identifier
FROM silver.cve_cleaned
WHERE affected_products IS NULL 
   OR jsonb_array_length(affected_products) = 0;

-- Vue: Statistiques par catégorie (originale vs prédite)
CREATE OR REPLACE VIEW silver.vw_cve_stats_by_category AS
SELECT 
    category,
    COUNT(*) AS total_cves,
    MIN(published_date) AS first_cve_date,
    MAX(published_date) AS last_cve_date,
    COUNT(CASE WHEN remotely_exploit = TRUE THEN 1 END) AS remotely_exploitable,
    COUNT(CASE WHEN predicted_category IS NOT NULL THEN 1 END) AS with_prediction
FROM silver.cve_cleaned
GROUP BY category
ORDER BY total_cves DESC;

-- ✨ NOUVELLE VUE: Comparaison catégorie originale vs prédite
CREATE OR REPLACE VIEW silver.vw_category_comparison AS
SELECT 
    category AS original_category,
    predicted_category,
    COUNT(*) AS count,
    ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 2) AS percentage
FROM silver.cve_cleaned
WHERE predicted_category IS NOT NULL
GROUP BY category, predicted_category
ORDER BY count DESC;

-- ✨ NOUVELLE VUE: Statistiques de prédiction ML
CREATE OR REPLACE VIEW silver.vw_prediction_stats AS
SELECT 
    COUNT(*) AS total_cves,
    COUNT(CASE WHEN predicted_category IS NOT NULL THEN 1 END) AS predicted_count,
    COUNT(CASE WHEN predicted_category IS NULL THEN 1 END) AS unpredicted_count,
    ROUND(COUNT(CASE WHEN predicted_category IS NOT NULL THEN 1 END) * 100.0 / COUNT(*), 2) AS prediction_rate,
    COUNT(CASE WHEN category = predicted_category THEN 1 END) AS matches,
    ROUND(COUNT(CASE WHEN category = predicted_category THEN 1 END) * 100.0 / 
          NULLIF(COUNT(CASE WHEN predicted_category IS NOT NULL THEN 1 END), 0), 2) AS accuracy
FROM silver.cve_cleaned;

-- ✨ NOUVELLE VUE: Top catégories prédites
CREATE OR REPLACE VIEW silver.vw_top_predicted_categories AS
SELECT 
    predicted_category,
    COUNT(*) AS count,
    ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 2) AS percentage,
    MIN(published_date) AS first_seen,
    MAX(published_date) AS last_seen
FROM silver.cve_cleaned
WHERE predicted_category IS NOT NULL
GROUP BY predicted_category
ORDER BY count DESC
LIMIT 20;

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

-- ✨ NOUVELLE FONCTION: Statistiques de qualité des prédictions
CREATE OR REPLACE FUNCTION silver.get_prediction_quality_report()
RETURNS TABLE (
    metric TEXT,
    value NUMERIC,
    description TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        'Total CVEs'::TEXT,
        COUNT(*)::NUMERIC,
        'Nombre total de CVEs dans Silver'::TEXT
    FROM silver.cve_cleaned
    
    UNION ALL
    
    SELECT 
        'CVEs with Predictions'::TEXT,
        COUNT(CASE WHEN predicted_category IS NOT NULL THEN 1 END)::NUMERIC,
        'CVEs avec catégorie prédite'::TEXT
    FROM silver.cve_cleaned
    
    UNION ALL
    
    SELECT 
        'Prediction Rate (%)'::TEXT,
        ROUND(COUNT(CASE WHEN predicted_category IS NOT NULL THEN 1 END) * 100.0 / COUNT(*), 2),
        'Pourcentage de CVEs avec prédiction'::TEXT
    FROM silver.cve_cleaned
    
    UNION ALL
    
    SELECT 
        'Exact Matches'::TEXT,
        COUNT(CASE WHEN category = predicted_category THEN 1 END)::NUMERIC,
        'Prédictions exactes (category = predicted_category)'::TEXT
    FROM silver.cve_cleaned
    WHERE predicted_category IS NOT NULL
    
    UNION ALL
    
    SELECT 
        'Model Accuracy (%)'::TEXT,
        ROUND(COUNT(CASE WHEN category = predicted_category THEN 1 END) * 100.0 / 
              NULLIF(COUNT(CASE WHEN predicted_category IS NOT NULL THEN 1 END), 0), 2),
        'Précision du modèle de prédiction'::TEXT
    FROM silver.cve_cleaned;
END;
$$ LANGUAGE plpgsql;

-- ================================================================
-- COMMENTAIRES POUR DOCUMENTATION
-- ================================================================

COMMENT ON SCHEMA silver IS 'Silver Layer: Données nettoyées et standardisées issues de la couche Bronze';
COMMENT ON TABLE silver.cve_cleaned IS 'CVEs nettoyées avec données validées et standardisées, prêtes pour transformation en Gold';
COMMENT ON COLUMN silver.cve_cleaned.cve_id IS 'Identifiant unique CVE (format: CVE-YYYY-NNNNN)';
COMMENT ON COLUMN silver.cve_cleaned.category IS 'Catégorie originale du CVE';
COMMENT ON COLUMN silver.cve_cleaned.predicted_category IS 'Catégorie prédite par modèle ML (basé sur title + description)';
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
    RAISE NOTICE 'Views: 7 (stats, quality checks & ML analysis)';
    RAISE NOTICE 'Indexes: 7 (performance optimization)';
    RAISE NOTICE 'Functions: 2 (utilities & ML quality report)';
    RAISE NOTICE '================================================================';
    RAISE NOTICE '';
    RAISE NOTICE '🤖 NEW FEATURES:';
    RAISE NOTICE '  - Column: predicted_category (ML predictions)';
    RAISE NOTICE '  - View: vw_category_comparison (original vs predicted)';
    RAISE NOTICE '  - View: vw_prediction_stats (ML performance metrics)';
    RAISE NOTICE '  - View: vw_top_predicted_categories (distribution analysis)';
    RAISE NOTICE '  - Function: get_prediction_quality_report() (quality metrics)';
    RAISE NOTICE '================================================================';
END $$;