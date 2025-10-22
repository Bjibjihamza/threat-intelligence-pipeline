-- ================================================================
-- SILVER LAYER SCHEMA (Cleaned Data, 1 seule colonne de classe)
-- Table: silver.cve_cleaned
-- Colonnes supprimées: title, description, url, predicted_category,
--                      category, cwe_family
-- Nouvelle colonne: vulnarbilit (xss, injection, ...), dérivée du CWE
-- ================================================================

CREATE SCHEMA IF NOT EXISTS silver;
SET search_path TO silver, public;

DROP TABLE IF EXISTS silver.cve_cleaned CASCADE;

CREATE TABLE silver.cve_cleaned (
    -- Clé
    cve_id              VARCHAR(20) PRIMARY KEY,

    -- Classe normalisée (xss, injection, memory_corruption, ...)
    vulnarbilit         VARCHAR(50) DEFAULT 'uncategorized',

    -- Dates
    published_date      TIMESTAMP,
    last_modified       TIMESTAMP,
    loaded_at           TIMESTAMP,

    -- Métadonnées
    remotely_exploit    BOOLEAN,
    source_identifier   TEXT,

    -- Données structurées (TEXT à l’insert; convertible en JSONB via fonction)
    affected_products   TEXT,
    cvss_scores         TEXT,

    -- Audit
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Optionnel : convertir TEXT → JSONB après insertion
CREATE OR REPLACE FUNCTION silver.convert_json_columns()
RETURNS void AS $$
BEGIN
    ALTER TABLE silver.cve_cleaned 
        ALTER COLUMN affected_products TYPE JSONB USING
            CASE 
                WHEN affected_products IS NULL OR affected_products = '' THEN NULL
                ELSE affected_products::jsonb 
            END;

    ALTER TABLE silver.cve_cleaned 
        ALTER COLUMN cvss_scores TYPE JSONB USING
            CASE 
                WHEN cvss_scores IS NULL OR cvss_scores = '' THEN NULL
                ELSE cvss_scores::jsonb 
            END;

    RAISE NOTICE 'JSON columns converted to JSONB';
END;
$$ LANGUAGE plpgsql;

-- Index
CREATE INDEX idx_silver_cve_published   ON silver.cve_cleaned(published_date);
CREATE INDEX idx_silver_cve_modified    ON silver.cve_cleaned(last_modified);
CREATE INDEX idx_silver_cve_class       ON silver.cve_cleaned(vulnarbilit);
CREATE INDEX idx_silver_cve_source      ON silver.cve_cleaned(source_identifier);

-- (À activer après conversion TEXT→JSONB)
-- CREATE INDEX idx_silver_cve_products_gin ON silver.cve_cleaned USING GIN(affected_products);
-- CREATE INDEX idx_silver_cve_scores_gin   ON silver.cve_cleaned USING GIN(cvss_scores);

-- Helpers robustes TEXT/JSONB
CREATE OR REPLACE FUNCTION silver._json_array_len(x TEXT)
RETURNS INTEGER AS $$
BEGIN
    IF x IS NULL OR x = '' THEN RETURN 0; END IF;
    RETURN jsonb_array_length(x::jsonb);
EXCEPTION WHEN others THEN
    RETURN 0;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE OR REPLACE FUNCTION silver._jsonb_array_len(x JSONB)
RETURNS INTEGER AS $$
BEGIN
    IF x IS NULL THEN RETURN 0; END IF;
    RETURN jsonb_array_length(x);
EXCEPTION WHEN others THEN
    RETURN 0;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Vues
CREATE OR REPLACE VIEW silver.vw_cve_stats_by_year AS
SELECT 
    EXTRACT(YEAR FROM published_date) AS year,
    COUNT(*) AS total_cves,
    COUNT(*) FILTER (WHERE remotely_exploit IS TRUE) AS remotely_exploitable,
    COUNT(*) FILTER (
        WHERE (
            (pg_typeof(cvss_scores)::text = 'jsonb' AND silver._jsonb_array_len(cvss_scores::jsonb) > 0) OR
            (pg_typeof(cvss_scores)::text <> 'jsonb' AND silver._json_array_len(cvss_scores) > 0)
        )
    ) AS with_cvss,
    COUNT(*) FILTER (
        WHERE (
            (pg_typeof(affected_products)::text = 'jsonb' AND silver._jsonb_array_len(affected_products::jsonb) > 0) OR
            (pg_typeof(affected_products)::text <> 'jsonb' AND silver._json_array_len(affected_products) > 0)
        )
    ) AS with_products
FROM silver.cve_cleaned
GROUP BY EXTRACT(YEAR FROM published_date)
ORDER BY year DESC;

CREATE OR REPLACE VIEW silver.vw_cve_missing_cvss AS
SELECT cve_id, published_date, vulnarbilit, source_identifier
FROM silver.cve_cleaned
WHERE
    (
        (pg_typeof(cvss_scores)::text = 'jsonb' AND silver._jsonb_array_len(cvss_scores::jsonb) = 0) OR
        (pg_typeof(cvss_scores)::text <> 'jsonb' AND silver._json_array_len(cvss_scores) = 0)
    );

CREATE OR REPLACE VIEW silver.vw_cve_missing_products AS
SELECT cve_id, published_date, vulnarbilit, source_identifier
FROM silver.cve_cleaned
WHERE
    (
        (pg_typeof(affected_products)::text = 'jsonb' AND silver._jsonb_array_len(affected_products::jsonb) = 0) OR
        (pg_typeof(affected_products)::text <> 'jsonb' AND silver._json_array_len(affected_products) = 0)
    );

CREATE OR REPLACE VIEW silver.vw_cve_stats_by_class AS
SELECT 
    vulnarbilit,
    COUNT(*) AS total_cves,
    MIN(published_date) AS first_cve_date,
    MAX(published_date) AS last_cve_date,
    COUNT(*) FILTER (WHERE remotely_exploit IS TRUE) AS remotely_exploitable
FROM silver.cve_cleaned
GROUP BY vulnarbilit
ORDER BY total_cves DESC;

-- Trigger updated_at
CREATE OR REPLACE FUNCTION silver.update_modified_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_cve_cleaned_modtime
    BEFORE UPDATE ON silver.cve_cleaned
    FOR EACH ROW
    EXECUTE FUNCTION silver.update_modified_column();

-- Commentaires
COMMENT ON SCHEMA silver IS 'Silver Layer: données nettoyées issues de Bronze (1 seule colonne de classe: vulnarbilit).';
COMMENT ON TABLE  silver.cve_cleaned IS 'CVEs nettoyées (dates typées, JSON prêts à conversion), prêtes pour Gold.';
COMMENT ON COLUMN silver.cve_cleaned.vulnarbilit IS 'Classe normalisée (xss, injection, memory_corruption, ...).';

ANALYZE silver.cve_cleaned;

DO $$
BEGIN
    RAISE NOTICE '===============================================================';
    RAISE NOTICE 'SILVER LAYER (clean, 1 colonne "vulnarbilit") CREATED';
    RAISE NOTICE 'Tables: silver.cve_cleaned';
    RAISE NOTICE 'Vues  : vw_cve_stats_by_year, vw_cve_missing_cvss,';
    RAISE NOTICE '        vw_cve_missing_products, vw_cve_stats_by_class';
    RAISE NOTICE '===============================================================';
END $$;
