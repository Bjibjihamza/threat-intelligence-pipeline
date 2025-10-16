\set ON_ERROR_STOP on

BEGIN;

-- ============================================================================
-- SCHEMA & SEARCH PATH
-- ============================================================================
CREATE SCHEMA IF NOT EXISTS gold;
SET search_path TO gold, public;

COMMENT ON SCHEMA gold IS 'Gold Layer: Business-ready analytical tables, KPIs, and dashboards for CVE data.';

-- ============================================================================
-- 1) MASTER TABLE: gold_cve_summary
--    (Enrichi au niveau CVE, correspond au DF "gold_cve_summary")
-- ============================================================================
DROP TABLE IF EXISTS gold.gold_cve_summary CASCADE;
CREATE TABLE gold.gold_cve_summary (
  cve_id                    varchar(20) PRIMARY KEY,
  title                     text NOT NULL,
  description               text,
  category                  varchar(50),

  published_date            timestamptz NOT NULL,
  last_modified             timestamptz NOT NULL,
  cve_year                  integer NOT NULL,

  remotely_exploit          boolean,
  source_identifier         text,

  cvss_version              varchar(10),
  cvss_score                numeric(4,2),
  cvss_severity             varchar(12),
  cvss_exploitability_score numeric(5,2),
  cvss_impact_score         numeric(5,2),

  affected_products_count   integer,
  cvss_sources_count        integer,

  risk_score                numeric(6,2),
  is_critical               boolean,

  created_at                timestamptz NOT NULL DEFAULT now(),
  updated_at                timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE  gold.gold_cve_summary IS 'CVE enrichi (Gold) pour la BI';
COMMENT ON COLUMN gold.gold_cve_summary.affected_products_count IS 'Nb de produits affectés (bridge)';
COMMENT ON COLUMN gold.gold_cve_summary.cvss_sources_count IS 'Nb de sources CVSS distinctes pour le CVE';

-- trigger "updated_at"
CREATE OR REPLACE FUNCTION gold.update_modified_timestamp()
RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS trg_gold_cve_summary_touch ON gold.gold_cve_summary;
CREATE TRIGGER trg_gold_cve_summary_touch
BEFORE UPDATE ON gold.gold_cve_summary
FOR EACH ROW
EXECUTE FUNCTION gold.update_modified_timestamp();

-- Indexes principaux
CREATE INDEX IF NOT EXISTS idx_gold_cve_year        ON gold.gold_cve_summary(cve_year);
CREATE INDEX IF NOT EXISTS idx_gold_cve_severity    ON gold.gold_cve_summary(cvss_severity);
CREATE INDEX IF NOT EXISTS idx_gold_cve_risk_score  ON gold.gold_cve_summary(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_gold_cve_critical    ON gold.gold_cve_summary(is_critical);
CREATE INDEX IF NOT EXISTS idx_gold_cve_pubdate     ON gold.gold_cve_summary(published_date);

-- ============================================================================
-- 2) TENDANCES: gold_vulnerability_trends
--    (Agrégations mensuelles, correspond au DF "gold_vulnerability_trends")
-- ============================================================================
DROP TABLE IF EXISTS gold.gold_vulnerability_trends CASCADE;
CREATE TABLE gold.gold_vulnerability_trends (
  period                     varchar(7)  NOT NULL,  -- 'YYYY-MM'
  total_cves                 integer,
  avg_cvss_score             numeric(4,2),
  median_cvss_score          numeric(4,2),
  max_cvss_score             numeric(4,2),
  remote_exploitable_count   integer,
  dominant_category          varchar(50),
  period_type                varchar(16) NOT NULL DEFAULT 'monthly',
  year                       integer
);

COMMENT ON TABLE gold.gold_vulnerability_trends IS 'Agrégations temporelles (mensuelles) des CVE';

CREATE INDEX IF NOT EXISTS idx_gold_trends_period ON gold.gold_vulnerability_trends(period);
CREATE INDEX IF NOT EXISTS idx_gold_trends_year   ON gold.gold_vulnerability_trends(year);

-- ============================================================================
-- 3) PROFIL RISQUE PRODUIT: gold_product_risk_profile
--    (Par produit, correspond au DF "gold_product_risk_profile")
-- ============================================================================
DROP TABLE IF EXISTS gold.gold_product_risk_profile CASCADE;
CREATE TABLE gold.gold_product_risk_profile (
  product_id                  integer PRIMARY KEY,
  vendor                      text,
  product_name                text,

  total_vulnerabilities       integer,
  avg_cvss_score              numeric(4,2),
  median_cvss_score           numeric(4,2),
  max_cvss_score              numeric(4,2),
  min_cvss_score              numeric(4,2),
  avg_exploitability          numeric(5,2),
  avg_impact                  numeric(5,2),
  remote_exploitable_count    integer,

  first_vulnerability_date    timestamptz,
  last_vulnerability_date     timestamptz,

  product_lifespan_days       numeric(12,2),
  vulnerability_density       numeric(12,2),
  critical_vulnerability_ratio numeric(6,3),

  product_risk_score          numeric(6,2),
  risk_category               varchar(10)
);

COMMENT ON TABLE gold.gold_product_risk_profile IS 'KPIs de risque par produit';

CREATE INDEX IF NOT EXISTS idx_gold_product_vendor      ON gold.gold_product_risk_profile(vendor);
CREATE INDEX IF NOT EXISTS idx_gold_product_risk_score  ON gold.gold_product_risk_profile(product_risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_gold_product_risk_cat    ON gold.gold_product_risk_profile(risk_category);

-- ============================================================================
-- 4) COMPARAISON DE VERSIONS CVSS: gold_cvss_version_comparison
--    (Pivot des scores par version, correspond au DF "gold_cvss_version_comparison")
-- ============================================================================
DROP TABLE IF EXISTS gold.gold_cvss_version_comparison CASCADE;
CREATE TABLE gold.gold_cvss_version_comparison (
  cve_id              varchar(20) PRIMARY KEY,

  score_cvss_2_0      numeric(4,2),
  score_cvss_3_0      numeric(4,2),
  score_cvss_3_1      numeric(4,2),
  score_cvss_4_0      numeric(4,2),

  score_variance      numeric(6,2),
  score_range         numeric(6,2),
  versions_count      integer,

  source_diversity    integer,
  dominant_severity   varchar(12),

  is_consistent       boolean
);

COMMENT ON TABLE gold.gold_cvss_version_comparison IS 'Scores CVSS par version + métriques de variance/consistance';

-- ============================================================================
-- 5) METRICS FOURNISSEUR: gold_vendor_security_metrics
--    (Par vendor, correspond au DF "gold_vendor_security_metrics")
-- ============================================================================
DROP TABLE IF EXISTS gold.gold_vendor_security_metrics CASCADE;
CREATE TABLE gold.gold_vendor_security_metrics (
  vendor                        text PRIMARY KEY,
  total_products                integer,
  total_vulnerabilities         integer,
  avg_cvss_score                numeric(4,2),
  max_cvss_score                numeric(4,2),
  avg_exploitability            numeric(5,2),
  remote_exploitable_count      integer,
  vulnerability_span_years      integer,
  vulnerabilities_per_product   numeric(10,2),
  vendor_risk_score             numeric(6,2),
  risk_rank                     integer
);

COMMENT ON TABLE gold.gold_vendor_security_metrics IS 'KPIs de sécurité agrégés par fournisseur';

CREATE INDEX IF NOT EXISTS idx_gold_vendor_name ON gold.gold_vendor_security_metrics(vendor);
CREATE INDEX IF NOT EXISTS idx_gold_vendor_risk ON gold.gold_vendor_security_metrics(vendor_risk_score DESC);

-- ============================================================================
-- 6) VUES MATERIALISEES UTILES (avec index uniques pour CONCURRENTLY)
-- ============================================================================
-- Top critical CVEs (extrait de gold_cve_summary)
DROP MATERIALIZED VIEW IF EXISTS gold.mv_top_critical_cves;
CREATE MATERIALIZED VIEW gold.mv_top_critical_cves AS
SELECT
  cve_id, title, cvss_score, cvss_severity, published_date
FROM gold.gold_cve_summary
WHERE cvss_severity = 'CRITICAL'
ORDER BY cvss_score DESC NULLS LAST, published_date DESC
LIMIT 500;

-- Unique index requis pour REFRESH CONCURRENTLY
CREATE UNIQUE INDEX IF NOT EXISTS ux_mv_top_critical_cves
  ON gold.mv_top_critical_cves (cve_id);

-- Statistiques annuelles
DROP MATERIALIZED VIEW IF EXISTS gold.mv_yearly_statistics;
CREATE MATERIALIZED VIEW gold.mv_yearly_statistics AS
SELECT
  cve_year,
  COUNT(*)                                                        AS total_cves,
  SUM( (cvss_severity = 'CRITICAL')::int )                        AS critical_cves,
  AVG(cvss_score)                                                 AS avg_score
FROM gold.gold_cve_summary
GROUP BY cve_year;

CREATE UNIQUE INDEX IF NOT EXISTS ux_mv_yearly_statistics
  ON gold.mv_yearly_statistics (cve_year);

-- ============================================================================
-- 7) HELPER: refresh des dashboards
-- ============================================================================
CREATE OR REPLACE FUNCTION gold.refresh_dashboards()
RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
  REFRESH MATERIALIZED VIEW CONCURRENTLY gold.mv_top_critical_cves;
  REFRESH MATERIALIZED VIEW CONCURRENTLY gold.mv_yearly_statistics;
END
$$;

COMMIT;

-- ============================================================================
-- 8) QUICK CHECKS
-- ============================================================================
-- \d+ gold.gold_cve_summary
-- \d+ gold.gold_vulnerability_trends
-- \d+ gold.gold_product_risk_profile
-- \d+ gold.gold_cvss_version_comparison
-- \d+ gold.gold_vendor_security_metrics
-- SELECT gold.refresh_dashboards();
