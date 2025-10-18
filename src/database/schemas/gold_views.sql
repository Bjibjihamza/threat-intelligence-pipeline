-- ================================================================
-- GOLD LAYER - BI VIEWS FOR POWER BI VISUALIZATION (FIXED)
-- ================================================================
SET search_path TO gold, public;

-- ---------- Optional cleanup to avoid conflicts ----------
DROP VIEW IF EXISTS fact_cve_timeline CASCADE;
DROP VIEW IF EXISTS agg_cve_age_analysis CASCADE;
DROP VIEW IF EXISTS agg_exploitability_analysis CASCADE;
DROP VIEW IF EXISTS agg_vendor_product_matrix CASCADE;
DROP VIEW IF EXISTS agg_weekly_cve_heatmap CASCADE;
DROP VIEW IF EXISTS dashboard_executive_summary CASCADE;
DROP VIEW IF EXISTS agg_cia_impact_analysis CASCADE;
DROP VIEW IF EXISTS agg_top_attack_vectors CASCADE;
DROP VIEW IF EXISTS agg_cvss_version_comparison CASCADE;
DROP VIEW IF EXISTS agg_monthly_cve_trends CASCADE;
DROP VIEW IF EXISTS agg_product_vulnerability CASCADE;
DROP VIEW IF EXISTS agg_vendor_risk_score CASCADE;
DROP VIEW IF EXISTS agg_cve_by_category CASCADE;
DROP VIEW IF EXISTS agg_cve_by_year CASCADE;
DROP VIEW IF EXISTS fact_cve_products CASCADE;
DROP VIEW IF EXISTS fact_cve_complete CASCADE;

-- ================================================================
-- VUE 1: FACT_CVE_COMPLETE  (all CVSS side-by-side + "best" fields)
-- Precedence for "best": v4 -> v3 -> v2
-- ================================================================
CREATE OR REPLACE VIEW gold.fact_cve_complete AS
SELECT 
    c.cve_id,
    c.title,
    c.description,
    c.category,
    c.predicted_category,
    c.published_date,
    c.last_modified,
    c.cve_year,
    c.remotely_exploit,
    c.source_identifier,

    -- CVSS V2
    v2.cvss_v2_id,
    v2.cvss_score            AS cvss_v2_score,
    v2.cvss_severity         AS cvss_v2_severity,
    v2.cvss_vector           AS cvss_v2_vector,
    v2.cvss_v2_av,
    v2.cvss_v2_ac,
    v2.cvss_v2_au,
    v2.cvss_v2_c,
    v2.cvss_v2_i,
    v2.cvss_v2_a,
    v2.cvss_exploitability_score AS cvss_v2_exploitability,
    v2.cvss_impact_score         AS cvss_v2_impact,

    -- CVSS V3
    v3.cvss_v3_id,
    v3.cvss_version         AS cvss_v3_version,
    v3.cvss_score           AS cvss_v3_score,
    v3.cvss_severity        AS cvss_v3_severity,
    v3.cvss_vector          AS cvss_v3_vector,
    v3.cvss_v3_base_av,
    v3.cvss_v3_base_ac,
    v3.cvss_v3_base_pr,
    v3.cvss_v3_base_ui,
    v3.cvss_v3_base_s,
    v3.cvss_v3_base_c,
    v3.cvss_v3_base_i,
    v3.cvss_v3_base_a,
    v3.cvss_exploitability_score AS cvss_v3_exploitability,
    v3.cvss_impact_score         AS cvss_v3_impact,

    -- CVSS V4
    v4.cvss_v4_id,
    v4.cvss_score           AS cvss_v4_score,
    v4.cvss_severity        AS cvss_v4_severity,
    v4.cvss_vector          AS cvss_v4_vector,
    v4.cvss_v4_av,
    v4.cvss_v4_at,
    v4.cvss_v4_ac,
    v4.cvss_v4_vc,
    v4.cvss_v4_vi,
    v4.cvss_v4_va,
    v4.cvss_v4_sc,
    v4.cvss_v4_si,
    v4.cvss_v4_sa,

    -- Best-of fields (v4 -> v3 -> v2)
    COALESCE(v4.cvss_score, v3.cvss_score, v2.cvss_score)       AS best_cvss_score,
    COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity, 'UNKNOWN') AS best_cvss_severity,
    CASE
        WHEN v4.cvss_score IS NOT NULL THEN 'CVSS V4'
        WHEN v3.cvss_score IS NOT NULL THEN 'CVSS V3'
        WHEN v2.cvss_score IS NOT NULL THEN 'CVSS V2'
        ELSE 'NO CVSS'
    END AS primary_cvss_version
FROM gold.dim_cve c
LEFT JOIN gold.cvss_v2 v2 ON c.cve_id = v2.cve_id AND v2.source_id = 144
LEFT JOIN gold.cvss_v3 v3 ON c.cve_id = v3.cve_id AND v3.source_id = 144
LEFT JOIN gold.cvss_v4 v4 ON c.cve_id = v4.cve_id;

COMMENT ON VIEW gold.fact_cve_complete IS 'CVE + CVSS v2/v3/v4 side-by-side with "best" fields';

-- ================================================================
-- VUE 2: FACT_CVE_PRODUCTS  (CVE x Product with vendor & best score)
-- ================================================================
CREATE OR REPLACE VIEW gold.fact_cve_products AS
SELECT 
    b.bridge_id,
    b.cve_id,
    c.title AS cve_title,
    c.category AS cve_category,
    c.predicted_category,
    c.published_date,
    c.cve_year,
    c.remotely_exploit,

    p.product_id,
    p.product_name,
    p.total_cves AS product_total_cves,

    v.vendor_id,
    v.vendor_name,
    v.total_products AS vendor_total_products,
    v.total_cves     AS vendor_total_cves,

    -- Best score (v4 -> v3 -> v2)
    COALESCE(v4.cvss_score, v3.cvss_score, v2.cvss_score)         AS cvss_score,
    COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) AS cvss_severity,

    b.created_at AS relationship_created
FROM gold.bridge_cve_products b
JOIN gold.dim_cve     c ON b.cve_id = c.cve_id
JOIN gold.dim_products p ON b.product_id = p.product_id
JOIN gold.dim_vendor   v ON p.vendor_id = v.vendor_id
LEFT JOIN gold.cvss_v3 v3 ON c.cve_id = v3.cve_id AND v3.source_id = 144
LEFT JOIN gold.cvss_v2 v2 ON c.cve_id = v2.cve_id AND v2.source_id = 144
LEFT JOIN gold.cvss_v4 v4 ON c.cve_id = v4.cve_id;

COMMENT ON VIEW gold.fact_cve_products IS 'CVE x Product x Vendor with best CVSS';

-- ================================================================
-- VUE 3: AGG_CVE_BY_YEAR
-- ================================================================
CREATE OR REPLACE VIEW gold.agg_cve_by_year AS
SELECT 
    c.cve_year,
    COUNT(DISTINCT c.cve_id)                                                  AS total_cves,
    COUNT(DISTINCT CASE WHEN c.category IS NOT NULL AND c.category <> 'undefined' THEN c.cve_id END) AS categorized_cves,
    COUNT(DISTINCT CASE WHEN c.remotely_exploit IS TRUE THEN c.cve_id END)    AS remote_exploit_cves,

    -- CVSS V2
    COUNT(DISTINCT v2.cve_id)                         AS cves_with_v2,
    AVG(v2.cvss_score)                                AS avg_cvss_v2_score,
    COUNT(*) FILTER (WHERE v2.cvss_severity = 'HIGH')     AS high_severity_v2,
    COUNT(*) FILTER (WHERE v2.cvss_severity = 'CRITICAL') AS critical_severity_v2,

    -- CVSS V3
    COUNT(DISTINCT v3.cve_id)                         AS cves_with_v3,
    AVG(v3.cvss_score)                                AS avg_cvss_v3_score,
    COUNT(*) FILTER (WHERE v3.cvss_severity = 'HIGH')     AS high_severity_v3,
    COUNT(*) FILTER (WHERE v3.cvss_severity = 'CRITICAL') AS critical_severity_v3,

    -- CVSS V4
    COUNT(DISTINCT v4.cve_id)                         AS cves_with_v4,
    AVG(v4.cvss_score)                                AS avg_cvss_v4_score,

    MIN(c.published_date)                             AS first_cve_date,
    MAX(c.published_date)                             AS last_cve_date
FROM gold.dim_cve c
LEFT JOIN gold.cvss_v2 v2 ON c.cve_id = v2.cve_id AND v2.source_id = 144
LEFT JOIN gold.cvss_v3 v3 ON c.cve_id = v3.cve_id AND v3.source_id = 144
LEFT JOIN gold.cvss_v4 v4 ON c.cve_id = v4.cve_id
GROUP BY c.cve_year
ORDER BY c.cve_year DESC;

COMMENT ON VIEW gold.agg_cve_by_year IS 'CVE yearly stats with CVSS metrics';

-- ================================================================
-- VUE 4: AGG_CVE_BY_CATEGORY
-- (grouped by effective category: predicted first, else labeled)
-- ================================================================
CREATE OR REPLACE VIEW gold.agg_cve_by_category AS
WITH base AS (
  SELECT
    c.cve_id,
    COALESCE(c.predicted_category, NULLIF(c.category, 'undefined'), 'uncategorized') AS category_name
  FROM gold.dim_cve c
)
SELECT 
    b.category_name,
    COUNT(DISTINCT b.cve_id) AS total_cves,
    COUNT(DISTINCT c.cve_id) FILTER (WHERE c.remotely_exploit IS TRUE) AS remote_exploit_count,

    -- severity distribution using best of v4->v3->v2
    COUNT(*) FILTER (WHERE COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) = 'LOW')     AS low_severity,
    COUNT(*) FILTER (WHERE COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) = 'MEDIUM')  AS medium_severity,
    COUNT(*) FILTER (WHERE COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) = 'HIGH')    AS high_severity,
    COUNT(*) FILTER (WHERE COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) = 'CRITICAL') AS critical_severity,

    AVG(COALESCE(v4.cvss_score, v3.cvss_score, v2.cvss_score)) AS avg_cvss_score,
    MAX(COALESCE(v4.cvss_score, v3.cvss_score, v2.cvss_score)) AS max_cvss_score,
    MIN(COALESCE(v4.cvss_score, v3.cvss_score, v2.cvss_score)) AS min_cvss_score,

    MIN(c.published_date) AS first_cve_date,
    MAX(c.published_date) AS last_cve_date,
    MAX(c.cve_year)       AS latest_year
FROM base b
JOIN gold.dim_cve c ON c.cve_id = b.cve_id
LEFT JOIN gold.cvss_v3 v3 ON c.cve_id = v3.cve_id AND v3.source_id = 144
LEFT JOIN gold.cvss_v2 v2 ON c.cve_id = v2.cve_id AND v2.source_id = 144
LEFT JOIN gold.cvss_v4 v4 ON c.cve_id = v4.cve_id
GROUP BY b.category_name
ORDER BY total_cves DESC;

COMMENT ON VIEW gold.agg_cve_by_category IS 'CVE by effective category (predicted>labeled) with severity mix';

-- ================================================================
-- VUE 5: AGG_VENDOR_RISK_SCORE
-- ================================================================
CREATE OR REPLACE VIEW gold.agg_vendor_risk_score AS
SELECT 
    v.vendor_id,
    v.vendor_name,
    v.total_products,
    v.total_cves,

    COUNT(DISTINCT c.cve_id)      AS actual_cve_count,
    COUNT(DISTINCT p.product_id)  AS affected_products,

    COUNT(*) FILTER (WHERE COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) = 'CRITICAL') AS critical_cves,
    COUNT(*) FILTER (WHERE COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) = 'HIGH')     AS high_cves,
    COUNT(*) FILTER (WHERE COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) = 'MEDIUM')   AS medium_cves,
    COUNT(*) FILTER (WHERE COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) = 'LOW')      AS low_cves,

    AVG(COALESCE(v4.cvss_score, v3.cvss_score, v2.cvss_score)) AS avg_cvss_score,
    MAX(COALESCE(v4.cvss_score, v3.cvss_score, v2.cvss_score)) AS max_cvss_score,

    -- Simple weighted risk proxy
    ROUND((
        COUNT(*) FILTER (WHERE COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) = 'CRITICAL') * 10 +
        COUNT(*) FILTER (WHERE COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) = 'HIGH') * 5 +
        COUNT(*) FILTER (WHERE COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) = 'MEDIUM') * 2 +
        COUNT(*) FILTER (WHERE COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) = 'LOW') * 1
    )::numeric / NULLIF(COUNT(DISTINCT c.cve_id),0), 2) AS risk_score,

    v.first_cve_date,
    v.last_cve_date,
    (v.last_cve_date::date - v.first_cve_date::date) AS days_with_cves
FROM gold.dim_vendor v
LEFT JOIN gold.dim_products p ON v.vendor_id = p.vendor_id
LEFT JOIN gold.bridge_cve_products b ON p.product_id = b.product_id
LEFT JOIN gold.dim_cve c ON b.cve_id = c.cve_id
LEFT JOIN gold.cvss_v3 v3 ON c.cve_id = v3.cve_id AND v3.source_id = 144
LEFT JOIN gold.cvss_v2 v2 ON c.cve_id = v2.cve_id AND v2.source_id = 144
LEFT JOIN gold.cvss_v4 v4 ON c.cve_id = v4.cve_id
GROUP BY v.vendor_id, v.vendor_name, v.total_products, v.total_cves, v.first_cve_date, v.last_cve_date
HAVING COUNT(DISTINCT c.cve_id) > 0
ORDER BY risk_score DESC NULLS LAST;

COMMENT ON VIEW gold.agg_vendor_risk_score IS 'Vendor risk proxy with severity mix & time span';

-- ================================================================
-- VUE 6: AGG_PRODUCT_VULNERABILITY
-- ================================================================
CREATE OR REPLACE VIEW gold.agg_product_vulnerability AS
SELECT 
    p.product_id,
    p.product_name,
    v.vendor_id,
    v.vendor_name,
    p.total_cves,

    COUNT(*) FILTER (WHERE COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) = 'CRITICAL') AS critical_count,
    COUNT(*) FILTER (WHERE COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) = 'HIGH')     AS high_count,
    COUNT(*) FILTER (WHERE COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) = 'MEDIUM')   AS medium_count,
    COUNT(*) FILTER (WHERE COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) = 'LOW')      AS low_count,

    AVG(COALESCE(v4.cvss_score, v3.cvss_score, v2.cvss_score)) AS avg_cvss_score,
    MAX(COALESCE(v4.cvss_score, v3.cvss_score, v2.cvss_score)) AS max_cvss_score,
    MIN(COALESCE(v4.cvss_score, v3.cvss_score, v2.cvss_score)) AS min_cvss_score,

    COUNT(*) FILTER (WHERE c.remotely_exploit IS TRUE) AS remote_exploit_count,

    p.first_cve_date,
    p.last_cve_date,
    EXTRACT(YEAR FROM p.last_cve_date) AS last_cve_year,

    CASE 
        WHEN p.last_cve_date >= CURRENT_DATE - INTERVAL '1 year' THEN 'Active'
        WHEN p.last_cve_date >= CURRENT_DATE - INTERVAL '3 years' THEN 'Recent'
        ELSE 'Old'
    END AS activity_status
FROM gold.dim_products p
JOIN gold.dim_vendor v ON p.vendor_id = v.vendor_id
LEFT JOIN gold.bridge_cve_products b ON p.product_id = b.product_id
LEFT JOIN gold.dim_cve c ON b.cve_id = c.cve_id
LEFT JOIN gold.cvss_v3 v3 ON c.cve_id = v3.cve_id AND v3.source_id = 144
LEFT JOIN gold.cvss_v2 v2 ON c.cve_id = v2.cve_id AND v2.source_id = 144
LEFT JOIN gold.cvss_v4 v4 ON c.cve_id = v4.cve_id
GROUP BY p.product_id, p.product_name, v.vendor_id, v.vendor_name, p.total_cves, p.first_cve_date, p.last_cve_date
HAVING p.total_cves > 0
ORDER BY p.total_cves DESC, critical_count DESC;

COMMENT ON VIEW gold.agg_product_vulnerability IS 'Product vulnerability profile with severity & recency';

-- ================================================================
-- VUE 7: AGG_MONTHLY_CVE_TRENDS
-- ================================================================
CREATE OR REPLACE VIEW gold.agg_monthly_cve_trends AS
SELECT 
    DATE_TRUNC('month', c.published_date)::date AS month,
    EXTRACT(YEAR FROM c.published_date)  AS year,
    EXTRACT(MONTH FROM c.published_date) AS month_num,

    COUNT(DISTINCT c.cve_id) AS total_cves,
    COUNT(DISTINCT c.cve_id) FILTER (WHERE c.remotely_exploit IS TRUE) AS remote_cves,

    COUNT(*) FILTER (WHERE COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) = 'CRITICAL') AS critical_count,
    COUNT(*) FILTER (WHERE COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) = 'HIGH')     AS high_count,
    COUNT(*) FILTER (WHERE COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) = 'MEDIUM')   AS medium_count,
    COUNT(*) FILTER (WHERE COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) = 'LOW')      AS low_count,

    AVG(COALESCE(v4.cvss_score, v3.cvss_score, v2.cvss_score)) AS avg_cvss_score,

    COUNT(DISTINCT v.vendor_id)  AS affected_vendors_count,
    COUNT(DISTINCT p.product_id) AS affected_products_count
FROM gold.dim_cve c
LEFT JOIN gold.cvss_v3 v3 ON c.cve_id = v3.cve_id AND v3.source_id = 144
LEFT JOIN gold.cvss_v2 v2 ON c.cve_id = v2.cve_id AND v2.source_id = 144
LEFT JOIN gold.cvss_v4 v4 ON c.cve_id = v4.cve_id
LEFT JOIN gold.bridge_cve_products b ON c.cve_id = b.cve_id
LEFT JOIN gold.dim_products p ON b.product_id = p.product_id
LEFT JOIN gold.dim_vendor v ON p.vendor_id = v.vendor_id
WHERE c.published_date >= '2010-01-01'
GROUP BY DATE_TRUNC('month', c.published_date), EXTRACT(YEAR FROM c.published_date), EXTRACT(MONTH FROM c.published_date)
ORDER BY month DESC;

COMMENT ON VIEW gold.agg_monthly_cve_trends IS 'Monthly CVE trends with severity and coverage';

-- ================================================================
-- VUE 8: AGG_CVSS_VERSION_COMPARISON
-- ================================================================
CREATE OR REPLACE VIEW gold.agg_cvss_version_comparison AS
SELECT 
    c.cve_id,
    c.title,
    c.published_date,
    c.cve_year,

    v2.cvss_score    AS cvss_v2_score,
    v2.cvss_severity AS cvss_v2_severity,

    v3.cvss_score    AS cvss_v3_score,
    v3.cvss_severity AS cvss_v3_severity,
    v3.cvss_version  AS cvss_v3_version,

    v4.cvss_score    AS cvss_v4_score,
    v4.cvss_severity AS cvss_v4_severity,

    CASE 
        WHEN v2.cvss_score IS NOT NULL AND v3.cvss_score IS NOT NULL 
        THEN ROUND((v3.cvss_score - v2.cvss_score)::numeric, 2)
        ELSE NULL
    END AS score_difference_v3_vs_v2,

    CASE 
        WHEN v2.cvss_severity IS NOT NULL AND v3.cvss_severity IS NOT NULL 
             AND v2.cvss_severity <> v3.cvss_severity THEN 'Changed'
        WHEN v2.cvss_severity IS NOT NULL AND v3.cvss_severity IS NOT NULL 
             AND v2.cvss_severity  = v3.cvss_severity THEN 'Same'
        ELSE 'N/A'
    END AS severity_change,

    (v2.cvss_score IS NOT NULL)::int AS has_v2,
    (v3.cvss_score IS NOT NULL)::int AS has_v3,
    (v4.cvss_score IS NOT NULL)::int AS has_v4
FROM gold.dim_cve c
LEFT JOIN gold.cvss_v2 v2 ON c.cve_id = v2.cve_id AND v2.source_id = 144
LEFT JOIN gold.cvss_v3 v3 ON c.cve_id = v3.cve_id AND v3.source_id = 144
LEFT JOIN gold.cvss_v4 v4 ON c.cve_id = v4.cve_id
WHERE v2.cvss_score IS NOT NULL OR v3.cvss_score IS NOT NULL OR v4.cvss_score IS NOT NULL
ORDER BY c.published_date DESC;

COMMENT ON VIEW gold.agg_cvss_version_comparison IS 'Compare V2 vs V3 vs V4 when available';

-- ================================================================
-- VUE 9: AGG_TOP_ATTACK_VECTORS
-- ================================================================
CREATE OR REPLACE VIEW gold.agg_top_attack_vectors AS
SELECT 
    COALESCE(v3.cvss_v3_base_av, v2.cvss_v2_av) AS attack_vector,
    CASE 
        WHEN COALESCE(v3.cvss_v3_base_av, v2.cvss_v2_av) = 'N' THEN 'Network'
        WHEN COALESCE(v3.cvss_v3_base_av, v2.cvss_v2_av) = 'A' THEN 'Adjacent Network'
        WHEN COALESCE(v3.cvss_v3_base_av, v2.cvss_v2_av) = 'L' THEN 'Local'
        WHEN COALESCE(v3.cvss_v3_base_av, v2.cvss_v2_av) = 'P' THEN 'Physical'
        ELSE 'Unknown'
    END AS attack_vector_name,

    COUNT(DISTINCT c.cve_id) AS total_cves,

    COUNT(*) FILTER (WHERE COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) = 'CRITICAL') AS critical_count,
    COUNT(*) FILTER (WHERE COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) = 'HIGH')     AS high_count,
    COUNT(*) FILTER (WHERE COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) = 'MEDIUM')   AS medium_count,
    COUNT(*) FILTER (WHERE COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) = 'LOW')      AS low_count,

    AVG(COALESCE(v4.cvss_score, v3.cvss_score, v2.cvss_score)) AS avg_cvss_score,
    MAX(COALESCE(v4.cvss_score, v3.cvss_score, v2.cvss_score)) AS max_cvss_score,

    COUNT(*) FILTER (WHERE c.cve_year >= EXTRACT(YEAR FROM CURRENT_DATE) - 1) AS recent_cves_last_year
FROM gold.dim_cve c
LEFT JOIN gold.cvss_v3 v3 ON c.cve_id = v3.cve_id AND v3.source_id = 144
LEFT JOIN gold.cvss_v2 v2 ON c.cve_id = v2.cve_id AND v2.source_id = 144
LEFT JOIN gold.cvss_v4 v4 ON c.cve_id = v4.cve_id
WHERE COALESCE(v3.cvss_v3_base_av, v2.cvss_v2_av) IS NOT NULL
GROUP BY COALESCE(v3.cvss_v3_base_av, v2.cvss_v2_av)
ORDER BY total_cves DESC;

COMMENT ON VIEW gold.agg_top_attack_vectors IS 'Attack vector distribution with severity mix';

-- ================================================================
-- VUE 10: AGG_CIA_IMPACT_ANALYSIS
-- ================================================================
CREATE OR REPLACE VIEW gold.agg_cia_impact_analysis AS
SELECT 
    COALESCE(v3.cvss_v3_base_c, v2.cvss_v2_c) AS confidentiality_impact,
    CASE 
        WHEN COALESCE(v3.cvss_v3_base_c, v2.cvss_v2_c) = 'H' THEN 'High'
        WHEN COALESCE(v3.cvss_v3_base_c, v2.cvss_v2_c) = 'L' THEN 'Low'
        WHEN COALESCE(v3.cvss_v3_base_c, v2.cvss_v2_c) IN ('N','P') THEN 'None/Partial'
        ELSE 'Unknown'
    END AS confidentiality_level,

    COALESCE(v3.cvss_v3_base_i, v2.cvss_v2_i) AS integrity_impact,
    CASE 
        WHEN COALESCE(v3.cvss_v3_base_i, v2.cvss_v2_i) = 'H' THEN 'High'
        WHEN COALESCE(v3.cvss_v3_base_i, v2.cvss_v2_i) = 'L' THEN 'Low'
        WHEN COALESCE(v3.cvss_v3_base_i, v2.cvss_v2_i) IN ('N','P') THEN 'None/Partial'
        ELSE 'Unknown'
    END AS integrity_level,

    COALESCE(v3.cvss_v3_base_a, v2.cvss_v2_a) AS availability_impact,
    CASE 
        WHEN COALESCE(v3.cvss_v3_base_a, v2.cvss_v2_a) = 'H' THEN 'High'
        WHEN COALESCE(v3.cvss_v3_base_a, v2.cvss_v2_a) = 'L' THEN 'Low'
        WHEN COALESCE(v3.cvss_v3_base_a, v2.cvss_v2_a) IN ('N','P') THEN 'None/Partial'
        ELSE 'Unknown'
    END AS availability_level,

    COUNT(DISTINCT c.cve_id) AS total_cves,
    AVG(COALESCE(v4.cvss_score, v3.cvss_score, v2.cvss_score)) AS avg_cvss_score,

    CASE 
        WHEN COALESCE(v3.cvss_v3_base_c, v2.cvss_v2_c) = 'H'
         AND COALESCE(v3.cvss_v3_base_i, v2.cvss_v2_i) = 'H'
         AND COALESCE(v3.cvss_v3_base_a, v2.cvss_v2_a) = 'H'
        THEN 'Full CIA Impact'
        ELSE 'Partial Impact'
    END AS impact_type
FROM gold.dim_cve c
LEFT JOIN gold.cvss_v3 v3 ON c.cve_id = v3.cve_id AND v3.source_id = 144
LEFT JOIN gold.cvss_v2 v2 ON c.cve_id = v2.cve_id AND v2.source_id = 144
LEFT JOIN gold.cvss_v4 v4 ON c.cve_id = v4.cve_id
WHERE COALESCE(v3.cvss_v3_base_c, v2.cvss_v2_c) IS NOT NULL
   OR COALESCE(v3.cvss_v3_base_i, v2.cvss_v2_i) IS NOT NULL
   OR COALESCE(v3.cvss_v3_base_a, v2.cvss_v2_a) IS NOT NULL
GROUP BY 
    COALESCE(v3.cvss_v3_base_c, v2.cvss_v2_c),
    COALESCE(v3.cvss_v3_base_i, v2.cvss_v2_i),
    COALESCE(v3.cvss_v3_base_a, v2.cvss_v2_a)
ORDER BY total_cves DESC;

COMMENT ON VIEW gold.agg_cia_impact_analysis IS 'CIA impact distribution with severity & impact type';

-- ================================================================
-- VUE 11: DASHBOARD_EXECUTIVE_SUMMARY
-- ================================================================
CREATE OR REPLACE VIEW gold.dashboard_executive_summary AS
SELECT 
    (SELECT COUNT(*) FROM gold.dim_cve)        AS total_cves,
    (SELECT COUNT(*) FROM gold.dim_vendor)     AS total_vendors,
    (SELECT COUNT(*) FROM gold.dim_products)   AS total_products,

    (SELECT COUNT(*) FROM gold.dim_cve WHERE cve_year = EXTRACT(YEAR FROM CURRENT_DATE))     AS cves_current_year,
    (SELECT COUNT(*) FROM gold.dim_cve WHERE cve_year = EXTRACT(YEAR FROM CURRENT_DATE) - 1) AS cves_last_year,

    (SELECT COUNT(*) FROM gold.cvss_v3 WHERE cvss_severity = 'CRITICAL') AS total_critical_v3,
    (SELECT COUNT(*) FROM gold.cvss_v3 WHERE cvss_severity = 'HIGH')     AS total_high_v3,
    (SELECT COUNT(*) FROM gold.cvss_v3 WHERE cvss_severity = 'MEDIUM')   AS total_medium_v3,
    (SELECT COUNT(*) FROM gold.cvss_v3 WHERE cvss_severity = 'LOW')      AS total_low_v3,

    (SELECT ROUND(AVG(cvss_score)::numeric, 2) FROM gold.cvss_v3) AS avg_cvss_v3_score,
    (SELECT ROUND(AVG(cvss_score)::numeric, 2) FROM gold.cvss_v2) AS avg_cvss_v2_score,

    (SELECT COUNT(*) FROM gold.dim_cve WHERE remotely_exploit IS TRUE) AS total_remote_exploits,

    (SELECT COUNT(*) FROM gold.dim_cve WHERE published_date >= CURRENT_DATE - INTERVAL '30 days') AS cves_last_30_days,

    (SELECT vendor_name FROM gold.dim_vendor ORDER BY total_cves DESC LIMIT 1) AS top_vendor_by_cves,
    (SELECT total_cves FROM gold.dim_vendor ORDER BY total_cves DESC LIMIT 1) AS top_vendor_cve_count,

    (SELECT MAX(last_modified) FROM gold.dim_cve) AS latest_cve_update,
    (SELECT MAX(created_at)    FROM gold.dim_cve) AS data_load_timestamp;

COMMENT ON VIEW gold.dashboard_executive_summary IS 'Executive KPI snapshot for dashboards';

-- ================================================================
-- VUE 12: AGG_WEEKLY_CVE_HEATMAP
-- ================================================================
CREATE OR REPLACE VIEW gold.agg_weekly_cve_heatmap AS
SELECT 
    DATE_TRUNC('week', c.published_date)::date AS week_start,
    EXTRACT(YEAR FROM c.published_date)  AS year,
    EXTRACT(WEEK FROM c.published_date)  AS week_number,

    COUNT(DISTINCT c.cve_id) AS total_cves,

    COUNT(*) FILTER (WHERE COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) = 'CRITICAL') AS critical_count,
    COUNT(*) FILTER (WHERE COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) = 'HIGH')     AS high_count,
    COUNT(*) FILTER (WHERE COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) = 'MEDIUM')   AS medium_count,
    COUNT(*) FILTER (WHERE COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) = 'LOW')      AS low_count,

    AVG(COALESCE(v4.cvss_score, v3.cvss_score, v2.cvss_score)) AS avg_cvss_score,

    CASE 
        WHEN COUNT(*) FILTER (WHERE COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) = 'CRITICAL') > 10 THEN 'Very High Risk'
        WHEN COUNT(*) FILTER (WHERE COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) = 'CRITICAL') > 5  THEN 'High Risk'
        WHEN COUNT(*) FILTER (WHERE COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) = 'HIGH') > 20     THEN 'Elevated Risk'
        ELSE 'Normal'
    END AS risk_level
FROM gold.dim_cve c
LEFT JOIN gold.cvss_v3 v3 ON c.cve_id = v3.cve_id AND v3.source_id = 144
LEFT JOIN gold.cvss_v2 v2 ON c.cve_id = v2.cve_id AND v2.source_id = 144
LEFT JOIN gold.cvss_v4 v4 ON c.cve_id = v4.cve_id
WHERE c.published_date >= CURRENT_DATE - INTERVAL '2 years'
GROUP BY DATE_TRUNC('week', c.published_date), EXTRACT(YEAR FROM c.published_date), EXTRACT(WEEK FROM c.published_date)
ORDER BY week_start DESC;

COMMENT ON VIEW gold.agg_weekly_cve_heatmap IS 'Weekly heatmap metrics with heuristic risk bands';

-- ================================================================
-- VUE 13: AGG_VENDOR_PRODUCT_MATRIX
-- ================================================================
CREATE OR REPLACE VIEW gold.agg_vendor_product_matrix AS
SELECT 
    v.vendor_id,
    v.vendor_name,
    p.product_id,
    p.product_name,
    p.total_cves AS product_cves,

    COUNT(*) FILTER (WHERE COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) = 'CRITICAL') AS critical_cves,
    COUNT(*) FILTER (WHERE COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) = 'HIGH')     AS high_cves,
    COUNT(*) FILTER (WHERE COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) = 'MEDIUM')   AS medium_cves,
    COUNT(*) FILTER (WHERE COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) = 'LOW')      AS low_cves,

    AVG(COALESCE(v4.cvss_score, v3.cvss_score, v2.cvss_score)) AS avg_cvss_score,

    MIN(c.published_date) AS first_vulnerability,
    MAX(c.published_date) AS latest_vulnerability,
    EXTRACT(YEAR FROM MAX(c.published_date)) AS latest_year,

    CASE 
        WHEN MAX(c.published_date) >= CURRENT_DATE - INTERVAL '6 months' THEN 'Active Threats'
        WHEN MAX(c.published_date) >= CURRENT_DATE - INTERVAL '2 years'   THEN 'Recent History'
        ELSE 'Legacy Vulnerabilities'
    END AS threat_status,

    CASE 
        WHEN COUNT(*) FILTER (WHERE COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) = 'CRITICAL') > 0 THEN 'P1 - Critical'
        WHEN COUNT(*) FILTER (WHERE COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) = 'HIGH') > 10   THEN 'P2 - High'
        WHEN p.total_cves > 50 THEN 'P3 - Monitor'
        ELSE 'P4 - Low Priority'
    END AS priority_level
FROM gold.dim_vendor v
JOIN gold.dim_products p ON v.vendor_id = p.vendor_id
LEFT JOIN gold.bridge_cve_products b ON p.product_id = b.product_id
LEFT JOIN gold.dim_cve c ON b.cve_id = c.cve_id
LEFT JOIN gold.cvss_v3 v3 ON c.cve_id = v3.cve_id AND v3.source_id = 144
LEFT JOIN gold.cvss_v2 v2 ON c.cve_id = v2.cve_id AND v2.source_id = 144
LEFT JOIN gold.cvss_v4 v4 ON c.cve_id = v4.cve_id
WHERE p.total_cves > 0
GROUP BY v.vendor_id, v.vendor_name, p.product_id, p.product_name, p.total_cves
ORDER BY product_cves DESC, critical_cves DESC;

COMMENT ON VIEW gold.agg_vendor_product_matrix IS 'Cross-tab by Vendor/Product with priorities';

-- ================================================================
-- VUE 14: AGG_EXPLOITABILITY_ANALYSIS
-- ================================================================
CREATE OR REPLACE VIEW gold.agg_exploitability_analysis AS
SELECT 
    COALESCE(v3.cvss_v3_base_ac, v2.cvss_v2_ac) AS attack_complexity,
    CASE 
        WHEN COALESCE(v3.cvss_v3_base_ac, v2.cvss_v2_ac) = 'L' THEN 'Low Complexity'
        WHEN COALESCE(v3.cvss_v3_base_ac, v2.cvss_v2_ac) = 'M' THEN 'Medium Complexity'
        WHEN COALESCE(v3.cvss_v3_base_ac, v2.cvss_v2_ac) = 'H' THEN 'High Complexity'
        ELSE 'Unknown'
    END AS complexity_level,

    v3.cvss_v3_base_pr AS privileges_required,
    CASE 
        WHEN v3.cvss_v3_base_pr = 'N' THEN 'None Required'
        WHEN v3.cvss_v3_base_pr = 'L' THEN 'Low Privileges'
        WHEN v3.cvss_v3_base_pr = 'H' THEN 'High Privileges'
        ELSE 'Not Applicable'
    END AS privilege_level,

    COALESCE(v3.cvss_v3_base_ui, 'N/A') AS user_interaction,
    CASE 
        WHEN v3.cvss_v3_base_ui = 'N' THEN 'No Interaction'
        WHEN v3.cvss_v3_base_ui = 'R' THEN 'Requires Interaction'
        ELSE 'Unknown'
    END AS interaction_level,

    COUNT(DISTINCT c.cve_id) AS total_cves,
    AVG(COALESCE(v4.cvss_score, v3.cvss_score, v2.cvss_score)) AS avg_cvss_score,
    AVG(COALESCE(v3.cvss_exploitability_score, v2.cvss_exploitability_score)) AS avg_exploitability_score,

    COUNT(*) FILTER (
        WHERE COALESCE(v3.cvss_v3_base_ac, v2.cvss_v2_ac) = 'L'
          AND v3.cvss_v3_base_pr = 'N'
          AND v3.cvss_v3_base_ui = 'N'
    ) AS easy_to_exploit_count,

    COUNT(*) FILTER (WHERE COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) = 'CRITICAL') AS critical_count,
    COUNT(*) FILTER (WHERE COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) = 'HIGH')     AS high_count
FROM gold.dim_cve c
LEFT JOIN gold.cvss_v3 v3 ON c.cve_id = v3.cve_id AND v3.source_id = 144
LEFT JOIN gold.cvss_v2 v2 ON c.cve_id = v2.cve_id AND v2.source_id = 144
LEFT JOIN gold.cvss_v4 v4 ON c.cve_id = v4.cve_id
WHERE COALESCE(v3.cvss_v3_base_ac, v2.cvss_v2_ac) IS NOT NULL
GROUP BY 
    COALESCE(v3.cvss_v3_base_ac, v2.cvss_v2_ac),
    v3.cvss_v3_base_pr,
    v3.cvss_v3_base_ui
ORDER BY total_cves DESC;

COMMENT ON VIEW gold.agg_exploitability_analysis IS 'Exploitability by AC/PR/UI with severity and ease flags';

-- ================================================================
-- VUE 15: AGG_CVE_AGE_ANALYSIS
-- (days since publication; use date subtraction to get integer days)
-- ================================================================
CREATE OR REPLACE VIEW gold.agg_cve_age_analysis AS
SELECT 
    c.cve_id,
    c.title,
    c.published_date,
    c.cve_year,

    (CURRENT_DATE - c.published_date::date)                    AS days_since_published,
    ROUND(((CURRENT_DATE - c.published_date::date)::numeric / 365.25), 1) AS years_since_published,

    CASE 
        WHEN (CURRENT_DATE - c.published_date::date) <= 30  THEN '0-30 days'
        WHEN (CURRENT_DATE - c.published_date::date) <= 90  THEN '31-90 days'
        WHEN (CURRENT_DATE - c.published_date::date) <= 180 THEN '91-180 days'
        WHEN (CURRENT_DATE - c.published_date::date) <= 365 THEN '6-12 months'
        WHEN (CURRENT_DATE - c.published_date::date) <= 730 THEN '1-2 years'
        WHEN (CURRENT_DATE - c.published_date::date) <= 1825 THEN '2-5 years'
        ELSE '5+ years'
    END AS age_category,

    COALESCE(v4.cvss_score, v3.cvss_score, v2.cvss_score)         AS cvss_score,
    COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) AS cvss_severity,

    CASE 
        WHEN (CURRENT_DATE - c.published_date::date) <= 30 
             AND COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) IN ('CRITICAL','HIGH')
        THEN 'Urgent - New Critical'
        WHEN (CURRENT_DATE - c.published_date::date) <= 90
             AND COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) = 'CRITICAL'
        THEN 'High Priority - Recent Critical'
        WHEN (CURRENT_DATE - c.published_date::date) > 730
             AND COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) IN ('CRITICAL','HIGH')
        THEN 'Review - Old High Severity'
        ELSE 'Standard'
    END AS priority_status,

    c.remotely_exploit
FROM gold.dim_cve c
LEFT JOIN gold.cvss_v3 v3 ON c.cve_id = v3.cve_id AND v3.source_id = 144
LEFT JOIN gold.cvss_v2 v2 ON c.cve_id = v2.cve_id AND v2.source_id = 144
LEFT JOIN gold.cvss_v4 v4 ON c.cve_id = v4.cve_id
ORDER BY c.published_date DESC;

COMMENT ON VIEW gold.agg_cve_age_analysis IS 'Age since publication with buckets and priority rule';

-- ================================================================
-- VUE 16: FACT_CVE_TIMELINE
-- ================================================================
CREATE OR REPLACE VIEW gold.fact_cve_timeline AS
SELECT 
    c.cve_id,
    c.published_date,
    c.published_date::date AS published_date_only,
    c.last_modified,
    c.cve_year,
    EXTRACT(MONTH   FROM c.published_date) AS published_month,
    EXTRACT(QUARTER FROM c.published_date) AS published_quarter,
    TO_CHAR(c.published_date, 'YYYY-MM')    AS year_month,
    TO_CHAR(c.published_date, 'YYYY-"Q"Q')  AS year_quarter,

    c.title,
    c.category,
    c.predicted_category,
    c.remotely_exploit,

    COALESCE(v4.cvss_score, v3.cvss_score, v2.cvss_score)         AS cvss_score,
    COALESCE(v4.cvss_severity, v3.cvss_severity, v2.cvss_severity) AS cvss_severity,

    COUNT(DISTINCT p.product_id) AS affected_products_count,
    COUNT(DISTINCT v.vendor_id)  AS affected_vendors_count,

    COALESCE(v3.cvss_v3_base_av, v2.cvss_v2_av) AS attack_vector,
    COALESCE(v3.cvss_v3_base_ac, v2.cvss_v2_ac) AS attack_complexity,

    COALESCE(v3.cvss_v3_base_c, v2.cvss_v2_c) AS confidentiality_impact,
    COALESCE(v3.cvss_v3_base_i, v2.cvss_v2_i) AS integrity_impact,
    COALESCE(v3.cvss_v3_base_a, v2.cvss_v2_a) AS availability_impact
FROM gold.dim_cve c
LEFT JOIN gold.cvss_v3 v3 ON c.cve_id = v3.cve_id AND v3.source_id = 144
LEFT JOIN gold.cvss_v2 v2 ON c.cve_id = v2.cve_id AND v2.source_id = 144
LEFT JOIN gold.cvss_v4 v4 ON c.cve_id = v4.cve_id
LEFT JOIN gold.bridge_cve_products b ON c.cve_id = b.cve_id
LEFT JOIN gold.dim_products p ON b.product_id = p.product_id
LEFT JOIN gold.dim_vendor   v ON p.vendor_id = v.vendor_id
GROUP BY 
    c.cve_id, c.published_date, c.last_modified, c.cve_year, c.title, 
    c.category, c.predicted_category, c.remotely_exploit,
    v4.cvss_score, v3.cvss_score, v2.cvss_score,
    v4.cvss_severity, v3.cvss_severity, v2.cvss_severity,
    v3.cvss_v3_base_av, v2.cvss_v2_av,
    v3.cvss_v3_base_ac, v2.cvss_v2_ac,
    v3.cvss_v3_base_c, v2.cvss_v2_c,
    v3.cvss_v3_base_i, v2.cvss_v2_i,
    v3.cvss_v3_base_a, v2.cvss_v2_a
ORDER BY c.published_date DESC;

COMMENT ON VIEW gold.fact_cve_timeline IS 'Time-grain CVE facts with coverage, vectors, and impacts';
