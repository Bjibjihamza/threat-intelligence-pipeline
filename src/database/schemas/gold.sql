-- ============================================================================
-- GOLD LAYER SCHEMA V1.0 - CVE DATA WAREHOUSE (BI & ML READY)
-- Purpose: Business-ready aggregations, denormalized views, and ML features
-- ============================================================================

CREATE SCHEMA IF NOT EXISTS gold;
SET search_path TO gold, silver, public;

COMMENT ON SCHEMA gold IS 'Gold Layer: Business-ready analytics, aggregations, and ML features for CVE data.';

-- ============================================================================
-- 1. TIME DIMENSION (for time-series analysis)
-- ============================================================================

DROP TABLE IF EXISTS gold.dim_time CASCADE;

CREATE TABLE gold.dim_time (
    date_id DATE PRIMARY KEY,
    year INTEGER NOT NULL,
    quarter INTEGER NOT NULL,
    month INTEGER NOT NULL,
    week INTEGER NOT NULL,
    day_of_year INTEGER NOT NULL,
    day_of_month INTEGER NOT NULL,
    day_of_week INTEGER NOT NULL,
    month_name VARCHAR(20) NOT NULL,
    quarter_name VARCHAR(10) NOT NULL,
    is_weekend BOOLEAN NOT NULL,
    fiscal_year INTEGER NOT NULL,
    fiscal_quarter INTEGER NOT NULL
);

CREATE INDEX idx_dim_time_year ON gold.dim_time(year);
CREATE INDEX idx_dim_time_quarter ON gold.dim_time(year, quarter);
CREATE INDEX idx_dim_time_month ON gold.dim_time(year, month);

COMMENT ON TABLE gold.dim_time IS 'Time dimension for temporal analysis and reporting.';

-- ============================================================================
-- 2. CVE SUMMARY (denormalized, single source of truth)
-- ============================================================================

DROP TABLE IF EXISTS gold.fact_cve_summary CASCADE;

CREATE TABLE gold.fact_cve_summary (
    cve_id VARCHAR(20) PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    category VARCHAR(50),
    published_date DATE NOT NULL,
    published_year INTEGER NOT NULL,
    published_quarter INTEGER NOT NULL,
    published_month INTEGER NOT NULL,
    last_modified DATE NOT NULL,
    days_to_last_modified INTEGER,
    source_identifier TEXT,
    remotely_exploit BOOLEAN,
    
    -- CVSS Aggregations (primary/highest score)
    primary_cvss_version VARCHAR(10),
    primary_cvss_score NUMERIC(3,1),
    primary_cvss_severity VARCHAR(10),
    max_cvss_v2_score NUMERIC(3,1),
    max_cvss_v3_score NUMERIC(3,1),
    max_cvss_v4_score NUMERIC(3,1),
    cvss_source_count INTEGER,
    
    -- Product Counts
    affected_vendor_count INTEGER DEFAULT 0,
    affected_product_count INTEGER DEFAULT 0,
    
    -- Risk Classification
    risk_score NUMERIC(5,2), -- Composite risk score
    criticality_flag VARCHAR(20), -- CRITICAL, HIGH, MEDIUM, LOW, NONE
    exploit_likelihood VARCHAR(20), -- HIGH, MEDIUM, LOW based on features
    
    -- Metadata
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT fk_fact_cve_summary_date FOREIGN KEY (published_date) 
        REFERENCES gold.dim_time(date_id) ON DELETE CASCADE
);

CREATE INDEX idx_fact_cve_summary_published_date ON gold.fact_cve_summary(published_date);
CREATE INDEX idx_fact_cve_summary_year ON gold.fact_cve_summary(published_year);
CREATE INDEX idx_fact_cve_summary_severity ON gold.fact_cve_summary(primary_cvss_severity);
CREATE INDEX idx_fact_cve_summary_risk ON gold.fact_cve_summary(risk_score DESC);
CREATE INDEX idx_fact_cve_summary_category ON gold.fact_cve_summary(category);
CREATE INDEX idx_fact_cve_summary_remote ON gold.fact_cve_summary(remotely_exploit);

COMMENT ON TABLE gold.fact_cve_summary IS 'Denormalized CVE fact table with aggregated metrics for fast querying.';

-- ============================================================================
-- 3. VENDOR ANALYTICS (product portfolio risk)
-- ============================================================================

DROP TABLE IF EXISTS gold.fact_vendor_analytics CASCADE;

CREATE TABLE gold.fact_vendor_analytics (
    vendor_id SERIAL PRIMARY KEY,
    vendor VARCHAR(255) UNIQUE NOT NULL,
    total_products INTEGER DEFAULT 0,
    total_cves INTEGER DEFAULT 0,
    critical_cves INTEGER DEFAULT 0,
    high_cves INTEGER DEFAULT 0,
    medium_cves INTEGER DEFAULT 0,
    low_cves INTEGER DEFAULT 0,
    
    -- CVSS Statistics
    avg_cvss_score NUMERIC(4,2),
    max_cvss_score NUMERIC(3,1),
    median_cvss_score NUMERIC(3,1),
    
    -- Temporal Metrics
    first_cve_date DATE,
    last_cve_date DATE,
    active_days INTEGER,
    cves_per_year NUMERIC(8,2),
    
    -- Risk Indicators
    remote_exploit_percentage NUMERIC(5,2),
    avg_days_to_patch NUMERIC(8,2),
    vendor_risk_score NUMERIC(5,2),
    
    -- Trends (last 90 days)
    recent_cve_count INTEGER,
    trend_direction VARCHAR(20), -- INCREASING, STABLE, DECREASING
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_fact_vendor_analytics_total_cves ON gold.fact_vendor_analytics(total_cves DESC);
CREATE INDEX idx_fact_vendor_analytics_risk ON gold.fact_vendor_analytics(vendor_risk_score DESC);

COMMENT ON TABLE gold.fact_vendor_analytics IS 'Vendor-level aggregations for portfolio risk analysis.';

-- ============================================================================
-- 4. PRODUCT ANALYTICS (detailed product risk profiles)
-- ============================================================================

DROP TABLE IF EXISTS gold.fact_product_analytics CASCADE;

CREATE TABLE gold.fact_product_analytics (
    product_analytics_id SERIAL PRIMARY KEY,
    vendor VARCHAR(255) NOT NULL,
    product_name VARCHAR(255) NOT NULL,
    total_cves INTEGER DEFAULT 0,
    critical_cves INTEGER DEFAULT 0,
    high_cves INTEGER DEFAULT 0,
    
    -- CVSS Metrics
    avg_cvss_score NUMERIC(4,2),
    max_cvss_score NUMERIC(3,1),
    
    -- Temporal
    first_cve_date DATE,
    last_cve_date DATE,
    cve_frequency_days NUMERIC(8,2), -- Avg days between CVEs
    
    -- Risk Metrics
    product_risk_score NUMERIC(5,2),
    remote_exploit_count INTEGER,
    
    -- Market Position
    market_rank INTEGER, -- Ranking by CVE volume
    vulnerability_density NUMERIC(8,4), -- CVEs per active day
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT uk_product_analytics UNIQUE (vendor, product_name)
);

CREATE INDEX idx_fact_product_analytics_vendor ON gold.fact_product_analytics(vendor);
CREATE INDEX idx_fact_product_analytics_risk ON gold.fact_product_analytics(product_risk_score DESC);

COMMENT ON TABLE gold.fact_product_analytics IS 'Product-level risk analytics for targeted monitoring.';

-- ============================================================================
-- 5. TIME-SERIES AGGREGATIONS (for trending and forecasting)
-- ============================================================================

DROP TABLE IF EXISTS gold.fact_cve_time_series CASCADE;

CREATE TABLE gold.fact_cve_time_series (
    time_series_id SERIAL PRIMARY KEY,
    date_id DATE NOT NULL,
    granularity VARCHAR(20) NOT NULL, -- DAY, WEEK, MONTH, QUARTER, YEAR
    
    -- Volume Metrics
    total_cves INTEGER DEFAULT 0,
    new_cves INTEGER DEFAULT 0,
    modified_cves INTEGER DEFAULT 0,
    
    -- Severity Distribution
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    
    -- CVSS Statistics
    avg_cvss_score NUMERIC(4,2),
    median_cvss_score NUMERIC(3,1),
    
    -- Attack Vectors
    network_exploit_count INTEGER DEFAULT 0,
    local_exploit_count INTEGER DEFAULT 0,
    remote_exploit_count INTEGER DEFAULT 0,
    
    -- Category Distribution
    top_category VARCHAR(50),
    category_diversity_index NUMERIC(4,2),
    
    -- Source Metrics
    nvd_source_count INTEGER DEFAULT 0,
    mitre_source_count INTEGER DEFAULT 0,
    other_source_count INTEGER DEFAULT 0,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT fk_cve_ts_date FOREIGN KEY (date_id) 
        REFERENCES gold.dim_time(date_id) ON DELETE CASCADE,
    CONSTRAINT uk_cve_ts_date_granularity UNIQUE (date_id, granularity)
);

CREATE INDEX idx_fact_cve_ts_date ON gold.fact_cve_time_series(date_id);
CREATE INDEX idx_fact_cve_ts_granularity ON gold.fact_cve_time_series(granularity, date_id);

COMMENT ON TABLE gold.fact_cve_time_series IS 'Time-series aggregations for trending, forecasting, and anomaly detection.';

-- ============================================================================
-- 6. CVSS SOURCE RELIABILITY (for ML scoring)
-- ============================================================================

DROP TABLE IF EXISTS gold.fact_cvss_source_reliability CASCADE;

CREATE TABLE gold.fact_cvss_source_reliability (
    source_name VARCHAR(100) PRIMARY KEY,
    total_scores INTEGER DEFAULT 0,
    avg_score NUMERIC(4,2),
    score_stddev NUMERIC(4,2),
    
    -- Comparison with NVD baseline
    avg_deviation_from_nvd NUMERIC(4,2),
    agreement_rate NUMERIC(5,2), -- % within 1.0 of NVD
    
    -- Coverage
    unique_cves_scored INTEGER,
    coverage_percentage NUMERIC(5,2),
    
    -- Versioning
    v2_count INTEGER DEFAULT 0,
    v3_count INTEGER DEFAULT 0,
    v4_count INTEGER DEFAULT 0,
    
    -- Quality Indicators
    reliability_score NUMERIC(5,2), -- Composite score
    consistency_score NUMERIC(5,2),
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE gold.fact_cvss_source_reliability IS 'Source reliability metrics for weighted scoring algorithms.';

-- ============================================================================
-- 7. ML FEATURE TABLE (training dataset)
-- ============================================================================

DROP TABLE IF EXISTS gold.ml_cve_features CASCADE;

CREATE TABLE gold.ml_cve_features (
    cve_id VARCHAR(20) PRIMARY KEY,
    
    -- Target Variables (for supervised learning)
    cvss_v3_score NUMERIC(3,1),
    severity_class VARCHAR(10),
    exploit_predicted BOOLEAN,
    
    -- Temporal Features
    published_year INTEGER,
    published_month INTEGER,
    published_day_of_week INTEGER,
    days_since_first_cve INTEGER,
    
    -- Text Features (TF-IDF ready)
    description_length INTEGER,
    description_word_count INTEGER,
    title_length INTEGER,
    has_poc BOOLEAN, -- Proof of concept mentioned
    has_exploit_keyword BOOLEAN,
    
    -- CVSS Component Features
    cvss_av VARCHAR(20),
    cvss_ac VARCHAR(20),
    cvss_pr VARCHAR(20),
    cvss_ui VARCHAR(20),
    cvss_s VARCHAR(20),
    cvss_c VARCHAR(20),
    cvss_i VARCHAR(20),
    cvss_a VARCHAR(20),
    
    -- Product Features
    affected_product_count INTEGER,
    affected_vendor_count INTEGER,
    vendor_risk_score NUMERIC(5,2),
    
    -- Category Features (one-hot encoded ready)
    category VARCHAR(50),
    is_buffer_overflow BOOLEAN,
    is_injection BOOLEAN,
    is_xss BOOLEAN,
    is_authentication BOOLEAN,
    
    -- Source Features
    source_identifier VARCHAR(100),
    cvss_source_count INTEGER,
    
    -- Derived Risk Features
    remotely_exploit BOOLEAN,
    attack_complexity_low BOOLEAN,
    privileges_required_none BOOLEAN,
    user_interaction_none BOOLEAN,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_ml_cve_features_year ON gold.ml_cve_features(published_year);
CREATE INDEX idx_ml_cve_features_severity ON gold.ml_cve_features(severity_class);

COMMENT ON TABLE gold.ml_cve_features IS 'Feature-engineered dataset for ML model training (classification, regression, clustering).';

-- ============================================================================
-- 8. MATERIALIZED VIEWS FOR BI DASHBOARDS
-- ============================================================================

-- Dashboard 1: Executive Summary
DROP MATERIALIZED VIEW IF EXISTS gold.mv_executive_dashboard CASCADE;

CREATE MATERIALIZED VIEW gold.mv_executive_dashboard AS
SELECT 
    DATE_TRUNC('month', published_date)::DATE AS month,
    COUNT(*) AS total_cves,
    COUNT(*) FILTER (WHERE primary_cvss_severity = 'CRITICAL') AS critical_cves,
    COUNT(*) FILTER (WHERE primary_cvss_severity = 'HIGH') AS high_cves,
    COUNT(*) FILTER (WHERE remotely_exploit = TRUE) AS remote_exploits,
    AVG(primary_cvss_score) AS avg_cvss_score,
    COUNT(DISTINCT source_identifier) AS sources,
    COUNT(DISTINCT category) AS categories
FROM gold.fact_cve_summary
GROUP BY DATE_TRUNC('month', published_date)
ORDER BY month DESC;

CREATE UNIQUE INDEX idx_mv_exec_dash_month ON gold.mv_executive_dashboard(month);

-- Dashboard 2: Top Risky Vendors
DROP MATERIALIZED VIEW IF EXISTS gold.mv_top_risky_vendors CASCADE;

CREATE MATERIALIZED VIEW gold.mv_top_risky_vendors AS
SELECT 
    vendor,
    total_cves,
    critical_cves,
    vendor_risk_score,
    avg_cvss_score,
    remote_exploit_percentage,
    ROW_NUMBER() OVER (ORDER BY vendor_risk_score DESC) AS risk_rank
FROM gold.fact_vendor_analytics
ORDER BY vendor_risk_score DESC;

-- ML Training data view (balanced dataset)
CREATE OR REPLACE VIEW gold.v_ml_training_balanced AS
WITH severity_counts AS (
    SELECT severity_class, COUNT(*) as cnt,
           MIN(COUNT(*)) OVER () as min_cnt
    FROM gold.ml_cve_features
    WHERE severity_class IS NOT NULL
    GROUP BY severity_class
)
SELECT m.*
FROM gold.ml_cve_features m
JOIN severity_counts sc ON m.severity_class = sc.severity_class
WHERE m.cve_id IN (
    SELECT cve_id
    FROM gold.ml_cve_features
    WHERE severity_class = sc.severity_class
    ORDER BY RANDOM()
    LIMIT sc.min_cnt
)
ORDER BY RANDOM();

-- ============================================================================
-- 11. ADVANCED ANALYTICS FUNCTIONS
-- ============================================================================

-- Calculate anomaly scores (for outlier detection)
CREATE OR REPLACE FUNCTION gold.calculate_anomaly_scores()
RETURNS TABLE(cve_id VARCHAR, anomaly_score NUMERIC) AS $
BEGIN
    RETURN QUERY
    WITH stats AS (
        SELECT 
            AVG(primary_cvss_score) as avg_score,
            STDDEV(primary_cvss_score) as stddev_score,
            AVG(affected_product_count) as avg_products,
            STDDEV(affected_product_count) as stddev_products
        FROM gold.fact_cve_summary
        WHERE primary_cvss_score IS NOT NULL
    )
    SELECT 
        s.cve_id,
        ROUND(
            SQRT(
                POWER((s.primary_cvss_score - st.avg_score) / NULLIF(st.stddev_score, 0), 2) +
                POWER((s.affected_product_count - st.avg_products) / NULLIF(st.stddev_products, 0), 2)
            )::NUMERIC, 
            4
        ) as anomaly_score
    FROM gold.fact_cve_summary s
    CROSS JOIN stats st
    WHERE s.primary_cvss_score IS NOT NULL
    ORDER BY anomaly_score DESC;
END;
$ LANGUAGE plpgsql;

-- Predict vulnerability trend (simple linear regression)
CREATE OR REPLACE FUNCTION gold.predict_cve_trend(
    p_vendor VARCHAR DEFAULT NULL,
    p_months_ahead INTEGER DEFAULT 3
)
RETURNS TABLE(
    prediction_date DATE,
    predicted_cve_count INTEGER,
    confidence_level VARCHAR
) AS $
BEGIN
    RETURN QUERY
    WITH monthly_data AS (
        SELECT 
            DATE_TRUNC('month', published_date)::DATE as month,
            COUNT(*) as cve_count,
            EXTRACT(EPOCH FROM DATE_TRUNC('month', published_date)) as month_numeric
        FROM gold.fact_cve_summary s
        WHERE (p_vendor IS NULL OR EXISTS (
            SELECT 1 FROM silver.bridge_cve_products b
            JOIN silver.dim_products p ON b.product_id = p.product_id
            WHERE b.cve_id = s.cve_id AND p.vendor = p_vendor
        ))
        GROUP BY DATE_TRUNC('month', published_date)
        HAVING COUNT(*) > 0
    ),
    regression AS (
        SELECT 
            REGR_SLOPE(cve_count, month_numeric) as slope,
            REGR_INTERCEPT(cve_count, month_numeric) as intercept,
            REGR_R2(cve_count, month_numeric) as r_squared
        FROM monthly_data
    ),
    future_months AS (
        SELECT generate_series(1, p_months_ahead) as month_offset
    )
    SELECT 
        (DATE_TRUNC('month', CURRENT_DATE) + (fm.month_offset || ' months')::INTERVAL)::DATE,
        GREATEST(0, ROUND(
            r.intercept + r.slope * 
            EXTRACT(EPOCH FROM DATE_TRUNC('month', CURRENT_DATE) + (fm.month_offset || ' months')::INTERVAL)
        ))::INTEGER,
        CASE 
            WHEN r.r_squared >= 0.7 THEN 'HIGH'
            WHEN r.r_squared >= 0.4 THEN 'MEDIUM'
            ELSE 'LOW'
        END
    FROM future_months fm
    CROSS JOIN regression r;
END;
$ LANGUAGE plpgsql;

-- Calculate time-series metrics for specific period
CREATE OR REPLACE FUNCTION gold.etl_load_time_series(
    p_granularity VARCHAR DEFAULT 'MONTH'
)
RETURNS void AS $
BEGIN
    DELETE FROM gold.fact_cve_time_series WHERE granularity = p_granularity;
    
    INSERT INTO gold.fact_cve_time_series (
        date_id, granularity, total_cves, new_cves, critical_count, high_count,
        medium_count, low_count, avg_cvss_score, network_exploit_count,
        remote_exploit_count, nvd_source_count, mitre_source_count
    )
    SELECT 
        CASE p_granularity
            WHEN 'DAY' THEN published_date
            WHEN 'WEEK' THEN DATE_TRUNC('week', published_date)::DATE
            WHEN 'MONTH' THEN DATE_TRUNC('month', published_date)::DATE
            WHEN 'QUARTER' THEN DATE_TRUNC('quarter', published_date)::DATE
            WHEN 'YEAR' THEN DATE_TRUNC('year', published_date)::DATE
        END as period_date,
        p_granularity,
        COUNT(*),
        COUNT(*),
        COUNT(*) FILTER (WHERE primary_cvss_severity = 'CRITICAL'),
        COUNT(*) FILTER (WHERE primary_cvss_severity = 'HIGH'),
        COUNT(*) FILTER (WHERE primary_cvss_severity = 'MEDIUM'),
        COUNT(*) FILTER (WHERE primary_cvss_severity = 'LOW'),
        AVG(primary_cvss_score),
        COUNT(*) FILTER (WHERE description ILIKE '%network%'),
        COUNT(*) FILTER (WHERE remotely_exploit = TRUE),
        COUNT(*) FILTER (WHERE source_identifier ILIKE '%nvd%'),
        COUNT(*) FILTER (WHERE source_identifier ILIKE '%mitre%')
    FROM gold.fact_cve_summary
    GROUP BY period_date
    ORDER BY period_date;
    
    RAISE NOTICE 'Time series loaded for granularity: %', p_granularity;
END;
$ LANGUAGE plpgsql;

-- ============================================================================
-- 12. DATA QUALITY & MONITORING FUNCTIONS
-- ============================================================================

-- Data quality report
CREATE OR REPLACE FUNCTION gold.generate_data_quality_report()
RETURNS TABLE(
    metric_name VARCHAR,
    metric_value TEXT,
    status VARCHAR
) AS $
BEGIN
    RETURN QUERY
    SELECT 
        'Total CVEs'::VARCHAR,
        COUNT(*)::TEXT,
        'INFO'::VARCHAR
    FROM gold.fact_cve_summary
    
    UNION ALL
    
    SELECT 
        'CVEs Missing CVSS Score',
        COUNT(*)::TEXT,
        CASE WHEN COUNT(*) > 100 THEN 'WARNING' ELSE 'OK' END
    FROM gold.fact_cve_summary
    WHERE primary_cvss_score IS NULL
    
    UNION ALL
    
    SELECT 
        'CVEs Without Products',
        COUNT(*)::TEXT,
        CASE WHEN COUNT(*) > 50 THEN 'WARNING' ELSE 'OK' END
    FROM gold.fact_cve_summary
    WHERE affected_product_count = 0
    
    UNION ALL
    
    SELECT 
        'Orphan CVE IDs (not in Silver)',
        COUNT(*)::TEXT,
        CASE WHEN COUNT(*) > 0 THEN 'ERROR' ELSE 'OK' END
    FROM gold.fact_cve_summary s
    WHERE NOT EXISTS (SELECT 1 FROM silver.dim_cve c WHERE c.cve_id = s.cve_id)
    
    UNION ALL
    
    SELECT 
        'Date Range Coverage',
        MIN(published_date)::TEXT || ' to ' || MAX(published_date)::TEXT,
        'INFO'
    FROM gold.fact_cve_summary
    
    UNION ALL
    
    SELECT 
        'Avg CVEs per Vendor',
        ROUND(AVG(total_cves), 2)::TEXT,
        'INFO'
    FROM gold.fact_vendor_analytics
    
    UNION ALL
    
    SELECT 
        'ML Features Completeness',
        ROUND(
            (COUNT(*) FILTER (WHERE cvss_v3_score IS NOT NULL)::NUMERIC / COUNT(*)) * 100,
            2
        )::TEXT || '%',
        CASE 
            WHEN (COUNT(*) FILTER (WHERE cvss_v3_score IS NOT NULL)::NUMERIC / COUNT(*)) < 0.8 
            THEN 'WARNING' ELSE 'OK' 
        END
    FROM gold.ml_cve_features;
END;
$ LANGUAGE plpgsql;

-- Performance monitoring
CREATE OR REPLACE FUNCTION gold.get_table_statistics()
RETURNS TABLE(
    table_name TEXT,
    row_count BIGINT,
    total_size TEXT,
    index_size TEXT,
    last_vacuum TIMESTAMP,
    last_analyze TIMESTAMP
) AS $
BEGIN
    RETURN QUERY
    SELECT 
        schemaname || '.' || relname AS table_name,
        n_live_tup AS row_count,
        pg_size_pretty(pg_total_relation_size(schemaname || '.' || relname)) AS total_size,
        pg_size_pretty(pg_indexes_size(schemaname || '.' || relname)) AS index_size,
        last_vacuum,
        last_analyze
    FROM pg_stat_user_tables
    WHERE schemaname = 'gold'
    ORDER BY pg_total_relation_size(schemaname || '.' || relname) DESC;
END;
$ LANGUAGE plpgsql;

-- ============================================================================
-- 13. SCHEDULED REFRESH STRATEGY
-- ============================================================================

-- Incremental refresh (for daily updates)
CREATE OR REPLACE FUNCTION gold.etl_incremental_refresh(p_days_back INTEGER DEFAULT 7)
RETURNS void AS $
DECLARE
    v_cutoff_date DATE := CURRENT_DATE - p_days_back;
    v_affected_rows INTEGER;
BEGIN
    RAISE NOTICE 'Starting incremental refresh for last % days (since %)', p_days_back, v_cutoff_date;
    
    -- Update fact_cve_summary for recent CVEs
    WITH recent_cves AS (
        SELECT cve_id FROM silver.dim_cve 
        WHERE published_date::DATE >= v_cutoff_date 
           OR last_modified::DATE >= v_cutoff_date
    )
    DELETE FROM gold.fact_cve_summary 
    WHERE cve_id IN (SELECT cve_id FROM recent_cves);
    
    GET DIAGNOSTICS v_affected_rows = ROW_COUNT;
    RAISE NOTICE 'Deleted % stale CVE summary rows', v_affected_rows;
    
    -- Re-insert updated CVEs
    INSERT INTO gold.fact_cve_summary
    SELECT * FROM (
        SELECT 
            c.cve_id, c.title, c.description, c.category,
            c.published_date::DATE, EXTRACT(YEAR FROM c.published_date),
            EXTRACT(QUARTER FROM c.published_date), EXTRACT(MONTH FROM c.published_date),
            c.last_modified::DATE, EXTRACT(DAY FROM (c.last_modified - c.published_date)),
            c.source_identifier, c.remotely_exploit,
            (SELECT f.cvss_version FROM silver.fact_cvss_scores f 
             WHERE f.cve_id = c.cve_id ORDER BY f.cvss_score DESC LIMIT 1),
            (SELECT MAX(f.cvss_score) FROM silver.fact_cvss_scores f WHERE f.cve_id = c.cve_id),
            (SELECT f.cvss_severity FROM silver.fact_cvss_scores f 
             WHERE f.cve_id = c.cve_id ORDER BY f.cvss_score DESC LIMIT 1),
            (SELECT MAX(f.cvss_score) FROM silver.fact_cvss_scores f 
             WHERE f.cve_id = c.cve_id AND f.cvss_version LIKE 'v2%'),
            (SELECT MAX(f.cvss_score) FROM silver.fact_cvss_scores f 
             WHERE f.cve_id = c.cve_id AND f.cvss_version LIKE 'v3%'),
            (SELECT MAX(f.cvss_score) FROM silver.fact_cvss_scores f 
             WHERE f.cve_id = c.cve_id AND f.cvss_version LIKE 'v4%'),
            (SELECT COUNT(DISTINCT f.source_id) FROM silver.fact_cvss_scores f WHERE f.cve_id = c.cve_id),
            (SELECT COUNT(DISTINCT p.vendor) FROM silver.bridge_cve_products b 
             JOIN silver.dim_products p ON b.product_id = p.product_id WHERE b.cve_id = c.cve_id),
            (SELECT COUNT(DISTINCT b.product_id) FROM silver.bridge_cve_products b WHERE b.cve_id = c.cve_id),
            NULL, NULL, NULL, -- risk_score, criticality_flag, exploit_likelihood (to be updated)
            CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
        FROM silver.dim_cve c
        WHERE c.published_date::DATE >= v_cutoff_date 
           OR c.last_modified::DATE >= v_cutoff_date
    ) sub;
    
    GET DIAGNOSTICS v_affected_rows = ROW_COUNT;
    RAISE NOTICE 'Inserted % updated CVE summary rows', v_affected_rows;
    
    -- Update risk calculations
    UPDATE gold.fact_cve_summary
    SET 
        risk_score = COALESCE(primary_cvss_score, 0) * 
                     (1 + CASE WHEN remotely_exploit THEN 0.5 ELSE 0 END) *
                     (1 + (affected_product_count::NUMERIC / 100)),
        criticality_flag = CASE 
            WHEN primary_cvss_score >= 9.0 THEN 'CRITICAL'
            WHEN primary_cvss_score >= 7.0 THEN 'HIGH'
            WHEN primary_cvss_score >= 4.0 THEN 'MEDIUM'
            WHEN primary_cvss_score >= 0.1 THEN 'LOW'
            ELSE 'NONE'
        END,
        exploit_likelihood = CASE 
            WHEN remotely_exploit AND primary_cvss_score >= 7.0 THEN 'HIGH'
            WHEN remotely_exploit OR primary_cvss_score >= 7.0 THEN 'MEDIUM'
            ELSE 'LOW'
        END
    WHERE updated_at >= v_cutoff_date;
    
    -- Refresh vendor analytics (full reload for simplicity)
    PERFORM gold.etl_load_vendor_analytics();
    
    -- Refresh materialized views
    REFRESH MATERIALIZED VIEW CONCURRENTLY gold.mv_executive_dashboard;
    REFRESH MATERIALIZED VIEW CONCURRENTLY gold.mv_top_risky_vendors;
    
    RAISE NOTICE 'Incremental refresh completed successfully';
END;
$ LANGUAGE plpgsql;

-- ============================================================================
-- 14. EXPORT FUNCTIONS FOR ML/BI TOOLS
-- ============================================================================

-- Export to CSV (simulated - use COPY in production)
CREATE OR REPLACE FUNCTION gold.export_ml_dataset(
    p_output_path TEXT DEFAULT '/tmp/cve_ml_export.csv'
)
RETURNS TEXT AS $
DECLARE
    v_row_count INTEGER;
BEGIN
    -- In production, use: COPY (...) TO p_output_path WITH CSV HEADER;
    SELECT COUNT(*) INTO v_row_count FROM gold.ml_cve_features;
    
    RETURN format('ML dataset ready for export: %s rows to %s', v_row_count, p_output_path);
END;
$ LANGUAGE plpgsql;

-- ============================================================================
-- 15. FINAL SETUP & VALIDATION
-- ============================================================================

-- Grant permissions (adjust as needed)
GRANT USAGE ON SCHEMA gold TO PUBLIC;
GRANT SELECT ON ALL TABLES IN SCHEMA gold TO PUBLIC;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA gold TO PUBLIC;

-- Create update triggers
CREATE TRIGGER trg_fact_cve_summary_updated
    BEFORE UPDATE ON gold.fact_cve_summary
    FOR EACH ROW
    EXECUTE FUNCTION silver.update_modified_column();

CREATE TRIGGER trg_fact_vendor_analytics_updated
    BEFORE UPDATE ON gold.fact_vendor_analytics
    FOR EACH ROW
    EXECUTE FUNCTION silver.update_modified_column();

-- ============================================================================
-- INITIALIZATION SCRIPT
-- ============================================================================

-- Run this after creating all objects:
-- SELECT gold.populate_dim_time('2000-01-01', '2030-12-31');
-- SELECT gold.run_full_etl();

COMMENT ON SCHEMA gold IS 
'Gold Layer - Business Intelligence & Machine Learning Ready Layer
-----------------------------------------------------------------
This schema provides:
1. Denormalized fact tables for fast querying
2. Pre-aggregated analytics for dashboards
3. Time-series data for forecasting
4. ML-ready feature datasets
5. Materialized views for BI tools (Tableau, Power BI, etc.)
6. Advanced analytics functions

Refresh Strategy:
- Full ETL: gold.run_full_etl() - Weekly
- Incremental: gold.etl_incremental_refresh(7) - Daily
- MV Refresh: Included in ETL functions

Export Targets:
- Python/R: Use ml_cve_features table
- BI Tools: Use mv_executive_dashboard, mv_top_risky_vendors
- APIs: Use v_latest_critical_cves, v_vendor_scoreboard
';

-- Validation query
DO $
DECLARE
    v_table_count INTEGER;
    v_view_count INTEGER;
    v_function_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO v_table_count 
    FROM information_schema.tables 
    WHERE table_schema = 'gold' AND table_type = 'BASE TABLE';
    
    SELECT COUNT(*) INTO v_view_count 
    FROM information_schema.views 
    WHERE table_schema = 'gold'
    UNION ALL
    SELECT COUNT(*) FROM pg_matviews WHERE schemaname = 'gold';
    
    SELECT COUNT(*) INTO v_function_count 
    FROM information_schema.routines 
    WHERE routine_schema = 'gold';
    
    RAISE NOTICE '===========================================';
    RAISE NOTICE 'GOLD LAYER SETUP COMPLETE';
    RAISE NOTICE '===========================================';
    RAISE NOTICE 'Tables created: %', v_table_count;
    RAISE NOTICE 'Views/MVs created: %', v_view_count;
    RAISE NOTICE 'Functions created: %', v_function_count;
    RAISE NOTICE '===========================================';
    RAISE NOTICE 'Next steps:';
    RAISE NOTICE '1. Run: SELECT gold.populate_dim_time(''2000-01-01'', ''2030-12-31'');';
    RAISE NOTICE '2. Run: SELECT gold.run_full_etl();';
    RAISE NOTICE '3. Schedule: SELECT gold.etl_incremental_refresh(7); -- Daily';
    RAISE NOTICE '===========================================';
END $;
WHERE total_cves >= 5
ORDER BY vendor_risk_score DESC
LIMIT 100;

-- Dashboard 3: Vulnerability Category Trends
DROP MATERIALIZED VIEW IF EXISTS gold.mv_category_trends CASCADE;

CREATE MATERIALIZED VIEW gold.mv_category_trends AS
SELECT 
    category,
    published_year,
    COUNT(*) AS cve_count,
    AVG(primary_cvss_score) AS avg_score,
    COUNT(*) FILTER (WHERE remotely_exploit = TRUE) AS remote_count
FROM gold.fact_cve_summary
WHERE category IS NOT NULL
GROUP BY category, published_year
HAVING COUNT(*) >= 10
ORDER BY published_year DESC, cve_count DESC;

-- Dashboard 4: CVSS Score Distribution
DROP MATERIALIZED VIEW IF EXISTS gold.mv_cvss_distribution CASCADE;

CREATE MATERIALIZED VIEW gold.mv_cvss_distribution AS
SELECT 
    primary_cvss_version AS cvss_version,
    FLOOR(primary_cvss_score) AS score_bucket,
    COUNT(*) AS cve_count,
    AVG(affected_product_count) AS avg_products_affected
FROM gold.fact_cve_summary
WHERE primary_cvss_score IS NOT NULL
GROUP BY primary_cvss_version, FLOOR(primary_cvss_score)
ORDER BY cvss_version, score_bucket;

-- ============================================================================
-- 9. ETL FUNCTIONS (Silver → Gold transformations)
-- ============================================================================

-- Populate Time Dimension
CREATE OR REPLACE FUNCTION gold.populate_dim_time(start_date DATE, end_date DATE)
RETURNS void AS $$
DECLARE
    curr_date DATE := start_date;
BEGIN
    WHILE curr_date <= end_date LOOP
        INSERT INTO gold.dim_time (
            date_id, year, quarter, month, week, day_of_year, day_of_month, day_of_week,
            month_name, quarter_name, is_weekend, fiscal_year, fiscal_quarter
        )
        VALUES (
            curr_date,
            EXTRACT(YEAR FROM curr_date),
            EXTRACT(QUARTER FROM curr_date),
            EXTRACT(MONTH FROM curr_date),
            EXTRACT(WEEK FROM curr_date),
            EXTRACT(DOY FROM curr_date),
            EXTRACT(DAY FROM curr_date),
            EXTRACT(DOW FROM curr_date),
            TO_CHAR(curr_date, 'Month'),
            'Q' || EXTRACT(QUARTER FROM curr_date),
            EXTRACT(DOW FROM curr_date) IN (0, 6),
            CASE WHEN EXTRACT(MONTH FROM curr_date) >= 10 
                 THEN EXTRACT(YEAR FROM curr_date) + 1 
                 ELSE EXTRACT(YEAR FROM curr_date) END,
            CASE WHEN EXTRACT(MONTH FROM curr_date) >= 10 
                 THEN EXTRACT(QUARTER FROM curr_date) - 2 
                 ELSE EXTRACT(QUARTER FROM curr_date) + 2 END
        )
        ON CONFLICT (date_id) DO NOTHING;
        
        curr_date := curr_date + INTERVAL '1 day';
    END LOOP;
    
    RAISE NOTICE 'Time dimension populated from % to %', start_date, end_date;
END;
$$ LANGUAGE plpgsql;

-- ETL: Load fact_cve_summary
CREATE OR REPLACE FUNCTION gold.etl_load_cve_summary()
RETURNS void AS $$
BEGIN
    TRUNCATE TABLE gold.fact_cve_summary;
    
    INSERT INTO gold.fact_cve_summary (
        cve_id, title, description, category, published_date, published_year,
        published_quarter, published_month, last_modified, days_to_last_modified,
        source_identifier, remotely_exploit, primary_cvss_version, primary_cvss_score,
        primary_cvss_severity, max_cvss_v2_score, max_cvss_v3_score, max_cvss_v4_score,
        cvss_source_count, affected_vendor_count, affected_product_count
    )
    SELECT 
        c.cve_id,
        c.title,
        c.description,
        c.category,
        c.published_date::DATE,
        EXTRACT(YEAR FROM c.published_date),
        EXTRACT(QUARTER FROM c.published_date),
        EXTRACT(MONTH FROM c.published_date),
        c.last_modified::DATE,
        EXTRACT(DAY FROM (c.last_modified - c.published_date)),
        c.source_identifier,
        c.remotely_exploit,
        (SELECT f.cvss_version FROM silver.fact_cvss_scores f 
         WHERE f.cve_id = c.cve_id ORDER BY f.cvss_score DESC LIMIT 1) AS primary_cvss_version,
        (SELECT MAX(f.cvss_score) FROM silver.fact_cvss_scores f WHERE f.cve_id = c.cve_id),
        (SELECT f.cvss_severity FROM silver.fact_cvss_scores f 
         WHERE f.cve_id = c.cve_id ORDER BY f.cvss_score DESC LIMIT 1),
        (SELECT MAX(f.cvss_score) FROM silver.fact_cvss_scores f 
         WHERE f.cve_id = c.cve_id AND f.cvss_version LIKE 'v2%'),
        (SELECT MAX(f.cvss_score) FROM silver.fact_cvss_scores f 
         WHERE f.cve_id = c.cve_id AND f.cvss_version LIKE 'v3%'),
        (SELECT MAX(f.cvss_score) FROM silver.fact_cvss_scores f 
         WHERE f.cve_id = c.cve_id AND f.cvss_version LIKE 'v4%'),
        (SELECT COUNT(DISTINCT f.source_id) FROM silver.fact_cvss_scores f WHERE f.cve_id = c.cve_id),
        (SELECT COUNT(DISTINCT p.vendor) FROM silver.bridge_cve_products b 
         JOIN silver.dim_products p ON b.product_id = p.product_id WHERE b.cve_id = c.cve_id),
        (SELECT COUNT(DISTINCT b.product_id) FROM silver.bridge_cve_products b WHERE b.cve_id = c.cve_id)
    FROM silver.dim_cve c;
    
    -- Update risk scores
    UPDATE gold.fact_cve_summary
    SET risk_score = COALESCE(primary_cvss_score, 0) * 
                     (1 + CASE WHEN remotely_exploit THEN 0.5 ELSE 0 END) *
                     (1 + (affected_product_count::NUMERIC / 100)),
        criticality_flag = CASE 
            WHEN primary_cvss_score >= 9.0 THEN 'CRITICAL'
            WHEN primary_cvss_score >= 7.0 THEN 'HIGH'
            WHEN primary_cvss_score >= 4.0 THEN 'MEDIUM'
            WHEN primary_cvss_score >= 0.1 THEN 'LOW'
            ELSE 'NONE'
        END,
        exploit_likelihood = CASE 
            WHEN remotely_exploit AND primary_cvss_score >= 7.0 THEN 'HIGH'
            WHEN remotely_exploit OR primary_cvss_score >= 7.0 THEN 'MEDIUM'
            ELSE 'LOW'
        END;
    
    RAISE NOTICE 'CVE summary table loaded with % rows', (SELECT COUNT(*) FROM gold.fact_cve_summary);
END;
$$ LANGUAGE plpgsql;

-- ETL: Load vendor analytics
CREATE OR REPLACE FUNCTION gold.etl_load_vendor_analytics()
RETURNS void AS $$
BEGIN
    TRUNCATE TABLE gold.fact_vendor_analytics;
    
    INSERT INTO gold.fact_vendor_analytics (
        vendor, total_products, total_cves, critical_cves, high_cves, medium_cves, low_cves,
        avg_cvss_score, max_cvss_score, first_cve_date, last_cve_date, active_days,
        remote_exploit_percentage
    )
    SELECT 
        p.vendor,
        COUNT(DISTINCT p.product_id),
        COUNT(DISTINCT b.cve_id),
        COUNT(DISTINCT CASE WHEN s.primary_cvss_severity = 'CRITICAL' THEN b.cve_id END),
        COUNT(DISTINCT CASE WHEN s.primary_cvss_severity = 'HIGH' THEN b.cve_id END),
        COUNT(DISTINCT CASE WHEN s.primary_cvss_severity = 'MEDIUM' THEN b.cve_id END),
        COUNT(DISTINCT CASE WHEN s.primary_cvss_severity = 'LOW' THEN b.cve_id END),
        AVG(s.primary_cvss_score),
        MAX(s.primary_cvss_score),
        MIN(s.published_date),
        MAX(s.published_date),
        EXTRACT(DAY FROM (MAX(s.published_date) - MIN(s.published_date))),
        (COUNT(DISTINCT CASE WHEN s.remotely_exploit THEN b.cve_id END)::NUMERIC / 
         NULLIF(COUNT(DISTINCT b.cve_id), 0)) * 100
    FROM silver.dim_products p
    JOIN silver.bridge_cve_products b ON p.product_id = b.product_id
    JOIN gold.fact_cve_summary s ON b.cve_id = s.cve_id
    GROUP BY p.vendor
    HAVING COUNT(DISTINCT b.cve_id) > 0;
    
    -- Calculate vendor risk scores
    UPDATE gold.fact_vendor_analytics
    SET vendor_risk_score = (
            (critical_cves * 10 + high_cves * 5 + medium_cves * 2 + low_cves * 1)::NUMERIC / 
            NULLIF(total_cves, 0)
        ) * (1 + remote_exploit_percentage / 100);
    
    RAISE NOTICE 'Vendor analytics loaded with % vendors', (SELECT COUNT(*) FROM gold.fact_vendor_analytics);
END;
$$ LANGUAGE plpgsql;

-- ETL: Load ML features
CREATE OR REPLACE FUNCTION gold.etl_load_ml_features()
RETURNS void AS $$
BEGIN
    TRUNCATE TABLE gold.ml_cve_features;
    
    INSERT INTO gold.ml_cve_features (
        cve_id, cvss_v3_score, severity_class, exploit_predicted,
        published_year, published_month, published_day_of_week,
        description_length, description_word_count, title_length,
        has_poc, has_exploit_keyword,
        cvss_av, cvss_ac, cvss_pr, cvss_ui, cvss_s, cvss_c, cvss_i, cvss_a,
        affected_product_count, affected_vendor_count,
        category, remotely_exploit, source_identifier, cvss_source_count
    )
    SELECT 
        s.cve_id,
        s.max_cvss_v3_score,
        s.primary_cvss_severity,
        s.remotely_exploit,
        s.published_year,
        s.published_month,
        EXTRACT(DOW FROM s.published_date),
        LENGTH(s.description),
        array_length(string_to_array(s.description, ' '), 1),
        LENGTH(s.title),
        (s.description ILIKE '%proof of concept%' OR s.description ILIKE '%poc%'),
        (s.description ILIKE '%exploit%' OR s.title ILIKE '%exploit%'),
        (SELECT f.cvss_av FROM silver.fact_cvss_scores f 
         WHERE f.cve_id = s.cve_id AND f.cvss_version LIKE 'v3%' LIMIT 1),
        (SELECT f.cvss_ac FROM silver.fact_cvss_scores f 
         WHERE f.cve_id = s.cve_id AND f.cvss_version LIKE 'v3%' LIMIT 1),
        (SELECT f.cvss_pr FROM silver.fact_cvss_scores f 
         WHERE f.cve_id = s.cve_id AND f.cvss_version LIKE 'v3%' LIMIT 1),
        (SELECT f.cvss_ui FROM silver.fact_cvss_scores f 
         WHERE f.cve_id = s.cve_id AND f.cvss_version LIKE 'v3%' LIMIT 1),
        (SELECT f.cvss_s FROM silver.fact_cvss_scores f 
         WHERE f.cve_id = s.cve_id AND f.cvss_version LIKE 'v3%' LIMIT 1),
        (SELECT f.cvss_c FROM silver.fact_cvss_scores f 
         WHERE f.cve_id = s.cve_id AND f.cvss_version LIKE 'v3%' LIMIT 1),
        (SELECT f.cvss_i FROM silver.fact_cvss_scores f 
         WHERE f.cve_id = s.cve_id AND f.cvss_version LIKE 'v3%' LIMIT 1),
        (SELECT f.cvss_a FROM silver.fact_cvss_scores f 
         WHERE f.cve_id = s.cve_id AND f.cvss_version LIKE 'v3%' LIMIT 1),
        s.affected_product_count,
        s.affected_vendor_count,
        s.category,
        s.remotely_exploit,
        s.source_identifier,
        s.cvss_source_count
    FROM gold.fact_cve_summary s;
    
    -- Feature engineering
    UPDATE gold.ml_cve_features
    SET 
        is_buffer_overflow = (category ILIKE '%buffer%overflow%'),
        is_injection = (category ILIKE '%injection%' OR category ILIKE '%sql%'),
        is_xss = (category ILIKE '%xss%' OR category ILIKE '%cross%site%'),
        is_authentication = (category ILIKE '%auth%' OR category ILIKE '%login%'),
        attack_complexity_low = (cvss_ac IN ('LOW', 'L')),
        privileges_required_none = (cvss_pr IN ('NONE', 'N')),
        user_interaction_none = (cvss_ui IN ('NONE', 'N'));
    
    RAISE NOTICE 'ML features table loaded with % rows', (SELECT COUNT(*) FROM gold.ml_cve_features);
END;
$$ LANGUAGE plpgsql;

-- Master ETL orchestrator
CREATE OR REPLACE FUNCTION gold.run_full_etl()
RETURNS void AS $$
BEGIN
    RAISE NOTICE 'Starting Gold Layer ETL...';
    
    -- Ensure time dimension is populated
    PERFORM gold.populate_dim_time(
        (SELECT MIN(published_date::DATE) FROM silver.dim_cve),
        CURRENT_DATE + INTERVAL '1 year'
    );
    
    -- Load fact tables
    PERFORM gold.etl_load_cve_summary();
    PERFORM gold.etl_load_vendor_analytics();
    PERFORM gold.etl_load_ml_features();
    
    -- Refresh materialized views
    REFRESH MATERIALIZED VIEW CONCURRENTLY gold.mv_executive_dashboard;
    REFRESH MATERIALIZED VIEW CONCURRENTLY gold.mv_top_risky_vendors;
    REFRESH MATERIALIZED VIEW CONCURRENTLY gold.mv_category_trends;
    REFRESH MATERIALIZED VIEW CONCURRENTLY gold.mv_cvss_distribution;
    
    RAISE NOTICE 'Gold Layer ETL completed successfully!';
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 10. UTILITY VIEWS FOR QUICK ACCESS
-- ============================================================================

-- Latest CVEs (for operational dashboards)
CREATE OR REPLACE VIEW gold.v_latest_critical_cves AS
SELECT 
    cve_id,
    title,
    primary_cvss_score,
    primary_cvss_severity,
    published_date,
    affected_product_count,
    remotely_exploit
FROM gold.fact_cve_summary
WHERE primary_cvss_severity IN ('CRITICAL', 'HIGH')
  AND published_date >= CURRENT_DATE - INTERVAL '30 days'
ORDER BY published_date DESC, primary_cvss_score DESC;

-- Vendor risk scoreboard
CREATE OR REPLACE VIEW gold.v_vendor_scoreboard AS
SELECT 
    vendor,
    total_cves,
    critical_cves,
    vendor_risk_score,
    RANK() OVER (ORDER BY vendor_risk_score DESC) AS risk_rank,
    RANK() OVER (ORDER BY total_cves DESC) AS volume_rank
FROM gold.fact_vendor_analytics