# 📊 Documentation des Vues BI - Gold Layer CVE Analytics

## Architecture Générale

```
┌─────────────────────────────────────────────────────────────────┐
│                     GOLD LAYER SCHEMA                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │   dim_cve    │  │ dim_vendor   │  │ dim_products │          │
│  │  (77,525)    │  │  (12,077)    │  │  (56,456)    │          │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘          │
│         │                 │                  │                   │
│  ┌──────┴───────┐  ┌──────┴──────────────────┴───────┐          │
│  │   cvss_v2    │  │      bridge_cve_products         │          │
│  │   cvss_v3    │  │         (285,641)                │          │
│  │   cvss_v4    │  └──────────────────────────────────┘          │
│  └──────────────┘                                                │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                    16 VUES BI ANALYTIQUES                        │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐                │
│  │   FACTS    │  │ AGGREGATES │  │ DASHBOARDS │                │
│  └────────────┘  └────────────┘  └────────────┘                │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📑 CATÉGORIE 1: VUES DE FAITS (FACT TABLES)

### 🔷 **1. fact_cve_complete**
**Description:** Vue centrale qui combine chaque CVE avec TOUS ses scores CVSS disponibles (V2, V3, V4)

**Colonnes Principales:**
- Informations CVE: `cve_id`, `title`, `description`, `category`, `published_date`, `cve_year`
- Scores CVSS V2: `cvss_v2_score`, `cvss_v2_severity`, métriques (AV, AC, AU, C, I, A)
- Scores CVSS V3: `cvss_v3_score`, `cvss_v3_severity`, métriques (AV, AC, PR, UI, S, C, I, A)
- Scores CVSS V4: `cvss_v4_score`, `cvss_v4_severity`, métriques V4
- **Calculs automatiques**: `best_cvss_score`, `best_cvss_severity`, `primary_cvss_version`

**Relations:**
- JOIN avec `dim_cve` (1:1)
- LEFT JOIN avec `cvss_v2`, `cvss_v3`, `cvss_v4` (1:n)

**Usage Power BI:**
```
📊 Visualisations recommandées:
- Table détaillée des CVE avec filtres sur severity
- Cards pour afficher les scores moyens
- Scatter plot: CVSS V2 vs V3 comparison
- Gauge chart pour "best_cvss_score"

🔗 Relations Power BI:
- Lier à dim_cve par cve_id (many-to-one)
- Utiliser comme table de faits principale
```

---

### 🔷 **2. fact_cve_products**
**Description:** Relation enrichie CVE ↔ Products ↔ Vendors avec scores CVSS

**Colonnes Principales:**
- IDs: `cve_id`, `product_id`, `vendor_id`, `bridge_id`
- CVE info: `cve_title`, `cve_category`, `published_date`, `cve_year`
- Product: `product_name`, `product_total_cves`
- Vendor: `vendor_name`, `vendor_total_products`, `vendor_total_cves`
- CVSS: `cvss_score`, `cvss_severity` (priorité V3 > V2 > V4)

**Relations:**
- JOIN `bridge_cve_products` + `dim_cve` + `dim_products` + `dim_vendor`
- Résout la relation many-to-many

**Usage Power BI:**
```
📊 Visualisations recommandées:
- Matrix: Vendors × Products avec count de CVE
- Treemap: Hiérarchie Vendor > Product > CVE
- Stacked bar chart: Top vendors par severity
- Drill-down: Vendor → Products → CVEs

🔗 Relations Power BI:
- Lier à dim_vendor par vendor_id
- Lier à dim_products par product_id
- Utiliser pour analyses croisées
```

---

### 🔷 **3. fact_cve_timeline**
**Description:** Timeline complète avec dimensions temporelles multiples pour analyses de séries temporelles

**Colonnes Principales:**
- Dates: `published_date`, `published_date_only`, `last_modified`
- Dimensions temporelles: `cve_year`, `published_month`, `published_quarter`, `year_month`, `year_quarter`
- CVE info: `title`, `category`, `cvss_score`, `cvss_severity`
- Métriques: `affected_products_count`, `affected_vendors_count`
- Détails techniques: `attack_vector`, `attack_complexity`, impacts CIA

**Relations:**
- Agrégation de `dim_cve` + CVSS + produits/vendors
- GROUP BY par CVE avec counts

**Usage Power BI:**
```
📊 Visualisations recommandées:
- Line chart: Évolution CVE par mois/trimestre
- Area chart: Distribution severity dans le temps
- Calendar visual: Heatmap par date
- Time slicer pour filtrage temporel

🔗 Relations Power BI:
- Créer table Calendar séparée
- Lier published_date à Calendar[Date]
- Utiliser year_month pour agrégations
```

---

## 📊 CATÉGORIE 2: VUES D'AGRÉGATION TEMPORELLE

### 🔶 **4. agg_cve_by_year**
**Description:** Agrégation annuelle complète avec statistiques CVSS par version

**Métriques Calculées:**
- Counts: `total_cves`, `categorized_cves`, `remote_exploit_cves`
- CVSS V2: `cves_with_v2`, `avg_cvss_v2_score`, counts par severity
- CVSS V3: `cves_with_v3`, `avg_cvss_v3_score`, counts par severity
- CVSS V4: `cves_with_v4`, `avg_cvss_v4_score`
- Dates: `first_cve_date`, `last_cve_date`

**Grain:** Une ligne par année

**Usage Power BI:**
```
📊 Visualisations:
- Column chart: Total CVE par année
- Stacked column: Distribution severity par année
- Line chart multi-séries: Avg scores V2 vs V3
- KPI cards: YoY growth %

🎯 Mesures DAX recommandées:
YoY_Growth = 
DIVIDE(
    [Total CVEs Current Year] - [Total CVEs Previous Year],
    [Total CVEs Previous Year]
)
```

---

### 🔶 **5. agg_monthly_cve_trends**
**Description:** Tendances mensuelles détaillées avec distribution de sévérité

**Métriques:**
- Counts: `total_cves`, `remote_cves`
- Severity: `critical_count`, `high_count`, `medium_count`, `low_count`
- Stats: `avg_cvss_score`
- Metadata: `affected_vendors_count`, `affected_products_count`

**Grain:** Une ligne par mois (depuis 2010)

**Usage Power BI:**
```
📊 Visualisations:
- Area chart: Trend mensuel avec severity colors
- Ribbon chart: Évolution ranking severity
- Waterfall chart: Variation month-over-month
- Moving average: Smooth trends

📅 Filtres temporels:
- Slicer sur year + month_num
- Relative date filtering (Last 12 months)
```

---

### 🔶 **6. agg_weekly_cve_heatmap**
**Description:** Carte thermique hebdomadaire avec indicateurs de risque

**Métriques:**
- Temporal: `week_start`, `year`, `week_number`
- Counts: `total_cves`, severity distribution
- Calculated: `avg_cvss_score`, `risk_level`

**Valeurs risk_level:**
- "Very High Risk" (>10 critical)
- "High Risk" (5-10 critical)
- "Elevated Risk" (>20 high)
- "Normal"

**Usage Power BI:**
```
📊 Visualisations:
- Matrix heatmap: Week × Risk Level (conditional formatting)
- Line chart: CVE count par semaine
- Calendar visual avec color coding
- Anomaly detection visuals

🎨 Conditional Formatting:
Risk Level → Color:
- Very High: #D32F2F (rouge foncé)
- High: #F57C00 (orange)
- Elevated: #FBC02D (jaune)
- Normal: #388E3C (vert)
```

---

## 🏢 CATÉGORIE 3: VUES VENDOR/PRODUCT

### 🔵 **7. agg_vendor_risk_score**
**Description:** Score de risque calculé par vendor avec formule pondérée

**Métriques:**
- Counts: `total_cves`, `affected_products`
- Severity: `critical_cves`, `high_cves`, `medium_cves`, `low_cves`
- Scores: `avg_cvss_score`, `max_cvss_score`
- **Risk Score (formule)**: `(Critical×10 + High×5 + Medium×2 + Low×1) / Total CVEs`
- Temporal: `days_with_cves`

**Usage Power BI:**
```
📊 Visualisations:
- Bar chart: Top 20 vendors par risk_score
- Scatter plot: Total CVEs (X) vs Risk Score (Y)
- Table with conditional formatting
- Gauge charts pour top vendors

🎯 Top Vendors KPI:
CREATE MEASURE [Top Vendor Risk] = 
CALCULATE(
    MAX([risk_score]),
    TOPN(1, ALL(Vendors), [risk_score], DESC)
)
```

---

### 🔵 **8. agg_product_vulnerability**
**Description:** Analyse détaillée des vulnérabilités par produit

**Métriques:**
- Product: `product_name`, `total_cves`
- Vendor: `vendor_name`
- Severity distribution complète
- CVSS: `avg_cvss_score`, `max_cvss_score`, `min_cvss_score`
- `remote_exploit_count`
- **Activity Status**: "Active" / "Recent" / "Old"

**Usage Power BI:**
```
📊 Visualisations:
- Treemap: Product size by total_cves, color by avg_cvss_score
- Table: Sortable product list avec drill-through
- Donut chart: Activity status distribution
- Clustered bar: Top products par vendor

🔍 Drill-through page:
Product Detail → Liste des CVE individuels
Filtres: Severity, Activity Status, Date Range
```

---

### 🔵 **9. agg_vendor_product_matrix**
**Description:** Matrice croisée complète avec priorités de risque

**Métriques:**
- IDs et noms vendor/product
- Severity breakdown complet
- `avg_cvss_score`
- Temporal: `first_vulnerability`, `latest_vulnerability`, `latest_year`
- **Threat Status**: "Active Threats" / "Recent History" / "Legacy Vulnerabilities"
- **Priority Level**: P1-Critical, P2-High, P3-Monitor, P4-Low

**Usage Power BI:**
```
📊 Visualisations:
- Matrix: Vendor (rows) × Product (cols) → CVE count
- Heat table avec conditional formatting
- Decomposition tree: Vendor → Product → Priority
- Slicers: Threat Status, Priority Level

📋 Priority Dashboard:
Tabs par priority:
- P1: Immediate action required
- P2: Schedule remediation
- P3: Monitoring dashboard
- P4: Archive/Reference
```

---

## 🔬 CATÉGORIE 4: ANALYSES TECHNIQUES

### 🟣 **10. agg_cvss_version_comparison**
**Description:** Comparaison directe entre scores CVSS V2 et V3

**Métriques:**
- Scores: `cvss_v2_score`, `cvss_v3_score`
- Severities: `cvss_v2_severity`, `cvss_v3_severity`
- **Calculated**: `score_difference_v3_vs_v2`
- **Severity Change**: "Changed" / "Same" / "N/A"
- Flags: `has_v2`, `has_v3`, `has_v4`

**Usage Power BI:**
```
📊 Visualisations:
- Scatter plot: V2 Score (X) vs V3 Score (Y), diagonal reference line
- Histogram: Distribution of score_difference
- Table: CVEs where severity changed
- Funnel: Count by version availability

💡 Insights à chercher:
- CVEs upgraded to higher severity in V3
- Average score increase V2→V3
- % of CVEs with changed severity classification
```

---

### 🟣 **11. agg_top_attack_vectors**
**Description:** Distribution des CVE par vecteur d'attaque

**Vecteurs:**
- **N**: Network (le plus dangereux)
- **A**: Adjacent Network
- **L**: Local
- **P**: Physical

**Métriques:**
- `total_cves`, severity distribution
- `avg_cvss_score`, `max_cvss_score`
- `recent_cves_last_year`

**Usage Power BI:**
```
📊 Visualisations:
- Pie chart: Distribution par attack_vector_name
- Funnel chart: Network → Adjacent → Local → Physical
- Stacked bar: Severity within each vector
- Line trend: Evolution of network attacks over time

🎯 Security Focus:
Priority = Network attacks + (Critical OR High severity)
```

---

### 🟣 **12. agg_cia_impact_analysis**
**Description:** Analyse des impacts sur CIA Triad

**Dimensions:**
- **Confidentiality**: None/Low/High
- **Integrity**: None/Low/High
- **Availability**: None/Low/High
- **Impact Type**: "Full CIA Impact" vs "Partial Impact"

**Métriques:**
- `total_cves`, `avg_cvss_score`

**Usage Power BI:**
```
📊 Visualisations:
- 3D scatter (si disponible): C×I×A, size=count
- Matrix heatmap: C (rows) × I (cols), color=A
- Sankey diagram: Impact flow
- Donut: Full CIA vs Partial

🛡️ Business Impact:
High Confidentiality → Data breach risk
High Integrity → Data tampering risk
High Availability → Service disruption risk
```

---

### 🟣 **13. agg_exploitability_analysis**
**Description:** Facilité d'exploitation (combien c'est facile à exploiter)

**Dimensions:**
- **Attack Complexity**: Low/Medium/High
- **Privileges Required**: None/Low/High
- **User Interaction**: None/Required

**Métriques:**
- `avg_exploitability_score`
- **easy_to_exploit_count**: AC=Low + PR=None + UI=None (très dangereux!)

**Usage Power BI:**
```
📊 Visualisations:
- Funnel: Easy → Medium → Hard to exploit
- Matrix: Complexity × Privileges Required
- Bar chart: easy_to_exploit_count (alert visual!)
- Scatter: Exploitability vs Impact score

⚠️ Critical Filter:
WHERE easy_to_exploit = TRUE 
  AND severity IN ('CRITICAL', 'HIGH')
→ Immediate patching priority
```

---

### 🟣 **14. agg_cve_age_analysis**
**Description:** Âge des CVE avec priorités basées sur ancienneté

**Métriques:**
- `days_since_published`, `years_since_published`
- **Age Categories**:
  - 0-30 days
  - 31-90 days
  - 91-180 days
  - 6-12 months
  - 1-2 years
  - 2-5 years
  - 5+ years
- **Priority Status**: "Urgent", "High Priority", "Review", "Standard"

**Usage Power BI:**
```
📊 Visualisations:
- Column chart: CVE count par age_category
- Line trend: Age distribution over time
- Table: Urgent + High Priority items (top list)
- Donut: Priority Status distribution

⏰ SLA Tracking:
- 0-30 days + Critical = Missed SLA alert
- Old High Severity = Review required
```

---

## 📈 CATÉGORIE 5: VUES TABLEAU DE BORD

### 🟢 **15. dashboard_executive_summary**
**Description:** Vue unique avec TOUS les KPIs exécutifs (1 ligne seulement!)

**KPIs Inclus:**
```
Counts Globaux:
- total_cves, total_vendors, total_products

Current Year:
- cves_current_year, cves_last_year

Severity (all-time):
- total_critical, total_high, total_medium, total_low

Averages:
- avg_cvss_v3_score, avg_cvss_v2_score

Security:
- total_remote_exploits

Recent Activity:
- cves_last_30_days

Top Performers:
- top_vendor_by_cves, top_vendor_cve_count

Metadata:
- latest_cve_update, data_load_timestamp
```

**Usage Power BI:**
```
📊 Page "Executive Dashboard":

Row 1 - Big Numbers:
┌─────────────┬─────────────┬─────────────┬─────────────┐
│  Total CVEs │   Vendors   │  Products   │ Avg Score   │
│   77,525    │   12,077    │   56,456    │    7.2      │
└─────────────┴─────────────┴─────────────┴─────────────┘

Row 2 - Severity Distribution (Cards):
┌─────────────┬─────────────┬─────────────┬─────────────┐
│  Critical   │    High     │   Medium    │     Low     │
│  [number]   │  [number]   │  [number]   │  [number]   │
└─────────────┴─────────────┴─────────────┴─────────────┘

Row 3 - Trends:
┌─────────────────────┬───────────────────────────────┐
│  This Year vs Last  │   Last 30 Days Activity       │
│   [+15%] ↑          │   [number] new CVEs           │
└─────────────────────┴───────────────────────────────┘

Row 4 - Top Vendor Card:
┌─────────────────────────────────────────────────────┐
│  🏆 Most Affected: [vendor_name]                    │
│     Total CVEs: [count]                             │
└─────────────────────────────────────────────────────┘

Footer:
Last Updated: [data_load_timestamp]

🎯 Utilisation:
SELECT * FROM dashboard_executive_summary;
→ Retourne 1 ligne avec toutes les métriques
→ Parfait pour cards Power BI
→ Refresh rapide
```

---

## 🔗 RELATIONS ENTRE LES VUES DANS POWER BI

### Modèle de Données Recommandé:

```
                    ┌─────────────────────┐
                    │  Calendar Table     │ ← Dimension Date
                    │  (créée dans PBI)   │
                    └──────────┬──────────┘
                               │
                    ┌──────────┴──────────┐
                    │                     │
         ┌──────────▼────────┐ ┌─────────▼──────────┐
         │ fact_cve_timeline │ │ agg_monthly_trends │
         │ fact_cve_complete │ │ agg_weekly_heatmap │
         └──────────┬────────┘ └────────────────────┘
                    │
         ┌──────────┴──────────┐
         │                     │
┌────────▼────────┐   ┌────────▼─────────┐
│  dim_cve        │   │ dim_vendor       │
│  (dimension)    │   │ (dimension)      │
└────────┬────────┘   └────────┬─────────┘
         │                     │
         │            ┌────────▼─────────┐
         │            │ dim_products     │
         │            │ (dimension)      │
         │            └──────────────────┘
         │
┌────────▼────────────────────────────────┐
│      Toutes les vues d'agrégation       │
│  (agg_cve_by_year, agg_vendor_risk,     │
│   agg_product_vulnerability, etc.)      │
└─────────────────────────────────────────┘
```

### Configuration des Relations:

1. **Calendar ↔ Fact Tables**
   - `Calendar[Date]` ← → `fact_cve_timeline[published_date_only]`
   - Type: Many-to-one
   - Direction: Both

2. **dim_cve ↔ Fact Tables**
   - `dim_cve[cve_id]` ← → `fact_cve_complete[cve_id]`
   - Type: One-to-many
   - Direction: Both

3. **dim_vendor ↔ dim_products**
   - `dim_vendor[vendor_id]` ← → `dim_products[vendor_id]`
   - Type: One-to-many
   - Direction: Both

4. **Vues d'agrégation**: Généralement en mode Import, pas de relations directes (utilisées indépendamment)

---

## 📋 GUIDE D'IMPLÉMENTATION POWER BI

### Étape 1: Connexion PostgreSQL
```
Power BI Desktop → Get Data → PostgreSQL
Server: [votre_host]
Database: tip
Advanced: SET search_path TO gold;
```

### Étape 2: Importer les Vues (Ordre recommandé)

**Phase 1 - Dimensions (Import):**
1. dim_cve
2. dim_vendor
3. dim_products
4. dim_cvss_source

**Phase 2 - Facts (Import):**
5. fact_cve_complete
6. fact_cve_products
7. fact_cve_timeline

**Phase 3 - Agrégations (Import):**
8. dashboard_executive_summary
9. agg_cve_by_year
10. agg_monthly_cve_trends
11. agg_vendor_risk_score
12. agg_product_vulnerability
13. (autres selon besoins)

**Phase 4 - Analyses Spécialisées (DirectQuery ou Import selon volume):**
14. Vues techniques (CVSS comparison, CIA, etc.)

### Étape 3: Créer Calendar Table (DAX)
```dax
Calendar = 
ADDCOLUMNS(
    CALENDAR(DATE(2010,1,1), TODAY()),
    "Year", YEAR([Date]),
    "Month", MONTH([Date]),
    "MonthName", FORMAT([Date], "MMMM"),
    "Quarter", "Q" & FORMAT([Date], "Q"),
    "YearMonth", FORMAT([Date], "YYYY-MM"),
    "WeekNum", WEEKNUM([Date])
)
```

### Étape 4: Mesures DAX Essentielles

```dax
// === MESURES DE BASE ===
Total CVEs = COUNTROWS(fact_cve_complete)

Avg CVSS Score = AVERAGE(fact_cve_complete[best_cvss_score])

Critical Count = 
CALCULATE(
    [Total CVEs],
    fact_cve_complete[best_cvss_severity] = "CRITICAL"
)

// === MESURES TEMPORELLES ===
CVEs YoY Growth = 
VAR CurrentYear = [Total CVEs]
VAR PreviousYear = 
    CALCULATE(
        [Total CVEs],
        DATEADD(Calendar[Date], -1, YEAR)
    )
RETURN
DIVIDE(CurrentYear - PreviousYear, PreviousYear, 0)

CVEs MTD = 
CALCULATE(
    [Total CVEs],
    DATESMTD(Calendar[Date])
)

// === MESURES DE RISQUE ===
High Risk CVEs = 
CALCULATE(
    [Total CVEs],
    fact_cve_complete[best_cvss_score] >= 7
)

Risk Percentage = 
DIVIDE(
    [High Risk CVEs],
    [Total CVEs],
    0
)

// === MESURES VENDOR ===
Top Vendor = 
FIRSTNONBLANK(
    TOPN(1, VALUES(dim_vendor[vendor_name]), [Total CVEs], DESC),
    1
)

Vendor Risk Score = 
CALCULATE(
    AVERAGE(agg_vendor_risk_score[risk_score]),
    ALLSELECTED(dim_vendor)
)
```

---

## 🎨 PAGES POWER BI RECOMMANDÉES

### Page 1: Executive Dashboard
- Source: `dashboard_executive_summary`
- Visuals: Cards, Gauges, Trend sparklines
- Update: Real-time

### Page 2: CVE Trends
- Source: `agg_monthly_cve_trends`, `fact_cve_timeline`
- Visuals: Line charts, Area charts, Heatmap
- Filters: Date range, Severity

### Page 3: Vendor Risk Analysis
- Source: `agg_vendor_risk_score`, `agg_vendor_product_matrix`
- Visuals: Bar charts, Scatter plots, Matrix
- Drill-through: Vendor detail page

### Page 4: Product Vulnerabilities
- Source: `agg_product_vulnerability`, `fact_cve_products`
- Visuals: Treemap, Table, Donut charts
- Filters: Vendor, Activity Status

### Page 5: Technical Analysis
- Source: `agg_top_attack_vectors`, `agg_cia_impact_analysis`, `agg_exploitability_analysis`
- Visuals: Sankey, Matrix heatmaps, Funnel
- For: Security analysts

### Page 6: CVSS Comparison
- Source: `agg_cvss_version_comparison`
- Visuals: Scatter plot V2 vs V3, Histogram
- Insights: Scoring changes

### Page 7: Age & Priority
- Source: `agg_cve_age_analysis`
- Visuals: Column chart by age category, Priority table
- Alerts: Urgent items highlighted

---

## ⚡ OPTIMISATIONS PERFORMANCE

### Import vs DirectQuery:

**Import Mode (Recommandé pour):**
- dashboard_executive_summary
- Toutes les vues agg_*
- fact_cve_timeline

**DirectQuery (Si données très volumineuses):**
- fact_cve_complete (67K+ lignes CVSS)
- fact_cve_products (285K+ lignes bridge)

### Indexes PostgreSQL (déjà créés):
```sql
-- Déjà présents dans votre schéma
idx_gold_dim_cve_published
idx_gold_dim_cve_year
idx_gold_cvss_v3_score
idx_gold_cvss_v3_severity
```

### Refresh Strategy:
- **Dimensions**: Refresh quotidien (nuit)
- **Facts**: Refresh toutes les 4h
- **Agrégations**: Refresh après facts
- **Executive Summary**: Refresh en temps réel (cache 15min)

---

## 🎯 QUICK START CHECKLIST

```
□ 1. Exécuter le script SQL des 16 vues
□ 2. Vérifier les vues dans pgAdmin/psql
□ 3. Ouvrir Power BI Desktop
□ 4. Connexion PostgreSQL → gold schema
□ 5. Importer dashboard_executive_summary
□ 6. Créer page Executive avec cards
□ 7. Importer dim_cve, dim_vendor, dim_products
□ 8. Importer fact_cve_timeline
□ 9. Créer Calendar table (DAX)
□ 10. Configurer relations
□ 11. Créer mesures DAX essentielles
□ 12. Builder page Trends avec monthly data
□ 13. Builder page Vendor Risk
□ 14. Tester filtres et drill-through
□ 15. Publish vers Power BI Service
□ 16. Configurer scheduled refresh
```

---

## 📞 RÉSUMÉ DES VUES PAR USE CASE

| Use Case | Vues Recommandées | Visualisations |
|----------|-------------------|----------------|
| **Executive Reporting** | dashboard_executive_summary, agg_cve_by_year | Cards, KPIs, Trend lines |
| **Security Operations** | fact_cve_timeline, agg_weekly_heatmap, agg_cve_age_analysis | Calendar heatmap, Priority list |
| **Vendor Management** | agg_vendor_risk_score, agg_vendor_product_matrix | Risk matrix, Scatter plots |
| **Product Tracking** | agg_product_vulnerability, fact_cve_products | Treemap, Drill-down tables |
| **Threat Intelligence** | agg_top_attack_vectors, agg_exploitability_analysis | Funnel, Sankey diagram |
| **CVSS Analysis** | agg_cvss_version_comparison, fact_cve_complete | Scatter V2 vs V3, Histograms |
| **Compliance** | agg_cia_impact_analysis, agg_cve_by_category | Matrix heatmap, Distribution |

---

**🚀 Vous êtes maintenant prêt à créer des dashboards Power BI professionnels!**