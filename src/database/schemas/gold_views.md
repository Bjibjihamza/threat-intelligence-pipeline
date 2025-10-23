# 📊 Documentation des Vues BI – Gold Layer CVE Analytics (nouveau schéma “vulnarbilit”)

## Architecture générale

```
┌─────────────────────────────────────────────────────────────────┐
│                         GOLD LAYER SCHEMA                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │   dim_cve    │  │ dim_vendor   │  │ dim_products │          │
│  │  (cardinalités dynamiques selon vos chargements)            │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘          │
│         │                 │                  │                  │
│  ┌──────┴───────┐  ┌──────┴──────────────────┴───────┐         │
│  │   cvss_v2    │  │      bridge_cve_products         │         │
│  │   cvss_v3    │  │          (M:N CVE↔Produit)       │         │
│  │   cvss_v4    │  └──────────────────────────────────┘         │
│  └──────────────┘                                               │
└─────────────────────────────────────────────────────────────────┘
                               ↓
┌─────────────────────────────────────────────────────────────────┐
│                       VUES BI PRINCIPALES                       │
│  ┌────────────┐  ┌────────────┐  ┌───────────────────────────┐ │
│  │   FACTS    │  │ AGGREGATS  │  │   UTILITAIRES / RÉCENTS   │ │
│  └────────────┘  └────────────┘  └───────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📑 Catégorie 1 : Vues “Fact” (grain CVE)

### 🔷 1) `gold.v_cve_fact`

**Description** : ligne par CVE, enrichie avec **le meilleur CVSS v3** (score + métriques).  
**Colonnes clés** :

* Identité & dates : `cve_id`, `published_date`, `last_modified`, `loaded_at`, `cve_year`
* Catégorie : `category` (alias de `vulnarbilit`, fallback “uncategorized”)
* Remote : `remotely_exploit` (`true`/`false`/`unknown`)
* CVSS v3 (best): `cvss_version`, `cvss_score`, `cvss_severity`, `cvss_vector`, `base_av`, `base_ac`, `base_pr`, `base_ui`, `base_s`, `base_c`, `base_i`, `base_a`, `cvss_exploitability_score`, `cvss_impact_score`

**Sources** : `dim_cve` + `v_cvss_v3_best`  
**Usage PBI** :

* Table de faits principale (séries temporelles, distribution de sévérité)
* Slicers : année, catégorie, severité, remote

---

## 📊 Catégorie 2 : Vues d’agrégation

### 🔶 2) `gold.v_yearly_trend`

**Description** : total de CVEs par **année**.  
**Colonnes** : `cve_year`, `total_cves`  
**Visuals** : Column chart années, KPI YoY.

### 🔶 3) `gold.v_monthly_trend`

**Description** : total de CVEs par **mois**.  
**Colonnes** : `month_start (date)`, `total_cves`  
**Visuals** : Line chart mensuel, moving average.

### 🔶 4) `gold.v_cvss_buckets`

**Description** : répartition par **bucket** (Unscored/Low/Medium/High/Critical) selon `cvss_score` v3-best.  
**Colonnes** : `cvss_bucket`, `total_cves`  
**Visuals** : Donut/Stacked bar pour mix de sévérité.

### 🔶 5) `gold.v_top_vendors`

**Description** : top vendors par **nombre de CVEs distincts**.  
**Colonnes** : `vendor_id`, `vendor_name`, `total_cves`  
**Visuals** : Bar chart Top N vendors, drill-through vers produits.

### 🔶 6) `gold.v_top_products`

**Description** : top produits par **nombre de CVEs distincts**.  
**Colonnes** : `product_id`, `product_name`, `vendor_id`, `vendor_name`, `total_cves`  
**Visuals** : Treemap/Bar chart produits.

---

## 🧩 Catégorie 3 : Vues relationnelles & de sélection

### 🔵 7) `gold.v_cve_products`

**Description** : table de pont **CVE × Produit × Vendor** (noms inclus).  
**Colonnes** : `cve_id`, `product_id`, `product_name`, `vendor_id`, `vendor_name`, `link_created_at`  
**Usage** : matrices Vendor→Product, listes détaillées, drill-through.

### 🔵 8) `gold.v_cvss_v3_best`

**Description** : **meilleure** rangée CVSS v3 par CVE (score max, tie-break `created_at`).  
**Colonnes** : `cve_id`, `cvss_score`, `cvss_severity`, métriques v3, `source_id`, `cvss_version`  
**Usage** : normaliser l’analyse V3 (évite les doublons multi-sources).

### 🔵 9) `gold.v_recent_cves`

**Description** : CVEs publiées **sur les 30 derniers jours** (tri par date puis score).  
**Colonnes** : `cve_id`, `published_date`, `category`, `cvss_score`, `cvss_severity`  
**Usage** : “What’s new?” cards, page “Recent Activity”.

### 🔵 10) `gold.v_cve_vendor_summary`

**Description** : **CVE × Vendor** (une ligne par CVE×Vendor) + best v3.  
**Colonnes** :  
`cve_id`, `category`, `published_date`, `cve_year`, `remotely_exploit`,  
`vendor_id`, `vendor_name`, `cvss_v3_score_best`, `cvss_v3_severity`, `is_critical_v3`  
**Usage** : matrices Vendor/CVEs, filtres Vendor-first.

---

## 🔗 Modèle de données recommandé (Power BI)

* **Table calendrier** (DAX) reliée à `v_cve_fact[published_date]` (Many-to-one, single ou both)
* `dim_cve`/`dim_vendor`/`dim_products` peuvent être **importées** si besoin de slicers “maître”.
* Les **agrégats** (`v_*trend`, `v_*top*`, `v_cvss_buckets`) s’utilisent **sans relations** (pages dédiées / visuels directs).

**Calendar DAX (exemple)**

```dax
Calendar =
ADDCOLUMNS(
  CALENDAR(DATE(2010,1,1), TODAY()),
  "Year", YEAR([Date]),
  "Month", MONTH([Date]),
  "MonthName", FORMAT([Date], "MMMM"),
  "Quarter", "Q" & FORMAT([Date], "Q"),
  "YearMonth", FORMAT([Date], "YYYY-MM"),
  "WeekNum", WEEKNUM([Date], 2)
)
```

---

## 🧠 Mesures DAX utiles (basées sur `v_cve_fact`)

```dax
Total CVEs = COUNTROWS('v_cve_fact')

Avg CVSS (V3 Best) = AVERAGE('v_cve_fact'[cvss_score])

Critical Count =
CALCULATE([Total CVEs], 'v_cve_fact'[cvss_severity] = "CRITICAL")

CVEs YoY % =
VAR Cur = [Total CVEs]
VAR Prev = CALCULATE([Total CVEs], DATEADD(Calendar[Date], -1, YEAR))
RETURN DIVIDE(Cur - Prev, Prev, 0)

High Risk CVEs (≥7) =
CALCULATE([Total CVEs], 'v_cve_fact'[cvss_score] >= 7)

Recent 30 Days =
CALCULATE([Total CVEs], 'v_cve_fact'[published_date] >= TODAY() - 30)
```

---

## 🎨 Pages Power BI (suggestions rapides)

1. **Executive** :

* Cards : Total CVEs, Avg CVSS, Critical/High/Medium/Low
* Charts : Yearly trend (`v_yearly_trend`), Last 30 days (`v_recent_cves`)

2. **Trends** :

* Line chart : `v_monthly_trend`
* Donut : `v_cvss_buckets`
* Table : `v_cve_fact` (détails filtrables)

3. **Vendor/Product** :

* Bar chart : `v_top_vendors`
* Treemap / Bar : `v_top_products`
* Matrix : `v_cve_products` (Vendor→Product, count CVEs)

4. **Operations (Recent)** :

* Table : `v_recent_cves`
* Alert list : filtrer `cvss_severity IN ("CRITICAL","HIGH")`

---

## ⚡ Performances & refresh

* Les indexes critiques sont déjà présents (dates, années, score/severity).
* Mode **Import** recommandé pour les agrégats ; **DirectQuery** possible pour des pages “recent” à gros volume si nécessaire.
* Ordre de refresh : **dim** → **facts** → **agrégats** → pages exécutives.

---

## ✅ Checklist de mise en route

```
□ SET search_path TO gold; côté connecteur PBI
□ Importer v_cve_fact, v_yearly_trend, v_monthly_trend, v_cvss_buckets
□ Importer v_top_vendors, v_top_products, v_cve_products, v_recent_cves
□ (Option) Importer dim_* pour slicers globaux
□ Créer Calendar (DAX) + relations avec v_cve_fact
□ Ajouter mesures DAX ci-dessus
□ Construire pages Executive / Trends / Vendor-Product / Recent
```

---

## 🧭 Cartographie “Ancienne doc → Nouveau schéma”

| Ancienne notion         | Nouvelle vue/colonne                                      |
| ----------------------- | --------------------------------------------------------- |
| `category` texte        | `vulnarbilit` (exposé comme `category` dans `v_cve_fact`) |
| “Best CVSS”             | `v_cvss_v3_best` (puis joint dans `v_cve_fact`)           |
| “Vendor summary”        | `v_cve_vendor_summary`                                    |
| “Monthly/Yearly trends” | `v_monthly_trend` / `v_yearly_trend`                      |
| “Severity mix”          | `v_cvss_buckets`                                          |
| “CVE×Produit×Vendor”    | `v_cve_products`                                          |
| “Recent CVEs”           | `v_recent_cves`                                           |

---

### 📌 Rappel technique (schéma SQL réel)

* Tables : `dim_cve`, `dim_cvss_source`, `dim_vendor`, `dim_products`, `cvss_v2`, `cvss_v3`, `cvss_v4`, `bridge_cve_products`
* Vues : `v_cvss_v3_best`, `v_cve_products`, `v_cve_fact`, `v_top_vendors`, `v_top_products`, `v_monthly_trend`, `v_yearly_trend`, `v_cvss_buckets`, `v_recent_cves`, `v_cve_vendor_summary`
* La colonne métier de classification est **`vulnarbilit`** (et non “predicted_category”/“title/description”, absents du schéma actuel).

---

Si tu veux, je peux te générer **une page Power BI “Executive Dashboard” prête à brancher** (liste des visuels + champs exacts + mesures) ou ajouter des **vues avancées** (ex. `agg_vendor_risk_score`, `agg_cve_age_analysis`, `agg_cvss_version_comparison`) entièrement compatibles avec ton schéma “vulnarbilit”.