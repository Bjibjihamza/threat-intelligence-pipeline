

# --- Manipulation et analyse de données
import pandas as pd
import numpy as np

# --- Visualisation
import matplotlib.pyplot as plt
import seaborn as sns

# --- Traitement du texte
import re
import string

# --- Pré-traitement et machine learning utils
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.feature_extraction.text import TfidfVectorizer

# --- Date et temps
from datetime import datetime, timedelta

# --- Options d’affichage pandas
pd.set_option('display.max_columns', None)
pd.set_option('display.max_rows', 50)
pd.set_option('display.width', 120)
pd.set_option('display.float_format', '{:.2f}'.format)

# --- Style des graphiques
sns.set_theme(style="whitegrid")
plt.rcParams['figure.figsize'] = (10, 5)
plt.rcParams['axes.titlesize'] = 13
plt.rcParams['axes.labelsize'] = 11

from sqlalchemy import create_engine

DB_USER = "postgres"
DB_PASS = "tip_pwd"
DB_HOST = "localhost"
DB_PORT = "5432"
DB_NAME = "tip"

engine = create_engine(f"postgresql+psycopg2://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}")
df = pd.read_sql("SELECT * FROM raw.cve_details;", engine)


# ### Step 2 : Loading and Initial Inspection of the Dataset

# In[185]:


query_dims = """
WITH
rows_count AS (
  SELECT COUNT(*)::bigint AS rows
  FROM raw.cve_details
),
cols_count AS (
  SELECT COUNT(*)::int AS cols
  FROM information_schema.columns
  WHERE table_schema = 'raw'
    AND table_name   = 'cve_details'
)
SELECT rows_count.rows, cols_count.cols
FROM rows_count, cols_count;
"""

dims = pd.read_sql(query_dims, engine).iloc[0]
n_rows, n_cols = int(dims["rows"]), int(dims["cols"])

print("✅ Dataset loaded successfully!")
print(f"Dataset dimensions: {n_rows} rows × {n_cols} columns\n")


# In[186]:


# Preview of the first rows
display(df.head(5))


# In[187]:


# General information about the columns
print("Informations sur les types de colonnes :")
df.info()

# In[188]:


def normalize_date_str(s):
    """Normalise les variations communes avant parsing:
       - convertit None/NaN en None
       - remplace 'a.m.' / 'p.m.' / 'a.m' / 'pm.' etc par 'AM'/'PM'
       - enlève le point après month abbrev (e.g. 'Oct.' -> 'Oct')
       - supprime espaces multiples
    """
    if pd.isna(s):
        return None
    s = str(s).strip()

    # Normalize AM/PM variants to 'AM' / 'PM'
    s = re.sub(r'\b(a\.?m\.?|am)\b', 'AM', s, flags=re.IGNORECASE)
    s = re.sub(r'\b(p\.?m\.?|pm)\b', 'PM', s, flags=re.IGNORECASE)

    # Remove dot after 3-letter month abbreviations like 'Oct.' -> 'Oct'
    # only if it's followed by space and digit (month dot used only there)
    s = re.sub(r'([A-Za-z]{3})\.(?=\s+\d)', r'\1', s)

    # Also remove stray dots that break parsing (but be conservative)
    # e.g. 'CVE-...' might contain dots but dates are fine after previous fixes.
    # Remove remaining dots in the AM/PM area already handled.
    s = s.replace('..', '.')  # collapse double dots if any

    # Normalize commas/spaces: ensure one space after comma
    s = re.sub(r',\s*', ', ', s)

    # Examples of remaining forms:
    # "Oct 11, 2025, 5:15 PM", "Nov 11, 1988, 5 AM", "July 26, 1989, 4 AM"
    return s

def try_parse_date(s):
    """Try several parsing strategies, return pd.Timestamp or NaT."""
    if s is None:
        return pd.NaT

    # 1) Try common explicit formats (fast)
    formats = [
        "%b %d, %Y, %I:%M %p",   # "Oct 11, 2025, 5:15 PM"
        "%b %d, %Y, %I %p",      # "Nov 11, 1988, 5 PM" (no minutes)
        "%B %d, %Y, %I:%M %p",   # "July 26, 1989, 4:00 AM" (full month)
        "%B %d, %Y, %I %p",      # "July 26, 1989, 4 AM"
        "%Y-%m-%dT%H:%M:%S.%f",  # ISO-ish (if present)
        "%Y-%m-%d %H:%M:%S",     # fallback ISO/no-T
    ]
    for fmt in formats:
        try:
            return pd.to_datetime(s, format=fmt, errors='raise')
        except Exception:
            pass

    # 2) Try pandas with infer (which uses dateutil under the hood)
    try:
        return pd.to_datetime(s, infer_datetime_format=True, errors='raise')
    except Exception:
        pass

    # 3) Last fallback: direct dateutil parsing (most flexible)
    try:
        return parser.parse(s)
    except Exception:
        return pd.NaT

# Apply to your dataframe
for col in ["published_date", "last_modified"]:
    # 1) Normalize strings
    norm_col = f"{col}_norm"
    df[norm_col] = df[col].apply(normalize_date_str)

    # 2) Parse using the robust function
    parsed = df[norm_col].apply(try_parse_date)

    # 3) Assign back as datetime dtype
    df[col] = pd.to_datetime(parsed, errors='coerce')

    # Drop helper column if you want
    df.drop(columns=[norm_col], inplace=True)

# Quick checks
print("Dtypes:")
print(df[["published_date", "last_modified"]].dtypes)
print("\nHow many missing after parse?")
print(df["published_date"].isna().sum(), "published_date NaT")
print(df["last_modified"].isna().sum(), "last_modified NaT")

# Show the rows that still failed (to inspect problematic strings)
failed_pub = df[df["published_date"].isna()][["published_date", "published_date"]].head(10)
if len(failed_pub) > 0:
    print("\nSample rows with published_date still NaT (show original raw strings for debugging):")


# In[189]:


df[['published_date', 'last_modified']].head(5)


# In[190]:


# --- Normalize `loaded_at` ----------------------------------------------------
# Convert timezone-aware timestamps like '2025-10-12 17:56:02.356745+00:00'
# into simple UTC-naive format: '2025-10-12 17:56:02'

df['loaded_at'] = (
    pd.to_datetime(df['loaded_at'], utc=True, errors='coerce')  # ensure datetime & UTC
      .dt.tz_convert(None)                                      # drop timezone info
      .dt.strftime('%Y-%m-%d %H:%M:%S')                         # uniform format
)

# Quick check
print(df['loaded_at'].head(10))
print(df['loaded_at'].dtype)


# In[191]:


df.drop(columns=["url"], inplace=True, errors='ignore')



# In[192]:


# checking for duplicates
df.duplicated().any()

# Get all unique values in a column
unique_values = df['remotely_exploit'].unique()
print(unique_values)


# In[194]:


# Convert 'Yes !' to True and 'No' to False, leave existing True/False as is
df['remotely_exploit'] = df['remotely_exploit'].apply(
    lambda x: True if x == 'Yes !' else (False if x == 'No' else x)
)

# Check the result
print(df['remotely_exploit'].head())


# In[195]:


df.info()




# 1️⃣ Compter les lignes sans CVSS score (NaN ou liste vide)
missing_count = df["cvss_scores"].isna().sum() + (df["cvss_scores"].str.strip() == "[]").sum()
print(f"Number of rows without CVSS scores: {missing_count}")

# 2️⃣ Supprimer ces lignes directement dans df
df.drop(df[df["cvss_scores"].isna() | (df["cvss_scores"].str.strip() == "[]")].index, inplace=True)

# 3️⃣ Vérification
print(f"Remaining rows after drop: {len(df)}")


# In[197]:


df.head(5)


# In[198]:


import pandas as pd
import json

def extract_cvss_scores(df):
    """
    Extract and normalize CVSS scores from the cvss_scores column.
    Creates one row per CVSS version for each CVE.

    Parameters:
    -----------
    df : pandas.DataFrame
        DataFrame containing a 'cvss_scores' column with CVSS data

    Returns:
    --------
    pandas.DataFrame
        Normalized DataFrame with one row per CVSS score entry
    """

    # List to store expanded rows
    expanded_rows = []

    # Iterate through each CVE record
    for idx, row in df.iterrows():
        cvss_scores = row['cvss_scores']

        # Handle cases where cvss_scores might be None or empty
        if not cvss_scores or cvss_scores == '[]' or pd.isna(cvss_scores):
            # Keep the row but with null CVSS data
            row_dict = row.to_dict()
            row_dict.update({
                'cvss_score': None,
                'cvss_version': None,
                'cvss_severity': None,
                'cvss_vector': None,
                'cvss_exploitability_score': None,
                'cvss_impact_score': None,
                'cvss_source': None
            })
            expanded_rows.append(row_dict)
            continue

        # Parse JSON if it's a string
        if isinstance(cvss_scores, str):
            try:
                cvss_scores = json.loads(cvss_scores)
            except json.JSONDecodeError:
                # If parsing fails, skip or handle gracefully
                row_dict = row.to_dict()
                row_dict.update({
                    'cvss_score': None,
                    'cvss_version': None,
                    'cvss_severity': None,
                    'cvss_vector': None,
                    'cvss_exploitability_score': None,
                    'cvss_impact_score': None,
                    'cvss_source': None
                })
                expanded_rows.append(row_dict)
                continue

        # For each CVSS score entry, create a new row
        for cvss_entry in cvss_scores:
            row_dict = row.to_dict()

            # Extract CVSS-specific fields
            row_dict['cvss_score'] = cvss_entry.get('score')
            row_dict['cvss_version'] = cvss_entry.get('version')
            row_dict['cvss_severity'] = cvss_entry.get('severity')
            row_dict['cvss_vector'] = cvss_entry.get('vector')
            row_dict['cvss_exploitability_score'] = cvss_entry.get('exploitability_score')
            row_dict['cvss_impact_score'] = cvss_entry.get('impact_score')
            row_dict['cvss_source'] = cvss_entry.get('source')

            expanded_rows.append(row_dict)

    # Create new DataFrame from expanded rows
    df_expanded = pd.DataFrame(expanded_rows)

    # Drop the original cvss_scores column
    if 'cvss_scores' in df_expanded.columns:
        df_expanded = df_expanded.drop('cvss_scores', axis=1)

    # Convert numeric columns to appropriate types
    numeric_cols = ['cvss_score', 'cvss_exploitability_score', 'cvss_impact_score']
    for col in numeric_cols:
        if col in df_expanded.columns:
            df_expanded[col] = pd.to_numeric(df_expanded[col], errors='coerce')

    return df_expanded


def analyze_cvss_versions(df_expanded):
    """
    Analyze the distribution of CVSS versions in the normalized dataset.

    Parameters:
    -----------
    df_expanded : pandas.DataFrame
        Normalized DataFrame with CVSS data

    Returns:
    --------
    pandas.DataFrame
        Summary statistics by CVSS version
    """

    version_summary = df_expanded.groupby('cvss_version').agg({
        'cve_id': 'count',
        'cvss_score': ['mean', 'median', 'min', 'max'],
        'cvss_severity': lambda x: x.value_counts().to_dict()
    }).round(2)

    version_summary.columns = ['_'.join(col).strip() for col in version_summary.columns]
    version_summary = version_summary.rename(columns={'cve_id_count': 'total_entries'})

    return version_summary


# Example usage:
# ===============

# Assuming you have your DataFrame 'df' already loaded
# Extract and normalize CVSS scores - ASSIGN THE RESULT!
df = extract_cvss_scores(df)


# In[199]:


df.head(3)


# We can notice one thing: for entries where the CVSS version is **4.0**, the fields **cvss_exploitability** and **cvss_impact** are empty.

# In[200]:


df[df["cvss_version"] == "CVSS 4.0"][["cve_id", "cvss_version", "cvss_severity",   "cvss_vector" ,   "cvss_exploitability_score", "cvss_impact_score"]].head(5)


import pandas as pd
import re

# Mappings CVSS
MAPS_COMMON = {
    "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
    "AC": {"L": "Low", "H": "High"},
    "PR": {"N": "None", "L": "Low", "H": "High"},
    "UI": {"N": "None", "R": "Required"},
    "S": {"U": "Unchanged", "C": "Changed"},
    "C": {"N": "None", "L": "Low", "H": "High"},
    "I": {"N": "None", "L": "Low", "H": "High"},
    "A": {"N": "None", "L": "Low", "H": "High"}
}

MAPS_V2 = {
    "AV": {"N": "Network", "A": "Adjacent/Local", "L": "Local", "P": "Physical"},
    "Au": {"N": "None", "S": "Single", "M": "Multiple"},
    "C": {"N": "None", "P": "Partial", "C": "Complete", "L": "Low"},
    "I": {"N": "None", "P": "Partial", "C": "Complete", "L": "Low"},
    "A": {"N": "None", "P": "Partial", "C": "Complete", "L": "Low"}
}

MAPS_V40 = {
    "AT": {"N": "None", "P": "Present"},
    "VC": {"N": "None", "L": "Low", "H": "High"},
    "VI": {"N": "None", "L": "Low", "H": "High"},
    "VA": {"N": "None", "L": "Low", "H": "High"},
    "SC": {"N": "None", "L": "Low", "H": "High"},
    "SI": {"N": "None", "L": "Low", "H": "High"},
    "SA": {"N": "None", "L": "Low", "H": "High"}
}

def parse_cvss_vector(vector_str, version):
    """
    Parse un vecteur CVSS et retourne un dictionnaire des métriques
    """
    if pd.isna(vector_str) or not isinstance(vector_str, str):
        return {}

    metrics = {}

    # Déterminer les mappings à utiliser selon la version
    if version == "CVSS 2.0":
        maps = {**MAPS_V2}
    elif version == "CVSS 3.1" or version == "CVSS 3.0":
        maps = {**MAPS_COMMON}
    elif version == "CVSS 4.0":
        maps = {**MAPS_COMMON, **MAPS_V40}
    else:
        maps = {**MAPS_COMMON}

    # Nettoyer le vecteur (enlever le préfixe CVSS:3.1/ ou similaire)
    vector_str = re.sub(r'^CVSS:\d+\.\d+/', '', vector_str)

    # Parser les paires metric:value
    pairs = vector_str.split('/')
    for pair in pairs:
        if ':' in pair:
            metric, value = pair.split(':', 1)
            metric = metric.strip()
            value = value.strip()

            # Chercher la valeur décodée
            if metric in maps and value in maps[metric]:
                metrics[metric] = maps[metric][value]
            else:
                # Garder la valeur brute si pas de mapping
                metrics[metric] = value

    return metrics

def extract_cvss_metrics(df):
    """
    Extrait les métriques CVSS et les ajoute comme colonnes au DataFrame
    """
    # Créer une copie du DataFrame
    df_result = df.copy()

    # Parser tous les vecteurs
    parsed_metrics = []
    for idx, row in df_result.iterrows():
        metrics = parse_cvss_vector(row['cvss_vector'], row['cvss_version'])
        parsed_metrics.append(metrics)

    # Obtenir toutes les métriques uniques
    all_metrics = set()
    for metrics in parsed_metrics:
        all_metrics.update(metrics.keys())

    # Créer des colonnes pour chaque métrique
    for metric in sorted(all_metrics):
        column_name = f'cvss_metric_{metric}'
        df_result[column_name] = [metrics.get(metric, None) for metrics in parsed_metrics]

    return df_result


# Supposons que 'df' est votre DataFrame existant
df = extract_cvss_metrics(df)


# In[202]:


df.head(3)


# In[203]:


df.info()


# 1. Convert to category if they have limited unique values:
# 
# This is useful if the columns have many repeated values (e.g., many instances of High, Low, None).
# 
# Why Use category?
# 
# Memory efficiency: The category dtype uses less memory compared to object when the number of unique values is small.
# 
# Faster operations: Operations like sorting, filtering, and grouping are faster with category dtype compared to object (since internally category uses integer codes for values).

# In[204]:


# Convert relevant columns to 'category' dtype
metric_columns = [
    'cvss_metric_A', 'cvss_metric_AC', 'cvss_metric_AR', 'cvss_metric_AT', 'cvss_metric_AU',
    'cvss_metric_AV', 'cvss_metric_Au', 'cvss_metric_C', 'cvss_metric_CR', 'cvss_metric_E',
    'cvss_metric_I', 'cvss_metric_IR', 'cvss_metric_MAC', 'cvss_metric_MAT', 'cvss_metric_MAV',
    'cvss_metric_MPR', 'cvss_metric_MSA', 'cvss_metric_MSC', 'cvss_metric_MSI', 'cvss_metric_MUI',
    'cvss_metric_MVA', 'cvss_metric_MVC', 'cvss_metric_MVI', 'cvss_metric_PR', 'cvss_metric_R',
    'cvss_metric_RE', 'cvss_metric_S', 'cvss_metric_SA', 'cvss_metric_SC', 'cvss_metric_SI',
    'cvss_metric_U', 'cvss_metric_UI', 'cvss_metric_V', 'cvss_metric_VA', 'cvss_metric_VC',
    'cvss_metric_VI'
]

# Apply category dtype conversion
df[metric_columns] = df[metric_columns].apply(lambda x: x.astype('category'))

df.info()


import json

# ===== Extraire les produits uniques =====
products_dict = {}

for idx, row in df.iterrows():
    cve_id = row['cve_id']
    affected_products = row['affected_products']

    if affected_products and affected_products != '[]':
        try:
            if isinstance(affected_products, str):
                products = json.loads(affected_products)
            else:
                products = affected_products

            for product in products:
                vendor = product.get('vendor', '').strip()
                product_name = product.get('product', '').strip()

                if vendor and product_name:
                    key = (vendor.lower(), product_name.lower())

                    if key not in products_dict:
                        products_dict[key] = {
                            'vendor': vendor,
                            'product_name': product_name,
                            'cves': set()
                        }
                    products_dict[key]['cves'].add(cve_id)

        except (json.JSONDecodeError, TypeError):
            continue

# Créer df_products
products_data = []
product_lookup = {}

for product_id, ((vendor_lower, product_lower), data) in enumerate(products_dict.items(), start=1):
    products_data.append({
        'product_id': product_id,
        'vendor': data['vendor'],
        'product_name': data['product_name'],
        'total_cves': len(data['cves']),
        'cve_list_json': json.dumps(list(data['cves']))
    })
    product_lookup[(vendor_lower, product_lower)] = product_id

df_products = pd.DataFrame(products_data)

# ===== Enrichir avec les dates CVE =====
cve_products_for_dates = []

for idx, row in df.iterrows():
    cve_id = row['cve_id']
    published_date = row['published_date']
    affected_products = row['affected_products']

    if affected_products and affected_products != '[]':
        try:
            if isinstance(affected_products, str):
                products = json.loads(affected_products)
            else:
                products = affected_products

            for product in products:
                vendor = product.get('vendor', '').strip()
                product_name = product.get('product', '').strip()

                if vendor and product_name:
                    key = (vendor.lower(), product_name.lower())
                    product_id = product_lookup.get(key)

                    if product_id:
                        cve_products_for_dates.append({
                            'product_id': product_id,
                            'published_date': published_date
                        })
        except (json.JSONDecodeError, TypeError):
            continue

df_temp = pd.DataFrame(cve_products_for_dates)

# Agréger les dates par produit
product_dates = df_temp.groupby('product_id').agg({
    'published_date': ['min', 'max']
}).reset_index()

product_dates.columns = ['product_id', 'first_cve_date', 'last_cve_date']

# Joindre avec df_products
df_pr = df_products.merge(product_dates, on='product_id', how='left')


# In[163]:


df_pr.head(10)

# In[164]:


df.drop(columns=['affected_products'], inplace=True)
