import os
import pandas as pd
from datetime import datetime, timezone
from sqlalchemy import create_engine, text, types
from dotenv import load_dotenv
from sqlalchemy.exc import SQLAlchemyError

# Load environment
load_dotenv()

DB_USER = os.getenv("DB_USER", "postgres")
DB_PASS = os.getenv("DB_PASS", "tip_pwd")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "tip")

engine = create_engine(
    f"postgresql+psycopg2://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
)

csv_path = "../../../Data/cve_detailed_raw.csv"
print(f"📂 Loading CSV from: {csv_path}")

# --- Safe CSV load ---
df = pd.read_csv(
    csv_path,
    dtype=str,
    keep_default_na=False,
    on_bad_lines='skip',
    quotechar='"',
    escapechar='\\',
    engine='python'
)

df["loaded_at"] = datetime.now(timezone.utc).isoformat()
print(f"✅ CSV loaded successfully with {len(df):,} valid rows.")

# --- Prepare a temporary table ---
temp_table = "cve_details_temp"
schema = "raw"

dtype_text = {col: types.Text() for col in df.columns}
dtype_text["loaded_at"] = types.DateTime(timezone=True)

with engine.begin() as con:
    con.execute(text(f"CREATE SCHEMA IF NOT EXISTS {schema};"))
    # Replace temp table if exists
    df.to_sql(temp_table, con=con, schema=schema, if_exists="replace", index=False, dtype=dtype_text)

    print("🔄 Inserting new rows only (skipping duplicates)...")
    insert_sql = text(f"""
        INSERT INTO {schema}.cve_details
        SELECT * FROM {schema}.{temp_table}
        ON CONFLICT (cve_id) DO NOTHING;
    """)
    con.execute(insert_sql)
    con.execute(text(f"DROP TABLE IF EXISTS {schema}.{temp_table};"))

print(f"🚀 Done! Only new CVEs were inserted into {schema}.cve_details.")
