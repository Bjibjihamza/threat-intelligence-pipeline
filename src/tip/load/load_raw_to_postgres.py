import os
import pandas as pd
from datetime import datetime, timezone
from sqlalchemy import create_engine, types
from dotenv import load_dotenv

load_dotenv()

DB_USER = os.getenv("DB_USER", "postgres")
DB_PASS = os.getenv("DB_PASS", "tip_pwd")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "tip")

engine = create_engine(f"postgresql+psycopg2://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}")

csv_path = "../../../Data/cve_detailed_raw.csv"
print(f"📂 Loading CSV from: {csv_path}")

# Read CSV as pure text (no infer) and fill NaNs with empty strings
df = pd.read_csv(csv_path, dtype=str, keep_default_na=False)
df["loaded_at"] = datetime.now(timezone.utc).isoformat()

dtype_text = {
    "cve_id": types.Text(),
    "title": types.Text(),
    "description": types.Text(),
    "published_date": types.Text(),
    "last_modified": types.Text(),
    "remotely_exploit": types.Text(),
    "source": types.Text(),
    "category": types.Text(),
    "affected_products": types.Text(),  # JSON string stays TEXT
    "cvss_scores": types.Text(),        # JSON string stays TEXT
    "url": types.Text(),
    "loaded_at": types.DateTime(timezone=True),
}

with engine.begin() as con:
    df.to_sql(
        "cve_details",
        con=con,
        schema="raw",
        if_exists="append",
        index=False,
        dtype=dtype_text,
        method="multi",
        chunksize=1000,
    )

print(f"🚀 Loaded {len(df)} rows into raw.cve_details (TEXT staging).")
