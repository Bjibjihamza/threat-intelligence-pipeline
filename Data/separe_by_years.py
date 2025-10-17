#!/usr/bin/env python3
"""
Filter CVEs between 2020 and 2024 and save them to another CSV file.
"""

import pandas as pd
import re
import sys
from pathlib import Path

# -------------------------------
# Configuration
# -------------------------------
INPUT_FILE = "cve_ids_all_years_2002_2025_from_zip.csv"          # change to your actual filename
OUTPUT_FILE = "cves_2020_2024.csv"   # output file

# -------------------------------
# Main script
# -------------------------------
def extract_year(cve_id: str) -> int:
    """Extract the year from a CVE ID like CVE-2023-1234."""
    match = re.match(r"CVE-(\d{4})-", cve_id)
    return int(match.group(1)) if match else None

def main(input_file, output_file):
    df = pd.read_csv(input_file)

    # Ensure cve_id column exists
    if "cve_id" not in df.columns:
        print("❌ Error: 'cve_id' column not found in CSV.")
        sys.exit(1)

    # Extract year from CVE ID
    df["cve_year"] = df["cve_id"].apply(extract_year)

    # Filter rows between 2020 and 2024
    filtered = df[(df["cve_year"] >= 2020) & (df["cve_year"] <= 2024)]

    # Save result to new CSV
    filtered.to_csv(output_file, index=False)
    print(f"✅ Saved {len(filtered)} CVEs to {output_file}")

if __name__ == "__main__":
    main(INPUT_FILE, OUTPUT_FILE)
