import pandas as pd

# Load the combined CSV
csv_file = 'vulnerabilities_combined.csv'
df = pd.read_csv(csv_file)

# Assuming the ID column is named 'id' (change if it's different, e.g., 'cve_id')
id_column = 'status'  # Update this to the actual column name if needed

# Check for duplicates
if id_column not in df.columns:
    print(f"❌ Column '{id_column}' not found. Available columns: {list(df.columns)}")
    exit()

duplicates = df[df.duplicated(subset=[id_column], keep=False)]
duplicate_count = len(duplicates)

if duplicate_count == 0:
    print(f"✅ No duplicate IDs found in '{id_column}' column!")
    print(f"Total unique IDs: {df[id_column].nunique()}")
    print(f"Total rows: {len(df)}")
else:
    print(f"⚠️ Found {duplicate_count} rows with duplicate IDs in '{id_column}' column.")
    print(f"Number of duplicate IDs: {df[id_column].duplicated().sum()}")
    print(f"Unique IDs: {df[id_column].nunique()}")
    print(f"Total rows: {len(df)}")
    
    # Show first few duplicates
    print("\nFirst few duplicate IDs:")
    print(duplicates[[id_column]].head(10))
    
    # Optional: Save duplicates to a file
    duplicates.to_csv('duplicate_ids.csv', index=False)
    print(f"\n💾 Saved duplicates to 'duplicate_ids.csv'")