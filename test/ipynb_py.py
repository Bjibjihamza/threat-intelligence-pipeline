import json
import sys
from pathlib import Path

# --- Input and output files ---
input_path = Path("EDA.ipynb")
output_path = Path("EDA_extracted.py")

# --- Load the notebook as JSON ---
with open(input_path, "r", encoding="utf-8") as f:
    nb = json.load(f)

# --- Extract only code cells ---
with open(output_path, "w", encoding="utf-8") as out:
    for cell in nb.get("cells", []):
        if cell.get("cell_type") == "code":
            # Ignore Jupyter magics like %matplotlib or !pip
            lines = [
                l for l in cell.get("source", [])
                if not l.lstrip().startswith(("%", "!"))
            ]
            out.write("".join(lines))
            out.write("\n\n")  # separate cells

print(f"✅ Code extracted successfully → {output_path}")
