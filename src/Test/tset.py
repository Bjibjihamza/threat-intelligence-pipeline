#!/usr/bin/env python3
"""
Title-only category predictor with accuracy reporting.

- Input: a single CSV containing at least: 'title', 'category'
- Training: uses rows where category is present and not 'Unknown' (case-insensitive)
- Prediction: title -> predicted category (Naive Bayes with Laplace smoothing, optional bigrams)
- Output: prints overall accuracy on known categories (no files are written)

Usage (script):
    python predict_titles_only.py --csv path/to/your.csv

Usage (notebook):
    CSV_PATH = "stacked_deduplicated_dataset.csv"
    run(CSV_PATH)
"""

import argparse
import math
import re
from collections import Counter, defaultdict

import pandas as pd

# =========================
# CONFIG (you can tweak)
# =========================
ALPHA = 1.0          # Laplace smoothing
MIN_TOKEN_LEN = 2
USE_BIGRAMS = True

# Common low-signal words for CVE titles; adjust as you like
STOPWORDS = {
    "the","a","an","and","or","of","to","in","for","on","with","by","via",
    "from","at","as","is","are","be","was","were","this","that","these","those",
    "vulnerability","vulnerabilities","issue","bug","attack","remote","local",
    "privilege","escalation","denial","service","dos","code","execution","rce",
    "information","disclosure","leak","overflow","buffer","command","injection",
    "authentication","bypass","default","config","configuration","file","read",
    "write","arbitrary","server","client","kernel"
}

_non_alnum = re.compile(r"[^a-z0-9]+")

def tokenize(text: str):
    """Lowercase, keep alnum, drop stopwords, add bigrams optionally."""
    text = str(text or "").lower()
    text = _non_alnum.sub(" ", text)
    toks = [t for t in text.split() if len(t) >= MIN_TOKEN_LEN and t not in STOPWORDS]
    if USE_BIGRAMS and len(toks) >= 2:
        toks.extend(f"{toks[i]}_{toks[i+1]}" for i in range(len(toks)-1))
    return toks

def train_keyword_model(df: pd.DataFrame):
    """Train simple multinomial NB on labeled rows (category known & not Unknown)."""
    labeled = df[df["category"].notna()].copy()
    labeled["category"] = labeled["category"].astype(str).str.strip()
    labeled = labeled[labeled["category"].str.len() > 0]
    labeled = labeled[~labeled["category"].str.lower().eq("unknown")]

    if labeled.empty:
        raise ValueError("No labeled rows found (category not present or all 'Unknown').")

    cat_doc_counts = Counter()
    cat_token_counts = defaultdict(Counter)
    vocab = Counter()

    for _, row in labeled.iterrows():
        cat = str(row["category"])
        cat_doc_counts[cat] += 1
        tokens = tokenize(row.get("title", ""))
        if tokens:
            cat_token_counts[cat].update(tokens)
            vocab.update(tokens)

    total_docs = sum(cat_doc_counts.values())
    priors_log = {cat: math.log(n/total_docs) for cat, n in cat_doc_counts.items()}
    total_tokens = {cat: sum(cnt.values()) for cat, cnt in cat_token_counts.items()}
    vocab_size = max(1, len(vocab))

    return {
        "priors_log": priors_log,
        "token_counts": cat_token_counts,
        "total_tokens": total_tokens,
        "vocab_size": vocab_size,
        "alpha": ALPHA
    }

def predict_category(title: str, model) -> str:
    tokens = tokenize(title)
    if not tokens:
        return "Unknown"

    priors_log = model["priors_log"]
    token_counts = model["token_counts"]
    total_tokens = model["total_tokens"]
    V = model["vocab_size"]
    alpha = model["alpha"]

    best_cat, best_score = None, -float("inf")
    for cat, prior in priors_log.items():
        denom = total_tokens.get(cat, 0) + alpha * V
        # If a category had no tokens (edge case), skip scoring it
        if denom <= 0:
            continue
        score = prior
        counts = token_counts.get(cat, {})
        for tok in tokens:
            score += math.log((counts.get(tok, 0) + alpha) / denom)
        if score > best_score:
            best_score, best_cat = score, cat

    return best_cat if best_cat else "Unknown"

def evaluate_accuracy(df: pd.DataFrame, preds_col: str = "Predicted_category") -> float:
    """Accuracy over rows where category is known & not Unknown."""
    if "category" not in df.columns:
        raise ValueError("Expected a 'category' column in the CSV.")
    if preds_col not in df.columns:
        raise ValueError(f"Expected a '{preds_col}' column in the DataFrame.")

    mask = df["category"].notna() & (~df["category"].astype(str).str.lower().eq("unknown"))
    known = df.loc[mask]
    if known.empty:
        raise ValueError("No rows with known (non-Unknown) categories to evaluate.")

    correct = (known["category"].astype(str) == known[preds_col].astype(str)).sum()
    total = len(known)
    return correct / total

def run(csv_path: str):
    # Load
    df = pd.read_csv(csv_path, low_memory=False)

    # Basic checks
    for col in ("title", "category"):
        if col not in df.columns:
            raise ValueError(f"CSV must contain a '{col}' column.")

    # Train from known categories (excluding Unknown)
    model = train_keyword_model(df)

    # Predict (titles only) for every row (no file outputs)
    df["Predicted_category"] = df["title"].apply(lambda t: predict_category(t, model))

    # Compute accuracy on rows where category is known & not Unknown
    acc = evaluate_accuracy(df, "Predicted_category")

    # Print a concise report
    total_rows = len(df)
    known_rows = df["category"].notna() & (~df["category"].astype(str).str.lower().eq("unknown"))
    print("="*80)
    print("TITLE-ONLY CATEGORY PREDICTION — ACCURACY REPORT")
    print("="*80)
    print(f"CSV file: {csv_path}")
    print(f"Total rows: {total_rows}")
    print(f"Rows with known categories (eval set): {known_rows.sum()}")
    print(f"Overall Accuracy (excluding 'Unknown' & NaN in category): {acc*100:.2f}%")
    print("="*80)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Predict categories from titles and report accuracy.")
    parser.add_argument("--csv", required=True, help="Path to input CSV with 'title' and 'category' columns.")
    args = parser.parse_args()
    run(args.csv)
