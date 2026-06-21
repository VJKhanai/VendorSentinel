from pathlib import Path

import pandas as pd


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"

vendors_file = DATA_DIR / "vendor_registry.csv"
labels_file = DATA_DIR / "vendor_labels.csv"

vendors_df = pd.read_csv(vendors_file)
labels_df = pd.read_csv(labels_file)

print("Vendor registry rows:", len(vendors_df))
print("Vendor registry columns:", len(vendors_df.columns))

print("Vendor labels rows:", len(labels_df))
print("Vendor labels columns:", len(labels_df.columns))