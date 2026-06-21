from pathlib import Path
import sqlite3

import pandas as pd


# Project paths
PROJECT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_DIR / "data"
DATABASE_DIR = PROJECT_DIR / "database"

VENDORS_CSV = DATA_DIR / "vendor_registry.csv"
LABELS_CSV = DATA_DIR / "vendor_labels.csv"
DATABASE_FILE = DATABASE_DIR / "vendor_risk.db"


def create_database():
    """Load CSV data and create the SQLite database."""

    # Check that both CSV files exist
    if not VENDORS_CSV.exists():
        raise FileNotFoundError(f"Missing file: {VENDORS_CSV}")

    if not LABELS_CSV.exists():
        raise FileNotFoundError(f"Missing file: {LABELS_CSV}")

    print("Reading vendor datasets...")

    vendors_df = pd.read_csv(VENDORS_CSV)
    labels_df = pd.read_csv(LABELS_CSV)

    # Basic validation
    if "vendor_id" not in vendors_df.columns:
        raise ValueError("vendor_registry.csv does not contain vendor_id")

    if "vendor_id" not in labels_df.columns:
        raise ValueError("vendor_labels.csv does not contain vendor_id")

    duplicate_vendors = vendors_df["vendor_id"].duplicated().sum()
    duplicate_labels = labels_df["vendor_id"].duplicated().sum()

    if duplicate_vendors > 0:
        raise ValueError(
            f"Found {duplicate_vendors} duplicate vendor IDs in registry"
        )

    if duplicate_labels > 0:
        raise ValueError(
            f"Found {duplicate_labels} duplicate vendor IDs in labels"
        )

    print("Creating SQLite database...")

    with sqlite3.connect(DATABASE_FILE) as connection:

        # Store both CSV files as database tables
        vendors_df.to_sql(
            "vendors",
            connection,
            if_exists="replace",
            index=False,
        )

        labels_df.to_sql(
            "vendor_labels",
            connection,
            if_exists="replace",
            index=False,
        )

        # Create indexes for faster searches
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_vendors_id "
            "ON vendors(vendor_id)"
        )

        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_labels_id "
            "ON vendor_labels(vendor_id)"
        )

        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_risk_level "
            "ON vendors(risk_level)"
        )

        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_vendor_category "
            "ON vendors(category)"
        )

        # Create one combined view for the dashboard
        connection.execute("DROP VIEW IF EXISTS vendor_risk_view")

        connection.execute(
            """
            CREATE VIEW vendor_risk_view AS
            SELECT
                v.*,
                l.is_anomaly,
                l.anomaly_type,
                l.severity,
                l.expired_certifications,
                l.explanation
            FROM vendors v
            LEFT JOIN vendor_labels l
                ON v.vendor_id = l.vendor_id
            """
        )

        connection.commit()

        vendor_count = connection.execute(
            "SELECT COUNT(*) FROM vendors"
        ).fetchone()[0]

        label_count = connection.execute(
            "SELECT COUNT(*) FROM vendor_labels"
        ).fetchone()[0]

        combined_count = connection.execute(
            "SELECT COUNT(*) FROM vendor_risk_view"
        ).fetchone()[0]

    print("\nDatabase created successfully!")
    print(f"Database location: {DATABASE_FILE}")
    print(f"Vendors stored: {vendor_count}")
    print(f"Labels stored: {label_count}")
    print(f"Combined records: {combined_count}")


if __name__ == "__main__":
    create_database()