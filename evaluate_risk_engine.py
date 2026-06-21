import sqlite3
from pathlib import Path

import pandas as pd


BASE_DIR = Path(__file__).resolve().parent
DATABASE_FILE = BASE_DIR / "database" / "vendor_risk.db"


def safe_percentage(numerator, denominator):
    if denominator == 0:
        return 0.0

    return round((numerator / denominator) * 100, 2)


def evaluate():
    with sqlite3.connect(DATABASE_FILE) as connection:
        df = pd.read_sql_query(
            """
            SELECT
                s.vendor_id,
                s.vendor_name,
                s.category,
                s.final_risk_score,
                s.final_risk_level,
                l.severity,
                l.anomaly_type
            FROM vendor_scores s
            JOIN vendor_labels l
                ON s.vendor_id = l.vendor_id
            """,
            connection,
        )

    actual_critical = df["severity"] == "CRITICAL"
    predicted_critical = (
        df["final_risk_level"] == "CRITICAL"
    )

    true_positive = int(
        (actual_critical & predicted_critical).sum()
    )

    false_negative = int(
        (actual_critical & ~predicted_critical).sum()
    )

    false_positive = int(
        (~actual_critical & predicted_critical).sum()
    )

    true_negative = int(
        (~actual_critical & ~predicted_critical).sum()
    )

    critical_recall = safe_percentage(
        true_positive,
        true_positive + false_negative,
    )

    critical_precision = safe_percentage(
        true_positive,
        true_positive + false_positive,
    )

    print("CRITICAL RISK EVALUATION")
    print("------------------------")
    print("True Positives:", true_positive)
    print("False Negatives:", false_negative)
    print("False Positives:", false_positive)
    print("True Negatives:", true_negative)

    print("\nCritical Recall:", f"{critical_recall}%")
    print("Critical Precision:", f"{critical_precision}%")

    if critical_recall >= 90:
        print("\nTARGET ACHIEVED: Critical recall is 90% or higher.")
    else:
        print("\nTARGET NOT ACHIEVED: The rules need tuning.")

    missed = df[
        actual_critical & ~predicted_critical
    ].copy()

    if not missed.empty:
        print("\nMISSED CRITICAL VENDORS")
        print("-----------------------")

        print(
            missed[
                [
                    "vendor_id",
                    "vendor_name",
                    "category",
                    "final_risk_score",
                    "final_risk_level",
                    "anomaly_type",
                ]
            ].to_string(index=False)
        )
    else:
        print("\nNo Critical vendors were missed.")


if __name__ == "__main__":
    evaluate()