from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path

import pandas as pd


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DATABASE = BASE_DIR / "database" / "vendor_risk.db"
DEFAULT_OUTPUT = BASE_DIR / "evaluation" / "company_dataset_evaluation.txt"
DEFAULT_MISMATCHES = BASE_DIR / "evaluation" / "evaluation_mismatches.csv"

SEVERITY_ORDER = {
    "NONE": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def safe_divide(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate VendorSentinel against the provided ground truth."
    )
    parser.add_argument(
        "--database",
        type=Path,
        default=DEFAULT_DATABASE,
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
    )
    parser.add_argument(
        "--mismatches",
        type=Path,
        default=DEFAULT_MISMATCHES,
    )
    return parser.parse_args()


def evaluate(database_path: Path) -> tuple[str, pd.DataFrame]:
    with sqlite3.connect(database_path) as connection:
        frame = pd.read_sql_query(
            """
            SELECT
                s.vendor_id,
                s.vendor_name,
                s.company_risk_score,
                s.final_risk_score,
                s.final_risk_level,
                s.predicted_anomaly,
                s.predicted_severity,
                s.predicted_is_anomaly,
                l.is_anomaly AS actual_is_anomaly,
                l.anomaly_type AS actual_anomaly,
                l.severity AS actual_severity,
                l.explanation
            FROM vendor_scores s
            JOIN vendor_labels l
                ON s.vendor_id = l.record_id
            ORDER BY s.vendor_id
            """,
            connection,
        )

        metadata_rows = connection.execute(
            "SELECT metadata_key, metadata_value FROM dataset_metadata"
        ).fetchall()

    metadata = dict(metadata_rows)

    predicted = frame["predicted_is_anomaly"].astype(int)
    actual = frame["actual_is_anomaly"].astype(int)

    true_positive = int(((predicted == 1) & (actual == 1)).sum())
    false_positive = int(((predicted == 1) & (actual == 0)).sum())
    false_negative = int(((predicted == 0) & (actual == 1)).sum())
    true_negative = int(((predicted == 0) & (actual == 0)).sum())

    precision = safe_divide(true_positive, true_positive + false_positive)
    recall = safe_divide(true_positive, true_positive + false_negative)
    accuracy = safe_divide(true_positive + true_negative, len(frame))

    critical = frame[frame["actual_severity"] == "CRITICAL"].copy()
    critical_caught = critical["predicted_severity"].map(SEVERITY_ORDER).ge(
        SEVERITY_ORDER["CRITICAL"]
    )
    critical_recall = float(critical_caught.mean()) if len(critical) else 0.0

    high_critical = frame[
        frame["actual_severity"].isin(["HIGH", "CRITICAL"])
    ].copy()
    high_critical_caught = high_critical.apply(
        lambda row: (
            SEVERITY_ORDER.get(str(row["predicted_severity"]), 0)
            >= SEVERITY_ORDER.get(str(row["actual_severity"]), 0)
        ),
        axis=1,
    )
    high_critical_recall = (
        float(high_critical_caught.mean()) if len(high_critical) else 0.0
    )

    exact_anomaly_accuracy = float(
        (frame["predicted_anomaly"] == frame["actual_anomaly"]).mean()
    )
    exact_severity_accuracy = float(
        (frame["predicted_severity"] == frame["actual_severity"]).mean()
    )

    mismatch_mask = (
        (frame["predicted_anomaly"] != frame["actual_anomaly"])
        | (frame["predicted_severity"] != frame["actual_severity"])
        | (predicted != actual)
    )
    mismatches = frame[mismatch_mask].copy()

    severity_matrix = pd.crosstab(
        frame["actual_severity"],
        frame["predicted_severity"],
        rownames=["Actual"],
        colnames=["Predicted"],
        dropna=False,
    )

    anomaly_matrix = pd.crosstab(
        frame["actual_anomaly"],
        frame["predicted_anomaly"],
        rownames=["Actual"],
        colnames=["Predicted"],
        dropna=False,
    )

    report = f"""VENDORSENTINEL COMPANY DATASET EVALUATION
==========================================

Dataset: {metadata.get('dataset_name', 'Company sample dataset')}
Dataset snapshot date: {metadata.get('dataset_as_of_date', 'Unknown')}
Vendors evaluated: {len(frame)}

BINARY ANOMALY DETECTION
------------------------
True Positives:  {true_positive}
False Positives: {false_positive}
False Negatives: {false_negative}
True Negatives:  {true_negative}

Precision: {precision:.2%}
Recall:    {recall:.2%}
Accuracy:  {accuracy:.2%}

PRIORITY METRICS
----------------
Critical vendors: {len(critical)}
Critical recall: {critical_recall:.2%}
High + Critical vendors: {len(high_critical)}
High + Critical severity recall: {high_critical_recall:.2%}

EXACT CLASSIFICATION
--------------------
Exact anomaly-type accuracy: {exact_anomaly_accuracy:.2%}
Exact severity accuracy:     {exact_severity_accuracy:.2%}
Mismatched records:          {len(mismatches)}

SEVERITY CONFUSION MATRIX
-------------------------
{severity_matrix.to_string()}

ANOMALY-TYPE CONFUSION MATRIX
-----------------------------
{anomaly_matrix.to_string()}

INTERPRETATION
--------------
The evaluation uses the company-provided label file only after scoring is
complete. Labels are not used as model inputs. The deterministic rules mirror
the published benchmark conditions: investigations, recent breaches combined
with high-access scopes, company risk thresholds, certification expiry,
contract expiry, and elevated-risk monitoring.

A perfect benchmark result means that the implementation reproduces the
published sample-data rules. It is not evidence of guaranteed real-world
accuracy, where vendor data can be incomplete, delayed, or contradictory.
"""

    return report, mismatches


def main() -> None:
    arguments = parse_arguments()
    report, mismatches = evaluate(arguments.database)

    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(report, encoding="utf-8")

    arguments.mismatches.parent.mkdir(parents=True, exist_ok=True)
    mismatches.to_csv(arguments.mismatches, index=False)

    print(report)
    print(f"Saved report: {arguments.output}")
    print(f"Saved mismatches: {arguments.mismatches}")


if __name__ == "__main__":
    main()
