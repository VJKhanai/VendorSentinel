import json
import sqlite3
from pathlib import Path

import pandas as pd

from algorithms.composite_risk import calculate_composite_risk


BASE_DIR = Path(__file__).resolve().parent
DATABASE_FILE = BASE_DIR / "database" / "vendor_risk.db"


def score_all_vendors() -> None:
    """Calculate and store the latest risk score for every vendor."""

    with sqlite3.connect(DATABASE_FILE) as connection:
        connection.row_factory = sqlite3.Row

        vendors = connection.execute(
            """
            SELECT *
            FROM vendor_risk_view
            """
        ).fetchall()

        scored_records: list[dict[str, object]] = []

        for vendor in vendors:
            vendor_dict = dict(vendor)
            result = calculate_composite_risk(vendor_dict)

            components = result["component_scores"]

            scored_records.append(
                {
                    "vendor_id": vendor_dict["vendor_id"],
                    "vendor_name": vendor_dict["vendor_name"],
                    "category": vendor_dict["category"],

                    "ground_truth_severity": vendor_dict["severity"],
                    "ground_truth_anomaly": vendor_dict["anomaly_type"],

                    "access_risk_score": components["access_risk"],
                    "breach_risk_score": components["breach_risk"],
                    "compliance_risk_score": components[
                        "compliance_risk"
                    ],
                    "lifecycle_risk_score": components[
                        "lifecycle_risk"
                    ],
                    "financial_risk_score": components[
                        "financial_risk"
                    ],
                    "financial_rating": result[
                        "financial_rating"
                    ],

                    "final_risk_score": result["final_risk_score"],
                    "final_risk_level": result["final_risk_level"],

                    "risk_reasons": json.dumps(
                        result["risk_reasons"]
                    ),
                    "rule_overrides": json.dumps(
                        result["rule_overrides"]
                    ),
                    "recommendations": json.dumps(
                        result["recommendations"]
                    ),
                    "framework_mappings": json.dumps(
                        result["framework_mappings"]
                    ),
                }
            )

        scores_df = pd.DataFrame(scored_records)

        scores_df.to_sql(
            "vendor_scores",
            connection,
            if_exists="replace",
            index=False,
        )

        connection.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS
            idx_vendor_scores_id
            ON vendor_scores(vendor_id)
            """
        )

        connection.commit()

    print("All vendors scored successfully!")
    print("Total vendors scored:", len(scores_df))

    print("\nFinal risk distribution:")
    print(
        scores_df["final_risk_level"]
        .value_counts()
        .to_string()
    )

    print("\nAverage component scores:")
    print(
        scores_df[
            [
                "access_risk_score",
                "breach_risk_score",
                "compliance_risk_score",
                "lifecycle_risk_score",
                "financial_risk_score",
            ]
        ]
        .mean()
        .round(2)
        .to_string()
    )


if __name__ == "__main__":
    score_all_vendors()
