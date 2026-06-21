from __future__ import annotations

import argparse
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
DATABASE_FILE = BASE_DIR / "database" / "vendor_risk.db"


def get_current_quarter_label() -> str:
    """Return a label such as 2026-Q2."""

    now = datetime.now(timezone.utc)
    quarter = ((now.month - 1) // 3) + 1

    return f"{now.year}-Q{quarter}"


def create_history_table(
    connection: sqlite3.Connection,
) -> None:
    """Create the score-history table when it does not exist."""

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS risk_score_history (
            snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_label TEXT NOT NULL,
            snapshot_at TEXT NOT NULL,

            vendor_id TEXT NOT NULL,
            vendor_name TEXT NOT NULL,
            category TEXT,

            access_risk_score REAL,
            breach_risk_score REAL,
            compliance_risk_score REAL,
            lifecycle_risk_score REAL,
            financial_risk_score REAL,

            final_risk_score REAL NOT NULL,
            final_risk_level TEXT NOT NULL,

            UNIQUE(snapshot_label, vendor_id)
        )
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_risk_history_vendor
        ON risk_score_history(vendor_id)
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_risk_history_label
        ON risk_score_history(snapshot_label)
        """
    )


def save_snapshot(snapshot_label: str) -> None:
    """Store the latest score of every vendor as one snapshot."""

    snapshot_at = datetime.now(
        timezone.utc
    ).isoformat(timespec="seconds")

    with sqlite3.connect(DATABASE_FILE) as connection:
        connection.row_factory = sqlite3.Row

        create_history_table(connection)

        score_rows = connection.execute(
            """
            SELECT
                vendor_id,
                vendor_name,
                category,
                access_risk_score,
                breach_risk_score,
                compliance_risk_score,
                lifecycle_risk_score,
                financial_risk_score,
                final_risk_score,
                final_risk_level
            FROM vendor_scores
            """
        ).fetchall()

        if not score_rows:
            raise RuntimeError(
                "No vendor scores found. Run "
                "score_all_vendors.py first."
            )

        snapshot_rows = [
            (
                snapshot_label,
                snapshot_at,
                row["vendor_id"],
                row["vendor_name"],
                row["category"],
                row["access_risk_score"],
                row["breach_risk_score"],
                row["compliance_risk_score"],
                row["lifecycle_risk_score"],
                row["financial_risk_score"],
                row["final_risk_score"],
                row["final_risk_level"],
            )
            for row in score_rows
        ]

        connection.executemany(
            """
            INSERT INTO risk_score_history (
                snapshot_label,
                snapshot_at,
                vendor_id,
                vendor_name,
                category,
                access_risk_score,
                breach_risk_score,
                compliance_risk_score,
                lifecycle_risk_score,
                financial_risk_score,
                final_risk_score,
                final_risk_level
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

            ON CONFLICT(snapshot_label, vendor_id)
            DO UPDATE SET
                snapshot_at = excluded.snapshot_at,
                vendor_name = excluded.vendor_name,
                category = excluded.category,
                access_risk_score =
                    excluded.access_risk_score,
                breach_risk_score =
                    excluded.breach_risk_score,
                compliance_risk_score =
                    excluded.compliance_risk_score,
                lifecycle_risk_score =
                    excluded.lifecycle_risk_score,
                financial_risk_score =
                    excluded.financial_risk_score,
                final_risk_score =
                    excluded.final_risk_score,
                final_risk_level =
                    excluded.final_risk_level
            """,
            snapshot_rows,
        )

        connection.commit()

        stored_count = connection.execute(
            """
            SELECT COUNT(*) AS total
            FROM risk_score_history
            WHERE snapshot_label = ?
            """,
            (snapshot_label,),
        ).fetchone()["total"]

        total_snapshots = connection.execute(
            """
            SELECT COUNT(DISTINCT snapshot_label) AS total
            FROM risk_score_history
            """
        ).fetchone()["total"]

    print("Risk-score snapshot saved successfully!")
    print("Snapshot label:", snapshot_label)
    print("Snapshot timestamp:", snapshot_at)
    print("Vendors stored:", stored_count)
    print("Total snapshot periods:", total_snapshots)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Store the latest vendor-risk scores "
            "for historical comparison."
        )
    )

    parser.add_argument(
        "--label",
        default=get_current_quarter_label(),
        help=(
            "Snapshot label, for example 2026-Q2 "
            "or 2026-Annual."
        ),
    )

    arguments = parser.parse_args()

    save_snapshot(arguments.label.strip())


if __name__ == "__main__":
    main()