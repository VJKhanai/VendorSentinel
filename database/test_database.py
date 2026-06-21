from pathlib import Path
import sqlite3


PROJECT_DIR = Path(__file__).resolve().parent.parent
DATABASE_FILE = PROJECT_DIR / "database" / "vendor_risk.db"


def test_database():
    if not DATABASE_FILE.exists():
        raise FileNotFoundError(
            f"Database not found: {DATABASE_FILE}"
        )

    with sqlite3.connect(DATABASE_FILE) as connection:
        connection.row_factory = sqlite3.Row

        total_vendors = connection.execute(
            "SELECT COUNT(*) AS count FROM vendors"
        ).fetchone()["count"]

        anomaly_count = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM vendor_risk_view
            WHERE is_anomaly = 1
            """
        ).fetchone()["count"]

        critical_count = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM vendor_risk_view
            WHERE severity = 'CRITICAL'
            """
        ).fetchone()["count"]

        top_vendors = connection.execute(
            """
            SELECT
                vendor_id,
                vendor_name,
                category,
                risk_score,
                risk_level,
                severity,
                anomaly_type
            FROM vendor_risk_view
            ORDER BY risk_score DESC
            LIMIT 5
            """
        ).fetchall()

    print("DATABASE TEST RESULTS")
    print("---------------------")
    print("Total vendors:", total_vendors)
    print("Anomalous vendors:", anomaly_count)
    print("Critical vendors:", critical_count)

    print("\nTop 5 vendors by risk score:")

    for vendor in top_vendors:
        print(
            vendor["vendor_id"],
            "|",
            vendor["vendor_name"],
            "| Score:",
            vendor["risk_score"],
            "| Risk:",
            vendor["risk_level"],
            "| Severity:",
            vendor["severity"],
            "| Type:",
            vendor["anomaly_type"],
        )


if __name__ == "__main__":
    test_database()