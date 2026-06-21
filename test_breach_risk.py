import sqlite3
from pathlib import Path

from algorithms.breach_risk import calculate_breach_risk


BASE_DIR = Path(__file__).resolve().parent
DATABASE_FILE = BASE_DIR / "database" / "vendor_risk.db"


with sqlite3.connect(DATABASE_FILE) as connection:
    connection.row_factory = sqlite3.Row

    vendor = connection.execute(
        """
        SELECT *
        FROM vendors
        WHERE had_breach = 1
        ORDER BY breach_date DESC, data_sensitivity DESC
        LIMIT 1
        """
    ).fetchone()


if vendor is None:
    raise RuntimeError("No breached vendor was found.")


vendor_dict = dict(vendor)
result = calculate_breach_risk(vendor_dict)

print("Vendor:", vendor_dict["vendor_name"])
print("Category:", vendor_dict["category"])
print("Breach date:", vendor_dict["breach_date"])
print("Breach severity:", vendor_dict["breach_severity"])
print("Data sensitivity:", vendor_dict["data_sensitivity"])
print(
    "Under investigation:",
    vendor_dict["under_investigation"],
)

print("\nBREACH RISK RESULT")
print("------------------")
print("Score:", result["breach_risk_score"])
print("Level:", result["breach_risk_level"])

print("\nReasons:")
for reason in result["breach_risk_reasons"]:
    print("-", reason)