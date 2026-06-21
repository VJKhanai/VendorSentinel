import sqlite3
from pathlib import Path

from algorithms.access_risk import calculate_access_risk


BASE_DIR = Path(__file__).resolve().parent
DATABASE_FILE = BASE_DIR / "database" / "vendor_risk.db"


with sqlite3.connect(DATABASE_FILE) as connection:
    connection.row_factory = sqlite3.Row

    vendor = connection.execute(
        """
        SELECT *
        FROM vendors
        ORDER BY data_sensitivity DESC, access_scope DESC
        LIMIT 1
        """
    ).fetchone()


vendor_dict = dict(vendor)

result = calculate_access_risk(vendor_dict)

print("Vendor:", vendor_dict["vendor_name"])
print("Category:", vendor_dict["category"])
print("Systems:", vendor_dict["data_systems"])
print("Data sensitivity:", vendor_dict["data_sensitivity"])
print("Access scope:", vendor_dict["access_scope"])
print("Access type:", vendor_dict["access_type"])

print("\nACCESS RISK RESULT")
print("------------------")
print("Score:", result["access_risk_score"])
print("Level:", result["access_risk_level"])

print("\nReasons:")
for reason in result["access_risk_reasons"]:
    print("-", reason)