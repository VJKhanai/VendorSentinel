import sqlite3
from pathlib import Path

from algorithms.lifecycle_risk import (
    calculate_lifecycle_risk,
)


BASE_DIR = Path(__file__).resolve().parent
DATABASE_FILE = BASE_DIR / "database" / "vendor_risk.db"


with sqlite3.connect(DATABASE_FILE) as connection:
    connection.row_factory = sqlite3.Row

    vendor = connection.execute(
        """
        SELECT *
        FROM vendors
        WHERE date(contract_end) < date('now')
        ORDER BY
            data_sensitivity DESC,
            contract_end ASC
        LIMIT 1
        """
    ).fetchone()


if vendor is None:
    raise RuntimeError(
        "No vendor with an expired contract was found."
    )


vendor_dict = dict(vendor)
result = calculate_lifecycle_risk(vendor_dict)

print("Vendor:", vendor_dict["vendor_name"])
print("Category:", vendor_dict["category"])
print("Contract end:", vendor_dict["contract_end"])
print("Systems:", vendor_dict["data_systems"])
print("Access type:", vendor_dict["access_type"])
print("Data sensitivity:", vendor_dict["data_sensitivity"])

print("\nLIFECYCLE RISK RESULT")
print("---------------------")
print("Score:", result["lifecycle_risk_score"])
print("Level:", result["lifecycle_risk_level"])
print(
    "Days until contract end:",
    result["days_until_contract_end"],
)

print("\nReasons:")
for reason in result["lifecycle_risk_reasons"]:
    print("-", reason)

print("\nRecommended actions:")
for action in result["lifecycle_recommendations"]:
    print("-", action)