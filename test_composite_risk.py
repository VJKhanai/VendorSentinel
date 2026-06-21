import sqlite3
from pathlib import Path

from algorithms.composite_risk import (
    calculate_composite_risk,
)


BASE_DIR = Path(__file__).resolve().parent
DATABASE_FILE = BASE_DIR / "database" / "vendor_risk.db"


with sqlite3.connect(DATABASE_FILE) as connection:
    connection.row_factory = sqlite3.Row

    vendor = connection.execute(
        """
        SELECT *
        FROM vendor_risk_view
        WHERE severity = 'CRITICAL'
        ORDER BY risk_score DESC
        LIMIT 1
        """
    ).fetchone()


if vendor is None:
    raise RuntimeError("No critical vendor was found.")


vendor_dict = dict(vendor)
result = calculate_composite_risk(vendor_dict)

print("Vendor:", vendor_dict["vendor_name"])
print("Category:", vendor_dict["category"])
print("Ground-truth severity:", vendor_dict["severity"])
print("Ground-truth anomaly:", vendor_dict["anomaly_type"])

print("\nCOMPONENT SCORES")
print("----------------")
for component, score in result["component_scores"].items():
    print(component, ":", score)

print("\nFINAL RESULT")
print("------------")
print("Final score:", result["final_risk_score"])
print("Final level:", result["final_risk_level"])

print("\nRule overrides:")
if result["rule_overrides"]:
    for override in result["rule_overrides"]:
        print("-", override)
else:
    print("- No critical override applied.")

print("\nMain risk reasons:")
for reason in result["risk_reasons"]:
    print("-", reason)

print("\nRecommendations:")
for recommendation in result["recommendations"]:
    print("-", recommendation)

print("\nCompliance mappings:")
for framework in result["framework_mappings"]:
    print("-", framework)