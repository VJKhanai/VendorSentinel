import sqlite3
from pathlib import Path

from algorithms.compliance_risk import (
    calculate_compliance_risk,
)


BASE_DIR = Path(__file__).resolve().parent
DATABASE_FILE = BASE_DIR / "database" / "vendor_risk.db"


with sqlite3.connect(DATABASE_FILE) as connection:
    connection.row_factory = sqlite3.Row

    vendor = connection.execute(
        """
        SELECT *
        FROM vendors
        ORDER BY
            compliance_gap_score DESC,
            assessment_overdue DESC,
            data_sensitivity DESC
        LIMIT 1
        """
    ).fetchone()


if vendor is None:
    raise RuntimeError("No vendor record was found.")


vendor_dict = dict(vendor)
result = calculate_compliance_risk(vendor_dict)

print("Vendor:", vendor_dict["vendor_name"])
print("SOC 2:", vendor_dict["soc2_type2"])
print("SOC 2 expiry:", vendor_dict["soc2_expiry"])
print("ISO 27001:", vendor_dict["iso27001"])
print("ISO expiry:", vendor_dict["iso27001_expiry"])
print("GDPR DPA:", vendor_dict["gdpr_dpa"])
print("Assessment overdue:", vendor_dict["assessment_overdue"])
print("Data sensitivity:", vendor_dict["data_sensitivity"])

print("\nCOMPLIANCE RISK RESULT")
print("----------------------")
print("Score:", result["compliance_risk_score"])
print("Level:", result["compliance_risk_level"])

print("\nReasons:")
for reason in result["compliance_risk_reasons"]:
    print("-", reason)

print("\nFramework mappings:")
for framework in result["framework_mappings"]:
    print("-", framework)