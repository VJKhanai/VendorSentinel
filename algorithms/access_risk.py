from __future__ import annotations

from typing import Any


CRITICAL_SYSTEMS = {
    "customer_pii_db",
    "payment_gateway",
    "database_primary",
    "payroll_db",
    "transaction_logs",
    "backup_storage",
}


def safe_number(value: Any, default: float = 0) -> float:
    """Convert a value into a number safely."""
    try:
        if value is None:
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def calculate_access_risk(vendor: dict[str, Any]) -> dict[str, Any]:
    """
    Calculate vendor access risk from 0 to 100.

    Factors:
    1. Data sensitivity
    2. Access scope
    3. Read-only or read/write access
    4. Access to critical banking systems
    """

    reasons: list[str] = []

    data_sensitivity = safe_number(
        vendor.get("data_sensitivity")
    )

    access_scope = safe_number(
        vendor.get("access_scope")
    )

    access_type = str(
        vendor.get("access_type", "")
    ).strip().lower()

    systems_text = str(
        vendor.get("data_systems", "")
    ).strip().lower()

    systems = {
        system.strip()
        for system in systems_text.split("|")
        if system.strip()
    }

    # 1. Data sensitivity contributes up to 60 points
    sensitivity_score = min(
        60,
        data_sensitivity * 6,
    )

    if data_sensitivity >= 8:
        reasons.append(
            "Vendor accesses highly sensitive or financial data."
        )
    elif data_sensitivity >= 6:
        reasons.append(
            "Vendor accesses moderately sensitive business data."
        )

    # 2. Access scope contributes up to 25 points
    scope_score = min(
        25,
        access_scope * 2.5,
    )

    if access_scope >= 7:
        reasons.append(
            "Vendor has broad access across multiple systems."
        )
    elif access_scope >= 4:
        reasons.append(
            "Vendor has access to several enterprise systems."
        )

    # 3. Access type contributes up to 10 points
    if access_type == "read_write":
        access_type_score = 10
        reasons.append(
            "Vendor has read and write permissions."
        )
    elif access_type == "read_only":
        access_type_score = 3
    else:
        access_type_score = 5
        reasons.append(
            "Vendor access permission is unclear."
        )

    # 4. Critical banking-system access contributes 5 points
    matched_critical_systems = systems.intersection(
        CRITICAL_SYSTEMS
    )

    if matched_critical_systems:
        critical_system_score = 5

        readable_systems = ", ".join(
            sorted(matched_critical_systems)
        )

        reasons.append(
            f"Vendor accesses critical systems: "
            f"{readable_systems}."
        )
    else:
        critical_system_score = 0

    final_score = (
        sensitivity_score
        + scope_score
        + access_type_score
        + critical_system_score
    )

    final_score = round(
        min(100, max(0, final_score)),
        1,
    )

    if final_score >= 80:
        level = "CRITICAL"
    elif final_score >= 65:
        level = "HIGH"
    elif final_score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    if not reasons:
        reasons.append(
            "No major access-risk indicators were detected."
        )

    return {
        "access_risk_score": final_score,
        "access_risk_level": level,
        "access_risk_reasons": reasons,
    }