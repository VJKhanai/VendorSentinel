from __future__ import annotations

from datetime import datetime
from typing import Any

from algorithms.access_risk import calculate_access_risk
from algorithms.breach_risk import calculate_breach_risk
from algorithms.compliance_risk import calculate_compliance_risk
from algorithms.financial_risk import calculate_financial_risk
from algorithms.lifecycle_risk import calculate_lifecycle_risk


def safe_boolean(value: Any) -> bool:
    """Convert common database/string values into a Boolean."""

    if isinstance(value, bool):
        return value

    if value is None:
        return False

    return str(value).strip().lower() in {
        "1",
        "true",
        "yes",
        "y",
    }


def is_recent_breach(date_value: Any) -> bool:
    """Check whether a breach occurred within the last 12 months."""

    if date_value is None:
        return False

    text = str(date_value).strip()

    if not text or text.lower() in {"none", "nan"}:
        return False

    try:
        breach_date = datetime.strptime(text, "%Y-%m-%d")
        days_since = (datetime.today() - breach_date).days
        return 0 <= days_since <= 365
    except ValueError:
        return False


def calculate_composite_risk(
    vendor: dict[str, Any],
) -> dict[str, Any]:
    """
    Integrate all vendor-risk algorithms into one final score.

    Weighting:
    Access Risk      = 30%
    Breach Risk      = 25%
    Compliance Risk  = 20%
    Lifecycle Risk   = 15%
    Financial Risk   = 10%

    The access algorithm already evaluates data sensitivity,
    access scope, access type, and critical-system access.
    """

    access_result = calculate_access_risk(vendor)
    breach_result = calculate_breach_risk(vendor)
    compliance_result = calculate_compliance_risk(vendor)
    lifecycle_result = calculate_lifecycle_risk(vendor)
    financial_result = calculate_financial_risk(vendor)

    access_score = access_result["access_risk_score"]
    breach_score = breach_result["breach_risk_score"]
    compliance_score = compliance_result["compliance_risk_score"]
    lifecycle_score = lifecycle_result["lifecycle_risk_score"]
    financial_score = financial_result["score"]

    weighted_score = (
        access_score * 0.30
        + breach_score * 0.25
        + compliance_score * 0.20
        + lifecycle_score * 0.15
        + financial_score * 0.10
    )

    try:
        data_sensitivity = float(
            vendor.get("data_sensitivity", 0) or 0
        )
    except (TypeError, ValueError):
        data_sensitivity = 0.0

    try:
        access_scope = float(
            vendor.get("access_scope", 0) or 0
        )
    except (TypeError, ValueError):
        access_scope = 0.0

    under_investigation = safe_boolean(
        vendor.get("under_investigation")
    )

    had_breach = safe_boolean(
        vendor.get("had_breach")
    )

    access_type = str(
        vendor.get("access_type", "")
    ).strip().lower()

    recent_breach = (
        had_breach
        and is_recent_breach(vendor.get("breach_date"))
    )

    rule_overrides: list[str] = []

    # Critical override 1: Active security investigation.
    if under_investigation:
        weighted_score = max(weighted_score, 90)

        rule_overrides.append(
            "Critical override: vendor is currently under "
            "security investigation."
        )

    # Critical override 2: Recent breach with sensitive,
    # broad read/write access.
    if (
        recent_breach
        and data_sensitivity >= 8
        and access_scope >= 4
        and access_type == "read_write"
    ):
        weighted_score = max(weighted_score, 85)

        rule_overrides.append(
            "Critical override: recent breach combined with "
            "high-sensitivity, broad read/write access."
        )

    # High-risk override: Expired contract with active access.
    days_until_contract_end = lifecycle_result[
        "days_until_contract_end"
    ]

    if (
        days_until_contract_end is not None
        and days_until_contract_end < 0
        and lifecycle_score >= 70
    ):
        weighted_score = max(weighted_score, 70)

        rule_overrides.append(
            "High-risk override: contract expired while active "
            "system access remains."
        )

    final_score = round(
        min(100, max(0, weighted_score)),
        1,
    )

    if final_score >= 80:
        risk_level = "CRITICAL"
    elif final_score >= 65:
        risk_level = "HIGH"
    elif final_score >= 40:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # Combine explanations from every algorithm.
    all_reasons = (
        access_result["access_risk_reasons"]
        + breach_result["breach_risk_reasons"]
        + compliance_result["compliance_risk_reasons"]
        + lifecycle_result["lifecycle_risk_reasons"]
        + financial_result["reasons"]
        + rule_overrides
    )

    unique_reasons = list(dict.fromkeys(all_reasons))

    recommendations: list[str] = []

    if risk_level == "CRITICAL":
        recommendations.extend(
            [
                "Escalate the vendor to Cyber Risk and Procurement.",
                "Restrict unnecessary privileged or write access.",
                "Begin an immediate vendor security reassessment.",
            ]
        )

    elif risk_level == "HIGH":
        recommendations.extend(
            [
                "Create a time-bound remediation plan.",
                "Increase vendor monitoring frequency.",
                "Request missing or renewed compliance evidence.",
            ]
        )

    elif risk_level == "MEDIUM":
        recommendations.extend(
            [
                "Review the vendor during the next assessment cycle.",
                "Track identified gaps until they are resolved.",
            ]
        )

    else:
        recommendations.append(
            "Continue normal vendor monitoring."
        )

    recommendations.extend(
        lifecycle_result["lifecycle_recommendations"]
    )

    recommendations.extend(
        financial_result["recommendations"]
    )

    unique_recommendations = list(
        dict.fromkeys(recommendations)
    )

    return {
        "final_risk_score": final_score,
        "final_risk_level": risk_level,
        "component_scores": {
            "access_risk": access_score,
            "breach_risk": breach_score,
            "compliance_risk": compliance_score,
            "lifecycle_risk": lifecycle_score,
            "financial_risk": financial_score,
        },
        "financial_rating": financial_result["rating"],
        "risk_reasons": unique_reasons,
        "rule_overrides": rule_overrides,
        "recommendations": unique_recommendations,
        "framework_mappings": compliance_result[
            "framework_mappings"
        ],
    }
