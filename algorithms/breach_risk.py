from __future__ import annotations

from datetime import datetime
from typing import Any


SEVERITY_BASE_SCORES = {
    "LOW": 25,
    "MEDIUM": 45,
    "HIGH": 70,
    "CRITICAL": 85,
}


def safe_boolean(value: Any) -> bool:
    """Convert common database values into a boolean."""
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


def calculate_breach_risk(vendor: dict[str, Any]) -> dict[str, Any]:
    """
    Calculate breach risk from 0 to 100.

    Factors:
    1. Whether the vendor suffered a breach
    2. Breach severity
    3. Breach recency
    4. Sensitive-data access
    5. Current security investigation
    """

    reasons: list[str] = []

    had_breach = safe_boolean(vendor.get("had_breach"))
    under_investigation = safe_boolean(
        vendor.get("under_investigation")
    )

    breach_date_text = vendor.get("breach_date")
    breach_severity = str(
        vendor.get("breach_severity", "")
    ).strip().upper()

    try:
        data_sensitivity = float(
            vendor.get("data_sensitivity", 0)
        )
    except (TypeError, ValueError):
        data_sensitivity = 0

    # Vendor under investigation, even if no breach is confirmed
    if not had_breach and under_investigation:
        return {
            "breach_risk_score": 85.0,
            "breach_risk_level": "CRITICAL",
            "breach_risk_reasons": [
                "Vendor is currently under a security investigation."
            ],
        }

    # No breach and no investigation
    if not had_breach:
        return {
            "breach_risk_score": 0.0,
            "breach_risk_level": "LOW",
            "breach_risk_reasons": [
                "No known vendor breach was detected."
            ],
        }

    base_score = SEVERITY_BASE_SCORES.get(
        breach_severity,
        40,
    )

    reasons.append(
        f"Vendor has a known {breach_severity or 'UNKNOWN'} "
        "severity breach."
    )

    # Calculate breach recency
    recency_weight = 0.5

    if breach_date_text:
        try:
            breach_date = datetime.strptime(
                str(breach_date_text),
                "%Y-%m-%d",
            )

            days_since_breach = (
                datetime.today() - breach_date
            ).days

            if days_since_breach <= 90:
                recency_weight = 1.0
                reasons.append(
                    "The breach occurred within the last 90 days."
                )
            elif days_since_breach <= 180:
                recency_weight = 0.9
                reasons.append(
                    "The breach occurred within the last 6 months."
                )
            elif days_since_breach <= 365:
                recency_weight = 0.8
                reasons.append(
                    "The breach occurred within the last 12 months."
                )
            elif days_since_breach <= 1095:
                recency_weight = 0.5
                reasons.append(
                    "The breach occurred within the last 3 years."
                )
            else:
                recency_weight = 0.25
                reasons.append(
                    "The breach is more than 3 years old."
                )

        except ValueError:
            reasons.append(
                "The breach date is missing or invalid."
            )

    score = base_score * recency_weight

    # Sensitive-data bonus
    if data_sensitivity >= 8:
        score += 10
        reasons.append(
            "Vendor has access to highly sensitive customer "
            "or financial data."
        )
    elif data_sensitivity >= 6:
        score += 5
        reasons.append(
            "Vendor has access to moderately sensitive data."
        )

    # Investigation bonus
    if under_investigation:
        score += 20
        reasons.append(
            "Vendor is currently under a security investigation."
        )

    final_score = round(
        min(100, max(0, score)),
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

    return {
        "breach_risk_score": final_score,
        "breach_risk_level": level,
        "breach_risk_reasons": reasons,
    }