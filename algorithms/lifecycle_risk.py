from __future__ import annotations

from datetime import datetime
from typing import Any

def safe_boolean(value: Any) -> bool:
    """Convert database values into a boolean."""
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

def parse_date(value: Any) -> datetime | None:
    """Convert a YYYY-MM-DD value into a datetime."""
    if value is None:
        return None

    text = str(value).strip()

    if not text or text.lower() in {"none", "nan"}:
        return None

    try:
        return datetime.strptime(text, "%Y-%m-%d")
    except ValueError:
        return None


def calculate_lifecycle_risk(
    vendor: dict[str, Any],
) -> dict[str, Any]:
    """
    Calculate contract and vendor lifecycle risk.

    Factors:
    1. Contract already expired
    2. Contract approaching expiry
    3. Access permissions remaining after expiry
    4. Sensitive-data exposure
    5. Read/write access
    """

    score = 0
    reasons: list[str] = []
    recommended_actions: list[str] = []

    contract_end = parse_date(vendor.get("contract_end"))

    systems_text = str(
        vendor.get("data_systems", "")
    ).strip()

    access_type = str(
        vendor.get("access_type", "")
    ).strip().lower()

    try:
        data_sensitivity = float(
            vendor.get("data_sensitivity", 0) or 0
        )
    except (TypeError, ValueError):
        data_sensitivity = 0

    # A current access record exists when systems and permissions
    # are still listed in the vendor registry.
    access_active = safe_boolean(
    vendor.get("access_active")
)

    days_until_contract_end: int | None = None

    if contract_end is None:
        score += 20
        reasons.append(
            "Contract expiry date is missing or invalid."
        )
        recommended_actions.append(
            "Verify and update the vendor contract dates."
        )

    else:
        days_until_contract_end = (
            contract_end - datetime.today()
        ).days

        # Contract already expired
        if days_until_contract_end < 0:
            days_expired = abs(days_until_contract_end)

            score += 15
            reasons.append(
                f"Vendor contract expired {days_expired} days ago."
            )

            recommended_actions.append(
                "Review whether the vendor relationship should "
                "be renewed or terminated."
            )

            # Potential orphaned access
            if access_active:
                score += 50
                reasons.append(
                    "Active system access remains after contract expiry."
)

                recommended_actions.append(
                    "Immediately verify and revoke unnecessary "
                    "vendor access."
                )

            if data_sensitivity >= 8:
                score += 15
                reasons.append(
                    "The expired vendor relationship involves "
                    "highly sensitive data."
                )

            if access_type == "read_write":
                score += 10
                reasons.append(
                    "The vendor retains recorded read/write "
                    "permissions."
                )

        # Contract expiring soon
        elif days_until_contract_end <= 30:
            score += 30
            reasons.append(
                f"Vendor contract expires in "
                f"{days_until_contract_end} days."
            )

            recommended_actions.append(
                "Begin an urgent contract renewal and risk review."
            )

        elif days_until_contract_end <= 60:
            score += 20
            reasons.append(
                f"Vendor contract expires in "
                f"{days_until_contract_end} days."
            )

            recommended_actions.append(
                "Start the vendor renewal assessment."
            )

        elif days_until_contract_end <= 90:
            score += 10
            reasons.append(
                f"Vendor contract expires in "
                f"{days_until_contract_end} days."
            )

            recommended_actions.append(
                "Schedule the contract renewal assessment."
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

    if not reasons:
        reasons.append(
            "No significant contract lifecycle risks were detected."
        )

    if not recommended_actions:
        recommended_actions.append(
            "Continue normal contract monitoring."
        )

    return {
        "lifecycle_risk_score": final_score,
        "lifecycle_risk_level": level,
        "days_until_contract_end": days_until_contract_end,
        "lifecycle_risk_reasons": reasons,
        "lifecycle_recommendations": recommended_actions,
    }