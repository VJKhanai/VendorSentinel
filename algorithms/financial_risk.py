from __future__ import annotations

from typing import Any, Mapping


RATING_TO_RISK_SCORE = {
    "A+": 10.0,
    "A": 15.0,
    "A-": 20.0,
    "B+": 35.0,
    "B": 45.0,
    "B-": 60.0,
    "C": 75.0,
    "D": 95.0,
}


def clamp(value: float, minimum: float, maximum: float) -> float:
    """Restrict a number to the required range."""

    return max(minimum, min(value, maximum))


def calculate_financial_risk(
    vendor: Mapping[str, Any],
) -> dict[str, Any]:
    """
    Calculate vendor financial-health risk on a 0–100 scale.

    The generated dataset stores financial_score on a 1–10 scale,
    where a higher number indicates weaker financial health.
    """

    financial_rating = str(
        vendor.get("financial_rating") or ""
    ).strip().upper()

    raw_financial_score = vendor.get("financial_score")

    try:
        if raw_financial_score not in (None, ""):
            score_1_to_10 = float(raw_financial_score)

            financial_risk_score = clamp(
                score_1_to_10 * 10,
                0,
                100,
            )
        else:
            financial_risk_score = RATING_TO_RISK_SCORE.get(
                financial_rating,
                50.0,
            )

    except (TypeError, ValueError):
        financial_risk_score = RATING_TO_RISK_SCORE.get(
            financial_rating,
            50.0,
        )

    reasons: list[str] = []
    recommendations: list[str] = []

    if financial_risk_score >= 90:
        reasons.append(
            "Vendor has a distressed or very weak financial rating."
        )
        recommendations.append(
            "Escalate the vendor for immediate financial viability review."
        )

    elif financial_risk_score >= 70:
        reasons.append(
            "Vendor financial health presents a high continuity risk."
        )
        recommendations.append(
            "Request updated financial statements and a business "
            "continuity assurance plan."
        )

    elif financial_risk_score >= 50:
        reasons.append(
            "Vendor has below-average financial strength."
        )
        recommendations.append(
            "Increase financial monitoring and review the vendor "
            "before contract renewal."
        )

    elif financial_risk_score >= 30:
        reasons.append(
            "Vendor financial health is acceptable but should "
            "continue to be monitored."
        )
        recommendations.append(
            "Continue periodic financial-health monitoring."
        )

    else:
        reasons.append(
            "Vendor demonstrates strong financial health."
        )
        recommendations.append(
            "Continue normal financial monitoring."
        )

    if financial_rating:
        reasons.append(
            f"Recorded financial rating is {financial_rating}."
        )

    return {
        "score": round(financial_risk_score, 1),
        "rating": financial_rating or "NOT AVAILABLE",
        "reasons": reasons,
        "recommendations": recommendations,
    }