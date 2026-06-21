from __future__ import annotations

from typing import Any


def _as_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    return []


def generate_ai_risk_narrative(vendor: dict[str, Any]) -> dict[str, Any]:
    """Generate an offline, explainable narrative from deterministic results."""

    level = str(vendor.get("final_risk_level") or "LOW").upper()
    score = float(vendor.get("final_risk_score") or 0)
    company_score = float(vendor.get("company_risk_score") or 0)

    factors = _as_list(vendor.get("risk_reasons"))[:5]
    recommendations = _as_list(vendor.get("recommendations"))

    if level == "CRITICAL":
        posture = "requires immediate escalation and access review"
    elif level == "HIGH":
        posture = "requires a time-bound remediation plan"
    elif level == "MEDIUM":
        posture = "requires targeted follow-up and monitored closure"
    else:
        posture = "can remain under proportionate routine monitoring"

    summary = (
        f"VendorSentinel classifies this vendor as {level} with an operational "
        f"score of {score:.1f}/100. The company-provided baseline score is "
        f"{company_score:.1f}/100. Based on the available access, breach, "
        f"certification, lifecycle, and financial-exposure evidence, the vendor "
        f"{posture}."
    )

    recommendation = (
        recommendations[0]
        if recommendations
        else "Continue proportionate monitoring and retain current evidence."
    )

    return {
        "executive_summary": summary,
        "risk_factors": factors or ["No material risk factors were recorded."],
        "recommendation": recommendation,
        "generated_by": "Deterministic explanation engine",
    }
