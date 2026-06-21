from __future__ import annotations

from datetime import datetime
from typing import Any


def safe_boolean(value: Any) -> bool:
    """Convert database values such as 1, 0, true and false."""
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


def days_until(date_value: Any) -> int | None:
    """Return the number of days remaining until a date."""
    if date_value is None:
        return None

    date_text = str(date_value).strip()

    if not date_text or date_text.lower() in {"none", "nan"}:
        return None

    try:
        parsed_date = datetime.strptime(date_text, "%Y-%m-%d")
        return (parsed_date - datetime.today()).days
    except ValueError:
        return None


def calculate_compliance_risk(
    vendor: dict[str, Any],
) -> dict[str, Any]:
    """
    Calculate compliance risk from 0 to 100.

    Checks:
    1. SOC 2 certification
    2. ISO 27001 certification
    3. GDPR Data Processing Agreement
    4. Certification expiry
    5. Overdue vendor assessment
    """

    score = 0
    reasons: list[str] = []
    framework_mappings: list[str] = []

    has_soc2 = safe_boolean(vendor.get("soc2_type2"))
    has_iso = safe_boolean(vendor.get("iso27001"))
    has_gdpr_dpa = safe_boolean(vendor.get("gdpr_dpa"))
    assessment_overdue = safe_boolean(
        vendor.get("assessment_overdue")
    )

    data_sensitivity = float(
        vendor.get("data_sensitivity", 0) or 0
    )

    soc2_days = days_until(vendor.get("soc2_expiry"))
    iso_days = days_until(vendor.get("iso27001_expiry"))

    # SOC 2 checks
    if not has_soc2:
        score += 20
        reasons.append("SOC 2 Type II certification is missing.")
        framework_mappings.append(
            "SOX 404 — Third-party control assurance"
        )

    elif soc2_days is not None:
        if soc2_days < 0:
            score += 25
            reasons.append("SOC 2 Type II certification has expired.")
        elif soc2_days <= 30:
            score += 18
            reasons.append(
                f"SOC 2 certification expires in {soc2_days} days."
            )
        elif soc2_days <= 60:
            score += 10
            reasons.append(
                f"SOC 2 certification expires in {soc2_days} days."
            )

    # ISO 27001 checks
    if not has_iso:
        score += 15
        reasons.append("ISO 27001 certification is missing.")
        framework_mappings.append(
            "NIST SA-9 — External system service security"
        )

    elif iso_days is not None:
        if iso_days < 0:
            score += 20
            reasons.append("ISO 27001 certification has expired.")
        elif iso_days <= 30:
            score += 15
            reasons.append(
                f"ISO 27001 certification expires in {iso_days} days."
            )
        elif iso_days <= 60:
            score += 8
            reasons.append(
                f"ISO 27001 certification expires in {iso_days} days."
            )

    # GDPR agreement check
    if not has_gdpr_dpa:
        score += 25
        reasons.append(
            "GDPR Data Processing Agreement is missing."
        )
        framework_mappings.append(
            "GDPR Article 28 — Processor agreement required"
        )

    # Assessment check
    if assessment_overdue:
        score += 20
        reasons.append(
            "The vendor security assessment is overdue."
        )
        framework_mappings.append(
            "NIST SA-9 — Regular third-party assessment"
        )

    # Sensitive data increases compliance impact
    if data_sensitivity >= 8 and score > 0:
        score += 10
        reasons.append(
            "Compliance gaps affect highly sensitive data."
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
            "No major compliance gaps were detected."
        )

    if not framework_mappings:
        framework_mappings.append(
            "Vendor currently meets the evaluated baseline controls."
        )

    return {
        "compliance_risk_score": final_score,
        "compliance_risk_level": level,
        "compliance_risk_reasons": reasons,
        "framework_mappings": list(
            dict.fromkeys(framework_mappings)
        ),
    }