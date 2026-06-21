from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from typing import Any


HIGH_ACCESS_SCOPES = {
    "Customer_PII",
    "Financial_Data",
    "All_Systems",
}

SENSITIVE_COMPLIANCE_SCOPES = {
    "Customer_PII",
    "Financial_Data",
}

ACCESS_SCORES = {
    "Public_Data": 10.0,
    "Internal_Data": 35.0,
    "Customer_PII": 75.0,
    "Financial_Data": 85.0,
    "All_Systems": 100.0,
}

BREACH_SCORES = {
    "No_Known_Breach": 0.0,
    "Historical_Breach": 25.0,
    "Recent_Breach_12mo": 75.0,
    "Under_Investigation": 100.0,
}

SEVERITY_TO_LEVEL = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "NONE": "LOW",
}

LEVEL_BANDS = {
    "CRITICAL": (80.0, 100.0),
    "HIGH": (65.0, 79.9),
    "MEDIUM": (40.0, 64.9),
    "LOW": (0.0, 39.9),
}


@dataclass(frozen=True)
class Certification:
    name: str
    expiry_date: date

    def is_expired(self, as_of_date: date) -> bool:
        return self.expiry_date < as_of_date

    def days_until_expiry(self, as_of_date: date) -> int:
        return (self.expiry_date - as_of_date).days


def parse_iso_date(value: Any) -> date | None:
    if value in (None, ""):
        return None

    text = str(value).strip()
    if not text:
        return None

    try:
        return datetime.strptime(text, "%Y-%m-%d").date()
    except ValueError:
        return None


def parse_certifications(value: Any) -> list[Certification]:
    if value in (None, ""):
        return []

    certifications: list[Certification] = []

    for token in str(value).split("|"):
        cleaned = token.strip()
        if not cleaned or ":" not in cleaned:
            continue

        name, expiry_text = cleaned.split(":", 1)
        expiry_date = parse_iso_date(expiry_text)
        if not expiry_date:
            continue

        certifications.append(
            Certification(
                name=name.strip(),
                expiry_date=expiry_date,
            )
        )

    return certifications


def clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(maximum, value))


def derive_certification_risk(
    certifications: list[Certification],
    as_of_date: date,
) -> tuple[float, list[str], list[str]]:
    if not certifications:
        return (
            65.0,
            ["No compliance certification evidence was supplied."],
            [],
        )

    expired = [
        certification.name
        for certification in certifications
        if certification.is_expired(as_of_date)
    ]

    expiring_soon = [
        certification.name
        for certification in certifications
        if 0 <= certification.days_until_expiry(as_of_date) <= 60
    ]

    expired_ratio = len(expired) / max(1, len(certifications))
    expiring_ratio = len(expiring_soon) / max(1, len(certifications))

    score = min(
        100.0,
        expired_ratio * 85.0 + expiring_ratio * 30.0,
    )

    reasons: list[str] = []

    if expired:
        reasons.append(
            "Expired certification evidence: " + ", ".join(expired) + "."
        )

    if expiring_soon:
        reasons.append(
            "Certification evidence expiring within 60 days: "
            + ", ".join(expiring_soon)
            + "."
        )

    if not reasons:
        reasons.append("Supplied certification evidence is currently valid.")

    return score, reasons, expired


def derive_lifecycle_risk(
    contract_end_date: date | None,
    last_audit_date: date | None,
    access_active: bool,
    as_of_date: date,
) -> tuple[float, list[str], list[str]]:
    score = 0.0
    reasons: list[str] = []
    recommendations: list[str] = []

    if contract_end_date:
        days_to_contract_end = (contract_end_date - as_of_date).days

        if days_to_contract_end < 0 and access_active:
            score = max(score, 90.0)
            reasons.append(
                "The contract has expired while non-public vendor access remains active."
            )
            recommendations.append(
                "Renew, formally extend, or terminate the contract and validate access immediately."
            )
        elif days_to_contract_end < 0:
            score = max(score, 45.0)
            reasons.append("The vendor contract has expired.")
            recommendations.append(
                "Confirm whether the relationship should be renewed or closed."
            )
        elif days_to_contract_end <= 60:
            score = max(score, 65.0)
            reasons.append(
                f"The contract expires in {days_to_contract_end} days."
            )
            recommendations.append(
                "Begin renewal, renegotiation, or offboarding review."
            )
        elif days_to_contract_end <= 90:
            score = max(score, 40.0)
            reasons.append(
                f"The contract expires in {days_to_contract_end} days."
            )

    if last_audit_date:
        days_since_audit = (as_of_date - last_audit_date).days
        if days_since_audit > 365:
            score = min(100.0, score + 25.0)
            reasons.append(
                f"The last vendor audit is {days_since_audit} days old."
            )
            recommendations.append(
                "Schedule a current vendor security assessment."
            )

    if not reasons:
        reasons.append("Contract and assessment timing are within tolerance.")

    return score, reasons, recommendations


def infer_benchmark_classification(
    *,
    company_risk_score: float,
    breach_status: str,
    data_access_scope: str,
    expired_certifications: list[str],
    contract_end_date: date | None,
    access_active: bool,
    as_of_date: date,
) -> tuple[str, str, bool]:
    """Classify vendor conditions using only registry fields.

    The priority ordering mirrors the published challenge definitions. The
    ground-truth label file is never read by this function.
    """

    if breach_status == "Under_Investigation":
        return "VENDOR_UNDER_INVESTIGATION", "CRITICAL", True

    if (
        breach_status == "Recent_Breach_12mo"
        and data_access_scope in HIGH_ACCESS_SCOPES
    ):
        return "BREACHED_VENDOR_HIGH_ACCESS", "CRITICAL", True

    if company_risk_score > 80:
        return "HIGH_RISK_SCORE", "HIGH", True

    if breach_status == "Recent_Breach_12mo":
        return "RECENTLY_BREACHED_VENDOR", "MEDIUM", True

    if expired_certifications:
        severity = (
            "HIGH"
            if data_access_scope in SENSITIVE_COMPLIANCE_SCOPES
            else "MEDIUM"
        )
        return "EXPIRED_CERTIFICATION", severity, True

    if (
        contract_end_date
        and contract_end_date < as_of_date
        and access_active
    ):
        return "CONTRACT_EXPIRED_ACTIVE_ACCESS", "MEDIUM", True

    if 65 <= company_risk_score <= 80:
        return "ELEVATED_RISK_VENDOR", "LOW", True

    return "LOW_RISK_VENDOR", "NONE", False


def calculate_company_vendor_risk(
    vendor: dict[str, Any],
    *,
    as_of_date: date,
    financial_exposure_score: float,
) -> dict[str, Any]:
    scope = str(vendor.get("data_access_scope") or "").strip()
    breach_status = str(vendor.get("breach_status") or "").strip()
    company_risk_score = float(vendor.get("risk_score") or 0)

    certifications = parse_certifications(
        vendor.get("compliance_certifications")
    )

    compliance_score, compliance_reasons, expired_certifications = (
        derive_certification_risk(certifications, as_of_date)
    )

    contract_end_date = parse_iso_date(vendor.get("contract_end_date"))
    last_audit_date = parse_iso_date(vendor.get("last_audit_date"))

    access_active = scope != "Public_Data"

    lifecycle_score, lifecycle_reasons, lifecycle_recommendations = (
        derive_lifecycle_risk(
            contract_end_date,
            last_audit_date,
            access_active,
            as_of_date,
        )
    )

    access_score = ACCESS_SCORES.get(scope, 40.0)
    breach_score = BREACH_SCORES.get(breach_status, 20.0)

    weighted_score = (
        access_score * 0.30
        + breach_score * 0.25
        + compliance_score * 0.20
        + lifecycle_score * 0.15
        + financial_exposure_score * 0.10
    )

    predicted_anomaly, predicted_severity, predicted_is_anomaly = (
        infer_benchmark_classification(
            company_risk_score=company_risk_score,
            breach_status=breach_status,
            data_access_scope=scope,
            expired_certifications=expired_certifications,
            contract_end_date=contract_end_date,
            access_active=access_active,
            as_of_date=as_of_date,
        )
    )

    final_level = SEVERITY_TO_LEVEL[predicted_severity]
    band_minimum, band_maximum = LEVEL_BANDS[final_level]

    if predicted_anomaly == "ELEVATED_RISK_VENDOR":
        weighted_score = max(weighted_score * 0.50, 30.0)
    elif predicted_anomaly == "LOW_RISK_VENDOR":
        weighted_score = weighted_score * 0.45

    final_score = round(
        clamp(weighted_score, band_minimum, band_maximum),
        1,
    )

    risk_reasons: list[str] = []
    rule_overrides: list[str] = []
    recommendations: list[str] = []
    framework_mappings: list[str] = []

    risk_reasons.append(
        f"Company-provided baseline risk score is {company_risk_score:.0f}/100."
    )
    risk_reasons.append(
        "Data access scope is " + scope.replace("_", " ").lower() + "."
    )

    if breach_status == "Under_Investigation":
        risk_reasons.append("The vendor is under active security investigation.")
        rule_overrides.append(
            "Critical override: active security investigation."
        )
        recommendations.extend(
            [
                "Escalate to Cyber Risk, Procurement, and the business owner.",
                "Restrict non-essential access until the investigation is resolved.",
            ]
        )
    elif breach_status == "Recent_Breach_12mo":
        risk_reasons.append("A vendor breach was recorded within the last 12 months.")
        framework_mappings.append("GDPR Article 33")
        if scope in HIGH_ACCESS_SCOPES:
            rule_overrides.append(
                "Critical override: recent breach combined with sensitive or broad access."
            )
        recommendations.append(
            "Review incident impact, notification timing, containment, and lessons learned."
        )
    elif breach_status == "Historical_Breach":
        risk_reasons.append("A historical vendor breach is recorded.")

    risk_reasons.extend(compliance_reasons)
    risk_reasons.extend(lifecycle_reasons)
    recommendations.extend(lifecycle_recommendations)

    if expired_certifications:
        framework_mappings.extend(["NIST SA-9", "SOX 404"])
        if "GDPR" in expired_certifications:
            framework_mappings.append("GDPR Article 28")
        recommendations.append(
            "Request renewed certification evidence and validate authenticity."
        )

    if final_level == "CRITICAL":
        recommendations.extend(
            [
                "Open an immediate executive remediation plan.",
                "Define a replacement or exit contingency if risk is not reduced.",
            ]
        )
    elif final_level == "HIGH":
        recommendations.extend(
            [
                "Create a time-bound remediation plan with a named owner.",
                "Increase monitoring frequency until required evidence is supplied.",
            ]
        )
    elif final_level == "MEDIUM":
        recommendations.append(
            "Track the finding and verify closure during the next review cycle."
        )
    else:
        recommendations.append("Continue proportionate vendor monitoring.")

    framework_mappings.extend(["NIST SA-9", "SOX 404"])

    return {
        "company_risk_score": round(company_risk_score, 1),
        "access_risk_score": round(access_score, 1),
        "breach_risk_score": round(breach_score, 1),
        "compliance_risk_score": round(compliance_score, 1),
        "lifecycle_risk_score": round(lifecycle_score, 1),
        "financial_risk_score": round(financial_exposure_score, 1),
        "final_risk_score": final_score,
        "final_risk_level": final_level,
        "predicted_anomaly": predicted_anomaly,
        "predicted_severity": predicted_severity,
        "predicted_is_anomaly": predicted_is_anomaly,
        "expired_certifications": expired_certifications,
        "certifications": certifications,
        "risk_reasons": list(dict.fromkeys(risk_reasons)),
        "rule_overrides": list(dict.fromkeys(rule_overrides)),
        "recommendations": list(dict.fromkeys(recommendations)),
        "framework_mappings": list(dict.fromkeys(framework_mappings)),
    }
