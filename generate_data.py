"""
Phase 1 - Data Generation
Generates vendor_registry.csv and vendor_labels.csv matching the
Societe Generale hackathon spec (400 vendors, realistic distributions).
"""

import pandas as pd
import numpy as np
import random
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from faker import Faker

fake = Faker()
random.seed(42)
np.random.seed(42)

TODAY = datetime.today()
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
# ── Vendor categories ──────────────────────────────────────────────────────────
CATEGORIES = [
    "Cloud Provider",
    "Managed Service Provider",
    "Payment Processor",
    "Software Vendor",
    "HR Platform",
    "Backup & Disaster Recovery",
    "Security Vendor",
    "Integration Partner",
    "Contractor & Consultant",
    "Data Analytics",
]

# ── Systems each category typically accesses ───────────────────────────────────
SYSTEMS_BY_CATEGORY = {
    "Cloud Provider":              ["Infrastructure", "Database_Primary", "FileServer_Corporate"],
    "Managed Service Provider":    ["Network", "Servers", "Database_Secondary"],
    "Payment Processor":           ["Payment_Gateway", "Customer_PII_DB", "Transaction_Logs"],
    "Software Vendor":             ["Application_Server", "Config_Management"],
    "HR Platform":                 ["Employee_Records", "Payroll_DB", "Customer_PII_DB"],
    "Backup & Disaster Recovery":  ["Database_Primary", "FileServer_Corporate", "Backup_Storage"],
    "Security Vendor":             ["SIEM", "Firewall_Config", "Endpoint_Management"],
    "Integration Partner":         ["API_Gateway", "Database_Secondary", "Message_Queue"],
    "Contractor & Consultant":     ["Source_Code", "Development_DB", "Internal_Wiki"],
    "Data Analytics":              ["Data_Warehouse", "Analytics_DB", "Customer_PII_DB"],
}

DATA_SENSITIVITY_BY_CATEGORY = {
    "Cloud Provider":              (6, 9),
    "Managed Service Provider":    (5, 8),
    "Payment Processor":           (8, 10),
    "Software Vendor":             (3, 6),
    "HR Platform":                 (7, 10),
    "Backup & Disaster Recovery":  (7, 10),
    "Security Vendor":             (6, 9),
    "Integration Partner":         (4, 7),
    "Contractor & Consultant":     (3, 7),
    "Data Analytics":              (6, 9),
}

FINANCIAL_RATINGS = ["A+", "A", "A-", "B+", "B", "B-", "C", "D"]
FINANCIAL_SCORE = {
    "A+": (1, 2), "A": (2, 3), "A-": (2, 4),
    "B+": (4, 5), "B": (5, 6), "B-": (6, 7),
    "C":  (7, 9), "D": (9, 10),
}

# ── Helper functions ───────────────────────────────────────────────────────────

def random_date(start_days_ago, end_days_ago=0):
    delta = random.randint(end_days_ago, start_days_ago)
    return TODAY - timedelta(days=delta)

def date_str(dt):
    return dt.strftime("%Y-%m-%d") if dt else None

def vendor_name(category):
    suffixes = {
        "Cloud Provider":             ["Cloud", "Systems", "Networks", "Tech"],
        "Managed Service Provider":   ["MSP", "Services", "Solutions", "IT"],
        "Payment Processor":          ["Pay", "Payments", "Fintech", "Clearing"],
        "Software Vendor":            ["Software", "Labs", "Technologies", "Apps"],
        "HR Platform":                ["HR", "People", "Workforce", "Talent"],
        "Backup & Disaster Recovery": ["Backup", "Recovery", "DataGuard", "Vault"],
        "Security Vendor":            ["Security", "Cyber", "Shield", "SecOps"],
        "Integration Partner":        ["Integrations", "Connect", "API", "Bridge"],
        "Contractor & Consultant":    ["Consulting", "Advisory", "Partners", "Group"],
        "Data Analytics":             ["Analytics", "Insights", "DataOps", "BI"],
    }
    company = fake.company().split(",")[0].split("and")[0].strip()
    suffix  = random.choice(suffixes[category])
    return f"{company} {suffix}"

def generate_certifications(category, force_expired=False, force_none=False):
    """Return SOC2, ISO27001, GDPR_DPA flags and expiry dates."""
    if force_none:
        return False, None, False, None, False

    has_soc2   = random.random() > 0.30
    has_iso    = random.random() > 0.50
    has_gdpr   = random.random() > 0.20

    if force_expired:
        # Expire one or both certs in the past
        soc2_expiry = date_str(random_date(730, 30))   # expired 30-730 days ago
        iso_expiry  = date_str(random_date(365, 30)) if has_iso else None
    else:
        soc2_expiry = date_str(TODAY + timedelta(days=random.randint(30, 730))) if has_soc2 else None
        iso_expiry  = date_str(TODAY + timedelta(days=random.randint(30, 730))) if has_iso else None

    return has_soc2, soc2_expiry, has_iso, iso_expiry, has_gdpr

def breach_history(force_recent=False, force_none=True):
    """Return (had_breach, breach_date, breach_severity)."""
    if force_none and not force_recent:
        return False, None, None
    if force_recent:
        breach_date = date_str(random_date(365, 1))   # within last 12 months
        severity    = random.choice(["HIGH", "CRITICAL"])
        return True, breach_date, severity
    # Random historical breach
    if random.random() < 0.15:
        breach_date = date_str(random_date(1825, 366)) # 1-5 years ago
        severity    = random.choice(["LOW", "MEDIUM", "HIGH"])
        return True, breach_date, severity
    return False, None, None

def compute_risk_score(row):
    """
    Risk Score = (Data_Sensitivity × Access_Scope) / 10
                 + Compliance_Gap_Score
                 + Breach_Score
                 + Financial_Score
    Scaled to 0–100.
    """
    ds   = row["data_sensitivity"]        # 1-10
    ac   = row["access_scope"]            # 1-10
    comp = row["compliance_gap_score"]    # 0-30
    brs  = row["breach_score"]            # 0-30
    fin  = row["financial_score"]         # 1-10

    raw = (ds * ac) / 10 + comp + brs + fin
    # raw range: ~0.1 + 0+0+1 = 1  to  10 + 30+30+10 = 80  → scale to 0-100
    scaled = min(100, round((raw / 80) * 100, 1))
    return scaled

# ── Main generator ─────────────────────────────────────────────────────────────

def generate_vendors(n=400):
    records = []
    labels  = []

    # Anomaly type quotas (to match the spec's ~80% flagged rate)
    quota = {
        "BREACHED_VENDOR_HIGH_ACCESS":    20,   # CRITICAL
        "VENDOR_UNDER_INVESTIGATION":     15,   # CRITICAL
        "HIGH_RISK_SCORE":                30,   # HIGH
        "EXPIRED_CERTIFICATION":          40,   # HIGH/MEDIUM
        "RECENTLY_BREACHED_VENDOR":       50,   # MEDIUM
        "CONTRACT_EXPIRED_ACTIVE_ACCESS": 35,   # MEDIUM
        "ELEVATED_RISK_VENDOR":           80,   # LOW
        "NORMAL":                         130,  # no anomaly (~20%)
    }
    # Build a flat list of anomaly types to assign
    anomaly_pool = []
    for atype, count in quota.items():
        anomaly_pool.extend([atype] * count)
    random.shuffle(anomaly_pool)

    vendor_id = 1000
    for i in range(n):
        atype    = anomaly_pool[i] if i < len(anomaly_pool) else "NORMAL"
        category = random.choice(CATEGORIES)
        vid      = f"VND-{vendor_id:04d}"
        vendor_id += 1

        # ── Contract dates ─────────────────────────────────────────────────
        contract_start = random_date(1825, 365)   # started 1-5 years ago
        if atype == "CONTRACT_EXPIRED_ACTIVE_ACCESS":
            contract_end = date_str(random_date(365, 1))   # expired
        else:
            contract_end = date_str(contract_start + timedelta(days=random.randint(365, 1095)))
        
        contract_end_date = datetime.strptime(
        contract_end,
        "%Y-%m-%d",
)

# Only the specific anomaly keeps active access after expiry.
        if atype == "CONTRACT_EXPIRED_ACTIVE_ACCESS":
            access_active = True
        else:
            access_active = contract_end_date >= TODAY

        # ── Data access ────────────────────────────────────────────────────
        ds_range = DATA_SENSITIVITY_BY_CATEGORY[category]
        ds = random.randint(*ds_range)
        # Ground-truth high-access breach vendors must handle sensitive data
        if atype == "BREACHED_VENDOR_HIGH_ACCESS":
            ds = max(ds, 8)

        systems = random.sample(
            SYSTEMS_BY_CATEGORY[category],
            k=min(random.randint(1, 3), len(SYSTEMS_BY_CATEGORY[category]))
        )
        access_scope  = len(systems) + random.randint(0, 2)
        access_scope  = min(10, access_scope)
        access_type   = random.choice(["read_only", "read_write", "read_write"])
        # Critical breached vendors have both sensitive and broad access
        if atype == "BREACHED_VENDOR_HIGH_ACCESS":
            ds = max(ds, 8)
        if atype == "BREACHED_VENDOR_HIGH_ACCESS":
            access_scope = max(access_scope, 4)
            access_type = "read_write"

# Ordinary recent-breach cases have a lower access scope
        if atype == "RECENTLY_BREACHED_VENDOR":
            ds = min(ds, 6)
            access_scope = min(access_scope, 3)
        is_under_inv  = (atype == "VENDOR_UNDER_INVESTIGATION")

        # ── Certifications ─────────────────────────────────────────────────
        force_exp  = (atype == "EXPIRED_CERTIFICATION")
        force_none_cert = (atype in ["BREACHED_VENDOR_HIGH_ACCESS", "VENDOR_UNDER_INVESTIGATION"]
                           and random.random() < 0.5)
        soc2, soc2_exp, iso, iso_exp, gdpr = generate_certifications(
            category, force_expired=force_exp, force_none=force_none_cert
        )

        # Compliance gap score (0-30)
        comp_gap = 0
        if not soc2:   comp_gap += 10
        if not iso:    comp_gap += 8
        if not gdpr:   comp_gap += 12
        if soc2 and soc2_exp:
            days_to_exp = (datetime.strptime(soc2_exp, "%Y-%m-%d") - TODAY).days
            if days_to_exp < 0:
                comp_gap += 15   # already expired
            elif days_to_exp < 60:
                comp_gap += 8    # expiring soon
        comp_gap = min(30, comp_gap)

        # ── Breach history ─────────────────────────────────────────────────
        force_recent_breach = atype in [
            "BREACHED_VENDOR_HIGH_ACCESS", "RECENTLY_BREACHED_VENDOR", "VENDOR_UNDER_INVESTIGATION"
        ]
        had_breach, breach_date, breach_sev = breach_history(
            force_recent=force_recent_breach,
            force_none=(not force_recent_breach)
        )

        # Breach score (0-30)
        breach_score = 0
        if had_breach and breach_date:
            days_since = (TODAY - datetime.strptime(breach_date, "%Y-%m-%d")).days
            if days_since <= 365:
                breach_score = 30 if ds >= 7 else 20
            elif days_since <= 1095:
                breach_score = 15
            else:
                breach_score = 5
        breach_score = min(30, breach_score)

        # ── Financial ─────────────────────────────────────────────────────
        fin_rating = random.choice(FINANCIAL_RATINGS)
        fin_score  = random.randint(*FINANCIAL_SCORE[fin_rating])
        annual_spend = random.randint(5000, 2000000)

        # ── Compute risk ───────────────────────────────────────────────────
        row_data = {
            "data_sensitivity":   ds,
            "access_scope":       access_scope,
            "compliance_gap_score": comp_gap,
            "breach_score":       breach_score,
            "financial_score":    fin_score,
        }
        risk_score = compute_risk_score(row_data)

        # Force high scores for HIGH_RISK_SCORE anomaly type
        if atype == "HIGH_RISK_SCORE":
            risk_score = random.uniform(80, 99)
        elif atype == "ELEVATED_RISK_VENDOR":
            risk_score = random.uniform(65, 79.9)

        risk_score = round(risk_score, 1)

        # Risk level from score
        if risk_score >= 80:   risk_level = "HIGH"
        elif risk_score >= 65: risk_level = "MEDIUM"
        elif risk_score >= 40: risk_level = "LOW"
        else:                  risk_level = "LOW"

        # Override for investigation
        if is_under_inv:
            risk_score = max(risk_score, 75.0)
            risk_level = "HIGH"

        # ── Assessment ────────────────────────────────────────────────────
        last_assessed = date_str(random_date(730, 30))
        assessment_overdue = (
            datetime.strptime(last_assessed, "%Y-%m-%d") < TODAY - timedelta(days=365)
        )

        # ── Vendor contact ────────────────────────────────────────────────
        liaison_name  = fake.name()
        liaison_email = fake.company_email()

        record = {
            "vendor_id":              vid,
            "vendor_name":            vendor_name(category),
            "category":               category,
            "contract_start":         date_str(contract_start),
            "contract_end":           contract_end,
            "data_systems":           "|".join(systems),
            "data_sensitivity":       ds,
            "access_scope":           access_scope,
            "access_type":            access_type,
            "access_active": access_active,
            "soc2_type2":             soc2,
            "soc2_expiry":            soc2_exp,
            "iso27001":               iso,
            "iso27001_expiry":        iso_exp,
            "gdpr_dpa":               gdpr,
            "had_breach":             had_breach,
            "breach_date":            breach_date,
            "breach_severity":        breach_sev,
            "under_investigation":    is_under_inv,
            "financial_rating":       fin_rating,
            "financial_score":        fin_score,
            "annual_spend_usd":       annual_spend,
            "last_assessed":          last_assessed,
            "assessment_overdue":     assessment_overdue,
            "liaison_name":           liaison_name,
            "liaison_email":          liaison_email,
            "risk_score":             risk_score,
            "risk_level":             risk_level,
            "compliance_gap_score":   comp_gap,
            "breach_score":           breach_score,
        }
        records.append(record)

        # ── Ground truth label ────────────────────────────────────────────
        is_anomaly    = (atype != "NORMAL")
        severity_map  = {
            "BREACHED_VENDOR_HIGH_ACCESS":    "CRITICAL",
            "VENDOR_UNDER_INVESTIGATION":     "CRITICAL",
            "HIGH_RISK_SCORE":                "HIGH",
            "EXPIRED_CERTIFICATION":          "HIGH" if ds >= 6 else "MEDIUM",
            "RECENTLY_BREACHED_VENDOR":       "MEDIUM",
            "CONTRACT_EXPIRED_ACTIVE_ACCESS": "MEDIUM",
            "ELEVATED_RISK_VENDOR":           "LOW",
            "NORMAL":                         None,
        }
        expired_certs = []
        if soc2 and soc2_exp:
            if datetime.strptime(soc2_exp, "%Y-%m-%d") < TODAY:
                expired_certs.append("SOC2")
        if iso and iso_exp:
            if datetime.strptime(iso_exp, "%Y-%m-%d") < TODAY:
                expired_certs.append("ISO27001")

        label = {
            "vendor_id":           vid,
            "is_anomaly":          int(is_anomaly),
            "anomaly_type":        atype if is_anomaly else "NORMAL",
            "severity":            severity_map[atype],
            "expired_certifications": "|".join(expired_certs) if expired_certs else None,
            "explanation":         _explain(atype, record),
        }
        labels.append(label)

    return pd.DataFrame(records), pd.DataFrame(labels)


def _explain(atype, r):
    exps = {
        "BREACHED_VENDOR_HIGH_ACCESS":    f"Vendor breached within last 12 months and has HIGH sensitivity data access (score={r['data_sensitivity']})",
        "VENDOR_UNDER_INVESTIGATION":     "Vendor currently under security investigation",
        "HIGH_RISK_SCORE":                f"Risk score {r['risk_score']} exceeds 80/100 threshold",
        "EXPIRED_CERTIFICATION":          f"SOC2/ISO27001 certification expired for vendor with sensitive data access",
        "RECENTLY_BREACHED_VENDOR":       f"Breach recorded on {r['breach_date']} (within last 12 months)",
        "CONTRACT_EXPIRED_ACTIVE_ACCESS": f"Contract ended {r['contract_end']} but vendor may retain system access",
        "ELEVATED_RISK_VENDOR":           f"Risk score {r['risk_score']} in 65-80 range requiring increased monitoring",
        "NORMAL":                         "No significant anomalies detected",
    }
    return exps.get(atype, "")


# ── Run ────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("Generating 400 vendor records...")
    vendors_df, labels_df = generate_vendors(400)

    # Save CSVs
    vendors_df.to_csv(DATA_DIR / "vendor_registry.csv", index=False)
    labels_df.to_csv(DATA_DIR / "vendor_labels.csv", index=False)
    print(f"vendor_registry.csv  → {len(vendors_df)} rows, {len(vendors_df.columns)} columns")
    print(f"vendor_labels.csv    → {len(labels_df)} rows")

    # Quick stats
    print("\nAnomaly distribution:")
    print(labels_df["anomaly_type"].value_counts().to_string())
    print("\nRisk level distribution:")
    print(vendors_df["risk_level"].value_counts().to_string())
    print("\nIs anomaly rate:", f"{labels_df['is_anomaly'].mean()*100:.1f}%")
    print("\nSample vendor record:")
    print(vendors_df.iloc[0].to_dict())