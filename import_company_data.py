from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

import pandas as pd

from algorithms.company_risk import (
    calculate_company_vendor_risk,
    parse_certifications,
    parse_iso_date,
)


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_REGISTRY = BASE_DIR / "data" / "vendor_registry.csv"
DEFAULT_LABELS = BASE_DIR / "data" / "vendor_labels.csv"
DEFAULT_DATABASE = BASE_DIR / "database" / "vendor_risk.db"
DEFAULT_AS_OF_DATE = date(2026, 4, 20)

REQUIRED_REGISTRY_COLUMNS = {
    "vendor_id",
    "vendor_name",
    "vendor_type",
    "contact_name",
    "contact_email",
    "compliance_certifications",
    "data_access_scope",
    "risk_score",
    "breach_status",
    "annual_spend",
    "contract_end_date",
    "last_audit_date",
}

REQUIRED_LABEL_COLUMNS = {
    "record_id",
    "vendor_name",
    "is_anomaly",
    "anomaly_type",
    "severity",
    "explanation",
    "expired_certifications",
}

DATA_SCOPE_MAPPING: dict[str, dict[str, Any]] = {
    "Public_Data": {
        "systems": ["Public Web Content"],
        "data_sensitivity": 2,
        "access_scope": 1,
        "access_type": "read_only",
        "access_active": 0,
    },
    "Internal_Data": {
        "systems": ["Internal Business Systems"],
        "data_sensitivity": 5,
        "access_scope": 3,
        "access_type": "read_only",
        "access_active": 1,
    },
    "Customer_PII": {
        "systems": ["Customer Profile Platform", "Customer PII Repository"],
        "data_sensitivity": 9,
        "access_scope": 5,
        "access_type": "read_write",
        "access_active": 1,
    },
    "Financial_Data": {
        "systems": ["Financial Processing Systems", "Transaction Data"],
        "data_sensitivity": 9,
        "access_scope": 5,
        "access_type": "read_write",
        "access_active": 1,
    },
    "All_Systems": {
        "systems": [
            "Enterprise Systems",
            "Customer PII Repository",
            "Financial Processing Systems",
        ],
        "data_sensitivity": 10,
        "access_scope": 10,
        "access_type": "read_write",
        "access_active": 1,
    },
}


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Import the company-provided vendor registry into VendorSentinel."
        )
    )
    parser.add_argument(
        "--registry",
        type=Path,
        default=DEFAULT_REGISTRY,
        help="Path to vendor_registry.csv",
    )
    parser.add_argument(
        "--labels",
        type=Path,
        default=DEFAULT_LABELS,
        help="Path to vendor_labels.csv",
    )
    parser.add_argument(
        "--database",
        type=Path,
        default=DEFAULT_DATABASE,
        help="Output SQLite database path",
    )
    parser.add_argument(
        "--as-of-date",
        default=DEFAULT_AS_OF_DATE.isoformat(),
        help=(
            "Benchmark snapshot date in YYYY-MM-DD format. "
            "Default: 2026-04-20."
        ),
    )
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Do not create a timestamped backup of an existing database.",
    )
    return parser.parse_args()


def validate_columns(
    dataframe: pd.DataFrame,
    required_columns: set[str],
    label: str,
) -> None:
    missing = sorted(required_columns - set(dataframe.columns))
    if missing:
        raise ValueError(
            f"{label} is missing required columns: {', '.join(missing)}"
        )


def validate_inputs(
    registry: pd.DataFrame,
    labels: pd.DataFrame,
) -> None:
    validate_columns(registry, REQUIRED_REGISTRY_COLUMNS, "vendor_registry.csv")
    validate_columns(labels, REQUIRED_LABEL_COLUMNS, "vendor_labels.csv")

    if registry["vendor_id"].duplicated().any():
        duplicates = registry.loc[
            registry["vendor_id"].duplicated(),
            "vendor_id",
        ].tolist()
        raise ValueError(f"Duplicate vendor IDs found: {duplicates[:5]}")

    if labels["record_id"].duplicated().any():
        duplicates = labels.loc[
            labels["record_id"].duplicated(),
            "record_id",
        ].tolist()
        raise ValueError(f"Duplicate label IDs found: {duplicates[:5]}")

    registry_ids = set(registry["vendor_id"].astype(str))
    label_ids = set(labels["record_id"].astype(str))

    if registry_ids != label_ids:
        missing_labels = sorted(registry_ids - label_ids)
        missing_registry = sorted(label_ids - registry_ids)
        raise ValueError(
            "Registry and label IDs do not match. "
            f"Missing labels: {missing_labels[:5]}; "
            f"missing registry records: {missing_registry[:5]}."
        )


def backup_existing_database(database_path: Path) -> Path | None:
    if not database_path.exists():
        return None

    backup_directory = database_path.parent / "backups"
    backup_directory.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = backup_directory / f"vendor_risk_{timestamp}.db"
    shutil.copy2(database_path, backup_path)
    return backup_path


def financial_exposure_scores(annual_spend: pd.Series) -> pd.Series:
    numeric = pd.to_numeric(annual_spend, errors="coerce").fillna(0.0)
    percentile = numeric.rank(method="average", pct=True)
    return (percentile * 100.0).round(1)


def breach_fields(
    breach_status: str,
    data_access_scope: str,
    as_of_date: date,
) -> dict[str, Any]:
    status = str(breach_status or "").strip()

    if status == "Recent_Breach_12mo":
        return {
            "had_breach": 1,
            "breach_date": (as_of_date - timedelta(days=90)).isoformat(),
            "breach_severity": (
                "CRITICAL"
                if data_access_scope in {
                    "Customer_PII",
                    "Financial_Data",
                    "All_Systems",
                }
                else "HIGH"
            ),
            "under_investigation": 0,
        }

    if status == "Historical_Breach":
        return {
            "had_breach": 1,
            "breach_date": (as_of_date - timedelta(days=730)).isoformat(),
            "breach_severity": "MEDIUM",
            "under_investigation": 0,
        }

    if status == "Under_Investigation":
        return {
            "had_breach": 0,
            "breach_date": None,
            "breach_severity": "UNDER_INVESTIGATION",
            "under_investigation": 1,
        }

    return {
        "had_breach": 0,
        "breach_date": None,
        "breach_severity": None,
        "under_investigation": 0,
    }


def certification_fields(
    certification_text: str,
    as_of_date: date,
) -> dict[str, Any]:
    certifications = parse_certifications(certification_text)
    by_name = {certification.name: certification for certification in certifications}

    soc2 = by_name.get("SOC2")
    iso27001 = by_name.get("ISO27001")
    gdpr = by_name.get("GDPR")

    expired = [
        certification.name
        for certification in certifications
        if certification.is_expired(as_of_date)
    ]

    return {
        "soc2_type2": int(soc2 is not None),
        "soc2_expiry": soc2.expiry_date.isoformat() if soc2 else None,
        "iso27001": int(iso27001 is not None),
        "iso27001_expiry": (
            iso27001.expiry_date.isoformat() if iso27001 else None
        ),
        "gdpr_dpa": int(
            gdpr is not None and not gdpr.is_expired(as_of_date)
        ),
        "expired_certifications": ", ".join(expired),
        "certifications": certifications,
    }


def assessment_overdue(last_audit_date: date | None, as_of_date: date) -> int:
    if not last_audit_date:
        return 1
    return int((as_of_date - last_audit_date).days > 365)


def create_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        PRAGMA foreign_keys = OFF;

        DROP VIEW IF EXISTS vendor_risk_view;
        DROP TABLE IF EXISTS risk_score_history;
        DROP TABLE IF EXISTS remediation_actions;
        DROP TABLE IF EXISTS vendor_scores;
        DROP TABLE IF EXISTS vendor_certifications;
        DROP TABLE IF EXISTS vendor_labels;
        DROP TABLE IF EXISTS vendors;
        DROP TABLE IF EXISTS dataset_metadata;

        CREATE TABLE dataset_metadata (
            metadata_key TEXT PRIMARY KEY,
            metadata_value TEXT NOT NULL
        );

        CREATE TABLE vendors (
            vendor_id TEXT PRIMARY KEY,
            vendor_name TEXT NOT NULL,
            category TEXT NOT NULL,
            source_vendor_type TEXT NOT NULL,
            contract_start TEXT,
            contract_end TEXT,
            data_systems TEXT NOT NULL,
            data_sensitivity INTEGER NOT NULL,
            access_scope INTEGER NOT NULL,
            access_type TEXT NOT NULL,
            access_active INTEGER NOT NULL,
            soc2_type2 INTEGER NOT NULL,
            soc2_expiry TEXT,
            iso27001 INTEGER NOT NULL,
            iso27001_expiry TEXT,
            gdpr_dpa INTEGER NOT NULL,
            had_breach INTEGER NOT NULL,
            breach_date TEXT,
            breach_severity TEXT,
            under_investigation INTEGER NOT NULL,
            financial_rating TEXT NOT NULL,
            financial_score REAL NOT NULL,
            annual_spend_usd REAL NOT NULL,
            last_assessed TEXT,
            assessment_overdue INTEGER NOT NULL,
            liaison_name TEXT,
            liaison_email TEXT,
            company_risk_score REAL NOT NULL,
            source_data_access_scope TEXT NOT NULL,
            source_breach_status TEXT NOT NULL,
            compliance_certifications TEXT NOT NULL,
            expired_certifications TEXT NOT NULL,
            source_snapshot_date TEXT NOT NULL
        );

        CREATE TABLE vendor_certifications (
            certification_id INTEGER PRIMARY KEY AUTOINCREMENT,
            vendor_id TEXT NOT NULL,
            certification_name TEXT NOT NULL,
            expiry_date TEXT NOT NULL,
            status_at_snapshot TEXT NOT NULL,
            FOREIGN KEY (vendor_id) REFERENCES vendors(vendor_id)
        );

        CREATE TABLE vendor_labels (
            record_id TEXT PRIMARY KEY,
            vendor_name TEXT NOT NULL,
            is_anomaly INTEGER NOT NULL,
            anomaly_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            explanation TEXT NOT NULL,
            expired_certifications TEXT NOT NULL
        );

        CREATE TABLE vendor_scores (
            vendor_id TEXT PRIMARY KEY,
            vendor_name TEXT NOT NULL,
            category TEXT NOT NULL,
            company_risk_score REAL NOT NULL,
            access_risk_score REAL NOT NULL,
            breach_risk_score REAL NOT NULL,
            compliance_risk_score REAL NOT NULL,
            lifecycle_risk_score REAL NOT NULL,
            financial_risk_score REAL NOT NULL,
            financial_rating TEXT NOT NULL,
            final_risk_score REAL NOT NULL,
            final_risk_level TEXT NOT NULL,
            predicted_anomaly TEXT NOT NULL,
            predicted_severity TEXT NOT NULL,
            predicted_is_anomaly INTEGER NOT NULL,
            risk_reasons TEXT NOT NULL,
            rule_overrides TEXT NOT NULL,
            recommendations TEXT NOT NULL,
            framework_mappings TEXT NOT NULL,
            ground_truth_severity TEXT,
            ground_truth_anomaly TEXT,
            FOREIGN KEY (vendor_id) REFERENCES vendors(vendor_id)
        );

        CREATE TABLE remediation_actions (
            vendor_id TEXT PRIMARY KEY,
            owner TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'NOT_STARTED',
            due_date TEXT,
            notes TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (vendor_id) REFERENCES vendors(vendor_id)
        );

        CREATE TABLE risk_score_history (
            history_id INTEGER PRIMARY KEY AUTOINCREMENT,
            vendor_id TEXT NOT NULL,
            snapshot_label TEXT NOT NULL,
            snapshot_at TEXT NOT NULL,
            access_risk_score REAL NOT NULL,
            breach_risk_score REAL NOT NULL,
            compliance_risk_score REAL NOT NULL,
            lifecycle_risk_score REAL NOT NULL,
            financial_risk_score REAL NOT NULL,
            final_risk_score REAL NOT NULL,
            final_risk_level TEXT NOT NULL,
            FOREIGN KEY (vendor_id) REFERENCES vendors(vendor_id)
        );

        CREATE INDEX idx_vendor_scores_level
            ON vendor_scores(final_risk_level, final_risk_score DESC);
        CREATE INDEX idx_vendors_category ON vendors(category);
        CREATE INDEX idx_cert_vendor ON vendor_certifications(vendor_id);
        CREATE INDEX idx_cert_expiry ON vendor_certifications(expiry_date);

        CREATE VIEW vendor_risk_view AS
        SELECT
            v.*,
            l.is_anomaly,
            l.anomaly_type,
            l.severity,
            l.explanation AS label_explanation,
            l.expired_certifications AS label_expired_certifications
        FROM vendors v
        LEFT JOIN vendor_labels l
            ON v.vendor_id = l.record_id;

        PRAGMA foreign_keys = ON;
        """
    )


def insert_metadata(
    connection: sqlite3.Connection,
    as_of_date: date,
    registry_rows: int,
) -> None:
    metadata = {
        "dataset_name": "Societe Generale Problem 06 sample data",
        "dataset_as_of_date": as_of_date.isoformat(),
        "registry_rows": str(registry_rows),
        "imported_at": datetime.now().isoformat(timespec="seconds"),
        "financial_component_note": (
            "The source dataset does not include vendor financial health. "
            "Annual spend percentile is used only as a financial exposure proxy."
        ),
        "evaluation_note": (
            "Ground-truth labels are stored for evaluation only and are not used "
            "by the scoring function."
        ),
    }

    connection.executemany(
        "INSERT INTO dataset_metadata(metadata_key, metadata_value) VALUES (?, ?)",
        list(metadata.items()),
    )


def import_data(
    registry_path: Path,
    labels_path: Path,
    database_path: Path,
    as_of_date: date,
    create_backup: bool = True,
) -> dict[str, Any]:
    registry = pd.read_csv(registry_path)
    labels = pd.read_csv(labels_path)
    validate_inputs(registry, labels)

    registry = registry.copy()
    labels = labels.copy()

    registry["financial_exposure_score"] = financial_exposure_scores(
        registry["annual_spend"]
    )

    label_lookup = labels.set_index("record_id").to_dict(orient="index")

    database_path.parent.mkdir(parents=True, exist_ok=True)
    backup_path = (
        backup_existing_database(database_path)
        if create_backup
        else None
    )

    if database_path.exists():
        database_path.unlink()

    vendor_rows: list[tuple[Any, ...]] = []
    certification_rows: list[tuple[Any, ...]] = []
    label_rows: list[tuple[Any, ...]] = []
    score_rows: list[tuple[Any, ...]] = []
    history_rows: list[tuple[Any, ...]] = []

    for row in registry.to_dict(orient="records"):
        vendor_id = str(row["vendor_id"])
        scope = str(row["data_access_scope"])
        mapping = DATA_SCOPE_MAPPING.get(
            scope,
            DATA_SCOPE_MAPPING["Internal_Data"],
        )

        last_audit_date = parse_iso_date(row.get("last_audit_date"))
        certification_data = certification_fields(
            str(row.get("compliance_certifications") or ""),
            as_of_date,
        )
        breach_data = breach_fields(
            str(row.get("breach_status") or ""),
            scope,
            as_of_date,
        )

        financial_exposure_score = float(row["financial_exposure_score"])
        financial_score_10 = round(financial_exposure_score / 10.0, 1)

        risk_result = calculate_company_vendor_risk(
            row,
            as_of_date=as_of_date,
            financial_exposure_score=financial_exposure_score,
        )

        label = label_lookup[vendor_id]

        vendor_rows.append(
            (
                vendor_id,
                str(row["vendor_name"]),
                str(row["vendor_type"]).replace("_", " "),
                str(row["vendor_type"]),
                None,
                str(row["contract_end_date"]),
                json.dumps(mapping["systems"]),
                int(mapping["data_sensitivity"]),
                int(mapping["access_scope"]),
                str(mapping["access_type"]),
                int(mapping["access_active"]),
                certification_data["soc2_type2"],
                certification_data["soc2_expiry"],
                certification_data["iso27001"],
                certification_data["iso27001_expiry"],
                certification_data["gdpr_dpa"],
                breach_data["had_breach"],
                breach_data["breach_date"],
                breach_data["breach_severity"],
                breach_data["under_investigation"],
                "Exposure Proxy",
                financial_score_10,
                float(row["annual_spend"]),
                str(row["last_audit_date"]),
                assessment_overdue(last_audit_date, as_of_date),
                str(row["contact_name"]),
                str(row["contact_email"]),
                float(row["risk_score"]),
                scope,
                str(row["breach_status"]),
                str(row["compliance_certifications"]),
                certification_data["expired_certifications"],
                as_of_date.isoformat(),
            )
        )

        for certification in certification_data["certifications"]:
            status = (
                "EXPIRED"
                if certification.expiry_date < as_of_date
                else "EXPIRING_60_DAYS"
                if 0 <= (certification.expiry_date - as_of_date).days <= 60
                else "VALID"
            )
            certification_rows.append(
                (
                    vendor_id,
                    certification.name,
                    certification.expiry_date.isoformat(),
                    status,
                )
            )

        score_rows.append(
            (
                vendor_id,
                str(row["vendor_name"]),
                str(row["vendor_type"]).replace("_", " "),
                risk_result["company_risk_score"],
                risk_result["access_risk_score"],
                risk_result["breach_risk_score"],
                risk_result["compliance_risk_score"],
                risk_result["lifecycle_risk_score"],
                risk_result["financial_risk_score"],
                "Exposure Proxy",
                risk_result["final_risk_score"],
                risk_result["final_risk_level"],
                risk_result["predicted_anomaly"],
                risk_result["predicted_severity"],
                int(risk_result["predicted_is_anomaly"]),
                json.dumps(risk_result["risk_reasons"]),
                json.dumps(risk_result["rule_overrides"]),
                json.dumps(risk_result["recommendations"]),
                json.dumps(risk_result["framework_mappings"]),
                str(label["severity"]),
                str(label["anomaly_type"]),
            )
        )

        history_rows.append(
            (
                vendor_id,
                "COMPANY-SAMPLE-2026-04",
                datetime.combine(as_of_date, datetime.min.time()).isoformat(),
                risk_result["access_risk_score"],
                risk_result["breach_risk_score"],
                risk_result["compliance_risk_score"],
                risk_result["lifecycle_risk_score"],
                risk_result["financial_risk_score"],
                risk_result["final_risk_score"],
                risk_result["final_risk_level"],
            )
        )

    for row in labels.to_dict(orient="records"):
        label_rows.append(
            (
                str(row["record_id"]),
                str(row["vendor_name"]),
                int(bool(row["is_anomaly"])),
                str(row["anomaly_type"]),
                str(row["severity"]),
                str(row["explanation"]),
                "" if pd.isna(row["expired_certifications"]) else str(row["expired_certifications"]),
            )
        )

    with sqlite3.connect(database_path) as connection:
        create_schema(connection)
        insert_metadata(connection, as_of_date, len(registry))

        connection.executemany(
            """
            INSERT INTO vendors (
                vendor_id, vendor_name, category, source_vendor_type,
                contract_start, contract_end, data_systems,
                data_sensitivity, access_scope, access_type, access_active,
                soc2_type2, soc2_expiry, iso27001, iso27001_expiry,
                gdpr_dpa, had_breach, breach_date, breach_severity,
                under_investigation, financial_rating, financial_score,
                annual_spend_usd, last_assessed, assessment_overdue,
                liaison_name, liaison_email, company_risk_score,
                source_data_access_scope, source_breach_status,
                compliance_certifications, expired_certifications,
                source_snapshot_date
            )
            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            vendor_rows,
        )

        connection.executemany(
            """
            INSERT INTO vendor_certifications (
                vendor_id, certification_name, expiry_date,
                status_at_snapshot
            )
            VALUES (?, ?, ?, ?)
            """,
            certification_rows,
        )

        connection.executemany(
            """
            INSERT INTO vendor_labels (
                record_id, vendor_name, is_anomaly, anomaly_type,
                severity, explanation, expired_certifications
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            label_rows,
        )

        connection.executemany(
            """
            INSERT INTO vendor_scores (
                vendor_id, vendor_name, category, company_risk_score,
                access_risk_score, breach_risk_score,
                compliance_risk_score, lifecycle_risk_score,
                financial_risk_score, financial_rating,
                final_risk_score, final_risk_level,
                predicted_anomaly, predicted_severity,
                predicted_is_anomaly, risk_reasons, rule_overrides,
                recommendations, framework_mappings,
                ground_truth_severity, ground_truth_anomaly
            )
            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?
            )
            """,
            score_rows,
        )

        connection.executemany(
            """
            INSERT INTO risk_score_history (
                vendor_id, snapshot_label, snapshot_at,
                access_risk_score, breach_risk_score,
                compliance_risk_score, lifecycle_risk_score,
                financial_risk_score, final_risk_score,
                final_risk_level
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            history_rows,
        )

        connection.commit()

    score_frame = pd.DataFrame(
        score_rows,
        columns=[
            "vendor_id",
            "vendor_name",
            "category",
            "company_risk_score",
            "access_risk_score",
            "breach_risk_score",
            "compliance_risk_score",
            "lifecycle_risk_score",
            "financial_risk_score",
            "financial_rating",
            "final_risk_score",
            "final_risk_level",
            "predicted_anomaly",
            "predicted_severity",
            "predicted_is_anomaly",
            "risk_reasons",
            "rule_overrides",
            "recommendations",
            "framework_mappings",
            "ground_truth_severity",
            "ground_truth_anomaly",
        ],
    )

    return {
        "database_path": database_path,
        "backup_path": backup_path,
        "vendor_count": len(vendor_rows),
        "certification_count": len(certification_rows),
        "risk_distribution": score_frame["final_risk_level"].value_counts().to_dict(),
        "predicted_anomaly_distribution": score_frame["predicted_anomaly"].value_counts().to_dict(),
    }


def main() -> None:
    arguments = parse_arguments()
    as_of_date = parse_iso_date(arguments.as_of_date)
    if not as_of_date:
        raise ValueError("--as-of-date must use YYYY-MM-DD format.")

    result = import_data(
        registry_path=arguments.registry,
        labels_path=arguments.labels,
        database_path=arguments.database,
        as_of_date=as_of_date,
        create_backup=not arguments.no_backup,
    )

    print("Company sample data imported successfully.")
    print(f"Database: {result['database_path']}")
    if result["backup_path"]:
        print(f"Backup: {result['backup_path']}")
    print(f"Vendors: {result['vendor_count']}")
    print(f"Certification records: {result['certification_count']}")
    print("Risk distribution:")
    for level, count in result["risk_distribution"].items():
        print(f"  {level}: {count}")


if __name__ == "__main__":
    main()
