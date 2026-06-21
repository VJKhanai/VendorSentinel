# Company Data Mapping

| Company CSV field | VendorSentinel field / use |
|---|---|
| vendor_id | vendor_id |
| vendor_name | vendor_name |
| vendor_type | category and source_vendor_type |
| contact_name | liaison_name |
| contact_email | liaison_email |
| compliance_certifications | parsed into vendor_certifications |
| data_access_scope | sensitivity, scope, access type, system mapping |
| risk_score | company_risk_score reference baseline |
| breach_status | breach and investigation component |
| annual_spend | annual_spend_usd and exposure percentile proxy |
| contract_end_date | contract_end and lifecycle alerts |
| last_audit_date | last_assessed and assessment_overdue |

## Data access mapping

| Source value | Sensitivity | Scope | Access type | Active access |
|---|---:|---:|---|---:|
| Public_Data | 2 | 1 | read_only | 0 |
| Internal_Data | 5 | 3 | read_only | 1 |
| Customer_PII | 9 | 5 | read_write | 1 |
| Financial_Data | 9 | 5 | read_write | 1 |
| All_Systems | 10 | 10 | read_write | 1 |

Public data is treated as non-active internal system access. This is required
to distinguish an expired public-data relationship from an expired contract
that still has enterprise access.

## Benchmark rule priority

The classifier checks conditions in this order:

1. Vendor under investigation → CRITICAL
2. Recent breach plus Customer PII, Financial Data or All Systems → CRITICAL
3. Company-provided risk score above 80 → HIGH
4. Recent breach with lower access → MEDIUM
5. Expired certification → HIGH for Customer PII/Financial Data, otherwise MEDIUM
6. Expired contract with non-public active access → MEDIUM
7. Company-provided risk score from 65 to 80 → LOW elevated monitoring
8. Otherwise → normal/LOW

The label file is not opened by the risk engine.
