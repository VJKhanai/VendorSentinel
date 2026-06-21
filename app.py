from __future__ import annotations

import csv
import json
import sqlite3
from collections import defaultdict
from io import StringIO
from pathlib import Path
from typing import Any

import plotly.graph_objects as go
import plotly.utils
from flask import (
    Flask,
    Response,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)

from services.ai_narrative import generate_ai_risk_narrative


BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "database" / "vendor_risk.db"

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def get_database_connection() -> sqlite3.Connection:
    """Return a SQLite connection whose rows behave like dictionaries."""

    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def parse_json_list(value: Any) -> list[str]:
    """Convert JSON text, pipe-separated text, lists, or empty values to a list."""

    if value is None:
        return []

    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]

    if isinstance(value, tuple):
        return [str(item) for item in value if str(item).strip()]

    if isinstance(value, str):
        cleaned = value.strip()

        if not cleaned:
            return []

        try:
            parsed = json.loads(cleaned)
            if isinstance(parsed, list):
                return [str(item) for item in parsed if str(item).strip()]
        except (json.JSONDecodeError, TypeError):
            pass

        if "|" in cleaned:
            return [item.strip() for item in cleaned.split("|") if item.strip()]

        if ";" in cleaned:
            return [item.strip() for item in cleaned.split(";") if item.strip()]

        return [cleaned]

    return [str(value)]


def row_to_dict(row: sqlite3.Row | None) -> dict[str, Any]:
    """Convert a SQLite row to a standard dictionary."""

    return dict(row) if row is not None else {}


def severity_rank(severity: str) -> int:
    """Return the display priority for an alert severity."""

    return {
        "CRITICAL": 1,
        "HIGH": 2,
        "MEDIUM": 3,
        "LOW": 4,
    }.get(str(severity).upper(), 99)


ITEMS_PER_PAGE = 20


def get_requested_page() -> int:
    """Return a safe positive page number from the query string."""

    try:
        return max(1, int(request.args.get("page", "1")))
    except (TypeError, ValueError):
        return 1


def build_pagination(
    total_items: int,
    requested_page: int,
    per_page: int = ITEMS_PER_PAGE,
) -> dict[str, Any]:
    """Create pagination metadata for templates and database queries."""

    safe_total = max(0, int(total_items))
    total_pages = max(1, (safe_total + per_page - 1) // per_page)
    current_page = min(max(1, requested_page), total_pages)

    offset = (current_page - 1) * per_page
    start_item = 0 if safe_total == 0 else offset + 1
    end_item = min(offset + per_page, safe_total)

    first_visible = max(1, current_page - 2)
    last_visible = min(total_pages, current_page + 2)

    return {
        "current_page": current_page,
        "total_pages": total_pages,
        "total_items": safe_total,
        "per_page": per_page,
        "offset": offset,
        "start_item": start_item,
        "end_item": end_item,
        "has_previous": current_page > 1,
        "has_next": current_page < total_pages,
        "previous_page": max(1, current_page - 1),
        "next_page": min(total_pages, current_page + 1),
        "page_numbers": list(range(first_visible, last_visible + 1)),
    }


def add_pagination_urls(
    pagination: dict[str, Any],
    endpoint: str,
    **query_parameters: Any,
) -> dict[str, Any]:
    """Attach filter-preserving page URLs to pagination metadata."""

    cleaned_parameters = {
        key: value
        for key, value in query_parameters.items()
        if value not in (None, "")
    }

    def page_url(page_number: int) -> str:
        return url_for(
            endpoint,
            page=page_number,
            **cleaned_parameters,
        )

    pagination["first_url"] = page_url(1)
    pagination["last_url"] = page_url(
        int(pagination["total_pages"])
    )
    pagination["previous_url"] = page_url(
        int(pagination["previous_page"])
    )
    pagination["next_url"] = page_url(
        int(pagination["next_page"])
    )
    pagination["links"] = [
        {
            "number": page_number,
            "url": page_url(page_number),
            "is_current": (
                page_number == pagination["current_page"]
            ),
        }
        for page_number in pagination["page_numbers"]
    ]

    return pagination


def initialize_remediation_table() -> None:
    """Create the lightweight remediation workflow table when required."""

    with get_database_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS remediation_actions (
                vendor_id TEXT PRIMARY KEY,
                owner TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'NOT_STARTED',
                due_date TEXT,
                notes TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (vendor_id) REFERENCES vendors(vendor_id)
            )
            """
        )
        connection.commit()


initialize_remediation_table()


# -----------------------------------------------------------------------------
# Dashboard
# -----------------------------------------------------------------------------

@app.route("/")
def dashboard():
    """Render the executive third-party risk dashboard."""

    with get_database_connection() as connection:
        summary_row = connection.execute(
            """
            SELECT
                COUNT(*) AS total_vendors,
                SUM(CASE WHEN final_risk_level = 'CRITICAL' THEN 1 ELSE 0 END)
                    AS critical_vendors,
                SUM(CASE WHEN final_risk_level = 'HIGH' THEN 1 ELSE 0 END)
                    AS high_vendors,
                SUM(CASE WHEN final_risk_level = 'MEDIUM' THEN 1 ELSE 0 END)
                    AS medium_vendors,
                SUM(CASE WHEN final_risk_level = 'LOW' THEN 1 ELSE 0 END)
                    AS low_vendors,
                ROUND(AVG(final_risk_score), 1) AS average_risk_score
            FROM vendor_scores
            """
        ).fetchone()

        distribution_rows = connection.execute(
            """
            SELECT
                final_risk_level AS risk_level,
                COUNT(*) AS vendor_count
            FROM vendor_scores
            GROUP BY final_risk_level
            """
        ).fetchall()

        top_vendor_rows = connection.execute(
            """
            SELECT
                vendor_id,
                vendor_name,
                category,
                final_risk_score,
                final_risk_level
            FROM vendor_scores
            ORDER BY
                CASE final_risk_level
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 4
                    ELSE 5
                END,
                final_risk_score DESC,
                vendor_name
            LIMIT 12
            """
        ).fetchall()

        category_risk_rows = connection.execute(
            """
            SELECT
                category,
                ROUND(AVG(final_risk_score), 1) AS average_risk_score,
                COUNT(*) AS vendor_count
            FROM vendor_scores
            GROUP BY category
            ORDER BY average_risk_score DESC, category
            LIMIT 10
            """
        ).fetchall()

        top_risk_chart_rows = connection.execute(
            """
            SELECT
                vendor_id,
                vendor_name,
                final_risk_score,
                final_risk_level
            FROM vendor_scores
            ORDER BY final_risk_score DESC, vendor_name
            LIMIT 10
            """
        ).fetchall()

    summary = row_to_dict(summary_row)
    risk_counts = {
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0,
    }

    for row in distribution_rows:
        level = str(row["risk_level"]).upper()
        if level in risk_counts:
            risk_counts[level] = int(row["vendor_count"])

    labels = ["LOW", "MEDIUM", "CRITICAL", "HIGH"]
    values = [risk_counts[label] for label in labels]

    figure = go.Figure(
        data=[
            go.Pie(
                labels=labels,
                values=values,
                hole=0.55,
                textinfo="label+value",
                sort=False,
                marker={
                    "colors": [
                        "#16a34a",
                        "#d18b00",
                        "#c51d25",
                        "#e85d04",
                    ]
                },
            )
        ]
    )

    figure.update_layout(
        margin={"l": 20, "r": 20, "t": 10, "b": 20},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        showlegend=True,
        legend={"orientation": "h", "y": -0.05, "x": 0.1},
        height=430,
    )

    chart_json = json.dumps(
        figure,
        cls=plotly.utils.PlotlyJSONEncoder,
    )

    category_names = [
        str(row["category"])
        for row in category_risk_rows
    ]

    category_average_scores = [
        float(row["average_risk_score"] or 0)
        for row in category_risk_rows
    ]

    category_vendor_counts = [
        int(row["vendor_count"] or 0)
        for row in category_risk_rows
    ]

    category_figure = go.Figure(
        data=[
            go.Bar(
                x=category_names,
                y=category_average_scores,
                text=category_average_scores,
                textposition="outside",
                customdata=category_vendor_counts,
                hovertemplate=(
                    "<b>%{x}</b><br>"
                    "Average risk: %{y}<br>"
                    "Vendors: %{customdata}"
                    "<extra></extra>"
                ),
                marker={"color": "#2563eb"},
            )
        ]
    )

    category_figure.update_layout(
        margin={"l": 45, "r": 20, "t": 20, "b": 95},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        height=430,
        xaxis={
            "title": "Vendor category",
            "tickangle": -35,
            "automargin": True,
        },
        yaxis={
            "title": "Average final risk score",
            "range": [0, 100],
            "gridcolor": "#e5e7eb",
        },
        showlegend=False,
    )

    category_chart_json = json.dumps(
        category_figure,
        cls=plotly.utils.PlotlyJSONEncoder,
    )

    top_chart_rows = list(reversed(top_risk_chart_rows))

    top_vendor_names = [
        str(row["vendor_name"])
        for row in top_chart_rows
    ]

    top_vendor_scores = [
        float(row["final_risk_score"] or 0)
        for row in top_chart_rows
    ]

    risk_colour_map = {
        "CRITICAL": "#b91c1c",
        "HIGH": "#ea580c",
        "MEDIUM": "#ca8a04",
        "LOW": "#16a34a",
    }

    top_vendor_colours = [
        risk_colour_map.get(
            str(row["final_risk_level"]).upper(),
            "#64748b",
        )
        for row in top_chart_rows
    ]

    top_vendor_levels = [
        str(row["final_risk_level"])
        for row in top_chart_rows
    ]

    top_vendor_ids = [
        str(row["vendor_id"])
        for row in top_chart_rows
    ]

    top_risk_figure = go.Figure(
        data=[
            go.Bar(
                x=top_vendor_scores,
                y=top_vendor_names,
                orientation="h",
                text=top_vendor_scores,
                textposition="outside",
                customdata=list(
                    zip(top_vendor_ids, top_vendor_levels)
                ),
                hovertemplate=(
                    "<b>%{y}</b><br>"
                    "Vendor ID: %{customdata[0]}<br>"
                    "Risk level: %{customdata[1]}<br>"
                    "Final score: %{x}"
                    "<extra></extra>"
                ),
                marker={"color": top_vendor_colours},
            )
        ]
    )

    top_risk_figure.update_layout(
        margin={"l": 165, "r": 45, "t": 20, "b": 50},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        height=430,
        xaxis={
            "title": "Final risk score",
            "range": [0, 105],
            "gridcolor": "#e5e7eb",
        },
        yaxis={
            "title": "",
            "automargin": True,
        },
        showlegend=False,
    )

    top_risk_chart_json = json.dumps(
        top_risk_figure,
        cls=plotly.utils.PlotlyJSONEncoder,
    )

    top_vendors = [dict(row) for row in top_vendor_rows]

    return render_template(
        "dashboard.html",
        summary=summary,
        risk_counts=risk_counts,
        chart_json=chart_json,
        risk_chart=chart_json,
        category_chart_json=category_chart_json,
        top_risk_chart_json=top_risk_chart_json,
        top_vendors=top_vendors,
        total_vendors=summary.get("total_vendors", 0),
        critical_vendors=summary.get("critical_vendors", 0),
        high_vendors=summary.get("high_vendors", 0),
        medium_vendors=summary.get("medium_vendors", 0),
        low_vendors=summary.get("low_vendors", 0),
    )


# -----------------------------------------------------------------------------
# Vendor register and vendor detail
# -----------------------------------------------------------------------------

@app.route("/vendors")
def vendors_page():
    """Render the searchable, paginated vendor risk register."""

    search_text = request.args.get("search", "").strip()
    selected_risk = request.args.get(
        "risk_level",
        "",
    ).strip().upper()
    selected_category = request.args.get(
        "category",
        "",
    ).strip()
    requested_page = get_requested_page()

    conditions: list[str] = []
    parameters: list[Any] = []

    if search_text:
        conditions.append(
            """
            (
                LOWER(s.vendor_name) LIKE LOWER(?)
                OR LOWER(s.vendor_id) LIKE LOWER(?)
                OR LOWER(s.category) LIKE LOWER(?)
            )
            """
        )
        search_pattern = f"%{search_text}%"
        parameters.extend(
            [search_pattern, search_pattern, search_pattern]
        )

    if selected_risk:
        conditions.append("s.final_risk_level = ?")
        parameters.append(selected_risk)

    if selected_category:
        conditions.append("s.category = ?")
        parameters.append(selected_category)

    where_clause = ""
    if conditions:
        where_clause = "WHERE " + " AND ".join(conditions)

    count_query = f"""
        SELECT
            COUNT(*) AS total_items,
            SUM(
                CASE
                    WHEN s.final_risk_level = 'CRITICAL'
                    THEN 1 ELSE 0
                END
            ) AS critical_count,
            SUM(
                CASE
                    WHEN s.final_risk_level = 'HIGH'
                    THEN 1 ELSE 0
                END
            ) AS high_count
        FROM vendor_scores s
        JOIN vendors v
            ON s.vendor_id = v.vendor_id
        {where_clause}
    """

    with get_database_connection() as connection:
        count_row = connection.execute(
            count_query,
            parameters,
        ).fetchone()

        total_items = int(count_row["total_items"] or 0)

        pagination = build_pagination(
            total_items,
            requested_page,
        )

        query = f"""
            SELECT
                s.vendor_id,
                s.vendor_name,
                s.category,
                s.final_risk_score,
                s.final_risk_level,
                s.company_risk_score,
                s.access_risk_score,
                s.breach_risk_score,
                s.compliance_risk_score,
                s.lifecycle_risk_score,
                s.financial_risk_score,
                v.data_sensitivity,
                v.access_scope,
                v.access_type,
                v.access_active,
                v.contract_end,
                v.assessment_overdue
            FROM vendor_scores s
            JOIN vendors v
                ON s.vendor_id = v.vendor_id
            {where_clause}
            ORDER BY
                CASE s.final_risk_level
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 4
                    ELSE 5
                END,
                s.final_risk_score DESC,
                s.vendor_name
            LIMIT ? OFFSET ?
        """

        page_parameters = [
            *parameters,
            ITEMS_PER_PAGE,
            pagination["offset"],
        ]

        vendor_rows = connection.execute(
            query,
            page_parameters,
        ).fetchall()

        category_rows = connection.execute(
            """
            SELECT DISTINCT category
            FROM vendors
            ORDER BY category
            """
        ).fetchall()

    pagination = add_pagination_urls(
        pagination,
        "vendors_page",
        search=search_text,
        risk_level=selected_risk,
        category=selected_category,
    )

    vendors = [dict(row) for row in vendor_rows]
    categories = [row["category"] for row in category_rows]

    filtered_summary = {
        "total_items": total_items,
        "critical_count": int(
            count_row["critical_count"] or 0
        ),
        "high_count": int(
            count_row["high_count"] or 0
        ),
    }

    return render_template(
        "vendors.html",
        vendors=vendors,
        categories=categories,
        search=search_text,
        search_text=search_text,
        selected_risk=selected_risk,
        selected_risk_level=selected_risk,
        selected_category=selected_category,
        filtered_summary=filtered_summary,
        pagination=pagination,
    )


@app.route("/vendors/<vendor_id>")
def vendor_detail(vendor_id: str):
    """Render a complete risk profile and explainable narrative for one vendor."""

    with get_database_connection() as connection:
        vendor_row = connection.execute(
            """
            SELECT
                s.vendor_id,
                s.vendor_name,
                s.category,
                s.access_risk_score,
                s.breach_risk_score,
                s.compliance_risk_score,
                s.lifecycle_risk_score,
                s.financial_risk_score,
                s.company_risk_score,
                s.final_risk_score,
                s.final_risk_level,
                s.risk_reasons,
                s.rule_overrides,
                s.recommendations,
                s.framework_mappings,

                v.contract_start,
                v.contract_end,
                v.data_systems,
                v.data_sensitivity,
                v.access_scope,
                v.access_type,
                v.access_active,
                v.soc2_type2,
                v.soc2_expiry,
                v.iso27001,
                v.iso27001_expiry,
                v.gdpr_dpa,
                v.had_breach,
                v.breach_date,
                v.breach_severity,
                v.under_investigation,
                v.financial_rating,
                v.financial_score,
                v.annual_spend_usd,
                v.last_assessed,
                v.assessment_overdue,
                v.liaison_name,
                v.liaison_email,
                v.source_data_access_scope,
                v.source_breach_status,
                v.compliance_certifications,
                v.expired_certifications,
                v.source_snapshot_date
            FROM vendor_scores s
            JOIN vendors v
                ON s.vendor_id = v.vendor_id
            WHERE s.vendor_id = ?
            """,
            (vendor_id,),
        ).fetchone()

        remediation_row = connection.execute(
            """
            SELECT
                vendor_id,
                owner,
                status,
                due_date,
                notes,
                updated_at
            FROM remediation_actions
            WHERE vendor_id = ?
            """,
            (vendor_id,),
        ).fetchone()

        certification_rows = connection.execute(
            """
            SELECT
                certification_name,
                expiry_date,
                CASE
                    WHEN date(expiry_date) < date('now') THEN 'EXPIRED'
                    WHEN date(expiry_date) <= date('now', '+60 day')
                        THEN 'EXPIRING_60_DAYS'
                    ELSE 'VALID'
                END AS current_status
            FROM vendor_certifications
            WHERE vendor_id = ?
            ORDER BY
                CASE
                    WHEN date(expiry_date) < date('now') THEN 1
                    WHEN date(expiry_date) <= date('now', '+60 day') THEN 2
                    ELSE 3
                END,
                expiry_date
            """,
            (vendor_id,),
        ).fetchall()

        try:
            history_rows = connection.execute(
                """
                SELECT
                    snapshot_label,
                    snapshot_at,
                    access_risk_score,
                    breach_risk_score,
                    compliance_risk_score,
                    lifecycle_risk_score,
                    financial_risk_score,
                    final_risk_score,
                    final_risk_level
                FROM risk_score_history
                WHERE vendor_id = ?
                ORDER BY snapshot_at, snapshot_label
                """,
                (vendor_id,),
            ).fetchall()
        except sqlite3.OperationalError:
            history_rows = []

    if vendor_row is None:
        abort(404)

    vendor = dict(vendor_row)

    vendor["risk_reasons"] = parse_json_list(vendor.get("risk_reasons"))
    vendor["rule_overrides"] = parse_json_list(vendor.get("rule_overrides"))
    vendor["recommendations"] = parse_json_list(vendor.get("recommendations"))
    vendor["framework_mappings"] = parse_json_list(
        vendor.get("framework_mappings")
    )
    vendor["data_systems"] = parse_json_list(vendor.get("data_systems"))
    vendor["certifications"] = [dict(row) for row in certification_rows]

    try:
        annual_spend = float(vendor.get("annual_spend_usd") or 0)
        vendor["annual_spend_display"] = f"${annual_spend:,.0f}"
    except (TypeError, ValueError):
        vendor["annual_spend_display"] = "$0"

    remediation = (
        dict(remediation_row)
        if remediation_row is not None
        else {
            "vendor_id": vendor_id,
            "owner": "",
            "status": "NOT_STARTED",
            "due_date": "",
            "notes": "",
            "updated_at": None,
        }
    )

    history = [dict(row) for row in history_rows]

    history_chart_json = None

    if history:
        snapshot_labels = [
            str(row["snapshot_label"])
            for row in history
        ]

        final_scores = [
            float(row["final_risk_score"] or 0)
            for row in history
        ]

        final_levels = [
            str(row["final_risk_level"])
            for row in history
        ]

        history_figure = go.Figure(
            data=[
                go.Scatter(
                    x=snapshot_labels,
                    y=final_scores,
                    mode="lines+markers+text",
                    text=final_scores,
                    textposition="top center",
                    customdata=final_levels,
                    line={
                        "color": "#e30613",
                        "width": 3,
                    },
                    marker={
                        "size": 10,
                        "color": "#e30613",
                    },
                    hovertemplate=(
                        "<b>%{x}</b><br>"
                        "Final score: %{y}<br>"
                        "Risk level: %{customdata}"
                        "<extra></extra>"
                    ),
                )
            ]
        )

        history_figure.update_layout(
            margin={"l": 50, "r": 25, "t": 20, "b": 55},
            height=330,
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            showlegend=False,
            xaxis={
                "title": "Snapshot period",
                "gridcolor": "#eef2f7",
            },
            yaxis={
                "title": "Final risk score",
                "range": [0, 100],
                "gridcolor": "#e5e7eb",
            },
        )

        history_chart_json = json.dumps(
            history_figure,
            cls=plotly.utils.PlotlyJSONEncoder,
        )

    ai_narrative = generate_ai_risk_narrative(vendor)

    return render_template(
        "vendor_detail.html",
        vendor=vendor,
        ai_narrative=ai_narrative,
        remediation=remediation,
        remediation_saved=(request.args.get("saved") == "1"),
        history=history,
        history_chart_json=history_chart_json,
    )


@app.post("/vendors/<vendor_id>/remediation")
def update_remediation(vendor_id: str):
    """Create or update the action owner, status, deadline and notes."""

    allowed_statuses = {
        "NOT_STARTED",
        "IN_PROGRESS",
        "BLOCKED",
        "COMPLETED",
    }

    owner = request.form.get("owner", "").strip()
    status = request.form.get("status", "NOT_STARTED").strip().upper()
    due_date = request.form.get("due_date", "").strip() or None
    notes = request.form.get("notes", "").strip()

    if status not in allowed_statuses:
        status = "NOT_STARTED"

    with get_database_connection() as connection:
        vendor_exists = connection.execute(
            "SELECT 1 FROM vendors WHERE vendor_id = ?",
            (vendor_id,),
        ).fetchone()

        if vendor_exists is None:
            abort(404)

        connection.execute(
            """
            INSERT INTO remediation_actions (
                vendor_id,
                owner,
                status,
                due_date,
                notes,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(vendor_id) DO UPDATE SET
                owner = excluded.owner,
                status = excluded.status,
                due_date = excluded.due_date,
                notes = excluded.notes,
                updated_at = CURRENT_TIMESTAMP
            """,
            (vendor_id, owner, status, due_date, notes),
        )
        connection.commit()

    return redirect(
        url_for(
            "vendor_detail",
            vendor_id=vendor_id,
            saved="1",
        )
    )


# -----------------------------------------------------------------------------
# Alerts
# -----------------------------------------------------------------------------

@app.route("/alerts")
def alerts_page():
    """Create, filter, prioritise, group, and paginate alerts."""

    selected_severity = request.args.get(
        "severity",
        "",
    ).strip().upper()
    requested_page = get_requested_page()

    with get_database_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                s.vendor_id,
                s.vendor_name,
                s.category,
                s.final_risk_score,
                s.final_risk_level,
                v.data_sensitivity,
                v.access_scope,
                v.access_type,
                v.access_active,
                v.contract_end,
                v.soc2_type2,
                v.soc2_expiry,
                v.iso27001,
                v.iso27001_expiry,
                v.had_breach,
                v.breach_date,
                v.breach_severity,
                v.under_investigation,
                v.assessment_overdue
            FROM vendor_scores s
            JOIN vendors v
                ON s.vendor_id = v.vendor_id
            """
        ).fetchall()

        certification_rows = connection.execute(
            """
            SELECT
                vendor_id,
                certification_name,
                expiry_date
            FROM vendor_certifications
            """
        ).fetchall()

    certifications_by_vendor: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for certification_row in certification_rows:
        certification = dict(certification_row)
        certifications_by_vendor[certification["vendor_id"]].append(certification)

    all_alerts: list[dict[str, Any]] = []

    for row in rows:
        vendor = dict(row)

        base_alert = {
            "vendor_id": vendor["vendor_id"],
            "vendor_name": vendor["vendor_name"],
            "category": vendor["category"],
            "final_risk_score": vendor["final_risk_score"],
            "final_risk_level": vendor["final_risk_level"],
        }

        if bool(vendor.get("under_investigation")):
            all_alerts.append(
                {
                    **base_alert,
                    "alert_type": "Security Investigation",
                    "alert_message": (
                        "Vendor is currently under security investigation."
                    ),
                    "alert_severity": "CRITICAL",
                }
            )

        if bool(vendor.get("had_breach")) and vendor.get(
            "breach_date"
        ):
            with get_database_connection() as connection:
                breach_is_recent = bool(
                    connection.execute(
                        """
                        SELECT
                            date(?) >= date(
                                'now',
                                '-365 day'
                            ) AS is_recent
                        """,
                        (vendor["breach_date"],),
                    ).fetchone()["is_recent"]
                )

            if breach_is_recent:
                critical_breach = (
                    int(vendor.get("data_sensitivity") or 0) >= 8
                    and int(vendor.get("access_scope") or 0) >= 4
                    and vendor.get("access_type") == "read_write"
                )

                all_alerts.append(
                    {
                        **base_alert,
                        "alert_type": "Recent Breach",
                        "alert_message": (
                            f"Breach recorded on "
                            f"{vendor['breach_date']} with severity "
                            f"{vendor.get('breach_severity') or 'UNKNOWN'}."
                        ),
                        "alert_severity": (
                            "CRITICAL"
                            if critical_breach
                            else "HIGH"
                        ),
                    }
                )

        if vendor.get("contract_end"):
            with get_database_connection() as connection:
                contract_status = connection.execute(
                    """
                    SELECT
                        CASE
                            WHEN date(?) < date('now')
                                 AND ? = 1
                            THEN 'EXPIRED_ACTIVE_ACCESS'

                            WHEN date(?) >= date('now')
                                 AND date(?) <= date(
                                     'now',
                                     '+60 day'
                                 )
                            THEN 'EXPIRING_60_DAYS'

                            ELSE 'NO_ALERT'
                        END AS status,
                        CAST(
                            julianday(date(?))
                            - julianday(date('now'))
                            AS INTEGER
                        ) AS days_remaining
                    """,
                    (
                        vendor["contract_end"],
                        int(bool(vendor.get("access_active"))),
                        vendor["contract_end"],
                        vendor["contract_end"],
                        vendor["contract_end"],
                    ),
                ).fetchone()

            if (
                contract_status["status"]
                == "EXPIRED_ACTIVE_ACCESS"
            ):
                all_alerts.append(
                    {
                        **base_alert,
                        "alert_type": "Expired Contract Access",
                        "alert_message": (
                            f"Contract ended on "
                            f"{vendor['contract_end']} but "
                            "vendor access remains active."
                        ),
                        "alert_severity": "HIGH",
                    }
                )

            elif (
                contract_status["status"]
                == "EXPIRING_60_DAYS"
            ):
                days_remaining = int(
                    contract_status["days_remaining"] or 0
                )

                all_alerts.append(
                    {
                        **base_alert,
                        "alert_type": "Contract Expiring",
                        "alert_message": (
                            f"Contract expires on "
                            f"{vendor['contract_end']} "
                            f"({days_remaining} days remaining). "
                            "Begin renewal or offboarding review."
                        ),
                        "alert_severity": "MEDIUM",
                    }
                )

        for certification in certifications_by_vendor.get(
            vendor["vendor_id"],
            [],
        ):
            expiry_date = certification.get("expiry_date")
            certificate_name = certification.get("certification_name")

            if not expiry_date:
                continue

            with get_database_connection() as connection:
                certificate_status = connection.execute(
                    """
                    SELECT
                        CASE
                            WHEN date(?) < date('now')
                            THEN 'EXPIRED'
                            WHEN date(?) <= date('now', '+60 day')
                            THEN 'EXPIRING'
                            ELSE 'VALID'
                        END AS status
                    """,
                    (expiry_date, expiry_date),
                ).fetchone()["status"]

            if certificate_status == "EXPIRED":
                all_alerts.append(
                    {
                        **base_alert,
                        "alert_type": f"Expired {certificate_name}",
                        "alert_message": (
                            f"{certificate_name} evidence expired on {expiry_date}."
                        ),
                        "alert_severity": (
                            "HIGH"
                            if vendor.get("data_sensitivity", 0) >= 8
                            else "MEDIUM"
                        ),
                    }
                )
            elif certificate_status == "EXPIRING":
                all_alerts.append(
                    {
                        **base_alert,
                        "alert_type": f"Expiring {certificate_name}",
                        "alert_message": (
                            f"{certificate_name} evidence expires on {expiry_date}."
                        ),
                        "alert_severity": "MEDIUM",
                    }
                )

        if bool(vendor.get("assessment_overdue")):
            all_alerts.append(
                {
                    **base_alert,
                    "alert_type": "Assessment Overdue",
                    "alert_message": (
                        "The vendor security assessment is overdue."
                    ),
                    "alert_severity": "MEDIUM",
                }
            )

    all_alerts.sort(
        key=lambda alert: (
            severity_rank(alert["alert_severity"]),
            -float(alert.get("final_risk_score") or 0),
            str(alert.get("vendor_name") or ""),
            str(alert.get("alert_type") or ""),
        )
    )

    summary = {
        "total_alerts": len(all_alerts),
        "critical_alerts": sum(
            1
            for alert in all_alerts
            if alert["alert_severity"] == "CRITICAL"
        ),
        "high_alerts": sum(
            1
            for alert in all_alerts
            if alert["alert_severity"] == "HIGH"
        ),
        "affected_vendors": len(
            {
                alert["vendor_id"]
                for alert in all_alerts
            }
        ),
    }

    displayed_alerts = all_alerts

    if selected_severity:
        displayed_alerts = [
            alert
            for alert in all_alerts
            if alert["alert_severity"]
            == selected_severity
        ]

    grouped: dict[str, dict[str, Any]] = {}

    for alert in displayed_alerts:
        vendor_id = alert["vendor_id"]

        if vendor_id not in grouped:
            grouped[vendor_id] = {
                "vendor_id": vendor_id,
                "vendor_name": alert["vendor_name"],
                "category": alert["category"],
                "final_risk_score": (
                    alert["final_risk_score"]
                ),
                "final_risk_level": (
                    alert["final_risk_level"]
                ),
                "highest_severity": (
                    alert["alert_severity"]
                ),
                "alerts": [],
            }

        grouped[vendor_id]["alerts"].append(alert)

        current_highest = grouped[
            vendor_id
        ]["highest_severity"]

        if (
            severity_rank(alert["alert_severity"])
            < severity_rank(current_highest)
        ):
            grouped[
                vendor_id
            ]["highest_severity"] = (
                alert["alert_severity"]
            )

    all_vendor_alert_groups = list(grouped.values())

    for group in all_vendor_alert_groups:
        group["alerts"].sort(
            key=lambda alert: (
                severity_rank(
                    alert["alert_severity"]
                ),
                alert["alert_type"],
            )
        )

    all_vendor_alert_groups.sort(
        key=lambda group: (
            severity_rank(group["highest_severity"]),
            -float(
                group.get("final_risk_score") or 0
            ),
            group["vendor_name"],
        )
    )

    pagination = build_pagination(
        len(all_vendor_alert_groups),
        requested_page,
    )
    pagination = add_pagination_urls(
        pagination,
        "alerts_page",
        severity=selected_severity,
    )

    page_start = int(pagination["offset"])
    page_end = page_start + ITEMS_PER_PAGE

    vendor_alert_groups = (
        all_vendor_alert_groups[
            page_start:page_end
        ]
    )

    page_alert_count = sum(
        len(group["alerts"])
        for group in vendor_alert_groups
    )

    return render_template(
        "alerts.html",
        summary=summary,
        vendor_alert_groups=vendor_alert_groups,
        displayed_alert_count=len(displayed_alerts),
        page_alert_count=page_alert_count,
        selected_severity=selected_severity,
        pagination=pagination,
    )


# -----------------------------------------------------------------------------
# Compliance
# -----------------------------------------------------------------------------

@app.route("/compliance")
def compliance_page():
    """Display third-party compliance posture and evidence gaps."""

    with get_database_connection() as connection:
        summary_row = connection.execute(
            """
            SELECT
                COUNT(*) AS total_vendors,

                SUM(
                    CASE WHEN gdpr_dpa = 1
                    THEN 1 ELSE 0 END
                ) AS gdpr_dpa_ready,

                SUM(
                    CASE WHEN soc2_type2 = 1
                    THEN 1 ELSE 0 END
                ) AS soc2_ready,

                SUM(
                    CASE
                        WHEN
                            (soc2_type2 = 1 OR iso27001 = 1)
                            AND assessment_overdue = 0
                        THEN 1
                        ELSE 0
                    END
                ) AS nist_ready,

                SUM(
                    CASE
                        WHEN
                            had_breach = 1
                            AND date(breach_date) >= date('now', '-365 day')
                        THEN 1
                        ELSE 0
                    END
                ) AS recent_breaches,

                SUM(
                    CASE
                        WHEN
                            date(contract_end) < date('now')
                            AND access_active = 1
                        THEN 1
                        ELSE 0
                    END
                ) AS expired_contract_access

            FROM vendors
            """
        ).fetchone()

        issue_rows = connection.execute(
            """
            WITH compliance_issues AS (

                SELECT
                    s.vendor_id,
                    s.vendor_name,
                    s.category,
                    s.final_risk_score,
                    s.final_risk_level,
                    'GDPR Article 28' AS framework,
                    'Missing Data Processing Agreement' AS issue,
                    CASE
                        WHEN v.data_sensitivity >= 8 THEN 'CRITICAL'
                        ELSE 'HIGH'
                    END AS severity,
                    'Obtain and validate a GDPR-compliant Data Processing Agreement.'
                        AS required_action
                FROM vendor_scores s
                JOIN vendors v ON s.vendor_id = v.vendor_id
                WHERE v.gdpr_dpa = 0

                UNION ALL

                SELECT
                    s.vendor_id,
                    s.vendor_name,
                    s.category,
                    s.final_risk_score,
                    s.final_risk_level,
                    'GDPR Article 33' AS framework,
                    'Recent Vendor Breach' AS issue,
                    CASE
                        WHEN v.data_sensitivity >= 8 THEN 'CRITICAL'
                        ELSE 'HIGH'
                    END AS severity,
                    'Review notification obligations and confirm the 72-hour response workflow.'
                        AS required_action
                FROM vendor_scores s
                JOIN vendors v ON s.vendor_id = v.vendor_id
                WHERE
                    v.had_breach = 1
                    AND date(v.breach_date) >= date('now', '-365 day')

                UNION ALL

                SELECT
                    s.vendor_id,
                    s.vendor_name,
                    s.category,
                    s.final_risk_score,
                    s.final_risk_level,
                    'NIST SA-9' AS framework,
                    'Missing Independent Assurance' AS issue,
                    'HIGH' AS severity,
                    'Request SOC 2 Type II, ISO 27001, or equivalent security assurance evidence.'
                        AS required_action
                FROM vendor_scores s
                JOIN vendors v ON s.vendor_id = v.vendor_id
                WHERE
                    v.soc2_type2 = 0
                    AND v.iso27001 = 0

                UNION ALL

                SELECT
                    s.vendor_id,
                    s.vendor_name,
                    s.category,
                    s.final_risk_score,
                    s.final_risk_level,
                    'NIST SA-9' AS framework,
                    'Vendor Assessment Overdue' AS issue,
                    'MEDIUM' AS severity,
                    'Schedule and complete the vendor security reassessment.'
                        AS required_action
                FROM vendor_scores s
                JOIN vendors v ON s.vendor_id = v.vendor_id
                WHERE v.assessment_overdue = 1

                UNION ALL

                SELECT
                    s.vendor_id,
                    s.vendor_name,
                    s.category,
                    s.final_risk_score,
                    s.final_risk_level,
                    'SOX 404' AS framework,
                    'Expired Contract With Active Access' AS issue,
                    'HIGH' AS severity,
                    'Validate the control owner and revoke unnecessary third-party access.'
                        AS required_action
                FROM vendor_scores s
                JOIN vendors v ON s.vendor_id = v.vendor_id
                WHERE
                    date(v.contract_end) < date('now')
                    AND v.access_active = 1

                UNION ALL

                SELECT
                    s.vendor_id,
                    s.vendor_name,
                    s.category,
                    s.final_risk_score,
                    s.final_risk_level,
                    'NIST SA-9' AS framework,
                    'Expired ' || c.certification_name || ' Certification' AS issue,
                    CASE
                        WHEN v.data_sensitivity >= 8 THEN 'HIGH'
                        ELSE 'MEDIUM'
                    END AS severity,
                    'Request renewed certification evidence and validate the issuing authority.'
                        AS required_action
                FROM vendor_scores s
                JOIN vendors v ON s.vendor_id = v.vendor_id
                JOIN vendor_certifications c ON s.vendor_id = c.vendor_id
                WHERE date(c.expiry_date) < date('now')
            )

            SELECT *
            FROM compliance_issues
            ORDER BY
                CASE severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    ELSE 4
                END,
                final_risk_score DESC,
                vendor_name
            """
        ).fetchall()

    summary = row_to_dict(summary_row)
    total = int(summary.get("total_vendors") or 1)

    summary["gdpr_percentage"] = round(
        int(summary.get("gdpr_dpa_ready") or 0) / total * 100,
        1,
    )
    summary["soc2_percentage"] = round(
        int(summary.get("soc2_ready") or 0) / total * 100,
        1,
    )
    summary["nist_percentage"] = round(
        int(summary.get("nist_ready") or 0) / total * 100,
        1,
    )

    all_issues = [dict(row) for row in issue_rows]

    pagination = build_pagination(
        len(all_issues),
        get_requested_page(),
    )
    pagination = add_pagination_urls(
        pagination,
        "compliance_page",
    )

    page_start = int(pagination["offset"])
    page_end = page_start + ITEMS_PER_PAGE
    issues = all_issues[page_start:page_end]

    return render_template(
        "compliance.html",
        summary=summary,
        issues=issues,
        total_issue_count=len(all_issues),
        pagination=pagination,
    )


# -----------------------------------------------------------------------------
# Reports
# -----------------------------------------------------------------------------

@app.route("/reports")
def reports_page():
    """Display report options and reporting statistics."""

    with get_database_connection() as connection:
        summary_row = connection.execute(
            """
            SELECT
                COUNT(*) AS total_vendors,
                SUM(
                    CASE WHEN final_risk_level = 'CRITICAL'
                    THEN 1 ELSE 0 END
                ) AS critical_vendors,
                SUM(
                    CASE WHEN final_risk_level = 'HIGH'
                    THEN 1 ELSE 0 END
                ) AS high_vendors
            FROM vendor_scores
            """
        ).fetchone()

        compliance_gaps = connection.execute(
            """
            SELECT COUNT(*) AS total
            FROM vendors
            WHERE
                gdpr_dpa = 0
                OR soc2_type2 = 0
                OR iso27001 = 0
                OR assessment_overdue = 1
                OR expired_certifications <> ''
            """
        ).fetchone()["total"]

        sensitive_access = connection.execute(
            """
            SELECT COUNT(*) AS total
            FROM vendors
            WHERE data_sensitivity >= 8
            """
        ).fetchone()["total"]

    report_summary = row_to_dict(summary_row)
    report_summary["compliance_gaps"] = compliance_gaps
    report_summary["sensitive_access"] = sensitive_access

    return render_template(
        "reports.html",
        summary=report_summary,
    )


@app.route("/reports/export/<report_type>")
def export_report(report_type: str):
    """Export a selected vendor-risk report as a CSV file."""

    report_queries = {
        "all-vendors": {
            "filename": "complete_vendor_risk_register.csv",
            "query": """
                SELECT
                    s.vendor_id,
                    s.vendor_name,
                    s.category,
                    s.company_risk_score,
                    s.final_risk_score,
                    s.final_risk_level,
                    s.predicted_anomaly,
                    s.predicted_severity,
                    s.access_risk_score,
                    s.breach_risk_score,
                    s.compliance_risk_score,
                    s.lifecycle_risk_score,
                    s.financial_risk_score,
                    s.financial_rating,
                    v.data_sensitivity,
                    v.access_scope,
                    v.access_type,
                    v.access_active,
                    v.contract_end,
                    v.soc2_type2,
                    v.iso27001,
                    v.gdpr_dpa,
                    v.had_breach,
                    v.breach_date,
                    v.assessment_overdue,
                    v.source_data_access_scope,
                    v.source_breach_status,
                    v.compliance_certifications,
                    v.expired_certifications
                FROM vendor_scores s
                JOIN vendors v ON s.vendor_id = v.vendor_id
                ORDER BY s.final_risk_score DESC
            """,
        },
        "critical-vendors": {
            "filename": "critical_vendor_report.csv",
            "query": """
                SELECT
                    s.vendor_id,
                    s.vendor_name,
                    s.category,
                    s.company_risk_score,
                    s.final_risk_score,
                    s.final_risk_level,
                    s.predicted_anomaly,
                    s.financial_risk_score,
                    s.financial_rating,
                    s.risk_reasons,
                    s.recommendations,
                    v.data_systems,
                    v.data_sensitivity,
                    v.access_type,
                    v.access_active,
                    v.had_breach,
                    v.breach_date,
                    v.breach_severity,
                    v.under_investigation
                FROM vendor_scores s
                JOIN vendors v ON s.vendor_id = v.vendor_id
                WHERE s.final_risk_level = 'CRITICAL'
                ORDER BY s.final_risk_score DESC
            """,
        },
        "compliance-gaps": {
            "filename": "vendor_compliance_gaps.csv",
            "query": """
                SELECT
                    s.vendor_id,
                    s.vendor_name,
                    s.category,
                    s.company_risk_score,
                    s.final_risk_score,
                    s.final_risk_level,
                    v.soc2_type2,
                    v.soc2_expiry,
                    v.iso27001,
                    v.iso27001_expiry,
                    v.gdpr_dpa,
                    v.assessment_overdue,
                    v.last_assessed,
                    v.contract_end,
                    v.access_active,
                    v.compliance_certifications,
                    v.expired_certifications
                FROM vendor_scores s
                JOIN vendors v ON s.vendor_id = v.vendor_id
                WHERE
                    v.gdpr_dpa = 0
                    OR v.soc2_type2 = 0
                    OR v.iso27001 = 0
                    OR v.assessment_overdue = 1
                    OR v.expired_certifications <> ''
                ORDER BY s.final_risk_score DESC
            """,
        },
        "sensitive-access": {
            "filename": "sensitive_data_access_report.csv",
            "query": """
                SELECT
                    s.vendor_id,
                    s.vendor_name,
                    s.category,
                    s.company_risk_score,
                    s.final_risk_score,
                    s.final_risk_level,
                    v.source_data_access_scope,
                    v.data_systems,
                    v.data_sensitivity,
                    v.access_scope,
                    v.access_type,
                    v.access_active,
                    v.contract_end,
                    v.had_breach,
                    v.breach_date
                FROM vendor_scores s
                JOIN vendors v ON s.vendor_id = v.vendor_id
                WHERE v.data_sensitivity >= 8
                ORDER BY
                    v.data_sensitivity DESC,
                    s.final_risk_score DESC
            """,
        },
    }

    report_config = report_queries.get(report_type)

    if report_config is None:
        abort(404)

    with get_database_connection() as connection:
        cursor = connection.execute(report_config["query"])
        rows = cursor.fetchall()
        headers = [description[0] for description in cursor.description]

    csv_buffer = StringIO()
    writer = csv.writer(csv_buffer)
    writer.writerow(headers)

    for row in rows:
        writer.writerow(list(row))

    return Response(
        csv_buffer.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition": (
                f"attachment; filename={report_config['filename']}"
            )
        },
    )


# -----------------------------------------------------------------------------
# Health check and errors
# -----------------------------------------------------------------------------

@app.route("/api/health")
def health_check():
    """Return a lightweight application and database health response."""

    try:
        with get_database_connection() as connection:
            vendor_count = connection.execute(
                "SELECT COUNT(*) AS total FROM vendor_scores"
            ).fetchone()["total"]

        return jsonify(
            {
                "status": "ok",
                "application": "VendorSentinel AI",
                "database": "connected",
                "scored_vendors": vendor_count,
                "narrative_engine": "deterministic fallback with optional LLM",
            }
        )
    except sqlite3.Error as error:
        return (
            jsonify(
                {
                    "status": "error",
                    "database": "unavailable",
                    "message": str(error),
                }
            ),
            500,
        )


@app.errorhandler(404)
def page_not_found(error: Exception):
    return (
        "<h1>404 - Page not found</h1>"
        "<p>The requested VendorSentinel page or vendor does not exist.</p>",
        404,
    )


@app.errorhandler(500)
def internal_server_error(error: Exception):
    return (
        "<h1>500 - Application error</h1>"
        "<p>Check the Flask terminal for the detailed error message.</p>",
        500,
    )


if __name__ == "__main__":
    app.run(debug=True)
