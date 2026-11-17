import csv
import io
import os
from uuid import UUID

import httpx
import psycopg
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from pydantic import BaseModel
from collectors import check_tokenized_payment_data


DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://compliance:compliance_dev@compliance-db:5432/compliance"
)

OPA_URL = os.getenv(
    "OPA_URL",
    "http://policy-engine:8181"
)

PAYMENT_SERVER_URL = os.getenv(
    "PAYMENT_SERVER_URL",
    "http://payment-server:8081"
)

app = FastAPI(
    title="PCI DSS Compliance API",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)


class PolicyInput(BaseModel):
    result: str
    reason: str = "No reason provided"
    severity_if_failed: str = "HIGH"


class RetailerCreate(BaseModel):
    name: str
    admin_email: str


class AssetCreate(BaseModel):
    asset_id: str
    name: str
    asset_type: str
    owner: str


DEMO_EVIDENCE = {
    "PCI-01-PORTS": (
        "PASS",
        "Only approved HTTPS and internal ports are exposed",
        "web-server"
    ),
    "PCI-02-CONFIG": (
        "PASS",
        "No vendor default credentials detected",
        "web-server"
    ),
    "PCI-03-STORAGE": (
        "PASS",
        "Only tokenized references are stored; no full PAN",
        "payment-db"
    ),
    "PCI-04-TLS": (
        "PASS",
        "TLS is required for public payment traffic",
        "payment-server"
    ),
    "PCI-05-MALWARE": (
        "PASS",
        "Malware protection status is current",
        "payment-server"
    ),
    "PCI-06-SOFTWARE": (
        "FAIL",
        "Critical dependency patch is overdue",
        "payment-server"
    ),
    "PCI-07-PRIVILEGE": (
        "PASS",
        "Service account uses least-privilege database role",
        "payment-db"
    ),
    "PCI-08-MFA": (
        "FAIL",
        "MFA is not enabled for one administrator account",
        "web-server"
    ),
    "PCI-09-PHYSICAL": (
        "MANUAL_REVIEW",
        "Physical access evidence requires assessor review",
        "payment-db"
    ),
    "PCI-10-LOGS": (
        "PASS",
        "Authentication and payment events are centrally retained",
        "payment-server"
    ),
    "PCI-11-TESTING": (
        "PASS",
        "Automated vulnerability and security tests completed",
        "payment-server"
    ),
    "PCI-12-POLICY": (
        "MANUAL_REVIEW",
        "Annual policy acknowledgement requires confirmation",
        "web-server"
    )
}


def connect():
    return psycopg.connect(
        DATABASE_URL,
        row_factory=dict_row
    )


def get_default_retailer_id(connection):
    row = connection.execute(
        """
        SELECT retailer_id
        FROM retailers
        ORDER BY created_at
        LIMIT 1
        """
    ).fetchone()

    if row is None:
        raise HTTPException(
            status_code=404,
            detail="No retailer has been registered"
        )

    return row["retailer_id"]


def require_retailer(connection, retailer_id):
    retailer = connection.execute(
        """
        SELECT retailer_id, name, admin_email, status, created_at
        FROM retailers
        WHERE retailer_id = %s
        """,
        (retailer_id,)
    ).fetchone()

    if retailer is None:
        raise HTTPException(
            status_code=404,
            detail="Retailer not found"
        )

    return retailer


def latest_scan_id(connection, retailer_id):
    row = connection.execute(
        """
        SELECT scan_id
        FROM scan_runs
        WHERE retailer_id = %s
          AND status = 'COMPLETED'
        ORDER BY completed_at DESC NULLS LAST, started_at DESC
        LIMIT 1
        """,
        (retailer_id,)
    ).fetchone()

    return row["scan_id"] if row else None


def find_asset(assets, logical_asset):
    keyword_sets = {
        "web-server": ["web", "nginx"],
        "payment-server": ["payment server", "payment api", "python", "application"],
        "payment-db": ["database", "postgres", "payment-db", " db"]
    }

    keywords = keyword_sets[logical_asset]

    for asset in assets:
        searchable_text = " ".join(
            [
                asset["asset_id"],
                asset["name"],
                asset["asset_type"]
            ]
        ).lower()

        if any(keyword in searchable_text for keyword in keywords):
            return asset

    return None


async def evaluate_policy(policy_data):
    request_body = {
        "input": policy_data
    }

    policy_url = (
        f"{OPA_URL.rstrip('/')}/v1/data/pci/decision"
    )

    try:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.post(
                policy_url,
                json=request_body
            )

            response.raise_for_status()
            return response.json()

    except httpx.HTTPError as error:
        raise HTTPException(
            status_code=503,
            detail=f"Policy engine unavailable: {error}"
        )


@app.get("/health")
def health():
    try:
        with connect() as connection:
            connection.execute("SELECT 1")

        return {
            "status": "ok",
            "service": "compliance-api",
            "database": "connected"
        }

    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Database unavailable"
        )


@app.get("/retailers")
def get_retailers():
    with connect() as connection:
        return connection.execute(
            """
            SELECT retailer_id, name, admin_email, status, created_at
            FROM retailers
            ORDER BY created_at
            """
        ).fetchall()


@app.post("/retailers")
def create_retailer(retailer: RetailerCreate):
    with connect() as connection:
        return connection.execute(
            """
            INSERT INTO retailers (name, admin_email)
            VALUES (%s, %s)
            RETURNING retailer_id, name, admin_email, status, created_at
            """,
            (retailer.name, retailer.admin_email)
        ).fetchone()


@app.get("/retailers/{retailer_id}")
def get_retailer(retailer_id: UUID):
    with connect() as connection:
        return require_retailer(connection, retailer_id)


@app.get("/retailers/{retailer_id}/assets")
def get_retailer_assets(retailer_id: UUID):
    with connect() as connection:
        require_retailer(connection, retailer_id)

        return connection.execute(
            """
            SELECT asset_id, retailer_id, name, asset_type, owner, status
            FROM assets
            WHERE retailer_id = %s
            ORDER BY asset_id
            """,
            (retailer_id,)
        ).fetchall()


@app.post("/retailers/{retailer_id}/assets")
def create_asset(retailer_id: UUID, asset: AssetCreate):
    with connect() as connection:
        require_retailer(connection, retailer_id)

        return connection.execute(
            """
            INSERT INTO assets (
                asset_id,
                retailer_id,
                name,
                asset_type,
                owner
            )
            VALUES (%s, %s, %s, %s, %s)
            RETURNING asset_id, retailer_id, name, asset_type, owner, status
            """,
            (
                asset.asset_id,
                retailer_id,
                asset.name,
                asset.asset_type,
                asset.owner
            )
        ).fetchone()


@app.get("/assets")
def get_assets(retailer_id: UUID | None = None):
    with connect() as connection:
        if retailer_id is None:
            return connection.execute(
                """
                SELECT asset_id, retailer_id, name, asset_type, owner, status
                FROM assets
                ORDER BY asset_id
                """
            ).fetchall()

        require_retailer(connection, retailer_id)

        return connection.execute(
            """
            SELECT asset_id, retailer_id, name, asset_type, owner, status
            FROM assets
            WHERE retailer_id = %s
            ORDER BY asset_id
            """,
            (retailer_id,)
        ).fetchall()


@app.get("/controls")
def get_controls():
    with connect() as connection:
        return connection.execute(
            """
            SELECT
                control_id,
                requirement_number,
                title,
                test_type,
                severity_if_failed
            FROM controls
            ORDER BY requirement_number
            """
        ).fetchall()


@app.get("/requirements")
def get_requirements(retailer_id: UUID | None = None):
    with connect() as connection:
        selected_retailer_id = (
            retailer_id
            if retailer_id is not None
            else get_default_retailer_id(connection)
        )

        require_retailer(connection, selected_retailer_id)
        scan_id = latest_scan_id(
            connection,
            selected_retailer_id
        )

        return connection.execute(
            """
            SELECT
                r.requirement_number AS number,
                r.title,
                r.goal,
                COUNT(DISTINCT c.control_id)::int AS control_count,
                COUNT(a.id) FILTER (
                    WHERE a.status = 'PASS'
                )::int AS passed,
                COUNT(a.id) FILTER (
                    WHERE a.status = 'FAIL'
                )::int AS failed,
                COUNT(a.id) FILTER (
                    WHERE a.status = 'MANUAL_REVIEW'
                )::int AS manual_review
            FROM requirements r
            LEFT JOIN controls c
                ON c.requirement_number = r.requirement_number
            LEFT JOIN assessments a
                ON a.control_id = c.control_id
               AND a.scan_id = %s
            GROUP BY
                r.requirement_number,
                r.title,
                r.goal
            ORDER BY r.requirement_number
            """,
            (scan_id,)
        ).fetchall()


@app.get("/findings")
def get_findings(retailer_id: UUID | None = None):
    with connect() as connection:
        selected_retailer_id = (
            retailer_id
            if retailer_id is not None
            else get_default_retailer_id(connection)
        )

        require_retailer(connection, selected_retailer_id)
        scan_id = latest_scan_id(
            connection,
            selected_retailer_id
        )

        if scan_id is None:
            return []

        return connection.execute(
            """
            SELECT
                finding_id,
                scan_id,
                control_id,
                asset_id,
                severity,
                status,
                description,
                owner,
                created_at
            FROM findings
            WHERE scan_id = %s
              AND status = 'OPEN'
            ORDER BY created_at DESC
            """,
            (scan_id,)
        ).fetchall()

@app.get("/summary")
def get_summary(retailer_id: UUID | None = None):
    with connect() as connection:
        selected_retailer_id = (
            retailer_id
            if retailer_id is not None
            else get_default_retailer_id(connection)
        )

        retailer = require_retailer(
            connection,
            selected_retailer_id
        )

        latest_scan = connection.execute(
            """
            SELECT
                scan_id,
                status,
                started_at,
                completed_at
            FROM scan_runs
            WHERE retailer_id = %s
            ORDER BY started_at DESC
            LIMIT 1
            """,
            (selected_retailer_id,)
        ).fetchone()

        if latest_scan is None:
            return {
                "retailer_id": selected_retailer_id,
                "retailer_name": retailer["name"],
                "monitoring_status": retailer["status"],
                "scan_id": None,
                "last_scan_status": "NOT_RUN",
                "last_scan_started": None,
                "last_scan_completed": None,
                "total": 0,
                "passed": 0,
                "failed": 0,
                "manual_review": 0,
                "open_findings": 0,
                "score": 0
            }

        scan_id = latest_scan_id(
            connection,
            selected_retailer_id
        )

        summary = connection.execute(
            """
            SELECT
                COUNT(*)::int AS total,
                COUNT(*) FILTER (
                    WHERE status = 'PASS'
                )::int AS passed,
                COUNT(*) FILTER (
                    WHERE status = 'FAIL'
                )::int AS failed,
                COUNT(*) FILTER (
                    WHERE status = 'MANUAL_REVIEW'
                )::int AS manual_review
            FROM assessments
            WHERE scan_id = %s
            """,
            (scan_id,)
        ).fetchone()

        open_findings = connection.execute(
            """
            SELECT COUNT(*)::int AS count
            FROM findings
            WHERE scan_id = %s
              AND status = 'OPEN'
            """,
            (scan_id,)
        ).fetchone()["count"]

    total = summary["total"]

    score = (
        round((summary["passed"] / total) * 100, 1)
        if total > 0
        else 0
    )

    return {
        "retailer_id": selected_retailer_id,
        "retailer_name": retailer["name"],
        "monitoring_status": retailer["status"],
        "scan_id": scan_id,
        "last_scan_status": latest_scan["status"],
        "last_scan_started": latest_scan["started_at"],
        "last_scan_completed": latest_scan["completed_at"],
        "total": total,
        "passed": summary["passed"],
        "failed": summary["failed"],
        "manual_review": summary["manual_review"],
        "open_findings": open_findings,
        "score": score
    }



@app.post("/policy-test")
async def policy_test(policy_input: PolicyInput):
    return await evaluate_policy(
        policy_input.model_dump()
    )


async def run_retailer_scan(retailer_id: UUID):
    decisions = []

    with connect() as connection:
        require_retailer(connection, retailer_id)

        scan = connection.execute(
            """
            INSERT INTO scan_runs (
                retailer_id,
                status
            )
            VALUES (%s, 'RUNNING')
            RETURNING scan_id
            """,
            (retailer_id,)
        ).fetchone()

        scan_id = scan["scan_id"]

        retailer_assets = connection.execute(
            """
            SELECT asset_id, name, asset_type, owner, status
            FROM assets
            WHERE retailer_id = %s
            """,
            (retailer_id,)
        ).fetchall()

        control_rows = connection.execute(
            "SELECT * FROM controls"
        ).fetchall()

        controls = {
            row["control_id"]: row
            for row in control_rows
        }

        for control_id, evidence in DEMO_EVIDENCE.items():
            result, details, logical_asset = evidence

            if control_id == "PCI-03-STORAGE":
                (
                    result,
                    details,
                    logical_asset
                ) = await check_tokenized_payment_data(
                    PAYMENT_SERVER_URL
                )

            asset = find_asset(
                retailer_assets,
                logical_asset
            )

            if asset is None:
                result = "MANUAL_REVIEW"
                details = (
                    f"No registered asset matches "
                    f"the expected {logical_asset} role"
                )

            policy_response = await evaluate_policy(
                {
                    "control_id": control_id,
                    "result": result,
                    "reason": details,
                    "severity_if_failed": controls[
                        control_id
                    ]["severity_if_failed"]
                }
            )

            decision = policy_response.get("result", {})

            status = decision.get(
                "status",
                "MANUAL_REVIEW"
            )

            severity = decision.get(
                "severity",
                controls[control_id]["severity_if_failed"]
            )

            reason = decision.get(
                "reason",
                details
            )

            asset_id = (
                asset["asset_id"]
                if asset is not None
                else None
            )

            connection.execute(
                """
                INSERT INTO evidence (
                    scan_id,
                    asset_id,
                    control_id,
                    result,
                    details
                )
                VALUES (%s, %s, %s, %s, %s)
                """,
                (
                    scan_id,
                    asset_id,
                    control_id,
                    status,
                    Jsonb({
                        "description": details
                    })
                )
            )

            connection.execute(
                """
                INSERT INTO assessments (
                    scan_id,
                    requirement_number,
                    control_id,
                    asset_id,
                    status,
                    severity,
                    reason
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    scan_id,
                    controls[control_id][
                        "requirement_number"
                    ],
                    control_id,
                    asset_id,
                    status,
                    severity,
                    reason
                )
            )

            if status != "PASS":
                connection.execute(
                    """
                    INSERT INTO findings (
                        scan_id,
                        control_id,
                        asset_id,
                        severity,
                        description,
                        owner
                    )
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (
                        scan_id,
                        control_id,
                        asset_id,
                        severity,
                        reason,
                        "Security Team"
                    )
                )

            decisions.append(
                {
                    "control_id": control_id,
                    "status": status,
                    "severity": severity
                }
            )

        connection.execute(
            """
            UPDATE scan_runs
            SET status = 'COMPLETED',
                completed_at = now()
            WHERE scan_id = %s
            """,
            (scan_id,)
        )

    return {
        "message": "Retailer compliance scan completed",
        "retailer_id": retailer_id,
        "scan_id": scan_id,
        "results": decisions,
        "summary": get_summary(retailer_id)
    }


@app.post("/scan")
async def run_default_scan():
    with connect() as connection:
        retailer_id = get_default_retailer_id(connection)

    return await run_retailer_scan(retailer_id)


@app.post("/retailers/{retailer_id}/scan")
async def run_specific_scan(retailer_id: UUID):
    return await run_retailer_scan(retailer_id)


@app.get("/report.csv")
def generate_report(retailer_id: UUID | None = None):
    with connect() as connection:
        selected_retailer_id = (
            retailer_id
            if retailer_id is not None
            else get_default_retailer_id(connection)
        )

        require_retailer(connection, selected_retailer_id)
        scan_id = latest_scan_id(
            connection,
            selected_retailer_id
        )

        report_rows = []

        if scan_id is not None:
            report_rows = connection.execute(
                """
                SELECT
                    a.requirement_number AS requirement,
                    c.title,
                    a.control_id AS control,
                    a.asset_id,
                    a.status,
                    a.severity,
                    a.reason,
                    a.assessed_at
                FROM assessments a
                JOIN controls c
                    ON c.control_id = a.control_id
                WHERE a.scan_id = %s
                ORDER BY a.requirement_number
                """,
                (scan_id,)
            ).fetchall()

    field_names = [
        "requirement",
        "title",
        "control",
        "asset_id",
        "status",
        "severity",
        "reason",
        "assessed_at"
    ]

    output = io.StringIO()

    writer = csv.DictWriter(
        output,
        fieldnames=field_names
    )

    writer.writeheader()

    if report_rows:
        writer.writerows(report_rows)
    else:
        writer.writerow({
            "requirement": "",
            "title": "",
            "control": "",
            "asset_id": "",
            "status": "NO_SCAN",
            "severity": "",
            "reason": "No scan has been run",
            "assessed_at": ""
        })

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": (
                "attachment; "
                "filename=pci-compliance-report.csv"
            )
        }
    )


