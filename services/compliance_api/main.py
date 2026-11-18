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
from collectors import (
    check_config,
    check_database_privileges,
    check_nmap,
    check_tokenized_payment_data,
    check_tls,
    check_trivy,
    check_zap,
)


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

SCANNER_URL = os.getenv(
    "SCANNER_URL",
    "http://scanner:9000"
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


DEMO_CHECKS = {
    "PCI-01-PORTS": {
        "field": "approved_ports",
        "asset": "web-server",
        "pass": "Only approved HTTPS and internal ports are exposed",
        "fail": "Unapproved network ports are exposed",
        "fix": "Restrict the web server to approved ports",
    },
    "PCI-02-CONFIG": {
        "field": "secure_configuration",
        "asset": "web-server",
        "pass": "No vendor default credentials detected",
        "fail": "The secure configuration baseline has not been applied",
        "fix": "Apply the secure configuration baseline",
    },
    "PCI-03-STORAGE": {
        "field": None,
        "asset": "payment-server",
        "pass": "Payment references are tokenized; no full PAN was returned",
        "fail": "A non-tokenized payment reference was detected",
        "fix": "Tokenize payment references before storage",
        "source": "payment-server",
    },
    "PCI-04-TLS": {
        "field": "tls_enabled",
        "asset": "web-server",
        "pass": "Public traffic uses strong TLS",
        "fail": "The retailer web service is not configured for TLS",
        "fix": "Enable HTTPS and strong TLS on the web service",
    },
    "PCI-05-MALWARE": {
        "field": "malware_protection_current",
        "asset": "payment-server",
        "pass": "Malware protection status is current",
        "fail": "Malware protection is missing or out of date",
        "fix": "Update and enable malware protection",
    },
    "PCI-06-SOFTWARE": {
        "field": "software_patched",
        "asset": "payment-server",
        "pass": "Critical software patches are current",
        "fail": "A critical dependency patch is overdue",
        "fix": "Apply the overdue dependency and rebuild the service",
    },
    "PCI-07-PRIVILEGE": {
        "field": "least_privilege_enabled",
        "asset": "payment-db",
        "pass": "Service accounts use least-privilege database roles",
        "fail": "A service account has more access than required",
        "fix": "Remove unnecessary database privileges",
    },
    "PCI-08-MFA": {
        "field": "mfa_enabled",
        "asset": "web-server",
        "pass": "Privileged accounts use MFA",
        "fail": "MFA is not enabled for one administrator account",
        "fix": "Enable MFA for privileged accounts",
    },
    "PCI-09-PHYSICAL": {
        "field": "physical_access_reviewed",
        "asset": "payment-db",
        "pass": "Physical-access evidence was reviewed",
        "fail": "Physical-access evidence requires assessor review",
        "fix": "Upload and approve the physical-access review",
        "manual": True,
    },
    "PCI-10-LOGS": {
        "field": "logging_enabled",
        "asset": "payment-server",
        "pass": "Authentication and payment events are centrally retained",
        "fail": "Required security logs are not being collected",
        "fix": "Enable centralized security logging",
    },
    "PCI-11-TESTING": {
        "field": "security_testing_current",
        "asset": "payment-server",
        "pass": "Automated vulnerability and security tests are current",
        "fail": "Required security testing evidence is out of date",
        "fix": "Run and document the required security tests",
    },
    "PCI-12-POLICY": {
        "field": "policy_current",
        "asset": "web-server",
        "pass": "The current security policy was acknowledged",
        "fail": "Annual policy acknowledgement requires confirmation",
        "fix": "Review and acknowledge the current security policy",
        "manual": True,
    },
}


LIVE_SCANNER_CONTROLS = {
    "PCI-01-PORTS": "nmap",
    "PCI-02-CONFIG": "docker-inspect",
    "PCI-03-STORAGE": "payment-server",
    "PCI-04-TLS": "python-ssl",
    "PCI-06-SOFTWARE": "trivy",
    "PCI-07-PRIVILEGE": "postgresql",
    "PCI-11-TESTING": "owasp-zap",
}

# The demo is intentionally scoped to controls for which the scanner can
# collect evidence from the running retailer containers. The remaining PCI
# controls stay in the seed data for future expansion, but are not assessed or
# shown by the active demo workflow.
LIVE_CONTROL_IDS = list(LIVE_SCANNER_CONTROLS)


DEMO_ENVIRONMENT_DDL = """
CREATE TABLE IF NOT EXISTS demo_environment (
    retailer_id UUID PRIMARY KEY REFERENCES retailers(retailer_id) ON DELETE CASCADE,
    approved_ports BOOLEAN NOT NULL DEFAULT TRUE,
    secure_configuration BOOLEAN NOT NULL DEFAULT TRUE,
    tls_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    malware_protection_current BOOLEAN NOT NULL DEFAULT TRUE,
    software_patched BOOLEAN NOT NULL DEFAULT FALSE,
    least_privilege_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    physical_access_reviewed BOOLEAN NOT NULL DEFAULT FALSE,
    logging_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    security_testing_current BOOLEAN NOT NULL DEFAULT TRUE,
    policy_current BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
)
"""


def connect():
    return psycopg.connect(
        DATABASE_URL,
        row_factory=dict_row
    )


def ensure_demo_environment_table(connection):
    """Create the demo posture table for clean and existing databases."""
    connection.execute(DEMO_ENVIRONMENT_DDL)
    connection.execute(
        """
        INSERT INTO demo_environment (retailer_id)
        SELECT retailer_id
        FROM retailers
        ON CONFLICT (retailer_id) DO NOTHING
        """
    )


def ensure_retailer_environment(connection, retailer_id):
    ensure_demo_environment_table(connection)
    connection.execute(
        """
        INSERT INTO demo_environment (retailer_id)
        VALUES (%s)
        ON CONFLICT (retailer_id) DO NOTHING
        """,
        (retailer_id,)
    )


def create_demo_assets(connection, retailer_id, retailer_name):
    """Give a newly onboarded demo retailer its three monitored assets."""
    prefix = "".join(
        character.lower() if character.isalnum() else "-"
        for character in retailer_name
    ).strip("-") or "retailer"
    suffix = str(retailer_id)[:8]

    assets = [
        (
            f"{prefix}-{suffix}-web-server",
            f"{retailer_name} Web Server",
            "Nginx container",
            "Web Team"
        ),
        (
            f"{prefix}-{suffix}-payment-server",
            f"{retailer_name} Payment Server",
            "Python container",
            "Payment Team"
        ),
        (
            f"{prefix}-{suffix}-payment-db",
            f"{retailer_name} Payment Database",
            "PostgreSQL container",
            "Database Team"
        ),
    ]

    for asset_id, name, asset_type, owner in assets:
        connection.execute(
            """
            INSERT INTO assets (
                asset_id,
                retailer_id,
                name,
                asset_type,
                owner
            )
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (asset_id) DO NOTHING
            """,
            (
                asset_id,
                retailer_id,
                name,
                asset_type,
                owner
            )
        )


def get_demo_environment(connection, retailer_id):
    ensure_retailer_environment(connection, retailer_id)
    return connection.execute(
        """
        SELECT *
        FROM demo_environment
        WHERE retailer_id = %s
        """,
        (retailer_id,)
    ).fetchone()


def environment_payload(environment, live_statuses=None):
    controls = []

    live_statuses = live_statuses or {}

    for control_id in LIVE_CONTROL_IDS:
        specification = DEMO_CHECKS[control_id]
        field = specification["field"]
        status = live_statuses.get(control_id, "FAIL")
        status = "PASS" if status == "PASS" else "FAIL"

        controls.append(
            {
                "control_id": control_id,
                "asset_role": specification["asset"],
                "field": field,
                "value": status == "PASS",
                "status": status,
                "fix_available": False,
                "fix_description": specification["fix"],
                "source": LIVE_SCANNER_CONTROLS[control_id],
            }
        )

    return {
        "retailer_id": environment["retailer_id"],
        "updated_at": environment["updated_at"],
        "controls": controls,
    }


def build_demo_evidence(control_id, environment):
    """Return a deterministic, explainable demo check result."""
    specification = DEMO_CHECKS[control_id]
    field = specification["field"]
    observed_value = bool(environment[field])

    if observed_value:
        result = "PASS"
        details = specification["pass"]
    elif specification.get("manual"):
        result = "MANUAL_REVIEW"
        details = specification["fail"]
    else:
        result = "FAIL"
        details = specification["fail"]

    metadata = {
        "source": "demo_environment",
        "field": field,
        "observed_value": observed_value,
        "remediation": specification["fix"],
    }

    return (
        result,
        details,
        specification["asset"],
        metadata
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


def latest_live_statuses(connection, retailer_id):
    """Return PASS/FAIL statuses for the latest live-control scan."""
    scan_id = latest_scan_id(connection, retailer_id)

    if scan_id is None:
        return {}

    rows = connection.execute(
        """
        SELECT control_id, status
        FROM assessments
        WHERE scan_id = %s
          AND control_id = ANY(%s)
        """,
        (scan_id, LIVE_CONTROL_IDS),
    ).fetchall()

    return {
        row["control_id"]: (
            "PASS" if row["status"] == "PASS" else "FAIL"
        )
        for row in rows
    }


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


@app.on_event("startup")
def initialize_demo_environment():
    """Apply the small demo migration to existing database volumes too."""
    with connect() as connection:
        ensure_demo_environment_table(connection)
        for control_id in LIVE_SCANNER_CONTROLS:
            connection.execute(
                """
                UPDATE controls
                SET test_type = 'LIVE'
                WHERE control_id = %s
                """,
                (control_id,)
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
        created = connection.execute(
            """
            INSERT INTO retailers (name, admin_email)
            VALUES (%s, %s)
            RETURNING retailer_id, name, admin_email, status, created_at
            """,
            (retailer.name, retailer.admin_email)
        ).fetchone()

        retailer_id = created["retailer_id"]
        ensure_retailer_environment(connection, retailer_id)
        create_demo_assets(
            connection,
            retailer_id,
            retailer.name
        )

        return created


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


@app.get("/retailers/{retailer_id}/environment")
def get_retailer_environment(retailer_id: UUID):
    with connect() as connection:
        require_retailer(connection, retailer_id)
        environment = get_demo_environment(
            connection,
            retailer_id
        )

        return environment_payload(
            environment,
            latest_live_statuses(connection, retailer_id),
        )


@app.post("/retailers/{retailer_id}/remediate/{control_id}")
def remediate_demo_control(retailer_id: UUID, control_id: str):
    specification = DEMO_CHECKS.get(control_id)

    if specification is None:
        raise HTTPException(
            status_code=404,
            detail="Control does not exist"
        )

    if control_id in LIVE_SCANNER_CONTROLS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"{control_id} is checked by "
                f"{LIVE_SCANNER_CONTROLS[control_id]}. "
                "Fix the retailer environment and run another scan."
            )
        )

    field = specification["field"]

    if field is None:
        raise HTTPException(
            status_code=400,
            detail=(
                "This control is checked by a live collector and "
                "must be fixed in the retailer environment"
            )
        )

    with connect() as connection:
        require_retailer(connection, retailer_id)
        ensure_retailer_environment(
            connection,
            retailer_id
        )

        # field comes only from the fixed DEMO_CHECKS mapping above.
        connection.execute(
            f"""
            UPDATE demo_environment
            SET "{field}" = TRUE,
                updated_at = now()
            WHERE retailer_id = %s
            """,
            (retailer_id,)
        )

        environment = get_demo_environment(
            connection,
            retailer_id
        )

        return {
            "message": "Demo remediation recorded",
            "control_id": control_id,
            "remediation": specification["fix"],
            "environment": environment_payload(
                environment,
                latest_live_statuses(connection, retailer_id),
            ),
        }


@app.post("/retailers/{retailer_id}/environment/reset")
def reset_demo_environment(retailer_id: UUID):
    with connect() as connection:
        require_retailer(connection, retailer_id)
        ensure_retailer_environment(
            connection,
            retailer_id
        )

        connection.execute(
            """
            UPDATE demo_environment
            SET approved_ports = TRUE,
                secure_configuration = TRUE,
                tls_enabled = FALSE,
                malware_protection_current = TRUE,
                software_patched = FALSE,
                least_privilege_enabled = TRUE,
                mfa_enabled = FALSE,
                physical_access_reviewed = FALSE,
                logging_enabled = FALSE,
                security_testing_current = TRUE,
                policy_current = FALSE,
                updated_at = now()
            WHERE retailer_id = %s
            """,
            (retailer_id,)
        )

        environment = get_demo_environment(
            connection,
            retailer_id
        )

        return {
            "message": "Demo environment reset",
            "environment": environment_payload(
                environment,
                latest_live_statuses(connection, retailer_id),
            ),
        }


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
            WHERE control_id = ANY(%s)
            ORDER BY requirement_number
            """,
            (LIVE_CONTROL_IDS,),
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
            JOIN controls c
                ON c.requirement_number = r.requirement_number
               AND c.control_id = ANY(%s)
            LEFT JOIN assessments a
                ON a.control_id = c.control_id
               AND a.scan_id = %s
            GROUP BY
                r.requirement_number,
                r.title,
                r.goal
            ORDER BY r.requirement_number
            """,
            (LIVE_CONTROL_IDS, scan_id)
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
              AND control_id = ANY(%s)
            ORDER BY created_at DESC
            """,
            (scan_id, LIVE_CONTROL_IDS)
        ).fetchall()


@app.get("/evidence")
def get_evidence(retailer_id: UUID | None = None):
    """Return the evidence collected by the latest completed scan."""
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
                e.id,
                e.scan_id,
                e.control_id,
                c.requirement_number,
                c.title AS control_title,
                e.asset_id,
                e.result,
                e.details,
                e.collected_at
            FROM evidence e
            JOIN controls c
                ON c.control_id = e.control_id
            WHERE e.scan_id = %s
              AND e.control_id = ANY(%s)
            ORDER BY c.requirement_number
            """,
            (scan_id, LIVE_CONTROL_IDS)
        ).fetchall()


@app.get("/scan-runs")
def get_scan_runs(retailer_id: UUID | None = None):
    """Return recent scan history so remediation can be demonstrated."""
    with connect() as connection:
        selected_retailer_id = (
            retailer_id
            if retailer_id is not None
            else get_default_retailer_id(connection)
        )

        require_retailer(connection, selected_retailer_id)
        rows = connection.execute(
            """
            SELECT
                s.scan_id,
                s.status,
                s.started_at,
                s.completed_at,
                COUNT(a.id)::int AS total,
                COUNT(a.id) FILTER (
                    WHERE a.status = 'PASS'
                )::int AS passed,
                COUNT(a.id) FILTER (
                    WHERE a.status = 'FAIL'
                )::int AS failed,
                COUNT(a.id) FILTER (
                    WHERE a.status = 'MANUAL_REVIEW'
                )::int AS manual_review
            FROM scan_runs s
            LEFT JOIN assessments a
                ON a.scan_id = s.scan_id
               AND a.control_id = ANY(%s)
            WHERE s.retailer_id = %s
            GROUP BY
                s.scan_id,
                s.status,
                s.started_at,
                s.completed_at
            ORDER BY s.started_at DESC
            LIMIT 10
            """,
            (LIVE_CONTROL_IDS, selected_retailer_id)
        ).fetchall()

        for row in rows:
            total = row["total"]
            row["score"] = (
                round((row["passed"] / total) * 100, 1)
                if total > 0
                else 0
            )

        return rows


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
              AND control_id = ANY(%s)
            """,
            (scan_id, LIVE_CONTROL_IDS)
        ).fetchone()

        open_findings = connection.execute(
            """
            SELECT COUNT(*)::int AS count
            FROM findings
            WHERE scan_id = %s
              AND status = 'OPEN'
              AND control_id = ANY(%s)
            """,
            (scan_id, LIVE_CONTROL_IDS)
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
            """
            SELECT *
            FROM controls
            WHERE control_id = ANY(%s)
            """,
            (LIVE_CONTROL_IDS,),
        ).fetchall()

        controls = {
            row["control_id"]: row
            for row in control_rows
        }

        passed_control_ids = []

        for control_id in LIVE_CONTROL_IDS:
            evidence_metadata = {}

            if control_id == "PCI-01-PORTS":
                (
                    result,
                    details,
                    logical_asset,
                    evidence_metadata
                ) = await check_nmap(
                    SCANNER_URL
                )
            elif control_id == "PCI-02-CONFIG":
                (
                    result,
                    details,
                    logical_asset,
                    evidence_metadata
                ) = await check_config(
                    SCANNER_URL
                )
            elif control_id == "PCI-03-STORAGE":
                (
                    result,
                    details,
                    logical_asset
                ) = await check_tokenized_payment_data(
                    PAYMENT_SERVER_URL
                )
                evidence_metadata = {
                    "source": "payment-server",
                    "endpoint": "/transactions/demo",
                    "check": "tokenized card references",
                }
            elif control_id == "PCI-04-TLS":
                (
                    result,
                    details,
                    logical_asset,
                    evidence_metadata
                ) = await check_tls(
                    SCANNER_URL
                )
            elif control_id == "PCI-06-SOFTWARE":
                (
                    result,
                    details,
                    logical_asset,
                    evidence_metadata
                ) = await check_trivy(
                    SCANNER_URL
                )
            elif control_id == "PCI-07-PRIVILEGE":
                (
                    result,
                    details,
                    logical_asset,
                    evidence_metadata
                ) = await check_database_privileges(
                    SCANNER_URL
                )
            elif control_id == "PCI-11-TESTING":
                (
                    result,
                    details,
                    logical_asset,
                    evidence_metadata
                ) = await check_zap(
                    SCANNER_URL
                )
            evidence_metadata.setdefault(
                "remediation",
                DEMO_CHECKS[control_id]["fix"]
            )

            asset = find_asset(
                retailer_assets,
                logical_asset
            )

            if asset is None:
                result = "FAIL"
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

            status = decision.get("status", "FAIL")
            status = "PASS" if status == "PASS" else "FAIL"

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
                    result,
                    Jsonb({
                        "description": details,
                        **evidence_metadata,
                        "policy_status": status,
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
            else:
                passed_control_ids.append(control_id)

            decisions.append(
                {
                    "control_id": control_id,
                    "status": status,
                    "severity": severity
                }
            )

        # A control is only considered remediated after a later scan passes.
        # Keep the old finding for audit history, but mark it resolved.
        for control_id in passed_control_ids:
            connection.execute(
                """
                UPDATE findings AS f
                SET status = 'RESOLVED'
                FROM scan_runs AS previous_scan
                WHERE f.scan_id = previous_scan.scan_id
                  AND previous_scan.retailer_id = %s
                  AND f.control_id = %s
                  AND f.status = 'OPEN'
                  AND f.scan_id <> %s
                """,
                (
                    retailer_id,
                    control_id,
                    scan_id
                )
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
                  AND a.control_id = ANY(%s)
                ORDER BY a.requirement_number
                """,
                (scan_id, LIVE_CONTROL_IDS)
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


