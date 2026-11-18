import json
import os
import shutil
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ElementTree

import docker
import psycopg
from fastapi import FastAPI, HTTPException
from psycopg.rows import dict_row
from pydantic import BaseModel


app = FastAPI(title="PCI Compliance Scanner")


ASSET_TARGETS = {
    "web-server": "web-server",
    "payment-server": "payment-server",
    "payment-db": "payment-db",
}


ALLOWED_PORTS = {
    "web-server": [80, 443],
    "payment-server": [8081],
    "payment-db": [5432],
}


IMAGE_TARGETS = {
    "compliance-api": "pci-demo/compliance-api:demo",
    "payment-server": "pci-demo/payment-server:demo",
    "dashboard": "pci-demo/dashboard:demo",
    "web-server": "pci-demo/web-server:demo",
}


CONFIG_TARGETS = {
    "web-server": "web-server",
    "payment-server": "payment-server",
    "payment-db": "payment-db",
}


TLS_TARGETS = {
    "web-server": {
        "host": "web-server",
        "port": 443,
    },
}


ZAP_TARGETS = {
    "web-server": "http://web-server",
}


PAYMENT_DATABASE_URL = os.getenv(
    "PAYMENT_DATABASE_URL",
    "postgresql://payments:payments_dev@payment-db:5432/payments",
)

PAYMENT_APP_ROLE = os.getenv(
    "PAYMENT_APP_ROLE",
    "payment_app",
)

ZAP_URL = os.getenv(
    "ZAP_URL",
    "http://zap:8090",
)


class AssetRequest(BaseModel):
    asset: str


def validate_asset(asset, targets):
    if asset not in targets:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unsupported asset '{asset}'. "
                f"Allowed values: {sorted(targets)}"
            ),
        )


def run_command(command, timeout):
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise HTTPException(
            status_code=504,
            detail=f"Scanner command timed out: {error}",
        )
    except OSError as error:
        raise HTTPException(
            status_code=503,
            detail=f"Scanner command could not start: {error}",
        )

    return completed


def parse_nmap_xml(xml_output):
    try:
        document = ElementTree.fromstring(xml_output)
    except ElementTree.ParseError as error:
        raise HTTPException(
            status_code=502,
            detail=f"Nmap returned invalid XML: {error}",
        )

    open_ports = []

    for port in document.findall(".//port"):
        state = port.find("state")

        if (
            state is not None
            and state.get("state") == "open"
            and port.get("portid") is not None
        ):
            open_ports.append(int(port.get("portid")))

    return sorted(set(open_ports))


def inspect_compose_container(service):
    """Return a live Docker container inspection for a Compose service."""
    client = None

    try:
        client = docker.from_env()
        containers = client.containers.list(
            filters={
                "label": f"com.docker.compose.service={service}"
            }
        )

        if not containers:
            raise HTTPException(
                status_code=404,
                detail=f"No running container found for service '{service}'",
            )

        container = containers[0]
        container.reload()

        return {
            "container_id": container.short_id,
            "name": container.name,
            "status": container.status,
            "attrs": container.attrs,
        }
    except HTTPException:
        raise
    except docker.errors.DockerException as error:
        raise HTTPException(
            status_code=503,
            detail=f"Docker inspection failed: {error}",
        )
    finally:
        if client is not None:
            client.close()


def scan_live_container_configuration(asset):
    service = CONFIG_TARGETS[asset]
    inspected = inspect_compose_container(service)
    attrs = inspected["attrs"]
    host_config = attrs.get("HostConfig", {})
    image = attrs.get("Config", {}).get("Image", "")
    network_mode = host_config.get("NetworkMode", "")

    issues = []
    checks = []

    privileged = bool(host_config.get("Privileged", False))
    checks.append({
        "check": "privileged_container",
        "passed": not privileged,
        "observed": privileged,
    })
    if privileged:
        issues.append("Container is running in privileged mode")

    host_network = network_mode == "host"
    checks.append({
        "check": "host_network",
        "passed": not host_network,
        "observed": network_mode,
    })
    if host_network:
        issues.append("Container uses the host network namespace")

    docker_socket_mounted = any(
        mount.get("Destination") == "/var/run/docker.sock"
        for mount in attrs.get("Mounts", [])
    )
    checks.append({
        "check": "docker_socket_mount",
        "passed": not docker_socket_mounted,
        "observed": docker_socket_mounted,
    })
    if docker_socket_mounted:
        issues.append("Container can access the Docker daemon socket")

    image_name = image.split("@", 1)[0]
    image_leaf = image_name.rsplit("/", 1)[-1]
    image_is_unpinned = ":" not in image_leaf or image_leaf.endswith(":latest")
    checks.append({
        "check": "pinned_image_reference",
        "passed": not image_is_unpinned,
        "observed": image,
    })
    if image_is_unpinned:
        issues.append("Image is not pinned to a non-latest tag or digest")

    passed = not issues
    reason = (
        f"Live Docker configuration checks passed for {service}"
        if passed
        else "; ".join(issues)
    )

    return {
        "tool": "docker-inspect",
        "asset": asset,
        "target": service,
        "container_id": inspected["container_id"],
        "container_name": inspected["name"],
        "container_status": inspected["status"],
        "image": image,
        "checks": checks,
        "issues": issues,
        "status": "PASS" if passed else "FAIL",
        "reason": reason,
    }


def scan_live_tls(asset):
    target = TLS_TARGETS[asset]
    host = target["host"]
    port = target["port"]

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=8) as raw_socket:
            with context.wrap_socket(
                raw_socket,
                server_hostname=host,
            ) as tls_socket:
                tls_version = tls_socket.version()
                cipher = tls_socket.cipher()
                certificate = tls_socket.getpeercert(
                    binary_form=True
                )

        passed = (
            tls_version in {"TLSv1.2", "TLSv1.3"}
            and bool(certificate)
        )

        return {
            "tool": "python-ssl",
            "asset": asset,
            "target": f"{host}:{port}",
            "tls_version": tls_version,
            "cipher": cipher[0] if cipher else None,
            "certificate_present": bool(certificate),
            "status": "PASS" if passed else "FAIL",
            "reason": (
                f"TLS handshake succeeded with {tls_version}"
                if passed
                else "TLS handshake did not meet the approved baseline"
            ),
        }
    except (OSError, ssl.SSLError) as error:
        return {
            "tool": "python-ssl",
            "asset": asset,
            "target": f"{host}:{port}",
            "status": "FAIL",
            "reason": f"TLS check failed: {error}",
        }


def scan_database_privileges(asset):
    role_name = PAYMENT_APP_ROLE

    try:
        with psycopg.connect(
            PAYMENT_DATABASE_URL,
            row_factory=dict_row,
        ) as connection:
            role = connection.execute(
                """
                SELECT
                    rolname,
                    rolsuper,
                    rolcreaterole,
                    rolcreatedb,
                    rolcanlogin,
                    rolreplication,
                    rolbypassrls
                FROM pg_roles
                WHERE rolname = %s
                """,
                (role_name,),
            ).fetchone()

            if role is None:
                return {
                    "tool": "postgresql",
                    "asset": asset,
                    "role": role_name,
                    "status": "FAIL",
                    "reason": (
                        f"Expected application role '{role_name}' does not exist"
                    ),
                    "remediation": (
                        "Create a dedicated non-superuser application role"
                    ),
                }

            grants = connection.execute(
                """
                SELECT
                    table_schema,
                    table_name,
                    privilege_type,
                    is_grantable
                FROM information_schema.table_privileges
                WHERE grantee = %s
                  AND table_schema NOT IN ('pg_catalog', 'information_schema')
                ORDER BY table_schema, table_name, privilege_type
                """,
                (role_name,),
            ).fetchall()

            public_grants = connection.execute(
                """
                SELECT
                    table_schema,
                    table_name,
                    privilege_type,
                    is_grantable
                FROM information_schema.table_privileges
                WHERE grantee = 'PUBLIC'
                  AND table_schema NOT IN ('pg_catalog', 'information_schema')
                ORDER BY table_schema, table_name, privilege_type
                """
            ).fetchall()

        issues = []
        elevated_flags = [
            flag
            for flag in (
                "rolsuper",
                "rolcreaterole",
                "rolcreatedb",
                "rolreplication",
                "rolbypassrls",
            )
            if role[flag]
        ]

        if elevated_flags:
            issues.append(
                "Application role has elevated attributes: "
                + ", ".join(elevated_flags)
            )

        if not role["rolcanlogin"]:
            issues.append("Application role cannot log in")

        grant_tuples = {
            (
                grant["table_schema"],
                grant["table_name"],
                grant["privilege_type"],
                grant["is_grantable"],
            )
            for grant in grants
        }

        required_grant = (
            "public",
            "demo_transactions",
            "SELECT",
            "NO",
        )
        if required_grant not in grant_tuples:
            issues.append(
                "Application role is missing its required SELECT grant"
            )

        allowed_grants = {required_grant}
        unexpected_grants = sorted(
            grant_tuples - allowed_grants
        )
        if unexpected_grants:
            issues.append(
                "Application role has unexpected table privileges"
            )

        if public_grants:
            issues.append(
                "PUBLIC has direct privileges on payment tables"
            )

        passed = not issues
        return {
            "tool": "postgresql",
            "asset": asset,
            "database": "payments",
            "role": role_name,
            "role_flags": dict(role),
            "grants": [dict(grant) for grant in grants],
            "public_grants": [
                dict(grant)
                for grant in public_grants
            ],
            "unexpected_grants": [
                list(grant)
                for grant in unexpected_grants
            ],
            "status": "PASS" if passed else "FAIL",
            "reason": (
                "Application role uses least privilege"
                if passed
                else "; ".join(issues)
            ),
        }
    except Exception as error:
        return {
            "tool": "postgresql",
            "asset": asset,
            "role": role_name,
            "status": "MANUAL_REVIEW",
            "reason": f"Database privilege check could not run: {error}",
        }


def zap_request(path, parameters=None, timeout=20):
    query = urllib.parse.urlencode(parameters or {})
    url = ZAP_URL.rstrip("/") + path
    if query:
        url += "?" + query

    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json"},
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as error:
        raise RuntimeError(f"ZAP API request failed: {error}")

    if "code" in payload and "message" in payload:
        raise RuntimeError(
            f"ZAP API error {payload['code']}: {payload['message']}"
        )

    return payload


def wait_for_zap_spider(scan_id, deadline):
    while time.monotonic() < deadline:
        payload = zap_request(
            "/JSON/spider/view/status/",
            {"scanId": scan_id},
        )
        status = int(payload.get("status", 0))
        if status >= 100:
            return status
        time.sleep(1)

    raise RuntimeError("ZAP spider scan timed out")


def wait_for_zap_passive_scan(deadline):
    while time.monotonic() < deadline:
        payload = zap_request(
            "/JSON/pscan/view/recordsToScan/"
        )
        records = int(payload.get("recordsToScan", 0))
        if records == 0:
            return
        time.sleep(1)

    raise RuntimeError("ZAP passive scan timed out")


def scan_web_security(asset):
    target = ZAP_TARGETS[asset]
    deadline = time.monotonic() + 150

    version = zap_request("/JSON/core/view/version/")
    spider = zap_request(
        "/JSON/spider/action/scan/",
        {
            "url": target,
            "recurse": "true",
            "inScopeOnly": "false",
        },
    )
    scan_id = str(spider.get("scan", ""))
    if not scan_id:
        raise RuntimeError("ZAP did not return a spider scan ID")

    wait_for_zap_spider(scan_id, deadline)
    wait_for_zap_passive_scan(deadline)

    alerts_payload = zap_request(
        "/JSON/core/view/alerts/",
        {
            "baseurl": target,
            "start": 0,
            "count": 100,
        },
    )
    alerts = alerts_payload.get("alerts", []) or []
    counts = {
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Informational": 0,
    }

    for alert in alerts:
        risk = alert.get("risk", "Informational")
        if risk in counts:
            counts[risk] += 1

    blocking_alerts = [
        alert
        for alert in alerts
        if alert.get("risk") in {"High", "Medium"}
    ]
    passed = not blocking_alerts

    return {
        "tool": "owasp-zap",
        "asset": asset,
        "target": target,
        "zap_version": version.get("version"),
        "scan_type": "spider and passive baseline",
        "alert_counts": counts,
        "alerts": [
            {
                "name": alert.get("name"),
                "risk": alert.get("risk"),
                "confidence": alert.get("confidence"),
                "url": alert.get("url"),
                "description": alert.get("description"),
            }
            for alert in alerts[:10]
        ],
        "status": "PASS" if passed else "FAIL",
        "reason": (
            "OWASP ZAP found no High or Medium baseline alerts"
            if passed
            else (
                f"OWASP ZAP found {counts['High']} High and "
                f"{counts['Medium']} Medium alerts"
            )
        ),
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "scanner",
        "nmap": shutil.which("nmap") is not None,
        "trivy": shutil.which("trivy") is not None,
        "docker_sdk": True,
        "postgres_client": True,
        "zap_url": ZAP_URL,
    }


@app.post("/scan/nmap")
def scan_ports(request: AssetRequest):
    validate_asset(request.asset, ASSET_TARGETS)

    target = ASSET_TARGETS[request.asset]
    allowed_ports = ALLOWED_PORTS[request.asset]

    command = [
        "nmap",
        "-sT",
        "-Pn",
        "-n",
        "-T4",
        "--open",
        "-p",
        "1-10000",
        "-oX",
        "-",
        target,
    ]

    completed = run_command(command, timeout=45)

    if completed.returncode != 0:
        raise HTTPException(
            status_code=502,
            detail=(
                "Nmap failed: "
                + (completed.stderr.strip() or "unknown error")
            ),
        )

    open_ports = parse_nmap_xml(completed.stdout)
    unexpected_ports = [
        port
        for port in open_ports
        if port not in allowed_ports
    ]
    missing_ports = [
        port
        for port in allowed_ports
        if port not in open_ports
    ]

    passed = not unexpected_ports and not missing_ports

    if passed:
        reason = (
            f"Nmap found only approved open ports: {open_ports}"
        )
    else:
        reason = (
            f"Unexpected ports: {unexpected_ports}; "
            f"missing approved ports: {missing_ports}"
        )

    return {
        "tool": "nmap",
        "target": target,
        "asset": request.asset,
        "allowed_ports": allowed_ports,
        "open_ports": open_ports,
        "unexpected_ports": unexpected_ports,
        "missing_ports": missing_ports,
        "status": "PASS" if passed else "FAIL",
        "reason": reason,
        "command": " ".join(command),
    }


@app.post("/scan/config")
def scan_config(request: AssetRequest):
    validate_asset(request.asset, CONFIG_TARGETS)
    return scan_live_container_configuration(request.asset)


@app.post("/scan/tls")
def scan_tls(request: AssetRequest):
    validate_asset(request.asset, TLS_TARGETS)
    return scan_live_tls(request.asset)


@app.post("/scan/db-privileges")
def scan_db_privileges(request: AssetRequest):
    validate_asset(request.asset, {"payment-db": "payment-db"})
    return scan_database_privileges(request.asset)


@app.post("/scan/zap")
def scan_zap(request: AssetRequest):
    validate_asset(request.asset, ZAP_TARGETS)

    try:
        return scan_web_security(request.asset)
    except RuntimeError as error:
        raise HTTPException(
            status_code=503,
            detail=str(error),
        )


@app.post("/scan/trivy")
def scan_image(request: AssetRequest):
    validate_asset(request.asset, IMAGE_TARGETS)

    image = IMAGE_TARGETS[request.asset]
    command = [
        "trivy",
        "image",
        "--quiet",
        "--format",
        "json",
        "--scanners",
        "vuln",
        "--severity",
        "HIGH,CRITICAL",
        "--ignore-unfixed",
        image,
    ]

    completed = run_command(command, timeout=180)

    if completed.returncode != 0:
        raise HTTPException(
            status_code=502,
            detail=(
                "Trivy failed: "
                + (completed.stderr.strip() or "unknown error")
            ),
        )

    try:
        report = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError as error:
        raise HTTPException(
            status_code=502,
            detail=f"Trivy returned invalid JSON: {error}",
        )

    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
    }
    findings = []

    for result in report.get("Results", []) or []:
        for vulnerability in result.get("Vulnerabilities", []) or []:
            severity = vulnerability.get("Severity", "UNKNOWN")

            if severity in counts:
                counts[severity] += 1

            if len(findings) < 10:
                findings.append(
                    {
                        "id": vulnerability.get("VulnerabilityID"),
                        "package": vulnerability.get("PkgName"),
                        "installed_version": vulnerability.get(
                            "InstalledVersion"
                        ),
                        "fixed_version": vulnerability.get(
                            "FixedVersion"
                        ),
                        "severity": severity,
                        "title": vulnerability.get("Title"),
                    }
                )

    passed = counts["CRITICAL"] == 0 and counts["HIGH"] == 0
    status = "PASS" if passed else "FAIL"

    reason = (
        f"Trivy found {counts['CRITICAL']} critical and "
        f"{counts['HIGH']} high vulnerabilities in {image}"
    )

    return {
        "tool": "trivy",
        "target": image,
        "asset": request.asset,
        "status": status,
        "reason": reason,
        "severity_counts": counts,
        "findings": findings,
        "command": " ".join(command),
    }
