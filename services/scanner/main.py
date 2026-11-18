import json
import shutil
import subprocess
import xml.etree.ElementTree as ElementTree

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel


app = FastAPI(title="PCI Compliance Scanner")


ASSET_TARGETS = {
    "web-server": "web-server",
    "payment-server": "payment-server",
    "payment-db": "payment-db",
}


ALLOWED_PORTS = {
    "web-server": [80],
    "payment-server": [8081],
    "payment-db": [5432],
}


IMAGE_TARGETS = {
    "compliance-api": "pci-demo/compliance-api:demo",
    "payment-server": "pci-demo/payment-server:demo",
    "dashboard": "pci-demo/dashboard:demo",
    "web-server": "nginx:1.27-alpine",
}


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
            detail=f"Scanner command timed out: {error}"
        )
    except OSError as error:
        raise HTTPException(
            status_code=503,
            detail=f"Scanner command could not start: {error}"
        )

    return completed


def parse_nmap_xml(xml_output):
    try:
        document = ElementTree.fromstring(xml_output)
    except ElementTree.ParseError as error:
        raise HTTPException(
            status_code=502,
            detail=f"Nmap returned invalid XML: {error}"
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


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "scanner",
        "nmap": shutil.which("nmap") is not None,
        "trivy": shutil.which("trivy") is not None,
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
            detail=f"Trivy returned invalid JSON: {error}"
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
