# Automated PCI-DSS Compliance Monitoring System

This repository contains a Dockerized PCI-DSS 4.0.1 compliance-monitoring
prototype for a demo retailer. The system registers a retailer, monitors its
web server, payment server, and payment database, runs repeatable checks, saves
evidence and findings, and displays the latest results on a dashboard.

This is an educational prototype, not a formal PCI-DSS certification tool.

## Architecture

- `compliance-api`: FastAPI service that registers retailers, runs scans,
  evaluates OPA policies, stores evidence, and returns dashboard data.
- `scheduler`: starts scans for active retailers every 60 seconds.
- `dashboard`: static Nginx frontend for retailer status, evidence, findings,
  remediation actions, and reports.
- `compliance-db`: PostgreSQL database for retailers, assets, controls,
  assessments, evidence, findings, and scan history.
- `payment-server`: demo payment service that reads tokenized transactions from
  `payment-db`.
- `payment-db`: PostgreSQL database representing the retailer's payment data.
- `scanner`: isolated Nmap, Docker inspection, PostgreSQL privilege, TLS, Trivy,
  and OWASP ZAP integration service.
- `zap`: OWASP ZAP daemon used for the live web security baseline check.
- `policy-engine`: Open Policy Agent service that maps evidence results to
  `PASS`, `FAIL`, or `MANUAL_REVIEW` decisions.
- `web-server`: Nginx container representing the retailer's monitored web
  server.

## Evidence model

Every scan creates a `scan_runs` record. Each control then produces evidence
with a result, asset, explanation, source, and collection time. The API sends
the result to OPA, stores the policy decision in `assessments`, and creates an
open `finding` for a failure or manual review.

PCI-01, PCI-02, PCI-03, PCI-04, PCI-06, PCI-07, and PCI-11 are live checks.

PCI-01 is checked with Nmap from the scanner container. The result is compared
with the approved-port list for the target asset. PCI-02 uses the Docker Engine
API to inspect the running Compose container for privileged mode, host-network
mode, Docker socket access, and unpinned image references.

PCI-03 is a live check. The compliance API calls
`http://payment-server:8081/transactions/demo`, and `collectors.py` verifies
that every `card_reference` matches the token pattern `tok_...`.

PCI-04 performs a TLS 1.2/1.3 handshake against the live Nginx HTTPS listener.
PCI-06 is checked with Trivy against the locally built payment-server image;
HIGH and CRITICAL findings cause the control to fail. PCI-07 queries the live
PostgreSQL roles and table grants for the restricted `payment_app` role.
PCI-11 runs an OWASP ZAP spider and passive baseline against the live web
server; High and Medium alerts cause the control to fail.

The other controls use the demo retailer environment state stored in the
`demo_environment` table. This lets the demonstration show an initial failure,
a remediation action, and a later passing rescan. In a production system,
those values would be replaced with collectors that inspect real server,
database, identity, vulnerability, and logging systems.

## Start the environment

```powershell
docker compose up --build -d
```

Check the services:

```powershell
docker compose ps
```

Open:

- Dashboard: http://localhost:3000
- Compliance API documentation: http://localhost:8000/docs
- API health: http://localhost:8000/health
- Web server: http://localhost:8080
- Web server over TLS: https://localhost:8443
- Payment server: http://localhost:8081/health
- Policy engine: http://localhost:8181

## Demo workflow

Run an initial scan:

```powershell
curl.exe -X POST http://localhost:8000/scan
```

The demo environment still contains controlled demo problems for the checks
that have not yet been connected to live collectors. The live TLS check uses
the self-signed classroom certificate, while the PostgreSQL payment service
uses a restricted `payment_app` role.

Open the dashboard and review the evidence and recommendations. The
**Apply demo fix** buttons are available only for simulated controls. For live
controls, correct the running resource (for example, remove an unexpected
port or repair a database grant) and then click **Run Scan Now**.

The second scan reads the changed state, creates new evidence, updates the
score, and resolves previous findings only when the corresponding control
passes in the new scan.

Useful endpoints:

```powershell
curl.exe http://localhost:8000/retailers
curl.exe http://localhost:8000/summary
curl.exe http://localhost:8000/evidence
curl.exe http://localhost:8000/scan-runs
curl.exe http://localhost:8000/findings
curl.exe http://localhost:8000/retailers/{retailer_id}/environment
curl.exe http://localhost:8081/transactions/demo
```

## Database inspection

```powershell
docker compose exec compliance-db psql -U compliance -d compliance -c "\dt"
docker compose exec compliance-db psql -U compliance -d compliance -c "SELECT * FROM evidence ORDER BY collected_at DESC LIMIT 20;"
docker compose exec compliance-db psql -U compliance -d compliance -c "SELECT * FROM assessments ORDER BY assessed_at DESC LIMIT 20;"
docker compose exec payment-db psql -U payments -d payments -c "SELECT * FROM demo_transactions;"
```

## Limitations

- PCI-01, PCI-02, PCI-03, PCI-04, PCI-06, PCI-07, and PCI-11 inspect live
  retailer resources or live scan results.
- PCI-05, PCI-08, and PCI-10 still use controlled demo environment state.
- Physical access and policy evidence are represented as manual review controls.
- The HTTPS certificate is self-signed for classroom use only.
- OWASP ZAP runs a passive baseline; it is not a full penetration test.
- Authentication, secrets management, and production certificate management
  are not implemented.
- The scanner mounts the local Docker socket so Trivy can inspect local images;
  this is for the local demonstration only and grants the scanner broad Docker
  daemon access.
- Do not use real cardholder data or production credentials.

## Resetting the demo

The dashboard's **Reset Demo Problems** button resets the selected retailer's
demo environment to its initial failing state without deleting database
history. Avoid `docker compose down -v` unless you intentionally want to
delete both PostgreSQL volumes and all stored data.
