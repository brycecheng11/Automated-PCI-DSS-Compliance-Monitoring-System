## Services To Do

- `compliance-api`: FastAPI service that exposes assets, requirements, and assessment endpoints.
- `dashboard`: Initial static dashboard placeholder.
- `compliance-db`: PostgreSQL database for requirements, assets, evidence, and findings.
- `policy-engine`: Open Policy Agent service with a starter PCI policy.
- `web-server`: Nginx container representing a monitored web server.
- `payment-server`: FastAPI container representing a monitored payment service.
- `payment-db`: PostgreSQL container representing the payment database.


## Start Environment

docker compose up --build


Open:

- Dashboard: http://localhost:3000
- Compliance API: http://localhost:8000/docs
- API health: http://localhost:8000/health
- Web server: http://localhost:8080
- Payment server: http://localhost:8081/health