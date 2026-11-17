import os
import time

import requests


API_URL = os.getenv(
    "API_URL",
    "http://compliance-api:8000"
)

INTERVAL_SECONDS = int(
    os.getenv("INTERVAL_SECONDS", "60")
)


def run_scheduled_scans():
    try:
        response = requests.get(
            f"{API_URL}/retailers",
            timeout=10
        )

        response.raise_for_status()
        retailers = response.json()

        if not retailers:
            print("No retailers are registered.", flush=True)
            return

        for retailer in retailers:
            if retailer.get("status") != "ACTIVE":
                continue

            retailer_id = retailer["retailer_id"]
            retailer_name = retailer["name"]

            scan_response = requests.post(
                f"{API_URL}/retailers/{retailer_id}/scan",
                timeout=60
            )

            scan_response.raise_for_status()

            print(
                f"Completed scan for {retailer_name}: "
                f"HTTP {scan_response.status_code}",
                flush=True
            )

    except requests.RequestException as error:
        print(
            f"Scheduler could not reach the API: {error}",
            flush=True
        )


print(
    f"Scheduler started. Scan interval: "
    f"{INTERVAL_SECONDS} seconds",
    flush=True
)

while True:
    run_scheduled_scans()
    time.sleep(INTERVAL_SECONDS)