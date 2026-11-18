import re

import httpx


async def check_scanner(scanner_url, endpoint, asset, timeout=180):
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(
                scanner_url.rstrip("/") + endpoint,
                json={"asset": asset},
            )
            response.raise_for_status()

        payload = response.json()
        status = payload.get("status", "MANUAL_REVIEW")
        details = payload.get(
            "reason",
            "The scanner did not return a reason"
        )

        return (
            status,
            details,
            asset,
            {
                "source": payload.get("tool", "scanner"),
                "scanner_endpoint": endpoint,
                "scanner_result": payload,
            },
        )

    except Exception as error:
        return (
            "MANUAL_REVIEW",
            f"Scanner check could not run: {error}",
            asset,
            {
                "source": "scanner",
                "scanner_endpoint": endpoint,
                "error": str(error),
            },
        )


async def check_nmap(scanner_url):
    return await check_scanner(
        scanner_url,
        "/scan/nmap",
        "web-server",
        timeout=60,
    )


async def check_config(scanner_url):
    return await check_scanner(
        scanner_url,
        "/scan/config",
        "web-server",
        timeout=60,
    )


async def check_tls(scanner_url):
    return await check_scanner(
        scanner_url,
        "/scan/tls",
        "web-server",
        timeout=30,
    )


async def check_trivy(scanner_url):
    return await check_scanner(
        scanner_url,
        "/scan/trivy",
        "payment-server",
        timeout=240,
    )


async def check_database_privileges(scanner_url):
    return await check_scanner(
        scanner_url,
        "/scan/db-privileges",
        "payment-db",
        timeout=30,
    )


async def check_zap(scanner_url):
    return await check_scanner(
        scanner_url,
        "/scan/zap",
        "web-server",
        timeout=210,
    )


async def check_tokenized_payment_data(payment_server_url):
    try:
        endpoint = (
            payment_server_url.rstrip("/") +
            "/transactions/demo"
        )

        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.get(endpoint)
            response.raise_for_status()

        payload = response.json()
        transactions = payload.get("transactions", [])

        if not transactions:
            return (
                "FAIL",
                "No payment transactions were returned",
                "payment-server"
            )

        token_pattern = re.compile(
            r"^tok_[A-Za-z0-9_-]+$"
        )

        for transaction in transactions:
            card_reference = str(
                transaction.get("card_reference", "")
            )

            if not token_pattern.fullmatch(card_reference):
                return (
                    "FAIL",
                    "A non-tokenized card reference was detected",
                    "payment-server"
                )

        return (
            "PASS",
            (
                f"Checked {len(transactions)} payment "
                "transactions; all references were tokenized"
            ),
            "payment-server"
        )

    except Exception as error:
        return (
            "MANUAL_REVIEW",
            f"Payment data check could not run: {error}",
            "payment-server"
        )
