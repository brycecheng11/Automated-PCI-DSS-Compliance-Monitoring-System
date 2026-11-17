import re

import httpx


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