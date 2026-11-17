from fastapi import FastAPI

app = FastAPI(title="Demo Payment Server")


DEMO_TRANSACTIONS = [
    {
        "id": "txn-1001",
        "amount": 49.99,
        "currency": "USD",
        "card_reference": "tok_demo_001",
        "status": "approved"
    },
    {
        "id": "txn-1002",
        "amount": 12.50,
        "currency": "USD",
        "card_reference": "tok_demo_002",
        "status": "approved"
    }
]


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "payment-server"
    }


@app.get("/transactions/demo")
def get_demo_transactions():
    return {
        "count": len(DEMO_TRANSACTIONS),
        "transactions": DEMO_TRANSACTIONS,
        "notice": "Demo tokenized references only. No real cardholder data is stored."
    }