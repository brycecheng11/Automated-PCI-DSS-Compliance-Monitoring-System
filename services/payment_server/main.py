import os

import psycopg
from fastapi import FastAPI, HTTPException
from psycopg.rows import dict_row


DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://payments:payments_dev@payment-db:5432/payments"
)


app = FastAPI(title="Demo Payment Server")


def connect():
    return psycopg.connect(
        DATABASE_URL,
        row_factory=dict_row
    )


def initialize_payment_database():
    with connect() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS demo_transactions (
                id TEXT PRIMARY KEY,
                amount NUMERIC(10, 2) NOT NULL,
                currency TEXT NOT NULL,
                card_reference TEXT NOT NULL,
                status TEXT NOT NULL
            )
            """
        )

        connection.execute(
            """
            INSERT INTO demo_transactions (
                id,
                amount,
                currency,
                card_reference,
                status
            )
            VALUES
                ('txn-1001', 49.99, 'USD', 'tok_demo_001', 'approved'),
                ('txn-1002', 12.50, 'USD', 'tok_demo_002', 'approved')
            ON CONFLICT (id) DO NOTHING
            """
        )


@app.on_event("startup")
def startup():
    initialize_payment_database()


@app.get("/health")
def health():
    try:
        with connect() as connection:
            connection.execute("SELECT 1")

        return {
            "status": "ok",
            "service": "payment-server",
            "database": "connected"
        }
    except Exception as error:
        raise HTTPException(
            status_code=503,
            detail=f"Payment database unavailable: {error}"
        )


@app.get("/transactions/demo")
def get_demo_transactions():
    try:
        with connect() as connection:
            transactions = connection.execute(
                """
                SELECT
                    id,
                    amount::float AS amount,
                    currency,
                    card_reference,
                    status
                FROM demo_transactions
                ORDER BY id
                """
            ).fetchall()

        return {
            "count": len(transactions),
            "transactions": transactions,
            "notice": (
                "Demo tokenized references only. "
                "No real cardholder data is stored."
            )
        }
    except Exception as error:
        raise HTTPException(
            status_code=503,
            detail=f"Payment database unavailable: {error}"
        )
