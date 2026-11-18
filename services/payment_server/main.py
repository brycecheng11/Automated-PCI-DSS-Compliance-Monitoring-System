import os

import psycopg
from fastapi import FastAPI, HTTPException
from psycopg.rows import dict_row
from psycopg import sql


DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://payment_app:payment_app_dev@payment-db:5432/payments"
)

ADMIN_DATABASE_URL = os.getenv(
    "ADMIN_DATABASE_URL",
    "postgresql://payments:payments_dev@payment-db:5432/payments"
)

PAYMENT_APP_USER = os.getenv(
    "PAYMENT_APP_USER",
    "payment_app"
)

PAYMENT_APP_PASSWORD = os.getenv(
    "PAYMENT_APP_PASSWORD",
    "payment_app_dev"
)


app = FastAPI(title="Demo Payment Server")


def connect(database_url=DATABASE_URL):
    return psycopg.connect(
        database_url,
        row_factory=dict_row
    )


def initialize_payment_database():
    # Use the bootstrap account only for one-time demo schema setup. The
    # payment API itself connects with the restricted payment_app role.
    with connect(ADMIN_DATABASE_URL) as connection:
        role_exists = connection.execute(
            """
            SELECT 1
            FROM pg_roles
            WHERE rolname = %s
            """,
            (PAYMENT_APP_USER,)
        ).fetchone()

        if role_exists is None:
            connection.execute(
                sql.SQL(
                    "CREATE ROLE {} LOGIN PASSWORD {} "
                    "NOSUPERUSER NOCREATEDB NOCREATEROLE "
                    "NOREPLICATION NOBYPASSRLS"
                ).format(
                    sql.Identifier(PAYMENT_APP_USER),
                    sql.Literal(PAYMENT_APP_PASSWORD)
                )
            )
        else:
            connection.execute(
                sql.SQL(
                    "ALTER ROLE {} LOGIN PASSWORD {} "
                    "NOSUPERUSER NOCREATEDB NOCREATEROLE "
                    "NOREPLICATION NOBYPASSRLS"
                ).format(
                    sql.Identifier(PAYMENT_APP_USER),
                    sql.Literal(PAYMENT_APP_PASSWORD)
                )
            )

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

        connection.execute("REVOKE ALL ON TABLE demo_transactions FROM PUBLIC")
        connection.execute(
            sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(
                sql.Identifier(PAYMENT_APP_USER)
            )
        )
        connection.execute(
            sql.SQL("GRANT SELECT ON TABLE demo_transactions TO {}").format(
                sql.Identifier(PAYMENT_APP_USER)
            )
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
