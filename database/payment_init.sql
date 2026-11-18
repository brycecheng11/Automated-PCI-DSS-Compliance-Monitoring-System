-- Demo payment database initialization.
-- The payment service creates the restricted payment_app role during startup
-- using the bootstrap account, then grants it the minimum required access.

CREATE TABLE IF NOT EXISTS demo_transactions (
    id TEXT PRIMARY KEY,
    amount NUMERIC(10, 2) NOT NULL,
    currency TEXT NOT NULL,
    card_reference TEXT NOT NULL,
    status TEXT NOT NULL
);

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
ON CONFLICT (id) DO NOTHING;

REVOKE ALL ON TABLE demo_transactions FROM PUBLIC;
