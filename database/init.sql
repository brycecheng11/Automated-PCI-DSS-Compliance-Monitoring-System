CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE retailers (
    retailer_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    admin_email TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE requirements (
    requirement_number INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    goal TEXT NOT NULL
);

CREATE TABLE controls (
    control_id TEXT PRIMARY KEY,
    requirement_number INTEGER REFERENCES requirements(requirement_number),
    title TEXT NOT NULL,
    test_type TEXT NOT NULL,
    severity_if_failed TEXT NOT NULL
);

CREATE TABLE assets (
    asset_id TEXT PRIMARY KEY,
    retailer_id UUID REFERENCES retailers(retailer_id),
    name TEXT NOT NULL,
    asset_type TEXT NOT NULL,
    owner TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'MONITORED'
);

-- Demo-only representation of the retailer's security posture.
-- In a production deployment, collectors would read these values from the
-- retailer's real servers, databases, identity provider, and security tools.
CREATE TABLE demo_environment (
    retailer_id UUID PRIMARY KEY REFERENCES retailers(retailer_id) ON DELETE CASCADE,
    approved_ports BOOLEAN NOT NULL DEFAULT TRUE,
    secure_configuration BOOLEAN NOT NULL DEFAULT TRUE,
    tls_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    malware_protection_current BOOLEAN NOT NULL DEFAULT TRUE,
    software_patched BOOLEAN NOT NULL DEFAULT FALSE,
    least_privilege_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    physical_access_reviewed BOOLEAN NOT NULL DEFAULT FALSE,
    logging_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    security_testing_current BOOLEAN NOT NULL DEFAULT TRUE,
    policy_current BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE scan_runs (
    scan_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    retailer_id UUID REFERENCES retailers(retailer_id),
    status TEXT NOT NULL,
    started_at TIMESTAMPTZ DEFAULT now(),
    completed_at TIMESTAMPTZ
);

CREATE TABLE evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scan_runs(scan_id),
    asset_id TEXT REFERENCES assets(asset_id),
    control_id TEXT REFERENCES controls(control_id),
    result TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    collected_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE assessments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scan_runs(scan_id),
    requirement_number INTEGER REFERENCES requirements(requirement_number),
    control_id TEXT REFERENCES controls(control_id),
    asset_id TEXT REFERENCES assets(asset_id),
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    reason TEXT NOT NULL,
    assessed_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE findings (
    finding_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scan_runs(scan_id),
    control_id TEXT REFERENCES controls(control_id),
    asset_id TEXT REFERENCES assets(asset_id),
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'OPEN',
    description TEXT NOT NULL,
    owner TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
);

INSERT INTO requirements VALUES
(1, 'Install and maintain network security controls', 'Secure network and systems'),
(2, 'Apply secure configurations to all system components', 'Secure network and systems'),
(3, 'Protect stored account data', 'Protect account data'),
(4, 'Protect cardholder data during transmission', 'Protect account data'),
(5, 'Protect systems from malicious software', 'Vulnerability management'),
(6, 'Develop and maintain secure systems and software', 'Vulnerability management'),
(7, 'Restrict access by business need to know', 'Access control'),
(8, 'Identify users and authenticate access', 'Access control'),
(9, 'Restrict physical access to cardholder data', 'Access control'),
(10, 'Log and monitor all access', 'Monitoring and testing'),
(11, 'Test security systems and processes regularly', 'Monitoring and testing'),
(12, 'Support information security with organizational policies', 'Information-security policy');

INSERT INTO controls VALUES
('PCI-01-PORTS', 1, 'Only approved network ports are exposed', 'AUTOMATED', 'HIGH'),
('PCI-02-CONFIG', 2, 'Secure configuration baseline passes', 'AUTOMATED', 'HIGH'),
('PCI-03-STORAGE', 3, 'Stored account data is protected', 'AUTOMATED', 'CRITICAL'),
('PCI-04-TLS', 4, 'Transmission uses strong TLS', 'AUTOMATED', 'HIGH'),
('PCI-05-MALWARE', 5, 'Malware protection is current', 'AUTOMATED', 'HIGH'),
('PCI-06-SOFTWARE', 6, 'No critical software vulnerabilities remain', 'AUTOMATED', 'CRITICAL'),
('PCI-07-PRIVILEGE', 7, 'Access follows least privilege', 'AUTOMATED', 'HIGH'),
('PCI-08-MFA', 8, 'Privileged accounts use MFA', 'AUTOMATED', 'HIGH'),
('PCI-09-PHYSICAL', 9, 'Physical-access review is current', 'MANUAL', 'MEDIUM'),
('PCI-10-LOGS', 10, 'Security logs are collected', 'AUTOMATED', 'HIGH'),
('PCI-11-TESTING', 11, 'Security testing is documented', 'AUTOMATED', 'HIGH'),
('PCI-12-POLICY', 12, 'Security policies are current', 'MANUAL', 'MEDIUM');

INSERT INTO retailers (
    name,
    admin_email
)
VALUES (
    'DemoMart',
    'security@demomart.local'
);

INSERT INTO assets (
    asset_id,
    retailer_id,
    name,
    asset_type,
    owner
)
SELECT
    'web-server',
    retailer_id,
    'DemoMart Web Server',
    'Nginx container',
    'Web Team'
FROM retailers
WHERE name = 'DemoMart';

INSERT INTO demo_environment (
    retailer_id,
    approved_ports,
    secure_configuration,
    tls_enabled,
    malware_protection_current,
    software_patched,
    least_privilege_enabled,
    mfa_enabled,
    physical_access_reviewed,
    logging_enabled,
    security_testing_current,
    policy_current
)
SELECT
    retailer_id,
    TRUE,
    TRUE,
    FALSE,
    TRUE,
    FALSE,
    TRUE,
    FALSE,
    FALSE,
    FALSE,
    TRUE,
    FALSE
FROM retailers
WHERE name = 'DemoMart';

INSERT INTO assets (
    asset_id,
    retailer_id,
    name,
    asset_type,
    owner
)
SELECT
    'payment-server',
    retailer_id,
    'DemoMart Payment Server',
    'Python container',
    'Payment Team'
FROM retailers
WHERE name = 'DemoMart';

INSERT INTO assets (
    asset_id,
    retailer_id,
    name,
    asset_type,
    owner
)
SELECT
    'payment-db',
    retailer_id,
    'DemoMart Payment Database',
    'PostgreSQL container',
    'Database Team'
FROM retailers
WHERE name = 'DemoMart';
