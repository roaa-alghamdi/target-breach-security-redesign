-- =====================================================================
-- Appendix C - Cardholder / customer data: schema, least-privilege
-- GRANT / REVOKE statements and role-restricted views (PostgreSQL 16)
-- =====================================================================

-- ---------- 0. Schemas: separate CDE data from corporate data ----------
CREATE SCHEMA cde;        -- cardholder-data environment (PCI scope)
CREATE SCHEMA corp;       -- corporate / billing data (out of PCI scope)

-- ---------- 1. Tables ----------
CREATE TABLE cde.customer (
    customer_id   BIGSERIAL PRIMARY KEY,
    full_name     TEXT NOT NULL,
    email         TEXT,
    phone         TEXT,
    street_addr   TEXT,
    zip_code      CHAR(5),
    created_at    TIMESTAMPTZ DEFAULT now()
);

-- The PAN never leaves the vault in clear. pan_ciphertext is AES-256-GCM
-- ciphertext produced by the HSM-backed tokenization service; the key is
-- NOT stored in the database.
CREATE TABLE cde.card_vault (
    card_token     CHAR(16) PRIMARY KEY,      -- format-preserving token
    pan_ciphertext BYTEA    NOT NULL,         -- column-level encryption
    pan_last4      CHAR(4)  NOT NULL,
    exp_month      SMALLINT NOT NULL,
    exp_year       SMALLINT NOT NULL,
    key_version    INT      NOT NULL,         -- supports key rotation
    customer_id    BIGINT REFERENCES cde.customer
);

CREATE TABLE cde.pos_transaction (
    txn_id      BIGSERIAL PRIMARY KEY,
    store_id    INT          NOT NULL,
    lane_id     INT          NOT NULL,
    card_token  CHAR(16)     REFERENCES cde.card_vault,
    amount      NUMERIC(10,2) NOT NULL,
    auth_code   CHAR(6),
    txn_time    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE corp.vendor (
    vendor_id    INT PRIMARY KEY,
    vendor_name  TEXT NOT NULL,
    bank_account TEXT NOT NULL                -- sensitive (internal)
);

CREATE TABLE corp.vendor_invoice (
    invoice_no   TEXT PRIMARY KEY,
    vendor_id    INT REFERENCES corp.vendor,
    store_id     INT,
    amount       NUMERIC(10,2),
    status       TEXT DEFAULT 'SUBMITTED',
    submitted_at TIMESTAMPTZ DEFAULT now()
);

-- ---------- 2. Start from zero: default-deny ----------
REVOKE ALL ON SCHEMA cde, corp FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA cde, corp FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

-- ---------- 3. Group roles (RBAC) - no login ----------
CREATE ROLE r_pos_app        NOLOGIN;   -- POS controller service
CREATE ROLE r_billing        NOLOGIN;   -- billing server / AP clerks
CREATE ROLE r_vendor_portal  NOLOGIN;   -- vendor-portal web app
CREATE ROLE r_cust_service   NOLOGIN;   -- customer-service agents
CREATE ROLE r_analyst        NOLOGIN;   -- marketing / BI analysts
CREATE ROLE r_tokenizer      NOLOGIN;   -- only the tokenization service

-- ---------- 4. Login accounts mapped to roles (one per service) ----------
CREATE ROLE svc_pos_ctrl     LOGIN PASSWORD 'from-vault-rotated-daily' IN ROLE r_pos_app;
CREATE ROLE svc_billing      LOGIN PASSWORD 'from-vault-rotated-daily' IN ROLE r_billing;
CREATE ROLE svc_vendorportal LOGIN PASSWORD 'from-vault-rotated-daily' IN ROLE r_vendor_portal;
CREATE ROLE svc_tokenizer    LOGIN PASSWORD 'from-vault-rotated-daily' IN ROLE r_tokenizer;

-- ---------- 5. Views that expose only permitted columns ----------
-- 5a. POS: may see token + last4 + expiry to complete a sale; never PAN.
CREATE VIEW cde.v_pos_card AS
    SELECT card_token, pan_last4, exp_month, exp_year
    FROM cde.card_vault;

-- 5b. Customer service: masked contact data, last-4 only.
CREATE VIEW cde.v_cs_customer AS
    SELECT c.customer_id,
           c.full_name,
           regexp_replace(c.email, '^(.).*(@.*)$', '\1***\2') AS email_masked,
           '***-***-' || right(c.phone, 4)                   AS phone_masked,
           v.pan_last4
    FROM cde.customer c
    LEFT JOIN cde.card_vault v ON v.customer_id = c.customer_id;

-- 5c. Billing: invoices only, no bank account numbers.
CREATE VIEW corp.v_billing_invoice AS
    SELECT i.invoice_no, i.vendor_id, v.vendor_name, i.store_id,
           i.amount, i.status, i.submitted_at
    FROM corp.vendor_invoice i JOIN corp.vendor v USING (vendor_id);

-- 5d. Vendor portal: a vendor sees ONLY its own invoices. The portal sets
--     app.vendor_id from the authenticated (federated) identity.
CREATE VIEW corp.v_vendor_my_invoices WITH (security_barrier) AS
    SELECT invoice_no, store_id, amount, status, submitted_at
    FROM corp.vendor_invoice
    WHERE vendor_id = current_setting('app.vendor_id')::INT;

-- 5e. Analysts: aggregates only, with a minimum query-set size (k >= 10)
--     to block statistical inference (see Part B, Q10).
CREATE VIEW cde.v_sales_by_zip_day AS
    SELECT c.zip_code, date_trunc('day', t.txn_time) AS day,
           count(*) AS n_txn, round(avg(t.amount), 2) AS avg_amount
    FROM cde.pos_transaction t
    JOIN cde.card_vault v ON v.card_token = t.card_token
    JOIN cde.customer  c ON c.customer_id = v.customer_id
    GROUP BY 1, 2
    HAVING count(DISTINCT c.customer_id) >= 10;

-- ---------- 6. GRANTs - least privilege ----------
GRANT USAGE ON SCHEMA cde  TO r_pos_app, r_cust_service, r_analyst, r_tokenizer;
GRANT USAGE ON SCHEMA corp TO r_billing, r_vendor_portal;

-- POS: insert sales, read the masked card view. No UPDATE/DELETE, no PAN.
GRANT INSERT ON cde.pos_transaction TO r_pos_app;
GRANT USAGE  ON SEQUENCE cde.pos_transaction_txn_id_seq TO r_pos_app;
GRANT SELECT ON cde.v_pos_card TO r_pos_app;

-- Tokenizer: the ONLY role that can write/read ciphertext.
GRANT SELECT, INSERT ON cde.card_vault TO r_tokenizer;

-- Billing: read invoices, change status only (column-level UPDATE).
GRANT SELECT ON corp.v_billing_invoice TO r_billing;
GRANT UPDATE (status) ON corp.vendor_invoice TO r_billing;
GRANT SELECT (invoice_no, status) ON corp.vendor_invoice TO r_billing;  -- needed for WHERE clause

-- Vendor portal: submit invoices, read only its own. No CDE schema at all.
GRANT INSERT (invoice_no, vendor_id, store_id, amount) ON corp.vendor_invoice TO r_vendor_portal;
GRANT SELECT ON corp.v_vendor_my_invoices TO r_vendor_portal;

-- Customer service / analysts: views only.
GRANT SELECT ON cde.v_cs_customer      TO r_cust_service;
GRANT SELECT ON cde.v_sales_by_zip_day TO r_analyst;

-- ---------- 7. Explicit REVOKEs (defence against later drift) ----------
REVOKE ALL ON cde.card_vault      FROM r_pos_app, r_billing, r_vendor_portal, r_cust_service, r_analyst;
REVOKE ALL ON cde.customer        FROM r_pos_app, r_billing, r_vendor_portal, r_analyst;
REVOKE UPDATE, DELETE, TRUNCATE ON cde.pos_transaction FROM r_pos_app;
REVOKE ALL ON corp.vendor         FROM r_vendor_portal;      -- bank details
REVOKE ALL ON SCHEMA cde          FROM r_vendor_portal, r_billing;

-- ---------- 8. Row-level security: a vendor can only act as itself ----------
ALTER TABLE corp.vendor_invoice ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_vendor_insert ON corp.vendor_invoice FOR INSERT TO r_vendor_portal
    WITH CHECK (vendor_id = current_setting('app.vendor_id')::INT);
CREATE POLICY p_billing_all   ON corp.vendor_invoice FOR ALL TO r_billing
    USING (true) WITH CHECK (true);
