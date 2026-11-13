"""Appendix C.2 - SQL injection against a vendor-portal invoice lookup,
and the parameterized-query fix. Runs on Python's built-in sqlite3."""
import sqlite3

db = sqlite3.connect(":memory:")
db.executescript("""
CREATE TABLE vendor_invoice(invoice_no TEXT, vendor_id INT, amount REAL, status TEXT);
INSERT INTO vendor_invoice VALUES ('INV-1', 77, 900.0, 'PAID'),
                                  ('INV-2', 88,  50.0, 'SUBMITTED'),
                                  ('INV-9', 91, 7200.0, 'SUBMITTED');
CREATE TABLE portal_user(username TEXT, pw_hash TEXT);
INSERT INTO portal_user VALUES ('fazio_ops', 'e10adc3949ba59abbe56e057f20f883e');
""")

# ---------- VULNERABLE: user input concatenated into the SQL string ----------
def find_invoice_vulnerable(vendor_id: int, invoice_no: str):
    sql = ("SELECT invoice_no, amount, status FROM vendor_invoice "
           f"WHERE vendor_id = {vendor_id} AND invoice_no = '{invoice_no}'")
    print("   SQL sent:", sql)
    return db.execute(sql).fetchall()

# ---------- FIXED: parameterized (prepared) query ----------
def find_invoice_safe(vendor_id: int, invoice_no: str):
    sql = ("SELECT invoice_no, amount, status FROM vendor_invoice "
           "WHERE vendor_id = ? AND invoice_no = ?")
    return db.execute(sql, (vendor_id, invoice_no)).fetchall()

normal    = "INV-1"
tautology = "x' OR '1'='1"
union     = "x' UNION SELECT username, pw_hash, 'leak' FROM portal_user --"

for label, payload in [("normal", normal), ("tautology", tautology), ("UNION", union)]:
    print(f"\n[{label}] input = {payload!r}")
    print("   vulnerable ->", find_invoice_vulnerable(77, payload))
    print("   safe       ->", find_invoice_safe(77, payload))
