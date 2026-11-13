# The Target 2013 Data Breach: Attack Analysis & Defense-in-Depth Redesign

**Applied Security Project · Group N · University of Tabuk**
Team: Roaa Alghamdi, Rania Alatwi, Shatha Alsulaimani, Ghadi Abdullah, Amani Hassan

In 2013, attackers phished a small HVAC contractor, used its vendor login to get into Target's network, and stole 40 million payment cards and 70 million customer records. We traced the kill chain and redesigned the controls that should have stopped each step.

See the full architecture diagram: [docs/architecture_diagram.pdf](docs/architecture_diagram.pdf)

## What's in `code/`
| File | What it does |
|---|---|
| `schema_and_grants.sql` | PostgreSQL 16 schema that separates cardholder data (`cde`) from corporate data, with least-privilege roles, `GRANT`/`REVOKE`, masking views and row-level security for vendors |
| `test_results.txt` | Each role trying allowed and blocked queries (e.g. the vendor portal can't insert invoices for another vendor because RLS blocks it) |
| `injection_demo.py` | SQL injection (tautology and UNION) against a vendor invoice lookup, then the parameterised-query fix, using Python's `sqlite3` |
| `fw4_cde.rules` | Default-deny `iptables` rulebook for the cardholder-data firewall |
| `nips_local.rules` | Snort rules for the inline IPS |

Run the injection demo:
```bash
python code/injection_demo.py
```

## Design in one line
Identity (MFA, RBAC + ABAC, PAM), segmentation (default-deny CDE), data protection (P2PE, tokenisation, HSM keys), endpoint allow-listing and one SIEM that correlates everything, so a stolen vendor password no longer leads to the card data.
