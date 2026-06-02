# certinext

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Python library and CLI scripts for managing your [CertiNext](https://us.certinext.io) environment via the REST API.

## Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Credentials](#credentials)
- [CLI commands](#cli-commands)
  - [certinext-setup-keyring](#certinext-setup-keyring)
  - [certinext-accounts](#certinext-accounts)
  - [certinext-domains](#certinext-domains)
  - [certinext-ledger](#certinext-ledger)
  - [certinext-list-certificates](#certinext-list-certificates)
  - [certinext-pending-dcv](#certinext-pending-dcv)
  - [certinext-domain-cert-count](#certinext-domain-cert-count)
  - [certinext-issue-cert](#certinext-issue-cert)
- [Python library](#python-library)
- [Examples](#examples)
- [API documentation](#api-documentation)
- [Project structure](#project-structure)

## Requirements

- Python 3.10+
- A CertiNext account with OAuth API credentials (account number + client secret)

## Installation

### From PyPI

```bash
pip install certinext
```

Or with `uv`:

```bash
uv add certinext
```

To use `certinext-issue-cert` (CSR parsing), also install the `csr` optional extra:

```bash
pip install "certinext[csr]"
```

To install the latest pre-release (alpha, beta, or release candidate):

```bash
pip install --pre certinext
uv add certinext --prerelease=allow
```

### From the UMS GitLab package registry

```bash
pip install certinext \
  --extra-index-url https://gitlab.its.maine.edu/api/v4/groups/2236/-/packages/pypi/simple
```

### Development install

Clone the repository, then install in editable mode:

```bash
uv venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # macOS / Linux

uv pip install -e .
```

This installs the `certinext` package and its dependencies (`requests`, `tabulate`, `python-dotenv`).

To use `certinext-issue-cert` (CSR parsing), also install the `csr` optional extra:

```bash
uv pip install -e .[csr]
```

## Credentials

You need two values from the CertiNext portal (Integrations → APIs → OAuth mode):

| Value | Description |
|---|---|
| Account number | Your CertiNext account number (used as the OAuth `client_id`) |
| Client secret | The OAuth access key generated in the portal |

The token endpoint defaults to `https://us-api.certinext.io/oauth/token`. Override with `--token-url` if yours differs.

### Storing credentials in the OS keychain (recommended)

Run the setup command once to store your credentials securely in the system
keychain (Windows Credential Manager on Windows, Keychain on macOS,
libsecret/SecretService on Linux):

```bash
uv pip install certinext[keyring]
certinext-setup-keyring
```

Scripts read credentials from the keychain automatically — no CLI flags or
environment variables needed for day-to-day use.

<details>
<summary>Named profiles and credential resolution order</summary>

#### Named profiles

Use `--profile NAME` to store multiple credential sets (e.g. different
accounts or environments):

```bash
certinext-setup-keyring --profile prod
```

Select a profile at runtime with `--profile` or the `CERTINEXT_PROFILE`
environment variable:

```bash
certinext-domains --profile prod list
CERTINEXT_PROFILE=prod certinext-pending-dcv
```

#### Credential resolution order

All scripts resolve credentials in this priority order:

1. Explicit CLI argument (`--account-number`, `--client-secret`)
2. OS keychain (active profile; see above)
3. Environment variables (`CERTINEXT_CLIENT_ID`, `CERTINEXT_CLIENT_SECRET`)
4. Interactive prompt (falls back to `getpass` for secrets)

</details>

### Sandbox environment

A sandbox environment is available at `https://sandbox-us-api.certinext.io` for
testing API calls without affecting production data.  Store sandbox credentials
once with:

```bash
certinext-setup-keyring --sandbox
```

Then pass `--sandbox` to any CLI command to target the sandbox:

```bash
certinext-accounts --sandbox
certinext-domains --sandbox list
certinext-ledger --sandbox
certinext-list-certificates --sandbox
certinext-pending-dcv --sandbox
certinext-domain-cert-count --sandbox
```

`--sandbox` is a shortcut that sets `--base-url` and `--token-url` to the
sandbox endpoints and defaults `--profile` to `sandbox`.

### Integration tests

The test suite includes integration tests that call the live sandbox API.
They are skipped automatically when credentials are not available, so they
are safe to include in CI environments that lack a keyring.

**Local development** — store credentials in the keyring once:

```bash
certinext-setup-keyring --sandbox
pytest -m integration
```

**GitLab CI** — set two CI/CD Variables in the project's Settings → CI/CD → Variables:

| Variable | Description |
|---|---|
| `CERTINEXT_SANDBOX_CLIENT_ID` | Sandbox account number (client ID) |
| `CERTINEXT_SANDBOX_CLIENT_SECRET` | Sandbox client secret |

The pipeline includes a dedicated `integration-test` job that runs `pytest -m integration`
automatically whenever these variables are defined.

---

## CLI commands

### certinext-setup-keyring

`certinext-setup-keyring` stores CertiNext API credentials in the OS keychain
interactively. Run it once before using the other commands.

```bash
# Store credentials for the default profile
certinext-setup-keyring

# Store credentials for a named profile
certinext-setup-keyring --profile prod

# Store credentials for the sandbox environment
certinext-setup-keyring --sandbox
```

The script prompts for your account number and client secret, shows any
currently stored value as a default so you can keep it by pressing Enter, and
masks the secret with asterisks on confirmation.

### certinext-accounts

`certinext-accounts` shows the current account identity, billing groups, and
pre-vetted organizations.

```bash
certinext-accounts
certinext-accounts --sandbox
certinext-accounts --json
```

| Argument | Description |
|---|---|
| `--json` | Output raw JSON instead of tabular format |

---

### certinext-domains

`certinext-domains` is a command-line interface for the domains API.

#### Common arguments

These appear before the subcommand. Credentials are optional when stored in the
keychain (see [Credentials](#credentials) above).

```
--profile NAME          Credential profile for keyring lookup (env: CERTINEXT_PROFILE)
--sandbox               Use the sandbox API and sandbox keyring profile
--account-number ACCT   CertiNext account number / client_id (env: CERTINEXT_CLIENT_ID)
--client-secret SECRET  OAuth2 client secret (env: CERTINEXT_CLIENT_SECRET)
--base-url URL          API base URL (default: https://us-api.certinext.io)
--token-url URL         Token endpoint URL (default: https://us-api.certinext.io/oauth/token)
--scope SCOPE           OAuth2 scope (optional)
--json                  Output raw JSON instead of tabular format
```

<details>
<summary>Subcommands</summary>

#### list

List all domains.

```bash
# credentials from keychain
certinext-domains list
certinext-domains list --offset 50 --limit 25

# credentials explicit
certinext-domains --account-number ACCT --client-secret SECRET list
```

#### get

Get a single domain by name or ID.

```bash
certinext-domains get maine.edu
certinext-domains get vuxwZgEXWWFXQQWC-...
```

#### create

Create a new domain. Additional API fields can be passed as `KEY=VALUE` pairs.

```bash
certinext-domains create newdomain.example.com
```

#### deactivate

Deactivate a domain by ID. Prompts for confirmation unless `-y` is passed.

```bash
certinext-domains deactivate DOMAIN_ID
certinext-domains deactivate DOMAIN_ID -y
```

#### get-dcv

Show current DCV status for a domain.

```bash
certinext-domains get-dcv DOMAIN_ID
```

#### verify-dcv

Trigger DCV verification for a domain.

```bash
certinext-domains verify-dcv DOMAIN_ID
```

#### change-dcv-method

Change the DCV method for a domain. Accepted values: `DNS-TXT`, `HTTP-URL`.

```bash
certinext-domains change-dcv-method DOMAIN_ID DNS-TXT
```

#### last-dcv-attempt

Show the most recent DCV attempt for a domain.

```bash
certinext-domains last-dcv-attempt DOMAIN_ID
```

#### dcv-attempt-history

Show the full DCV attempt history for a domain.

```bash
certinext-domains dcv-attempt-history DOMAIN_ID
```

</details>

#### JSON output

Add `--json` before the subcommand to get raw JSON instead of the default tabular output. Useful for piping into `jq`:

```bash
certinext-domains --json list | jq '.[] | .domainName'
```

### certinext-ledger

`certinext-ledger` shows the account transaction history (all debits, credits,
and running balance) with automatic pagination.

#### Arguments

```
--last N   Show only the N most recent transactions
--json     Output raw JSON instead of tabular format
```

#### Examples

```bash
certinext-ledger
certinext-ledger --last 20
certinext-ledger --sandbox --json
```

---

### certinext-list-certificates

`certinext-list-certificates` lists all SSL/TLS certificate orders from the
orders report. Use `--status` to filter by lifecycle status.

#### Arguments

```
--status STATUS   Filter by certificate status (issued, expired, pending-dcv, etc.)
--json            Output raw JSON instead of tabular format
```

#### Examples

```bash
certinext-list-certificates
certinext-list-certificates --status issued
certinext-list-certificates --status expired
certinext-list-certificates --status pending-dcv
certinext-list-certificates --sandbox --json
```

---

### certinext-pending-dcv

`certinext-pending-dcv` lists every active domain that has not yet completed
DCV verification. It is a quick read-only diagnostic — no changes are made to
any domain.

#### Arguments

```
--profile NAME          Credential profile for keyring lookup (env: CERTINEXT_PROFILE)
--sandbox               Use the sandbox API and sandbox keyring profile
--account-number ACCT   CertiNext account number (env: CERTINEXT_CLIENT_ID)
--client-secret SECRET  OAuth2 client secret (env: CERTINEXT_CLIENT_SECRET)
--base-url URL          API base URL (default: https://us-api.certinext.io)
--token-url URL         Token endpoint URL (default: https://us-api.certinext.io/oauth/token)
--pattern REGEX         Filter by domain name regex (re.fullmatch, case-insensitive)
--json                  Output raw JSON instead of tabular format
```

#### Examples

```bash
# Credentials from keychain (no flags needed after setup)
certinext-pending-dcv

# Use a named profile
certinext-pending-dcv --profile prod

# Filter to a specific subdomain pattern
certinext-pending-dcv --pattern ".*\.maine\.edu"

# Raw JSON output for scripting
certinext-pending-dcv --json | jq '.[] | .domainName'

# Credentials from environment variables
CERTINEXT_CLIENT_ID=ACCT CERTINEXT_CLIENT_SECRET=SECRET certinext-pending-dcv
```

### certinext-domain-cert-count

`certinext-domain-cert-count` shows all registered domains and how many
certificates each one has. It fetches the domain list and the orders report,
then matches each certificate to its most specific registered domain by suffix
— a cert for `host.subdomain.example.org` counts toward `subdomain.example.org`
when that domain is registered, rather than the less-specific `example.org`.

#### Arguments

```
--profile NAME           Credential profile for keyring lookup (env: CERTINEXT_PROFILE)
--sandbox                Use the sandbox API and sandbox keyring profile
--account-number ACCT    CertiNext account number (env: CERTINEXT_CLIENT_ID)
--client-secret SECRET   OAuth2 client secret (env: CERTINEXT_CLIENT_SECRET)
--base-url URL           API base URL (default: https://us-api.certinext.io)
--token-url URL          Token endpoint URL (default: https://us-api.certinext.io/oauth/token)
--status issued|expired  Filter to only issued or only expired certificates
--condense               Show only top-level domains; subdomain counts roll up into their apex
--json                   Output raw JSON instead of tabular format
```

#### Examples

```bash
# All certificates, all statuses (credentials from keychain)
certinext-domain-cert-count

# Only issued (active) certificates
certinext-domain-cert-count --status issued

# Only expired certificates
certinext-domain-cert-count --status expired

# Collapse subdomains — subdomain.example.org rolls into example.org
certinext-domain-cert-count --condense

# Condense + issued only
certinext-domain-cert-count --condense --status issued

# Raw JSON for scripting
certinext-domain-cert-count --json | jq '.[] | select(.certificates != "0")'
```

### certinext-issue-cert

`certinext-issue-cert` submits a CSR to CertiNext and downloads the issued
certificate.  It reads the domain and SANs directly from the CSR, creates a
certificate order, handles the full lifecycle (agreement, DCV if needed, CSR
submission), and writes the signed PEM to stdout or a file once the CA has
issued it.

Requires the `csr` optional extra:

```bash
pip install "certinext[csr]"
```

#### Arguments

```
# Connection
--profile NAME              Credential profile for keyring lookup (env: CERTINEXT_PROFILE)
--sandbox                   Use the sandbox API and sandbox keyring profile
--account-number ACCT       CertiNext account number (env: CERTINEXT_CLIENT_ID)
--client-secret SECRET      OAuth2 client secret (env: CERTINEXT_CLIENT_SECRET)

# Certificate
csr_file                    PEM-encoded CSR file (positional; omit to read from stdin)
--csr FILE                  Same as positional argument
--type dv|ov|ev             Validation type (default: dv)
--validity YEARS            Validity in years: 1, 2, or 3 (default: 1)
--org-id ID                 Organization ID — required for OV and EV certificates
--domain FQDN               Override the primary domain (default: extracted from CSR CN)
--san FQDN                  Override SANs (default: extracted from CSR; repeatable)
--auto-secure-www           Request automatic www-redirect coverage (API default: true)

# Requestor (can also be set via environment variables)
--requestor-name NAME       Full name of the requestor (env: CERTINEXT_REQUESTOR_NAME)
--requestor-email EMAIL     Email address of the requestor (env: CERTINEXT_REQUESTOR_EMAIL)
--requestor-phone PHONE     Phone in E.164 format, e.g. +12075551234 (env: CERTINEXT_REQUESTOR_PHONE)
--requestor-designation TTL Job title or designation (env: CERTINEXT_REQUESTOR_DESIGNATION)
--signer-place PLACE        City/location for the subscriber agreement (env: CERTINEXT_SIGNER_PLACE)

# Output / control
-o FILE, --output FILE      Write the certificate PEM to FILE (default: stdout)
--wait SECONDS              Seconds to wait for issuance (default: 300; 0 = submit and exit)
--order-id ID               Resume polling an existing order instead of creating a new one
-v, --verbose               Increase verbosity (-vvv for debug logging)
```

#### Examples

```bash
# DV certificate — credentials and requestor info from keychain / env vars
certinext-issue-cert example.com.csr

# Read CSR from stdin
certinext-issue-cert < example.com.csr

# Save certificate to a file
certinext-issue-cert example.com.csr --output example.com.pem

# OV certificate with explicit org
certinext-issue-cert example.com.csr --type ov --org-id 8921215

# Two-year DV certificate against the sandbox
certinext-issue-cert example.com.csr --validity 2 --sandbox

# Submit and exit immediately without waiting for issuance
certinext-issue-cert example.com.csr --wait 0

# Resume polling an order created in a previous run
certinext-issue-cert --order-id ORDER-ID --wait 600

# Resume and supply the CSR (in case the order is still in pending-csr)
certinext-issue-cert --order-id ORDER-ID --csr example.com.csr
```

Set requestor environment variables once to avoid repeating them on every call:

```bash
export CERTINEXT_REQUESTOR_NAME="Jane Doe"
export CERTINEXT_REQUESTOR_EMAIL="jane.doe@example.com"
export CERTINEXT_REQUESTOR_PHONE="+12075551234"
export CERTINEXT_REQUESTOR_DESIGNATION="Systems Administrator"
export CERTINEXT_SIGNER_PLACE="Portland, ME"

certinext-issue-cert example.com.csr --output example.com.pem
```

#### Certificate lifecycle

The tool handles the full CertiNext order lifecycle automatically:

1. **`pending-approval`** — waits for CA approval (no action needed)
2. **`pending-agreement`** — accepts the subscriber agreement on your behalf
3. **`pending-dcv`** — logs challenge details and triggers verification; in
   environments where domains are pre-validated (e.g. University of Maine
   System), DCV auto-resolves without manual intervention
4. **`pending-csr`** — submits the provided CSR
5. **`issued`** — downloads and writes the PEM certificate chain

If the order does not reach `issued` within `--wait` seconds, the tool exits
with code 1 and prints the order ID so you can resume with `--order-id`.

---

## Python library

### Creating a session

```python
import certinext

sess = certinext.session(
    client_id="YOUR_ACCOUNT_NUMBER",
    client_secret="YOUR_CLIENT_SECRET",
)
```

<details>
<summary>All session() parameters</summary>

```python
sess = certinext.session(
    client_id="YOUR_ACCOUNT_NUMBER",
    client_secret="YOUR_CLIENT_SECRET",
    scope="",           # optional
    sandbox=False,      # True → use sandbox endpoints automatically
    base_url="",        # override; defaults to production (or sandbox when sandbox=True)
    token_url="",       # override; defaults to match base_url
)
```

When `sandbox=True`, `base_url` and `token_url` default to the sandbox endpoints
(`https://sandbox-us-api.certinext.io`). Explicit `base_url` / `token_url` values
always take precedence over the `sandbox` flag.

</details>

The session obtains and caches an OAuth 2.0 bearer token automatically, refreshing it before it expires.

### Working with domains

#### List all domains

```python
domains = sess.domain.get_list()
for d in domains:
    print(d)
```

Paginate with `offset` and `limit`:

```python
page = sess.domain.get_list(offset=50, limit=25)
```

Filter by status server-side (reduces data transferred):

```python
# Only active domains with pending or rejected DCV
domains = sess.domain.get_list(domain_status="ACTIVE", dcv_status="PENDING,REJECTED,EXPIRED")
```

> **Note:** The API `search` parameter remains broken after the vendor's
> claimed fix (re-tested 2026-05-27). FQDN searches (any value containing `.`)
> still return all domains; substring searches (no `.`) return 0 results. Use
> `pattern` (below) for reliable filtering.

Filter by name with a regex (applied client-side after the API response):

```python
# Exact match
domains = sess.domain.get_list(pattern=r"maine\.edu")

# Multiple names via alternation
domains = sess.domain.get_list(pattern=r"maine\.edu|umaine\.edu")

# Subdomain wildcard
domains = sess.domain.get_list(pattern=r".*\.maine\.edu")
```

`pattern` uses `re.fullmatch` with `re.IGNORECASE`, so it must match the entire
domain name. Combine with status filters to narrow the API response first:

```python
domains = sess.domain.get_list(domain_status="ACTIVE", pattern=r".*\.maine\.edu")
```

#### List domains needing DCV

`get_pending_dcv()` returns active domains that have not yet completed DCV
verification. It fetches all domains and filters client-side using
`domain.needs_dcv`.

> **Note:** The API `domainStatus` and `dcvStatus` filter parameters return a
> 400 error when used together — confirmed vendor bug (reported 2026-05-20).
> Server-side status filtering is disabled until CertiNext notifies the fix is
> deployed.

```python
pending = sess.domain.get_pending_dcv()

# Narrow to a subset by name
pending = sess.domain.get_pending_dcv(pattern=r".*\.maine\.edu")
```

#### Get a domain

Look up by domain name or by domain ID:

```python
domain = sess.domain.get("maine.edu")
domain = sess.domain.get("vuxwZgEXWWFXQQWC-3zElI5VlhinKlE8xyYJqfeYNtFE0SAP")
```

When a name is passed (contains a `.`), the library lists all domains and finds the match. When an ID is passed, it calls the single-domain endpoint directly.

#### Create a domain

```python
domain = sess.domain.create("newdomain.example.com")
```

<details>
<summary>Domain properties and DcvInfo fields</summary>

#### Domain properties

| Property | Type | Description |
|---|---|---|
| `id` | `str \| None` | Domain ID |
| `name` | `str \| None` | Domain name (FQDN). Settable, but only updates the local object — does not persist to the API. |
| `status` | `str \| None` | `ACTIVE` or `INACTIVE` |
| `dcv_status` | `str \| None` | `VERIFIED`, `PENDING`, `REJECTED`, `EXPIRED`, etc. |
| `organization_id` | `str \| None` | Organization ID |
| `organization_name` | `str \| None` | Organization display name |
| `created_at` | `datetime \| None` | Creation timestamp (timezone-aware UTC) |
| `needs_dcv` | `bool` | `True` if status is `ACTIVE` and `dcv_status` is not `VERIFIED` |

`Domain` objects support `str()` and `repr()`:

```python
print(domain)
# Domain: maine.edu
#   id:              vuxwZgEXWWFXQQWC-...
#   status:          ACTIVE
#   dcv_status:      VERIFIED
#   organization:    University of Maine System
#   created:         2026-05-04 21:27:14+00:00

repr(domain)
# Domain(id='vuxwZgEXWWFXQQWC-...', name='maine.edu', status='ACTIVE', dcv_status='VERIFIED')
```

#### DcvInfo

`domain.get_dcv()` returns a `DcvInfo` dataclass with the following fields:

| Field | Type | Description |
|---|---|---|
| `method` | `str` | DCV method in upper case: `DNS-TXT` or `HTTP-URL` |
| `token` | `str` | Challenge value to publish (TXT record content for DNS-TXT, file token for HTTP-URL) |
| `host` | `str` | Sub-domain prefix for the challenge record (e.g. `_emudhra-challenge`). Empty string if not returned by the API. |

</details>

#### Domain methods

```python
# Re-fetch from API and update the object in place
domain.refresh()

# Deactivate (updates the object in place, returns self)
domain.deactivate()

# DCV — Domain Control Validation
dcv = domain.get_dcv()             # returns DcvInfo(method, token, host)
print(dcv.method)                  # e.g. "DNS-TXT" or "HTTP-URL"
print(dcv.token)                   # challenge value to publish
print(dcv.host)                    # sub-domain prefix for the challenge record

result = domain.verify()           # trigger verification; returns raw API response dict
domain.change_dcv_method("DNS-TXT")   # accepted values: "DNS-TXT", "HTTP-URL"
attempt = domain.last_dcv_attempt()   # returns raw API response dict
history = domain.dcv_attempt_history() # returns raw API response dict or list

# Get the raw API response dict
raw = domain.as_dict()
```

#### Example: verify all pending domains

```python
import certinext

sess = certinext.session(
    client_id="YOUR_ACCOUNT_NUMBER",
    client_secret="YOUR_CLIENT_SECRET",
)

# Due to a vendor API bug, server-side status filtering is currently disabled.
# get_pending_dcv() fetches all domains and filters client-side for needs_dcv.
for domain in sess.domain.get_pending_dcv():
    print(f"Verifying {domain.name} ...")
    domain.verify()
```

Or check `needs_dcv` manually if you already have a full domain list:

```python
for domain in sess.domain.get_list():
    if domain.needs_dcv:
        print(f"Verifying {domain.name} ...")
        domain.verify()
```

### Working with orders

`sess.orders` provides access to the CertiNext orders report API
(`GET /api/certinext/v2/reports/orders`).

#### Fetch all orders

```python
orders = sess.orders.get_list()
for o in orders:
    print(o.common_name, o.certificate_status)
```

Filter by certificate status:

```python
issued = sess.orders.get_list(status="issued")
expired = sess.orders.get_list(status="expired")
```

`get_list()` paginates automatically. Use `get_page()` for manual control:

```python
page = sess.orders.get_page(page=1, size=50, status="issued")
```

#### OrderRecord properties

| Property | Type | Description |
|---|---|---|
| `order_number` | `str \| None` | CertiNext order number |
| `request_number` | `str \| None` | Request number |
| `product_code` | `str \| None` | Product code (e.g. `OV_SSL`, `DV_SSL`) |
| `order_status` | `str \| None` | Order lifecycle status (e.g. `complete`) |
| `certificate_status` | `str \| None` | Certificate status (`issued`, `expired`, etc.) |
| `common_name` | `str \| None` | Certificate common name (hostname or domain) |

```python
o.as_dict()   # raw API response dict
o.to_row()    # flat dict[str, str] for tabular display
repr(o)       # OrderRecord(order_number='ORD-001', common_name='example.org', ...)
```

---

### Working with accounts

`sess.accounts` exposes the authenticated account identity, billing groups, and
pre-vetted organizations.

```python
me = sess.accounts.me()
print(me.account_number, me.account_name, me.account_type)

groups = sess.accounts.list_groups()
for g in groups:
    print(g.group_number, g.group_name)

orgs = sess.accounts.list_organizations()
for o in orgs:
    print(o.organization_number, o.organization_name, o.locality)

# Fetch a single organization by its number
org = sess.accounts.get_organization("8921215")
```

### Working with the catalog

`sess.catalog` lists available certificate products and their custom fields.

```python
categories = sess.catalog.list_products()
for cat in categories:
    for product in cat.products:
        print(product.product_code, product.product_name, product.price)

# Custom fields required for a specific product
fields = sess.catalog.get_custom_fields("842")
for f in fields:
    print(f.field_name, f.required)
```

### Working with the ledger

`sess.ledger` provides access to the account transaction history.

```python
records = sess.ledger.get_list()
for r in records:
    print(r.transaction_date, r.description, r.debit, r.credit, r.balance)

# Single page
page = sess.ledger.get_page(page=1, size=50)
```

`get_list()` paginates automatically. `LedgerRecord.to_row()` returns a flat
`dict[str, str]` suitable for `tabulate`.

### Working with SSL/TLS certificates

`sess.ssl` covers the full certificate lifecycle. Product codes are resolved
automatically from the catalog — you never hardcode a product code.

#### Create a certificate

Use `sess.ssl.create()` when the validation level is a runtime value (e.g. read
from configuration). It dispatches to the appropriate `create_*` method and
validates that `organization_id` is provided for OV and EV orders:

```python
# Product determined at runtime (e.g. from config)
order = sess.ssl.create("dv", "example.com", validity_years=1)
order = sess.ssl.create("ov", "example.com", organization_id="8921215", validity_years=1)
order = sess.ssl.create("ev", "example.com", organization_id="8921215", validity_years=1)
```

Or call the specific variant directly:

```python
# DV single-domain
order = sess.ssl.create_dv("example.com", validity_years=1)

# DV wildcard
order = sess.ssl.create_dv_wildcard("example.com", validity_years=1)

# OV single-domain (requires organization_id from sess.accounts.list_organizations())
order = sess.ssl.create_ov("example.com", organization_id="8921215", validity_years=1)

# EV single-domain
order = sess.ssl.create_ev("example.com", organization_id="8921215", validity_years=1)

# UCC (multi-domain) — pass a list for DV, OV, or EV
order = sess.ssl.create_dv_ucc(["example.com", "www.example.com"], validity_years=1)
```

#### DV lifecycle

Each mutation call returns an opaque response dict; call `order.refresh()` afterwards to see the updated `order.status`.

```python
# 1. Get challenges
for challenge in order.get_dcv():
    print(challenge.domain, challenge.method, challenge.host, challenge.token)

# 2. (Publish the DNS TXT or HTTP file challenge externally)

# 3. Trigger verification (publish the challenge first, then call this)
order.verify_dcv()
order.refresh()
print(order.status)  # "pending-csr" once DCV passes

# 4. Submit CSR
order.submit_csr(csr_pem)
order.refresh()

# 5. Accept agreement
order.accept_agreement()
order.refresh()
print(order.status)  # "pending-approval" or "issued"

# 6. Download once issued
cert = order.download_certificate()           # JSON — cert + chain PEM strings
pem  = order.download_certificate_pem()      # raw PEM bundle (ordering not guaranteed)
chain = order.download_certificate().as_pem_chain()  # leaf-first fullchain, normalised newline
der  = order.download_certificate_der()      # raw DER bytes
```

**Complete end-to-end DV example:**

```python
import certinext, time

sess = certinext.session(client_id="YOUR_ACCOUNT", client_secret="YOUR_SECRET")

order = sess.ssl.create_dv("example.com", validity_years=1)
print(f"Order {order.order_id} created, status={order.status}")

for ch in order.get_dcv():
    print(f"  {ch.domain}: add TXT at {ch.host!r}  value={ch.token!r}")

input("Press Enter once DNS TXT records are published…")

order.verify_dcv()
order.submit_csr(open("csr.pem").read())
order.accept_agreement()

while True:
    order.refresh()
    if order.status == "issued":
        break
    print(f"  status={order.status}, waiting…")
    time.sleep(30)

open("cert.pem", "w").write(order.download_certificate_pem())
print("Certificate written to cert.pem")
```

#### Retrieve an existing order

```python
order = sess.ssl.get("ORDER-ID")
print(order.status, order.domain, order.created_at)
order.refresh()   # re-fetch current state from the API
```

#### OrderWorkflow helpers

`OrderWorkflow` drives an order through its full lifecycle automatically.
Three helpers simplify common patterns:

```python
from certinext import OrderWorkflow

# Drive a new order to issuance (blocking)
wf = OrderWorkflow.from_csr(order, csr_pem, signer_name="Jane Doe")
pem = wf.run()   # blocks until issued or timeout

# Resume from a persisted order ID (e.g. after a restart)
wf = OrderWorkflow.from_order_id(sess, "ORDER-ID", signer_name="Jane Doe")
wf.advance(csr_pem)   # one non-blocking step

# Download the issued certificate as a deterministic leaf-first fullchain
chain = wf.download_chain()   # retries HTTP 422 ("not ready yet") automatically
```

`download_chain()` uses `CertificateDownload.as_pem_chain()` internally — the
end-entity certificate followed by its intermediates, with a single trailing
newline. Use this instead of `download()` when the bundle order matters (e.g.
when writing a `fullchain.pem` for an ACME server).

#### Other lifecycle operations

```python
order.cancel()
order.revoke(reason="keyCompromise")
order.reissue("rekey", csr=new_csr_pem)
```

---

## Examples

### DNS-TXT DCV automation

[`examples/dns_txt_dcv.py`](examples/dns_txt_dcv.py) is a ready-to-adapt script that automates the full DNS-TXT DCV pipeline: publishing the challenge token, waiting for DNS propagation, and triggering `domain.verify()` once the token is visible everywhere.

It contains two stub functions you implement for your DNS provider:

| Function | Purpose |
|---|---|
| `set_dns_txt_record(fqdn, value, dry_run)` | Publish the TXT record via your DNS provider API |
| `has_dns_txt_record(fqdn, value, nameserver)` | Check whether a nameserver returns the expected TXT value |

Each stub raises `NotImplementedError` until implemented and includes inline examples using **dnspython** (nsupdate/TSIG) and **AWS Route 53** (boto3).

<details>
<summary>Usage</summary>

```bash
export CERTINEXT_CLIENT_ID="your-account-number"
export CERTINEXT_CLIENT_SECRET="your-client-secret"

# Process all pending domains
python examples/dns_txt_dcv.py

# Preview without making changes
python examples/dns_txt_dcv.py --dry-run

# Limit to a specific domain or pattern
python examples/dns_txt_dcv.py example.com
python examples/dns_txt_dcv.py --pattern r".*\.example\.com"

# Configure nameserver propagation checks
python examples/dns_txt_dcv.py \
  --auth-nameservers ns1.example.com,ns2.example.com \
  --public-nameservers 8.8.8.8,1.1.1.1
```

Run the script repeatedly — each run advances every pending domain as far as it can go and exits cleanly when waiting for propagation. Once a domain is fully propagated, the script calls `domain.verify()` automatically.

</details>

---

## API documentation

The CertiNext REST API is documented in two places:

| Resource | URL | Notes |
|---|---|---|
| Swagger UI (sandbox) | [sandbox-us-api.certinext.io/swagger-ui/index.html](https://sandbox-us-api.certinext.io/swagger-ui/index.html) | Interactive; select **certinext-v2** from the spec dropdown |
| OpenAPI spec (sandbox) | [sandbox-us-api.certinext.io/v3/api-docs/certinext-v2](https://sandbox-us-api.certinext.io/v3/api-docs/certinext-v2) | Raw JSON — complete schema including undocumented fields |
| Postman collection | [documenter.getpostman.com/…](https://documenter.getpostman.com/view/40123569/2sBXqJJLFh) | Official docs; less complete than the Swagger spec |

Replace `sandbox-us-api.certinext.io` with `us-api.certinext.io` for the production equivalents.

The Swagger spec is the most authoritative source — it exposes fields not present in the Postman collection (e.g. `preVettingToken`, `csr` in the initial order body, `delegation`, `recipientEmails`, `tags`).

---

## Project structure

<details>
<summary>File tree</summary>

```
certinext/
    __init__.py                   # session() factory, top-level exports, URL constants
    _cli.py                       # shared CLI utilities (add_connection_args, add_requestor_args, fatal_api_error, build_session)
    _keyring.py                   # shared keyring helpers (keyring_service, keyring_get)
    accounts.py                   # AccountInfo, Group, Organization, AccountAccessor
    accounts_cli.py               # certinext-accounts CLI entry point
    auth.py                       # OAuth 2.0 client credentials token management
    catalog.py                    # Product, ProductCategory, CustomField, CatalogAccessor
    client.py                     # HTTP session wrapper (get/post/put/delete/get_bytes)
    csr.py                        # parse_csr() — extract CN and SANs from a PEM CSR (requires certinext[csr])
    domain_cert_count_cli.py      # certinext-domain-cert-count CLI entry point
    domains.py                    # Domain class and DomainAccessor
    domains_cli.py                # certinext-domains CLI entry point
    exceptions.py                 # CertiNextAPIError
    issue_certificate_cli.py      # certinext-issue-cert CLI entry point
    ledger.py                     # LedgerRecord and LedgerAccessor
    ledger_cli.py                 # certinext-ledger CLI entry point
    list_certificates_cli.py      # certinext-list-certificates CLI entry point
    orders.py                     # OrderRecord and OrderAccessor
    pending_dcv_cli.py            # certinext-pending-dcv CLI entry point
    session.py                    # CertiNextSession (accounts, catalog, domain, ledger, orders, ssl)
    setup_keyring_cli.py          # certinext-setup-keyring CLI entry point
    ssl_certificates.py           # SslOrder, DcvChallenge, CertificateDownload, SslAccessor, OrderWorkflow
                                  #   SslAccessor.create() — DV/OV/EV dispatcher
                                  #   CertificateDownload.as_pem_chain() — leaf-first fullchain
                                  #   OrderWorkflow.download_chain() — 422-retry + normalised chain
                                  #   OrderWorkflow.from_order_id() — resume from persisted order ID
tests/
    test_integration.py           # integration tests against the sandbox API (pytest -m integration)
examples/
    dns_txt_dcv.py                # DNS-TXT DCV automation example (see Examples above)
```

</details>
