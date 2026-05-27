# certinext

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Python library and CLI scripts for managing your [CertiNext](https://us.certinext.io) environment via the REST API.

> **Work in progress:** `list`, `get`, `get_dcv`, `verify`, and `change_dcv_method` have been tested against the live API. `create`, `deactivate`, `last_dcv_attempt`, and `dcv_attempt_history` are implemented based on the API documentation but remain untested against the live API.

## Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Credentials](#credentials)
- [CLI commands](#cli-commands)
  - [certinext-setup-keyring](#certinext-setup-keyring)
  - [certinext-domains](#certinext-domains)
  - [certinext-pending-dcv](#certinext-pending-dcv)
  - [certinext-domain-cert-count](#certinext-domain-cert-count)
- [Python library](#python-library)
- [Examples](#examples)
- [Project structure](#project-structure)

## Requirements

- Python 3.10+
- A CertiNext account with OAuth API credentials (account number + client secret)

## Installation

### From the package registry

```bash
pip install certinext \
  --extra-index-url https://gitlab.its.maine.edu/api/v4/groups/2236/-/packages/pypi/simple
```

Or with `uv`:

```bash
uv add certinext --index https://gitlab.its.maine.edu/api/v4/groups/2236/-/packages/pypi/simple
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
certinext-domains --sandbox list
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
    base_url="https://us-api.certinext.io",
    token_url="https://us-api.certinext.io/oauth/token",
    client_id="YOUR_ACCOUNT_NUMBER",
    client_secret="YOUR_CLIENT_SECRET",
    scope="",                              # optional
)
```

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

`list_pending_dcv()` returns active domains that have not yet completed DCV
verification. It fetches all domains and filters client-side using
`domain.needs_dcv`.

> **Note:** The API `domainStatus` and `dcvStatus` filter parameters return a
> 400 error when used together — confirmed vendor bug (reported 2026-05-20).
> Server-side status filtering is disabled until CertiNext notifies the fix is
> deployed.

```python
pending = sess.domain.list_pending_dcv()

# Narrow to a subset by name
pending = sess.domain.list_pending_dcv(pattern=r".*\.maine\.edu")
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
# list_pending_dcv() fetches all domains and filters client-side for needs_dcv.
for domain in sess.domain.list_pending_dcv():
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

## Project structure

<details>
<summary>File tree</summary>

```
certinext/
    __init__.py               # session() factory, top-level exports, URL constants
    _cli.py                   # shared CLI utilities (add_connection_args, build_session)
    _keyring.py               # shared keyring helpers (keyring_service, keyring_get)
    auth.py                   # OAuth 2.0 client credentials token management
    client.py                 # HTTP session wrapper (get/post/put/delete)
    domain_cert_count.py      # certinext-domain-cert-count CLI entry point
    domains.py                # Domain class and DomainAccessor
    domains_cli.py            # certinext-domains CLI entry point
    orders.py                 # OrderRecord and OrderAccessor
    pending_dcv.py            # certinext-pending-dcv CLI entry point
    session.py                # CertiNextSession (session.domain, session.orders)
    setup_keyring.py          # certinext-setup-keyring CLI entry point
tests/
    test_integration.py       # integration tests against the sandbox API (pytest -m integration)
examples/
    dns_txt_dcv.py            # DNS-TXT DCV automation example (see Examples above)
```

</details>
