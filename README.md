# certinext

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Python library and CLI scripts for managing your [CertiNext](https://us.certinext.io) environment via the REST API.

> **Work in progress:** Only the `list` and `get` domain operations have been tested against the live API so far. All other operations (create, deactivate, DCV methods) are implemented based on the API documentation but remain untested.

## Requirements

- Python 3.10+
- A CertiNext account with OAuth API credentials (account number + client secret)

## Installation

Install the package in editable mode inside a virtual environment:

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # macOS / Linux

pip install -e .
```

This installs the `certinext` package and its dependencies (`requests`, `tabulate`, `python-dotenv`).

## Credentials

You need two values from the CertiNext portal (Integrations → APIs → OAuth mode):

| Argument | Description |
|---|---|
| `--account-number` | Your CertiNext account number (used as the OAuth `client_id`) |
| `--client-secret` | The OAuth access key generated in the portal |

The token endpoint defaults to `https://us-api.certinext.io/oauth/token`. Override with `--token-url` if yours differs.

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

All parameters and their defaults:

```python
sess = certinext.session(
    base_url="https://us-api.certinext.io",
    token_url="https://us-api.certinext.io/oauth/token",
    client_id="YOUR_ACCOUNT_NUMBER",
    client_secret="YOUR_CLIENT_SECRET",
    scope="",                              # optional
)
```

The session obtains and caches an OAuth 2.0 bearer token automatically, refreshing it before it expires.

### Working with domains

#### List all domains

```python
domains = sess.domain.list()
for d in domains:
    print(d)
```

Paginate with `offset` and `limit`:

```python
page = sess.domain.list(offset=50, limit=25)
```

Filter by status server-side (reduces data transferred):

```python
# Only active domains with pending or rejected DCV
domains = sess.domain.list(domain_status="ACTIVE", dcv_status="PENDING,REJECTED,EXPIRED")
```

> **Note:** The API also accepts a `search` parameter intended for full-FQDN or
> substring matching. As of 2026-05-20 it does not appear to filter results
> server-side — all domains are returned regardless. Use `pattern` (below) for
> reliable filtering until this is resolved.

Filter by name with a regex (applied client-side after the API response):

```python
# Exact match
domains = sess.domain.list(pattern=r"maine\.edu")

# Multiple names via alternation
domains = sess.domain.list(pattern=r"maine\.edu|umaine\.edu")

# Subdomain wildcard
domains = sess.domain.list(pattern=r".*\.maine\.edu")
```

`pattern` uses `re.fullmatch` with `re.IGNORECASE`, so it must match the entire
domain name. Combine with status filters to narrow the API response first:

```python
domains = sess.domain.list(domain_status="ACTIVE", pattern=r".*\.maine\.edu")
```

#### List domains needing DCV

`list_pending_dcv()` returns active domains that have not yet completed DCV
verification. It applies server-side status filters automatically and is
equivalent to `list()` filtered by `domain.needs_dcv`.

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

#### Domain properties

| Property | Type | Description |
|---|---|---|
| `id` | `str \| None` | Domain ID |
| `name` | `str \| None` | Domain name (FQDN) |
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

result = domain.verify()           # trigger verification
domain.change_dcv_method("DNS-TXT")   # accepted values: "DNS-TXT", "HTTP-URL"
attempt = domain.last_dcv_attempt()
history = domain.dcv_attempt_history()

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

# list_pending_dcv() uses server-side filters to fetch only ACTIVE domains
# with non-VERIFIED DCV status, then returns those where needs_dcv is True.
for domain in sess.domain.list_pending_dcv():
    print(f"Verifying {domain.name} ...")
    domain.verify()
```

Or check `needs_dcv` manually if you already have a full domain list:

```python
for domain in sess.domain.list():
    if domain.needs_dcv:
        print(f"Verifying {domain.name} ...")
        domain.verify()
```

---

## domains script

`scripts/domains.py` is a command-line interface for the domains API.

### Common arguments

These appear before the subcommand and are required on every call:

```
--account-number ACCT   CertiNext account number (also accepted as --client-id)
--client-secret SECRET  OAuth2 client secret
--base-url URL          API base URL (default: https://us-api.certinext.io)
--token-url URL         Token endpoint URL (default: https://us-api.certinext.io/oauth/token)
--scope SCOPE           OAuth2 scope (optional)
--json                  Output raw JSON instead of tabular format
```

### Subcommands

#### list

List all domains.

```bash
python scripts/domains.py --account-number ACCT --client-secret SECRET list
python scripts/domains.py --account-number ACCT --client-secret SECRET list --offset 50 --limit 25
```

#### get

Get a single domain by name or ID.

```bash
python scripts/domains.py --account-number ACCT --client-secret SECRET get maine.edu
python scripts/domains.py --account-number ACCT --client-secret SECRET get vuxwZgEXWWFXQQWC-...
```

#### create

Create a new domain. Additional API fields can be passed as `KEY=VALUE` pairs.

```bash
python scripts/domains.py --account-number ACCT --client-secret SECRET create newdomain.example.com
```

#### deactivate

Deactivate a domain by ID. Prompts for confirmation unless `-y` is passed.

```bash
python scripts/domains.py --account-number ACCT --client-secret SECRET deactivate DOMAIN_ID
python scripts/domains.py --account-number ACCT --client-secret SECRET deactivate DOMAIN_ID -y
```

#### get-dcv

Show current DCV status for a domain.

```bash
python scripts/domains.py --account-number ACCT --client-secret SECRET get-dcv DOMAIN_ID
```

#### verify-dcv

Trigger DCV verification for a domain.

```bash
python scripts/domains.py --account-number ACCT --client-secret SECRET verify-dcv DOMAIN_ID
```

#### change-dcv-method

Change the DCV method for a domain (`EMAIL`, `DNS`, or `HTTP`).

```bash
python scripts/domains.py --account-number ACCT --client-secret SECRET change-dcv-method DOMAIN_ID DNS
```

#### last-dcv-attempt

Show the most recent DCV attempt for a domain.

```bash
python scripts/domains.py --account-number ACCT --client-secret SECRET last-dcv-attempt DOMAIN_ID
```

#### dcv-attempt-history

Show the full DCV attempt history for a domain.

```bash
python scripts/domains.py --account-number ACCT --client-secret SECRET dcv-attempt-history DOMAIN_ID
```

### JSON output

Add `--json` before the subcommand to get raw JSON instead of the default tabular output. Useful for piping into `jq`:

```bash
python scripts/domains.py --account-number ACCT --client-secret SECRET --json list | jq '.[] | .domainName'
```

---

## Project structure

```
certinext/
    __init__.py      # session() factory, top-level exports
    auth.py          # OAuth 2.0 client credentials token management
    client.py        # HTTP session wrapper (get/post/put/delete)
    domains.py       # Domain class and DomainAccessor
    session.py       # CertiNextSession (session.domain accessor)
scripts/
    domains.py       # CLI for domain management
```
