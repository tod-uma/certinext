# certinext

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Python library and CLI scripts for managing your [CertiNext](https://us.certinext.io) environment via the REST API.

## Contents

- [Requirements](#requirements)
- [AI-agent quickstart](#ai-agent-quickstart)
- [Installation](#installation)
- [Credentials](#credentials)
  - [Storing credentials in the OS keychain](#storing-credentials-in-the-os-keychain-recommended)
  - [Prevetting token](#prevetting-token-optional-ovev-orders)
  - [Storing issue-cert defaults](#storing-issue-cert-defaults-optional)
  - [Sandbox environment](#sandbox-environment)
  - [Integration tests](#integration-tests)
- [Using the CLI tools](#using-the-cli-tools)
  - [Old command names (aliases)](#old-command-names-aliases)
  - [Shell completion](#shell-completion)
  - [certinext setup keyring](#certinext-setup-keyring)
  - [certinext setup defaults](#certinext-setup-defaults)
  - [certinext accounts](#certinext-accounts)
  - [certinext domains](#certinext-domains)
  - [certinext ledger](#certinext-ledger)
  - [certinext list-certificates](#certinext-list-certificates)
  - [certinext pending-dcv](#certinext-pending-dcv)
  - [certinext domain-cert-count](#certinext-domain-cert-count)
  - [certinext issue-cert](#certinext-issue-cert)
  - [certinext parent-dcv-status](#certinext-parent-dcv-status)
  - [certinext healthcheck](#certinext-healthcheck)
- [Log output](#log-output)
- [Python library](#python-library)
  - [Working with domains](#working-with-domains)
  - [Working with orders](#working-with-orders)
  - [Working with accounts](#working-with-accounts)
  - [Working with the catalog](#working-with-the-catalog)
  - [Working with the ledger](#working-with-the-ledger)
  - [Working with SSL/TLS certificates](#working-with-ssltls-certificates)
  - [Error handling](#error-handling)
- [Examples](#examples)
- [API documentation](#api-documentation)
- [Project structure](#project-structure)
- [Migrating from 0.3.x to 1.0](docs/migrating-to-1.0.md)

## Requirements

- Python 3.10+ (installed automatically when using uv — see [Installation](#installation))
- A CertiNext account with OAuth API credentials (account number + client secret)

**Runtime dependencies** (`httpx`, `pydantic`, `pydantic-settings`, `tomlkit`, `typer`, `rich`, `structlog`) are installed automatically. `structlog` provides structured logging for the CLI tools and library internals — in cron or redirected contexts all output is emitted as JSON; in a terminal it uses a human-readable format. If you use certinext purely as a library and have a strong reason to exclude `structlog`, open an issue and we'll consider making it optional.

## AI-agent quickstart

The short version, for an agent wiring up certinext without reading the
whole README:

```bash
uv tool install "certinext[csr,keyring]"   # CLI
uv add certinext                            # or, as a library dependency
```

```python
import certinext

sess = certinext.session(client_id="ACCOUNT_NUMBER", client_secret="CLIENT_SECRET")
domain = sess.domain.get("example.com")
```

- **Run `certinext healthcheck` (or `--sandbox`) first**, before assuming any
  endpoint works for a given account — it's read-only, safe against
  production, and tells you in one shot what's reachable and what's returning
  vendor errors right now. See [certinext healthcheck](#certinext-healthcheck).
- **All API errors are `CertiNextAPIError`** (`.status_code`, `.body`); network
  failures are `httpx.HTTPError`. See [Error handling](#error-handling).
- **Known vendor API quirks** (broken filters, pagination gotchas, chain
  ordering) are documented inline next to the affected calls — search this
  README for "Note:" — and tracked as GitLab issues; see the in-repo
  `.claude/skills/certinext-api-bugs/SKILL.md` for the current list if you
  have repo access.
- **Migrating code written against 0.3.x?** See
  [Migrating from 0.3.x to 1.0](docs/migrating-to-1.0.md) — it's short; almost
  nothing changed except one exception base class and one internal import path.
- Full operational facts (config file, keyring, CI, release process) also
  live in [AGENTS.md](AGENTS.md); a machine-readable index of this README's
  sections is in [llms.txt](llms.txt).

## Installation

Instructions below default to [uv](https://docs.astral.sh/uv/)
([Install uv](#install-uv) if you don't have it yet).
You don't need Python installed first — uv downloads and manages Python for you.

To install the `certinext` CLI (issuing certificates, listing
domains, etc.):

```bash
uv tool install "certinext[csr,keyring]"
```

That's the whole install — the command now works from any terminal. (If a
command isn't found, run `uv tool update-shell` and open a new terminal.)
The two extras are recommended for CLI use: `csr` enables CSR parsing for
`certinext issue-cert`, and `keyring` lets the commands store and read
credentials in the OS keychain.

Everything else — installing uv itself, library use, pre-releases, the UMS
GitLab registry, development installs, and pip/pipx equivalents — is in the
collapsible sections below.

<a id="install-uv"></a>
<details>
<summary>Install uv (one-time, Windows / macOS / Linux)</summary>

**Windows** (PowerShell):

```powershell
winget install --id=astral-sh.uv -e
```

**macOS / Linux**:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

(On macOS, `brew install uv` also works.)

Then open a **new** terminal so `uv` is on your PATH. The first time a
command needs Python, uv downloads a suitable version automatically.

</details>

<details>
<summary>All uv install variants (library use, pre-releases, UMS GitLab registry, development)</summary>

**Library in your project** — if you want `import certinext` in your own
code, add it as a dependency of your uv-managed project:

```bash
uv add certinext
```

Add extras only if your code uses them: `certinext[csr]` (CSR parsing),
`certinext[keyring]` (OS keychain credential lookup), `certinext[dns]`
(DNS lookups).

**Pre-releases** — to get the latest alpha, beta, or release candidate:

```bash
uv tool install --prerelease=allow "certinext[csr,keyring]"   # CLI tools
uv add certinext --prerelease=allow                           # library
```

**From the UMS GitLab package registry** — releases are also published to
the UMS GitLab package registry:

```bash
uv tool install certinext \
  --extra-index-url https://gitlab.its.maine.edu/api/v4/groups/2236/-/packages/pypi/simple
```

**Development install** — clone the repository, then create a venv and
install in editable mode with the `dev` extra (test and lint toolchain plus
all runtime extras):

```bash
uv venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # macOS / Linux

uv pip install -e ".[dev]"
```

</details>

<details>
<summary>Using pip or pipx instead of uv</summary>

All of the above with pip or pipx (both require Python 3.10+ already
installed).

**CLI tools** — with [pipx](https://pipx.pypa.io/) (isolated install, like
`uv tool`):

```bash
pipx install "certinext[csr,keyring]"
pipx install --pip-args=--pre "certinext[csr,keyring]"   # pre-release
```

Or with plain pip (installs into the active Python environment, not
isolated):

```bash
pip install "certinext[csr,keyring]"
pip install --pre "certinext[csr,keyring]"               # pre-release
```

**Library in your project**:

```bash
pip install certinext
pip install --pre certinext        # pre-release
```

**Optional extras** — add any of `csr`, `keyring`, or `dns` after the fact,
e.g. the `keyring` extra needed by `certinext setup keyring`:

```bash
pip install "certinext[keyring]"
```

**From the UMS GitLab package registry**:

```bash
pip install certinext \
  --extra-index-url https://gitlab.its.maine.edu/api/v4/groups/2236/-/packages/pypi/simple
```

**Development install**:

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # macOS / Linux

pip install -e ".[dev]"
```

</details>

## Credentials

The CLI tools and Python library both talk to the CertiNext **REST API**,
so you need REST API (OAuth) credentials — your portal username and
password won't work. Generate the two required values in the CertiNext
portal under **Integrations → APIs → OAuth mode**:

| Value | Description |
|---|---|
| Account number | Your CertiNext account number (used as the OAuth `client_id`) |
| Client secret | The OAuth access key generated in the portal |
| Prevetting token | Optional, for auto-approving OV/EV orders — see [Prevetting token](#prevetting-token-optional-ovev-orders) |

The token endpoint defaults to `https://us-api.certinext.io/oauth/token`. Override with `--token-url` if yours differs.

### Storing credentials in the OS keychain (recommended)

Run the setup command once to store your credentials securely in the system
keychain (Windows Credential Manager on Windows, Keychain on macOS,
libsecret/SecretService on Linux):

```bash
certinext setup keyring
```

This needs the `keyring` extra. It's included in the recommended
`uv tool install "certinext[csr,keyring]"` from
[Installation](#installation); pip users can add it with
`pip install "certinext[keyring]"`.

Scripts read credentials from the keychain automatically — no CLI flags or
environment variables needed for day-to-day use.

<details>
<summary>Named profiles and credential resolution order</summary>

#### Named profiles

Use `--profile NAME` to store multiple credential sets (e.g. different
accounts or environments):

```bash
certinext setup keyring --profile prod
```

Select a profile at runtime with `--profile` or the `CERTINEXT_PROFILE`
environment variable:

```bash
certinext domains --profile prod list
CERTINEXT_PROFILE=prod certinext pending-dcv
```

#### Credential resolution order

All scripts resolve credentials in this priority order:

1. Explicit CLI argument (`--account-number`, `--client-secret`)
2. OS keychain (active profile; see above)
3. Environment variables (`CERTINEXT_CLIENT_ID`, `CERTINEXT_CLIENT_SECRET`)
4. Interactive prompt (falls back to `getpass` for secrets)

</details>

<details>
<summary>WSL and headless Linux (no keyring backend)</summary>

#### WSL and headless Linux

On Linux, `keyring` needs a running Secret Service daemon (gnome-keyring or
KWallet). WSL and headless servers usually have none, so `certinext setup keyring`
reports that no usable OS keyring backend was found. Options:

- **Skip the keyring.** All scripts fall back to the `CERTINEXT_CLIENT_ID` and
  `CERTINEXT_CLIENT_SECRET` environment variables (see the resolution order
  above).

- **WSL: bridge to the Windows Credential Manager** with
  [keyring-pybridge](https://pypi.org/project/keyring-pybridge/), which
  forwards keyring calls to a Python interpreter on the Windows host.
  Credentials are then shared between Windows and WSL.

  ```bash
  # Prerequisite: a Windows-side Python with the keyring package installed
  pip install keyring-pybridge
  export PYTHON_KEYRING_BACKEND=keyring_pybridge.PyBridgeKeyring
  export KEYRING_PROPERTY_PYTHON='C:\path\to\python.exe'
  certinext setup keyring
  ```

  Add the two `export` lines to your shell profile so every session uses the
  bridge.

- **Headless Linux: start a Secret Service daemon** such as gnome-keyring.

</details>

### Prevetting token (optional, OV/EV orders)

OV and EV certificate orders normally pause at a manual approval step at
the CA before issuance. If your organization has consent configured, an
**Organization Consent Token** (prevetting token) lets the CA auto-approve
the order — useful when you want `certinext issue-cert` to run end-to-end
without a human approving each order.

Find it in the CertiNext portal under **Organization Management →
Organization Consent / Consent Tokens** for the target organization.

**Recommended: store in the keyring once** (prompted by `certinext setup keyring`):

```bash
certinext setup keyring   # prompts for client ID, secret, and prevetting token
```

`certinext issue-cert` then resolves the token automatically from the keyring
(or the `CERTINEXT_PREVETTING_TOKEN` environment variable) — no flag needed per run.

To pass it explicitly for a single run:

```bash
certinext issue-cert example.com.csr --type ov --org-id 8921215 \
  --prevetting-token TOKEN
```

The token is never written to the config file by `--save-defaults` or
`certinext setup defaults` — use the keyring or env var for persistent storage.

### Storing issue-cert defaults (optional)

Store the values `certinext issue-cert` needs on every run — requestor
identity, certificate type, org ID, validity — so that issuing a certificate
is just:

```bash
certinext issue-cert new.csr
```

Run the interactive setup once:

```bash
certinext setup defaults
```

Or pass `--save-defaults` on any `certinext issue-cert` run to capture the
values you used. Or hand-edit the config file
(`~/.config/certinext/config.toml` on Linux/macOS,
`%APPDATA%\certinext\config.toml` on Windows, override with
`CERTINEXT_CONFIG`):

```toml
[defaults]
requestor_name  = "Jane Doe"       # required — cannot be read from a CSR
requestor_email = "jane@maine.edu" # optional if your CSR includes an emailAddress field
requestor_phone = "+12075551234"   # required — cannot be read from a CSR (E.164 format)
# requestor_designation = "Sys Admin"  # optional
signer_place    = "Orono, ME"      # optional if your CSR includes L and/or ST fields
type            = "ov"             # required (dv / ov / ev)
org_id          = "12345"         # required for OV and EV; omit for DV
validity        = 1                # optional; defaults to 1 year
# product       = "974"            # optional product code; omit to let the API pick

[profiles.sandbox]
# overrides applied when --sandbox / --profile sandbox is active
type    = "dv"
sandbox = true                         # target the sandbox API by default

[profiles.staging]
# point a profile at any endpoint (token_url defaults to <base_url>/oauth/token)
base_url  = "https://staging-api.certinext.io"
token_url = "https://staging-api.certinext.io/oauth/token"
```

The primary domain and SANs are read directly from the CSR and are not stored
here. `requestor_email` and `signer_place` are also read from the CSR when
present (the `emailAddress`, `L`, and `ST` subject fields), so you only need
to set them here if your CSRs don't include those fields.

A profile can also record **which endpoint it targets** so you don't have to
pass `--sandbox` (or `--base-url`) on every run:

- `sandbox = true` — the profile defaults to the sandbox endpoints.
- `base_url` / `token_url` — the profile defaults to an explicit endpoint.

With a stored endpoint, plain `certinext domains --profile sandbox` (or
`CERTINEXT_PROFILE=sandbox`) hits the sandbox API directly. A command-line
`--sandbox` or `--base-url` still overrides the stored value for that run.
Set these with `certinext setup defaults` (see below) or by hand-editing.

CERTInext runs several regions. Non-US customers can point a profile at theirs —
for example India production:

```toml
[profiles.india]
base_url  = "https://api.certinext.io"
token_url = "https://api.certinext.io/oauth/token"
```

The known endpoints (`certinext.KNOWN_API_ENDPOINTS`, from the OpenAPI `servers`
list) are: US production `https://us-api.certinext.io`, US sandbox
`https://sandbox-us-api.certinext.io`, India production `https://api.certinext.io`,
plus `qa-api` and `demo-api`. `certinext setup defaults` offers these as a menu.

Values resolve in priority order: explicit CLI argument → environment
variable → `[profiles.NAME]` → `[defaults]` → built-in default. Secrets
(client secret, prevetting token) are never stored here — use
`certinext setup keyring` for credentials.

### Sandbox environment

A sandbox environment is available at `https://sandbox-us-api.certinext.io` for
testing API calls without affecting production data.  Store sandbox credentials
once with:

```bash
certinext setup keyring --sandbox
```

Then pass `--sandbox` to any CLI command to target the sandbox:

```bash
certinext accounts --sandbox
certinext domains --sandbox list
certinext ledger --sandbox
certinext list-certificates --sandbox
certinext pending-dcv --sandbox
certinext domain-cert-count --sandbox
```

`--sandbox` is a shortcut that sets `--base-url` and `--token-url` to the
sandbox endpoints and defaults `--profile` to `sandbox`.

To avoid passing `--sandbox` every time, record it on a profile so the profile
targets the sandbox by default:

```bash
certinext setup defaults --profile srv-acct --sandbox   # stores sandbox = true
certinext domains --profile srv-acct list               # hits the sandbox API
```

See [Storing issue-cert defaults](#storing-issue-cert-defaults-optional) for
the per-profile `sandbox` / `base_url` settings.

### Integration tests

The test suite includes integration tests that call the live sandbox API.
They are skipped automatically when credentials are not available, so they
are safe to include in CI environments that lack a keyring.

**Local development** — store credentials in the keyring once:

```bash
certinext setup keyring --sandbox
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

## Using the CLI tools

The complete copy-paste path from nothing to an issued certificate
([Installation](#installation) covers the install command and uv itself;
[Credentials](#credentials) covers where the two credential values come
from):

```bash
uv tool install "certinext[csr,keyring]"
certinext setup keyring      # store API credentials in the OS keychain (once)
certinext setup defaults     # store requestor/cert defaults (once, optional)
certinext issue-cert example.com.csr --cert-out cert.pem --fullchain-out fullchain.pem
```

Everything is one `certinext` application with subcommands; run
`certinext --help` for the full tree. Each subcommand is documented below.

### Old command names (aliases)

Before 1.0 each operation was a separate `certinext-*` script. Those names
still work — each one is an alias that pre-selects its subcommand, with
identical flags, output, and exit codes — and they stay installed until at
least 2.0. New scripts and documentation should use the subcommand form.

| Old script | New subcommand |
| --- | --- |
| `certinext-setup-keyring` | `certinext setup keyring` |
| `certinext-setup-defaults` | `certinext setup defaults` |
| `certinext-accounts` | `certinext accounts` |
| `certinext-domains` | `certinext domains` |
| `certinext-ledger` | `certinext ledger` |
| `certinext-list-certificates` | `certinext list-certificates` |
| `certinext-pending-dcv` | `certinext pending-dcv` |
| `certinext-domain-cert-count` | `certinext domain-cert-count` |
| `certinext-issue-cert` | `certinext issue-cert` |
| `certinext-parent-dcv-status` | `certinext parent-dcv-status` |
| `certinext-healthcheck` | `certinext healthcheck` |

### Shell completion

The app can install tab completion for bash, zsh, fish, and PowerShell:

```bash
certinext --install-completion   # then open a new terminal
```

Completion covers subcommand names, flags, and enum values (e.g.
`--type dv|ov|ev`).

### certinext setup keyring

`certinext setup keyring` stores CertiNext API credentials in the OS keychain
interactively. Run it once before using the other commands.

```bash
# Store credentials for the default profile
certinext setup keyring

# Store credentials for a named profile
certinext setup keyring --profile prod

# Store credentials for the sandbox environment
certinext setup keyring --sandbox
```

The script prompts for your account number, client secret, and (optionally)
your Organization Consent Token (prevetting token for OV/EV orders). It shows
any currently stored value as a default so you can keep it by pressing Enter,
and masks secrets with asterisks on confirmation.

This command stores **only credentials, not a URL** — `--sandbox` here is just
a shortcut for `--profile sandbox`. If you pass both `--sandbox` and an explicit
`--profile NAME`, the `--sandbox` flag is ignored (the profile wins) and the
script warns you. To make a profile *use* the sandbox endpoint, set that on the
profile with `certinext setup defaults --profile NAME --sandbox`.

### certinext setup defaults

`certinext setup defaults` interactively stores defaults for
`certinext issue-cert` in the config file, so future issuance runs only need
the CSR.

If API credentials are not yet stored, the script offers to run
`certinext setup keyring` first — credentials are needed for the org picker
described below.

**API endpoint first.** The script begins by asking which endpoint this profile
should target, because the organization lookup below talks to that environment.
It shows a numbered menu of the known CERTInext endpoints plus a custom-URL
option:

```text
Which CERTInext API endpoint should this profile use?
  1. Production - US (default)  https://us-api.certinext.io  [current]
  2. Sandbox - US               https://sandbox-us-api.certinext.io
  3. Production - India         https://api.certinext.io
  4. QA                         https://qa-api.certinext.io
  5. Demo                       https://demo-api.certinext.io
  6. Custom URL…
```

The choice is stored on the profile (`sandbox = true` for the US sandbox, or
`base_url` / `token_url` for a region or custom host, with the token URL derived
as `<base_url>/oauth/token`), so later runs don't need `--sandbox` or
`--base-url`. Passing `--sandbox` or `--base-url` on the command line persists
that choice directly and skips the menu. The endpoint list comes from
`certinext.KNOWN_API_ENDPOINTS`.

**Then the certificate defaults.** It asks for certificate type (DV / OV / EV),
then prompts for each field, labelling it **[required]** or **[optional]** based
on the type you chose. Fields the tool can already read from a CSR
(`requestor_email`, `signer_place`) are labelled optional with a note — you only
need to set them here if your CSRs don't include the corresponding subject
fields (`emailAddress`, `L`, `ST`). The domain and SANs are never prompted —
they always come from the CSR.

If credentials are available, it then offers a **product** menu fetched from the
Catalog API, filtered to the type you chose and sorted with wildcard products
last. Pick one to store as the profile's default product code (sent as
`X-Product-Code` at issue time), or choose *API default* to let the server pick.
`certinext issue-cert --product CODE` overrides the stored default per run.

For OV and EV orders, if API credentials are available the script fetches your
organizations and presents them as a numbered menu filtered to pre-vetted orgs,
showing validation scope and status for each (e.g.
`#2517111, Orono, ME, OV, Validated`). A hint links to the portal
(us.certinext.io or sandbox-us.certinext.io) where the default org is marked
with a **D** badge. Falls back to free-text entry when credentials are
unavailable. The organization is asked **before** the signer place, so when you
pick one its location (`City, ST`) is offered as the signer-place default.

See [Storing issue-cert defaults](#storing-issue-cert-defaults-optional) for
the file format and resolution order.

```bash
# Edit the [defaults] section
certinext setup defaults

# Edit a profile section ([profiles.prod])
certinext setup defaults --profile prod

# Edit the sandbox profile (and store sandbox = true on it)
certinext setup defaults --sandbox

# Make a named profile target the sandbox endpoint by default
certinext setup defaults --profile srv-acct --sandbox
```

Each prompt shows the currently stored value — press Enter to keep it, or
enter `-` to clear it.

### certinext accounts

`certinext accounts` shows the current account identity, billing groups, and
pre-vetted organizations.

```bash
certinext accounts
certinext accounts --sandbox
certinext accounts --json
```

| Argument | Description |
|---|---|
| `--json` | Output raw JSON instead of tabular format |

---

### certinext domains

`certinext domains` is a command-line interface for the domains API.

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
certinext domains list
certinext domains list --offset 50 --limit 25

# credentials explicit
certinext domains --account-number ACCT --client-secret SECRET list
```

#### get

Get a single domain by name or ID.

```bash
certinext domains get maine.edu
certinext domains get vuxwZgEXWWFXQQWC-...
```

#### create

Create a new domain. Additional API fields can be passed as `KEY=VALUE` pairs.

```bash
certinext domains create newdomain.example.com
```

#### deactivate

Deactivate a domain by ID. Prompts for confirmation unless `-y` is passed.

```bash
certinext domains deactivate DOMAIN_ID
certinext domains deactivate DOMAIN_ID -y
```

#### get-dcv

Show current DCV status for a domain.

```bash
certinext domains get-dcv DOMAIN_ID
```

#### verify-dcv

Trigger DCV verification for a domain.

```bash
certinext domains verify-dcv DOMAIN_ID
```

#### change-dcv-method

Change the DCV method for a domain. Accepted values: `DNS-TXT`, `HTTP-URL`.

```bash
certinext domains change-dcv-method DOMAIN_ID DNS-TXT
```

#### last-dcv-attempt

Show the most recent DCV attempt for a domain.

```bash
certinext domains last-dcv-attempt DOMAIN_ID
```

#### dcv-attempt-history

Show the full DCV attempt history for a domain.

```bash
certinext domains dcv-attempt-history DOMAIN_ID
```

</details>

#### JSON output

Add `--json` before the subcommand to get raw JSON instead of the default tabular output. Useful for piping into `jq`:

```bash
certinext domains --json list | jq '.[] | .domainName'
```

### certinext ledger

`certinext ledger` shows the account transaction history (all debits, credits,
and running balance) with automatic pagination.

#### Arguments

```
--last N   Show only the N most recent transactions
--json     Output raw JSON instead of tabular format
```

#### Examples

```bash
certinext ledger
certinext ledger --last 20
certinext ledger --sandbox --json
```

---

### certinext list-certificates

`certinext list-certificates` lists all SSL/TLS certificate orders from the
orders report. Use `--status` to filter by lifecycle status.

#### Arguments

```
--status STATUS   Filter by certificate status (issued, expired, pending-dcv, etc.)
--json            Output raw JSON instead of tabular format
```

#### Examples

```bash
certinext list-certificates
certinext list-certificates --status issued
certinext list-certificates --status expired
certinext list-certificates --status pending-dcv
certinext list-certificates --sandbox --json
```

---

### certinext pending-dcv

`certinext pending-dcv` lists every active domain that has not yet completed
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
certinext pending-dcv

# Use a named profile
certinext pending-dcv --profile prod

# Filter to a specific subdomain pattern
certinext pending-dcv --pattern ".*\.maine\.edu"

# Raw JSON output for scripting
certinext pending-dcv --json | jq '.[] | .domainName'

# Credentials from environment variables
CERTINEXT_CLIENT_ID=ACCT CERTINEXT_CLIENT_SECRET=SECRET certinext pending-dcv
```

### certinext domain-cert-count

`certinext domain-cert-count` shows all registered domains and how many
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
certinext domain-cert-count

# Only issued (active) certificates
certinext domain-cert-count --status issued

# Only expired certificates
certinext domain-cert-count --status expired

# Collapse subdomains — subdomain.example.org rolls into example.org
certinext domain-cert-count --condense

# Condense + issued only
certinext domain-cert-count --condense --status issued

# Raw JSON for scripting
certinext domain-cert-count --json | jq '.[] | select(.certificates != "0")'
```

### certinext issue-cert

`certinext issue-cert` submits a CSR to CertiNext and downloads the issued
certificate.  It reads the domain and SANs directly from the CSR, creates a
certificate order, handles the full lifecycle (agreement, DCV if needed, CSR
submission), and writes the signed PEM to stdout or a file once the CA has
issued it.

Requires the `csr` optional extra — included in the recommended
`uv tool install "certinext[csr,keyring]"` from
[Installation](#installation).

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
--product CODE              Product code (X-Product-Code) selecting a specific
                            catalog product; default: API default for the type.
                            List codes with certinext setup defaults.
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
-o FILE, --output FILE      Write the certificate PEM bundle to FILE (default: stdout)
--cert-out FILE             Write only the end-entity (leaf) certificate PEM to FILE
--chain-out FILE            Write only the intermediate CA chain PEM to FILE (signing order)
--fullchain-out FILE        Write the leaf-first fullchain PEM (leaf + intermediates) to FILE
--der-out FILE              Write the end-entity certificate in DER (binary) format to FILE
--all-formats-out DIR       Write {domain}.pem and {domain}.der to DIR in one call
--raw-chain                 Emit the chain exactly as the API returns it, unsorted
                            (default: sort into leaf-first signing order; see below)
--wait SECONDS              Seconds to wait for issuance (default: 300; 0 = submit and exit)
--order-id ID               Resume polling an existing order instead of creating a new one
--save-defaults             Store the effective requestor/certificate values as config defaults
-v, --verbose               Increase verbosity (-vvv for debug logging)
```

Requestor and certificate values can also come from stored defaults — see
[Storing issue-cert defaults](#storing-issue-cert-defaults-optional).

#### Examples

```bash
# DV certificate — credentials and requestor info from keychain / env vars
certinext issue-cert example.com.csr

# Read CSR from stdin
certinext issue-cert < example.com.csr

# Save certificate to a file
certinext issue-cert example.com.csr --output example.com.pem

# Write leaf, intermediate chain, and fullchain to separate files
# (the layout nginx, Apache, and HAProxy configs typically expect)
certinext issue-cert example.com.csr --cert-out cert.pem --chain-out chain.pem --fullchain-out fullchain.pem

# Emit the chain exactly as the API returns it, without re-sorting (debugging)
certinext issue-cert example.com.csr --fullchain-out fullchain.pem --raw-chain

# OV certificate with explicit org
certinext issue-cert example.com.csr --type ov --org-id 8921215

# Two-year DV certificate against the sandbox
certinext issue-cert example.com.csr --validity 2 --sandbox

# Submit and exit immediately without waiting for issuance
certinext issue-cert example.com.csr --wait 0

# Resume polling an order created in a previous run
certinext issue-cert --order-id ORDER-ID --wait 600

# Resume and supply the CSR (in case the order is still in pending-csr)
certinext issue-cert --order-id ORDER-ID --csr example.com.csr

# Capture the values used on this run as defaults for future runs
certinext issue-cert example.com.csr --type ov --org-id 8921215 --save-defaults
```

To avoid repeating requestor flags on every call, store them once with
`certinext setup defaults` (or `--save-defaults` above), or set environment
variables (which take precedence over stored defaults):

```bash
export CERTINEXT_REQUESTOR_NAME="Jane Doe"
export CERTINEXT_REQUESTOR_EMAIL="jane.doe@example.com"
export CERTINEXT_REQUESTOR_PHONE="+12075551234"
export CERTINEXT_REQUESTOR_DESIGNATION="Systems Administrator"
export CERTINEXT_SIGNER_PLACE="Portland, ME"

certinext issue-cert example.com.csr --output example.com.pem
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

### certinext parent-dcv-status

`certinext parent-dcv-status` shows DCV status and expiry for every domain
that requires direct DCV validation — either because it has no registered
ancestor in the account, or because its own NS records form a DNS zone
boundary that blocks DCV inheritance from a parent.

By default an NS lookup is performed for each domain to detect zone
boundaries (requires `certinext[dns]`). Use `--no-ns-check` to skip DNS
lookups and list only account-level parents.

#### Arguments

```
--pattern REGEX         Filter domains by regex before identifying parents (re.fullmatch)
--status STATUS         Filter by DCV status: all (default), verified, expiring, pending, expired
--expiring-days DAYS    Days ahead to flag as expiring soon (default: 30)
--json                  Output raw JSON instead of tabular format
--no-ns-check           Skip DNS NS lookups; list account-level parents only
-v, --verbose           Increase verbosity (-v shows progress, -vvv enables debug logging)
```

#### Examples

```bash
# All parent domains with DCV status
certinext parent-dcv-status --sandbox

# Only domains expiring within 60 days
certinext parent-dcv-status --status expiring --expiring-days 60

# Skip DNS NS checks (faster, account-level parents only)
certinext parent-dcv-status --no-ns-check

# Raw JSON for scripting
certinext parent-dcv-status --json | jq '.[] | select(.dcv_status != "VERIFIED")'
```

---

### certinext healthcheck

`certinext healthcheck` probes (nearly) every read-only CertiNext endpoint the
library exposes, classifies each result, and prints a scannable report of what
works for the credentials it was given. It is **read-only and safe to run
against production** — it only ever issues GETs and never mutates anything.

Use it to answer two questions the CertiNext API makes surprisingly hard:

- *"What should work with our library right now, against this account?"* — the
  vendor changes behaviour that affects some orgs and environments but not
  others, and drifts over time.
- *(future, with fine-grained API keys)* *"Does this key have exactly the
  access it should?"* — a `DENIED` outcome is the permission-denied signal.

Probes run in two tiers. **Tier 1** needs no input and always runs. **Tier 2**
needs an ID derived from a Tier-1 result (a specific organization, product,
domain, or order); when that input is unavailable the probe is reported
`SKIPPED`, never as a failure. Use `--quick` to run Tier 1 only.

#### Outcomes

| Outcome | Meaning | Fails the run? |
|---|---|---|
| `PASS` | 2xx with data (or a legitimately empty result) | no |
| `EMPTY` | 2xx but unexpectedly empty where a baseline says it shouldn't be | only with `--strict` |
| `DENIED` | 401/403, or a token error naming `invalid_client` | yes |
| `NOT_FOUND` | 404 | yes |
| `SERVER_BUG` | 422 or 5xx — the raw RFC 7807 body is captured verbatim | yes |
| `RATE_LIMITED` | 429 | no |
| `NETWORK` | connection/timeout error with no HTTP response | yes |
| `SKIPPED` | a Tier-2 probe whose derived input was unavailable | no |

The process exits non-zero when any probe is `DENIED`, `NOT_FOUND`,
`SERVER_BUG`, or `NETWORK`. Add `--strict` to also fail on `EMPTY`.

#### Case study: the June 2026 `/domains` 422 (resolved)

In mid-June 2026 the CertiNext `/domains` list endpoint returned a generic
HTTP 422 for every request made with our production credentials (CertiNext
ticket #131869). The root cause turned out to be on the account side — a
credentials/provisioning problem, resolved 2026-06-25 by issuing new OAuth
client credentials — not a fault in this library.

While it lasted, `certinext healthcheck` reported the domain-list probe as
`SERVER_BUG` (with the raw RFC 7807 body captured verbatim) and the per-domain
Tier-2 probes that depend on a domain from that list as `SKIPPED`, so the run
exited non-zero. That is exactly the behaviour the tool exists for: it
pinpointed the broken endpoint and preserved the server's own error body,
instead of letting the failure surface as a confusing crash downstream. As of
2026-07-02 both production and sandbox runs are fully green.

#### Arguments

```
--quick                 Run Tier-1 probes only (skip derived-input Tier-2 probes)
--strict                Also exit non-zero on an unexpectedly empty baseline list (EMPTY)
--json                  Write the full results (with raw error bodies) as JSON
-v, --verbose           Increase verbosity (-v progress, -vvv per-probe debug)
```

#### Examples

```bash
# Probe the sandbox and show progress
certinext healthcheck --sandbox -v

# Probe production (read-only) — surfaces any endpoint that is down for this account
certinext healthcheck

# Tier-1 only, for a fast auth/connectivity canary
certinext healthcheck --quick

# Machine-readable output, with the raw RFC 7807 body for any 422
certinext healthcheck --json | python -m json.tool

# Nightly cron that alerts on regressions via the exit code
certinext healthcheck 2>> /var/log/certinext-health.log || mail -s "CertiNext health" ops@example.edu
```

---

## Log output

All CLI scripts write diagnostic messages to **stderr**. The format adapts to
the environment automatically:

| Context | Format |
|---|---|
| Interactive terminal (TTY) | `HH:MM:SS [level] event  field=value …` — human-readable, local time |
| Non-TTY (cron, redirected stderr) | One JSON object per line — suitable for log aggregators and `jq` |

**Verbosity flags** (cumulative, same for all scripts):

| Flag | Effect |
|---|---|
| `-v` | Show extra context fields (`correlation_id`, `pid`, credential profile, domain filters) |
| `-vvv` | Enable DEBUG logging |
| `-vvvv` | Also enable third-party DEBUG output (urllib3, keyring) |

**Cron example** — capture JSON logs to a file:

```bash
certinext parent-dcv-status --sandbox 2>> /var/log/certinext.log
```

Each line is a self-contained JSON object:

```json
{"timestamp": "2026-06-03T14:00:01.234Z", "level": "info", "event": "Connecting", "account": "5912517854", "profile": "default", "url": "https://us-api.certinext.io"}
{"timestamp": "2026-06-03T14:00:02.456Z", "level": "info", "event": "Fetched domains", "count": 234}
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

With no `offset`/`limit`, `get_list()` returns the **complete** account,
paging under an explicit `sortBy=domainName` sort behind the scenes — that
sort is a stable total order regardless of account size.

Pass `offset` and `limit` explicitly to fetch a single raw server page
instead, under whichever ordering the API applies by default:

```python
page = sess.domain.get_list(offset=50, limit=25)
```

> **Note:** the API's default sort order for a raw page like this is not a
> stable total order across offset values — rows can be skipped or
> duplicated between pages if you loop `offset` yourself. Omit
> `offset`/`limit` for a reliable full list instead.

Filter by status server-side (reduces data transferred):

```python
# Only active domains with pending or rejected DCV
domains = sess.domain.get_list(domain_status="ACTIVE", dcv_status="PENDING,REJECTED,EXPIRED")
```

> **Note:** The API `search` parameter behaves differently per environment
> (re-tested 2026-07-02, probe R01): exact FQDN matches work everywhere; the
> **sandbox** now also matches substrings correctly, but **production** still
> returns 0 results for substring searches — and results are capped at the
> server's ~50-row default page. Use `pattern` (below) for reliable filtering.

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
verification. It filters `domainStatus=ACTIVE` server-side and applies the
DCV-status half (`domain.needs_dcv`, i.e. anything other than `VERIFIED`)
client-side.

> **Note:** Probe R02 confirmed the combined `domainStatus`+`dcvStatus` filter
> is accepted in both environments (2026-07-02, GitLab issue #6), so the
> `domainStatus=ACTIVE` half moved server-side in 1.0. The `dcvStatus` half
> stays client-side deliberately: "needs DCV" means *anything other than
> `VERIFIED`*, and the server cannot express that — `dcvStatus=EXPIRED` still
> returns 400 (vendor #135290), and an allow-list filter would silently drop
> unknown future statuses. Revisit when issue #6 settles the enum membership.

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
| `verified_at` | `datetime \| None` | Timestamp DCV was last completed, or `None` if not yet verified |
| `dcv_expires` | `datetime \| None` | DCV token expiry (timezone-aware UTC); only set once DCV has completed |
| `needs_dcv` | `bool` | `True` if status is `ACTIVE` and `dcv_status` is not `VERIFIED` |

`Domain` objects support `str()` and `repr()`:

```python
print(domain)
# Domain: maine.edu
#   id:              vuxwZgEXWWFXQQWC-...
#   status:          ACTIVE
#   dcv_status:      VERIFIED
#   dcv_expires:     2026-12-14 00:00:00+00:00   (only shown once DCV has completed)
#   organization:    University of Maine System
#   created:         2026-05-04 21:27:14+00:00

repr(domain)
# Domain(name='maine.edu', status='ACTIVE')
```

#### DcvInfo

`domain.get_dcv()` returns a `DcvInfo` model with the following fields:

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

result = domain.verify()           # trigger verification; returns a DcvVerifyResult summary
domain.change_dcv_method("DNS-TXT")   # accepted values: "DNS-TXT", "HTTP-URL"
domain.reinitiate_dcv()            # force a fresh challenge token (e.g. after tokenExpiry lapses)
attempt = domain.last_dcv_attempt()   # returns raw API response dict
history = domain.dcv_attempt_history() # returns raw API response dict or list

# Is the DCV token about to expire?
if domain.dcv_expires_soon(days=30):
    print(f"{domain.name} needs re-validation soon")

# Does a registered ancestor already cover this domain's DCV?
# (used by `certinext parent-dcv-status`; requires certinext[dns] for the
# NS zone-boundary check — see that command's section above)
all_names = {d.name for d in sess.domain.get_list()}
parent = domain.dcv_covering_parent(all_names)

# Get the raw API response dict, or a flat dict[str, str] for tabular display
raw = domain.as_dict()
row = domain.to_row()
```

#### Example: verify all pending domains

```python
import certinext

sess = certinext.session(
    client_id="YOUR_ACCOUNT_NUMBER",
    client_secret="YOUR_CLIENT_SECRET",
)

# get_pending_dcv() filters domainStatus=ACTIVE server-side; the DCV-status
# half (needs_dcv, i.e. != VERIFIED) stays client-side (see note above).
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

`Organization` also exposes detail-endpoint properties not present in the
list response — `state_code`, `state_name`, `street_address_1`,
`street_address_2`, `business_category_id`, `validation_status_id`,
`validation_status`, `validation_for_id`, `validation_for`,
`subscriber_agreement_signed`, `subscriber_agreement_signer`,
`subscriber_agreement_date`, `org_representatives`, and `domains`. The
first access of any of these lazily fetches
`GET /api/certinext/v2/organizations/{number}` once and caches the result
(`org.as_dict()` reflects whatever has been fetched so far); an object
returned by `get_organization()` already has the detail loaded. On a
detached `Organization` (no attached client) or if the fetch fails, these
properties return `None`/empty rather than raising.

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
`dict[str, str]` suitable for tabular display (the CLI renders it with `rich`).

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

# 3. Trigger verification for each domain (publish the challenge first, then call this)
order.verify_dcv(domain="example.com", method="DNS-TXT")
order.refresh()
print(order.status)  # "pending-csr" once DCV passes

# 4. Submit CSR
order.submit_csr(csr_pem)
order.refresh()

# 5. Accept agreement
order.accept_agreement(signer_name="Jane Doe", signer_place="Portland, ME")
order.refresh()
print(order.status)  # "pending-approval" or "issued"

# 6. Download once issued
cert = order.download_certificate()           # JSON — cert + chain PEM strings
pem  = order.download_certificate_pem()      # raw PEM bundle (API order — see note below)
chain = order.download_certificate().as_pem_chain()  # leaf-first fullchain, sorted into signing order
der  = order.download_certificate_der()      # raw DER bytes
```

> **UMS note:** `get_dcv()`/`verify_dcv()` are for CAs that require explicit
> per-domain DCV. University of Maine System domains are pre-validated, so
> production UMS orders normally skip straight from `pending-agreement` to
> `pending-csr`/`issued` and these two methods are rarely called in practice
> (see [certinext issue-cert](#certinext-issue-cert)'s lifecycle notes).

**Complete end-to-end DV example:**

```python
import certinext, time

sess = certinext.session(client_id="YOUR_ACCOUNT", client_secret="YOUR_SECRET")

order = sess.ssl.create_dv("example.com", validity_years=1)
print(f"Order {order.order_id} created, status={order.status}")

for ch in order.get_dcv():
    print(f"  {ch.domain}: add TXT at {ch.host!r}  value={ch.token!r}")

input("Press Enter once DNS TXT records are published…")

order.verify_dcv(domain="example.com", method="DNS-TXT")
order.submit_csr(open("csr.pem").read())
order.accept_agreement(signer_name="Jane Doe", signer_place="Portland, ME")

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

> **Chain ordering.** CertiNext returns the chain in a non-standard order — the
> root CA appears right after the leaf instead of last — which breaks Windows
> Schannel / IIS validation ([GitLab #4](https://gitlab.its.maine.edu/sysadmin/python-libs/certinext/-/issues/4)).
> `as_pem_chain()` (and `download_chain()`, `--fullchain-out`, `--chain-out`, and
> the `--output`/stdout bundle) re-sort the chain into correct leaf-first signing
> order by default. Pass `as_pem_chain(sort=False)` — or `certinext issue-cert
> --raw-chain` — to emit the exact bytes the API returned. Sorting needs the
> `cryptography` package (`pip install certinext[csr]`); without it the CLI exits
> with guidance and the library raises `ImportError` unless you use the raw path.

#### Other lifecycle operations

```python
order.cancel()                              # cancel an in-progress order
order.reject()                              # reject a draft order
order.revoke(reason="keyCompromise")        # revoke an issued certificate
order.reissue("rekey", csr=new_csr_pem)     # reissue with a new key
```

### Error handling

All API errors raise `CertiNextAPIError` (or a typed subclass), which carries
`.status_code`, `.body`, `.ems_code`, and `.field_errors`. Typed subclasses
cover the statuses worth branching on: `CertiNextNotFoundError` (404),
`CertiNextConflictError` (409, with `.existing_domain_id`), and
`CertiNextRateLimitError` (429, with `.retry_after`).

Since 1.0, `CertiNextAPIError` subclasses plain `Exception` — deliberately
*not* the HTTP library's error type — so API errors and transport failures
are separate hierarchies:

```python
import httpx
from certinext.exceptions import CertiNextAPIError

try:
    domain = sess.domain.get("example.edu")
except CertiNextAPIError as exc:      # the API answered with an error
    print(f"API error {exc.status_code}: {exc.ems_code or exc.body}")
except httpx.HTTPError as exc:        # timeout, DNS, connection refused, ...
    print(f"network problem: {exc}")
```

> **Migrating from 0.3.x:** `CertiNextAPIError` used to subclass
> `requests.HTTPError`, so `except requests.HTTPError:` (or
> `requests.RequestException`) caught API errors too. That no longer works —
> catch `CertiNextAPIError` for API errors and `httpx.HTTPError` for
> transport failures, as above. Code that already caught `CertiNextAPIError`
> needs no changes.

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
    cli_support.py                # public CLI-support layer: resolve_connection, build_session,
                                  #   setup_logging, prompt_stderr, require_credential, fatal_api_error
                                  #   (replaces the pre-1.0 private certinext._cli)
    cli/                          # the consolidated `certinext` typer application (ADR 0004)
        __init__.py                #   main() entry point, exit-code handling
        _app.py                    #   the shared typer app object
        _aliases.py                #   certinext-* alias scripts pre-selecting a subcommand
        _shared.py                 #   shared Annotated option types, table/pairs rendering
        accounts.py, domains.py, domain_cert_count.py, healthcheck.py,
        issue_cert.py, ledger.py, list_certificates.py,
        parent_dcv_status.py, pending_dcv.py, setup_defaults.py,
        setup_keyring.py           #   one module per subcommand
    models/                       # pydantic response models (ADR 0003/0005)
        __init__.py, _base.py      #   CertiNextModel base, lenient_enum, coerce_flag
        accounts.py, catalog.py, domains.py, ledger.py, orders.py,
        ssl_certificates.py        #   per-API-area model classes; legacy modules below re-export these
    _config.py                     # stored issue-cert defaults (config.toml load/merge/save; writes via tomlkit)
    _keyring.py                    # shared keyring helpers (keyring_service, keyring_get, keyring_available)
    _chain.py                      # certificate-chain re-sorting (leaf-first signing order; GitLab #4)
    settings.py                    # pydantic-settings models: IssuanceDefaults, ConnectionSettings,
                                  #   CertiNextSettings (init → keyring → env precedence)
    accounts.py                    # AccountInfo, Group, Organization, AccountAccessor
    auth.py                        # OAuth 2.0 client credentials token management
    catalog.py                     # Product, ProductCategory, CustomField, CatalogAccessor
    client.py                      # httpx-based HTTP client (get/post/put/delete/get_bytes)
    csr.py                         # parse_csr() — extract CN and SANs from a PEM CSR (requires certinext[csr])
    domains.py                     # Domain class and DomainAccessor
    domain_cert_count.py           # operations layer for `certinext domain-cert-count` (join logic)
    exceptions.py                  # CertiNextAPIError and typed subclasses
    healthcheck.py                 # read-only probe engine for `certinext healthcheck`
    ledger.py                      # LedgerRecord and LedgerAccessor
    orders.py                      # OrderRecord and OrderAccessor
    session.py                     # CertiNextSession (accounts, catalog, domain, ledger, orders, ssl)
    ssl_certificates.py            # SslOrder, DcvChallenge, CertificateDownload, SslAccessor, OrderWorkflow
                                  #   SslAccessor.create() — DV/OV/EV dispatcher
                                  #   CertificateDownload.as_pem_chain() — leaf-first fullchain
                                  #   OrderWorkflow.download_chain() — 422-retry + normalised chain
                                  #   OrderWorkflow.from_order_id() — resume from persisted order ID
tests/
    test_integration.py, test_sandbox_integration.py  # live sandbox tests (pytest -m integration)
    test_probes.py                 # live probe suite backing `certinext healthcheck` (pytest -m probe)
    test_corpus_models.py          # parses committed sanitized API-response corpus through the models
    test_cli_help_snapshots.py, test_cli_json_goldens.py  # golden-file CLI regression tests
docs/
    migrating-to-1.0.md            # 0.3.x → 1.0 migration guide
    adr/                           # architecture decision records
    plans/pydantic-typer-refactor/ # phased refactor plan + per-phase implementation records
    wishlist/                      # deferred ideas
examples/
    dns_txt_dcv.py                 # DNS-TXT DCV automation example (see Examples above)
```

</details>
