# Migrating from 0.3.x to 1.0

certinext 1.0 replaces its internal stack (argparse → typer, `requests` →
httpx, hand-rolled dataclasses → pydantic, hand-rolled TOML/keyring
plumbing → pydantic-settings) but keeps the public surface as close to
0.3.x as the stack swap allows. This page covers the handful of things
that *do* change and confirms the (long) list of things that don't.

## Nothing to do

- **Config file** (`config.toml`) format, location, and precedence are
  unchanged. Existing `[defaults]` / `[profiles.NAME]` files load and save
  exactly as before (the writer switched from a hand-rolled TOML emitter to
  `tomlkit` internally, which round-trips your file byte-for-byte including
  comments — you won't notice).
- **Keyring** entries are unchanged: same service names
  (`certinext` / `certinext-<profile>`), same `CERTINEXT_CLIENT_ID` /
  `CERTINEXT_CLIENT_SECRET` keys. Nothing to re-enter.
- **CLI flags and output** are unchanged for every existing script name —
  see the alias table below. If nothing in UMS or your own scripts parses
  certinext's CLI stdout, you have nothing to change there either.
- **Python model attributes** you already access (`domain.name`,
  `order.status`, `.as_dict()`, `.to_row()`, ...) still work — models moved
  from dataclasses to pydantic `BaseModel` subclasses, but field access,
  `as_dict()`, and `repr()` all preserve the old shape.

## What changes

### 1. `CertiNextAPIError` no longer subclasses `requests.HTTPError`

`CertiNextAPIError` is now a plain `Exception` subclass, not a
`requests.HTTPError` subclass — there's no `requests` dependency left to
subclass. Transport-level failures (timeouts, connection errors) now raise
`httpx.HTTPError` instead of `requests.exceptions.*`.

**Before (0.3.x):**

```python
import requests
from certinext.exceptions import CertiNextAPIError

try:
    order = sess.ssl.create("dv", domain="example.com")
except CertiNextAPIError as exc:
    print(exc.status_code, exc.body)
except requests.exceptions.RequestException as exc:
    print("network error:", exc)
```

**After (1.0):**

```python
import httpx
from certinext.exceptions import CertiNextAPIError

try:
    order = sess.ssl.create("dv", domain="example.com")
except CertiNextAPIError as exc:
    print(exc.status_code, exc.body)
except httpx.HTTPError as exc:
    print("network error:", exc)
```

`.status_code` and `.body` are unchanged. A new `.response` attribute
carries the underlying `httpx.Response` (`None` if the error was
constructed outside the HTTP client). If your code only ever caught
`CertiNextAPIError` and its subclasses (`CertiNextNotFoundError`,
`CertiNextRateLimitError`, `CertiNextConflictError`,
`CertiNextTimeoutError`), nothing changes — those all still exist with the
same attributes. This break only affects code that separately caught
`requests.HTTPError` or `requests.exceptions.*` around a certinext call.

### 2. `certinext._cli` → `certinext.cli_support`

The private argparse-era CLI helper module is gone. If you imported from
`certinext._cli` to build your own script against certinext's connection
and credential resolution (as `ums-certinext-scripts` does), switch to the
public `certinext.cli_support` module — same responsibilities, no
argparse/typer/click dependency of its own:

| Old (`certinext._cli`) | New (`certinext.cli_support`) |
|---|---|
| connection/sandbox resolution | `resolve_connection(profile=, sandbox=, base_url=, token_url=) -> ResolvedConnection` |
| building an authenticated session | `build_session(connection, account_number=, client_secret=, scope=, prompt=) -> CertiNextSession` |
| logging setup | `setup_logging(verbose: int) -> None` |
| stderr prompts | `prompt_stderr(prompt: str) -> str` |
| resolving a required credential | `require_credential(value, env_var, prompt, secret=, allow_prompt=) -> str` |
| fatal API error reporting | `fatal_api_error(exc: CertiNextAPIError, message: str) -> NoReturn` |

`resolve_connection()` replaces the old `apply_sandbox()`-style endpoint
resolution and returns a frozen `ResolvedConnection` (`base_url`,
`token_url`, `sandbox`, `profile`) instead of mutating flags in place.
`build_session()` raises `cli_support.CredentialsNotFoundError` (a
`RuntimeError`) when `prompt=False` and no credential is available.

See [`examples/dns_txt_dcv.py`](../examples/dns_txt_dcv.py) for a worked
example, and `ums-certinext-scripts`' `dcv_update.py` /
`top_domains.py` for a second, independently-migrated reference.

### 3. Standalone scripts still work, but prefer the `certinext` subcommands

Every 0.3.x script name (`certinext-issue-cert`, `certinext-domains`, ...)
still installs and behaves identically — they're now thin aliases onto the
new `certinext` typer app. New code should call the unified command instead:

| 0.3.x script | 1.0 equivalent |
|---|---|
| `certinext-healthcheck` | `certinext healthcheck` |
| `certinext-accounts` | `certinext accounts` |
| `certinext-domains` | `certinext domains list` (bare `certinext domains` shows its own help) |
| `certinext-ledger` | `certinext ledger` |
| `certinext-list-certificates` | `certinext list-certificates` |
| `certinext-pending-dcv` | `certinext pending-dcv` |
| `certinext-domain-cert-count` | `certinext domain-cert-count` |
| `certinext-issue-cert` | `certinext issue-cert` |
| `certinext-parent-dcv-status` | `certinext parent-dcv-status` |
| `certinext-setup-keyring` | `certinext setup keyring` |
| `certinext-setup-defaults` | `certinext setup defaults` |

`certinext domains` also gained per-verb subcommands that didn't exist as
separate flags in 0.3.x: `list`, `get`, `create`, `deactivate`, `get-dcv`,
`verify-dcv`, `change-dcv-method`, `last-dcv-attempt`,
`dcv-attempt-history` — see the README's "certinext domains" section.

The alias scripts are planned to stick around no earlier than 2.0; there's
no forcing function to migrate off them today.

### 4. Import paths for models are unchanged (but there's now a canonical home)

`certinext.domains.Domain`, `certinext.orders.SslOrder`, etc. all still
import from the same legacy module paths. Internally those classes now
live under `certinext.models.*` (mirroring the accessor modules —
`models.catalog` ↔ `certinext.catalog`, and so on) and the legacy modules
re-export them. You don't need to change any import unless you want to;
both paths are documented as public for 1.0.

## Divergences found during the refactor (not breaking, worth knowing)

- **`domains get-dcv`** was silently broken since the phase-1 model
  migration (it called `dataclasses.asdict()` on a pydantic model) and is
  fixed as part of this release — if you were working around empty/error
  output from that subcommand, the workaround is no longer needed.
- **`domains deactivate`**'s confirmation prompt now correctly goes to
  stderr instead of stdout, matching every other interactive prompt in the
  CLI — only relevant if you were piping its stdout.
- A few CLIs (`accounts`, `ledger`, `list-certificates`, `pending-dcv`)
  previously never wired up `-v`/logging and leaked "Connecting..."-style
  lines onto stdout; they're now silent by default like the rest of the
  CLI, with `-v` opting into the log output.
- `--all-formats-out DIR` still requires `DIR` to already exist (unchanged
  from 0.3.x — not yet a QoL fix in 1.0).
- `certinext --version` is new — prints the installed package version and
  exits (reads from package metadata, so it reflects whatever's actually
  installed, editable dev checkout included).
- `healthcheck`, `parent-dcv-status`, and `issue-cert` now show a progress
  bar (or a per-item bar with `-v` on `healthcheck`) on stderr for their
  longer-running steps instead of sitting silent; `-vvv` hides the bars
  since the existing debug logs already itemize each step.

## If something doesn't match this page

File a GitLab issue against this repo. The
[phased refactor plan](plans/pydantic-typer-refactor/README.md) has the
full implementation record per phase if you need more detail than fits
here.

---
> **AI-assistant disclaimer:** Drafted by Claude (Claude Sonnet 5,
> `claude-sonnet-5`) from a conversation with Tod Detre. May contain
> inaccuracies or hallucinated details; verify specifics against current
> sources before relying on them.
