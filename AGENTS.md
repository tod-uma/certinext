# AGENTS.md

Operational facts for coding agents working in this repository (Claude
Code, Codex, Cursor, etc.). For a factual map of the project's docs, see
[llms.txt](llms.txt). For the human-facing library/CLI reference, see
[README.md](README.md).

## Setup

```bash
uv venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # macOS / Linux
uv sync --locked --extra dev
```

`uv sync` without `--extra dev` (or without `--all-extras`) omits `keyring`,
which makes any interactive CLI path (`certinext setup keyring`, credential
prompts) fail with `EOFError` in a non-interactive shell.

## Test, lint, type-check

```bash
uv run pytest tests/ -m "not integration and not probe"   # unit tests (fast, default)
uv run pytest -m integration                               # live sandbox integration tests
uv run pytest -m probe                                      # live sandbox/prod probe suite (needs creds)
uv run ruff check .
uv run ruff format .
uv run mypy .        # strict, package + tests
uv run pyright
```

Integration and probe tests are skipped automatically when sandbox
credentials aren't available (`certinext setup keyring --sandbox` locally,
or `CERTINEXT_SANDBOX_CLIENT_ID`/`CERTINEXT_SANDBOX_CLIENT_SECRET` CI
variables) — safe to run without them, they just won't do anything.

CI (`.gitlab-ci.yml` and `.github/workflows/ci.yml`) pins every job to
`uv sync --locked --extra dev` against the committed `uv.lock` — don't add
a dependency without updating the lockfile (`uv lock`), or CI will resolve
against stale specs while local runs use the new one.

## Project layout

See the README's [Project structure](README.md#project-structure) section
for the annotated file tree. Two things worth knowing before editing:

- `certinext/models/` holds the pydantic response models; the flat
  `certinext/domains.py`-style modules re-export them and remain the
  documented import path. Add new response fields in `models/`, not the
  legacy module.
- `certinext/cli/` holds one typer module per subcommand, thin over the
  library. `certinext/cli/_aliases.py` keeps the pre-1.0 `certinext-*`
  script names working — if you add a new top-level subcommand, it does not
  need a legacy alias (aliases are frozen to what existed at the 1.0 cut).

## GitLab project path

`sysadmin/python-libs/certinext` — use for GitLab CI references, clone
URLs, and API calls.

## Publish chain

Releases follow: **local → GitLab → GitHub → PyPI**.

To release: tag on GitLab and push to GitLab only — GitHub and PyPI follow
automatically.

- GitLab CI publishes to the GitLab package registry on tag.
- GitLab **auto-mirrors** to GitHub — do not push to the GitHub remote
  manually (it will say "Everything up-to-date" if the mirror already beat
  you to it).
- GitHub Actions triggers on the mirrored tag and publishes to public PyPI
  via OIDC trusted publishing.

Pre-release versions (rc, alpha, beta) land on PyPI but are only visible
with `pip install --pre certinext`. Version bumps follow the repo's
`version-scheme` convention (`1.0.0aN` → `1.0.0rcN` → `1.0.0` stable);
annotated release tags carry a curated changelog that CI reads for release
notes — never leave a tag message empty or auto-generated.

## Wishlist awareness

Deferred ideas live in `docs/wishlist/` (index in its README). When making
code changes or improvements, keep them in mind: prefer designs that keep
parked ideas cheap rather than foreclosing them, and mention in the MR when
a change materially advances or blocks one. Example: the 1.0 refactor keeps
CLI bodies as thin presentation over library functions specifically so
IDEA-001 (TUI) and IDEA-002 (MCP server) can reuse the operations layer.

## Known vendor API quirks

CertiNext's REST API has several confirmed bugs/quirks around domain
listing, filtering, and pagination. Don't rediscover these — read
`.claude/skills/certinext-api-bugs/SKILL.md` before changing
`certinext/domains.py` or any README section about listing/filtering
domains.
