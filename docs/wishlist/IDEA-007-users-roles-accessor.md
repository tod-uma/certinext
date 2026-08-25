# IDEA-007: Users/roles/permissions accessor

- **Status:** Proposed (coordinating issue: #22)
- **Created:** 2026-07-22
- **Updated:** 2026-07-22

## Context

Came up 2026-07-22 answering an ad hoc question — can the CertiNext API read
users, groups, roles, and custom role permissions? Checking the
`certinext-spec-snapshots` snapshots (`snapshots/prod.json` and
`snapshots/sandbox.json`) confirmed the vendor exposes a full set of GET
endpoints for this under `/api/v2/certinext/users/...`, but none of it is
wrapped in the `certinext` library today — the only accessor that exists is
`AccountAccessor` (`me`, `list_groups`, `list_organizations`) in
[accounts.py](../../certinext/accounts.py).

## The idea

Add a `UsersAccessor` (mirroring `AccountAccessor`'s shape) exposing the
read-only endpoints confirmed in the spec:

- `list_users()` — `GET /api/v2/certinext/users` (and `/users/detailed`)
- `list_roles()` / `get_role(id)` — `GET /api/v2/certinext/users/roles`,
  `GET /api/v2/certinext/users/roles/{id}`
- `get_role_permissions(id)` — `GET /api/v2/certinext/users/roles/{id}/permissions`
- `list_role_users(id)` — `GET /api/v2/certinext/users/roles/{id}/users`
- `list_group_members()` / `list_group_members(user_id)` —
  `GET /api/v2/certinext/users/groups/members[/{userId}]`
- `list_available_permissions()` —
  `GET /api/v2/certinext/discovery/permissions/available`

With corresponding pydantic models in a new `models/users.py` (`User`,
`Role`, `Permission`, ...), following the existing lenient-model pattern from
`models/accounts.py` (ADR 0005).

Note: the vendor's "permission groups" (`/discovery/permissions/groups`) are
a distinct concept from the billing/org `Group` already wrapped by
`AccountAccessor.list_groups()` (`/api/certinext/v2/groups`) — name these
carefully so the two aren't conflated.

## Why not now

- No consumer or task needs this yet — it surfaced from an ad hoc capability
  question, not from a project requirement.
- Response body shapes for these endpoints haven't been captured. The spec
  entries only have `summary` + a bare `200` response — `scripts/capture_corpus.py`
  doesn't currently hit any `/users/...` paths, so there's no real payload to
  model against (ADR 0005 requires validating lenient models against a live
  corpus, not just the spec).
- Unconfirmed whether the OAuth client credentials currently in use even carry
  permission-management scope — worth checking before investing modeling effort.

## Pros

- Closes a real, confirmed API capability gap.
- Enables future permission-auditing / access-review tooling (e.g. "what can
  this custom role actually do") without reaching for raw
  `session._client.get(...)` calls.
- Follows the existing accessor/model pattern — low design risk.

## Cons / costs

- Another accessor + model module to maintain.
- The `/users/...` namespace also has sensitive write endpoints (deactivate,
  activate, token reset, admin toggle) — day-one scope should stay
  strictly GET-only to avoid quietly building account-management tooling
  nobody asked for.

## Effort

Small–medium: scaffolding mirrors `AccountAccessor` directly; the real cost
is running `capture_corpus.py` against sandbox for these paths to get real
payloads before modeling.

## Open questions & caveats

- Exact response shape of `/users/roles/{id}/permissions` (only a summary is
  visible in the spec, no schema).
- Whether the current sandbox/prod OAuth client can actually call these
  endpoints (permission-management scope unconfirmed).

## Next steps

Run `capture_corpus.py` against sandbox for the `/users/...` paths above to
get example payloads, then draft `models/users.py` + a GET-only
`UsersAccessor`.

## References

- `certinext-spec-snapshots` snapshots: `snapshots/prod.json`,
  `snapshots/sandbox.json` (paths under `/api/v2/certinext/users/...` and
  `/api/v2/certinext/discovery/permissions/...`) — internal spec capture, no
  public vendor API docs exist to link.
- Related: [ADR 0005](../adr/0005-lenient-models-validated-against-live-payload-corpus.md)
  (lenient models validated against corpus); existing
  [accounts.py](../../certinext/accounts.py) accessor pattern.

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Sonnet 5,
> `claude-sonnet-5`) from a conversation with Tod Detre. May contain
> inaccuracies or hallucinated details; verify specifics against current
> sources before relying on them.
