---
name: certinext-api-bugs
description: Known CertiNext vendor API bugs affecting domain listing and filtering. Use when editing certinext/domains.py, dcv_update.py, or README.md sections about listing or filtering domains.
---

The following CertiNext API bugs were confirmed by vendor support on 2026-05-20. Vendor will notify when fixed.

## Broken parameters

**`domainStatus` + `dcvStatus` filters together on `GET /api/certinext/v2/domains`**
Originally returned HTTP 400 when both were used in one request (reported
2026-05-20). Probe R02 confirmed the combination now works in **both**
environments (2026-07-02, GitLab issue #6). Shipped in the 1.0 refactor
(phase 1, 2026-07-06): `get_pending_dcv()` now sends `domainStatus=ACTIVE`
server-side — it exactly matches the first conjunct of `Domain.needs_dcv`.
`dcvStatus` stays client-side deliberately: "needs DCV" means *anything
other than VERIFIED*, which the server can't express as a single filter
value — an allow-list filter would also silently drop unknown future
statuses. (`dcvStatus=EXPIRED` returning 400 is not part of this — see
Resolved below; it's expected behavior, not something to work around.)

## Resolved

**`search` on `GET /api/certinext/v2/domains`** — [GitLab issue #2](https://gitlab.its.maine.edu/sysadmin/python-libs/certinext/-/issues/2),
closed. History: returned everything regardless of value until ~2026-05;
exact-FQDN fixed 2026-06-05; substring matching fixed in sandbox 2026-07-02;
confirmed fixed in **production** too 2026-07-08 (probe R01). `search` is
now reliable server-side for exact-FQDN and substring (LIKE) matching in
both environments. It's still substring-only, not regex — `get_list()`'s
`pattern` param stays for cases `search` can't express (alternation,
anchoring, wildcards); that's a deliberate feature now, not a workaround for
this bug.

**`dcvStatus`/`domainStatus` enum discrepancies** — [GitLab issue #6](https://gitlab.its.maine.edu/sysadmin/python-libs/certinext/-/issues/6),
closed 2026-07-10. Not vendor bugs: the Postman collection (hand-maintained)
had `EXPIRED` listed as a valid `dcvStatus` and `DEACTIVATED` as a valid
`domainStatus` — both wrong. Vendor confirmed the OpenAPI spec at
`/v3/api-docs/certinext-v2` (generated from source, always matches the
running service) is canonical: `dcvStatus` is `PENDING`/`VERIFIED`/`REJECTED`
only, `domainStatus` is `ACTIVE`/`INACTIVE`/`EXPIRED` only. The 400s on
`dcvStatus=EXPIRED` and `domainStatus=DEACTIVATED` are correct, permanent
behavior — do not treat them as bugs to watch for a fix. `DcvStatus`/
`DomainStatus` in `certinext/models/domains.py` were tightened to match
(also dropped `REVOKED` from `DomainStatus`, which the spec never listed —
a discrepancy the vendor ticket didn't cover but the spec settles directly).
Whenever Postman and the OpenAPI spec disagree on this API going forward,
trust the OpenAPI spec.

## Pagination

`GET /api/certinext/v2/domains`'s default sort order (`createdAt desc`) is
not a documented stable total order across `offset` pages — vendor-confirmed;
looping raw `offset`/`limit` under it can skip or duplicate rows. `domainName`
is a documented, unique `sortBy` value, so `DomainAccessor.get_list()` pages
under `sortBy=domainName&sortDir=asc` whenever it's asked for the whole
account (no `offset`/`limit` given). Only pass `offset`/`limit` explicitly
when you want one raw server page and can tolerate the default ordering.

## Filing a new issue

When a new bug is confirmed, create a GitLab issue and assign it to yourself unless it clearly belongs to another team:

```bash
$env:GITLAB_HOST = "gitlab.its.maine.edu"
glab issue create -R sysadmin/python-libs/certinext \
  --title "CertiNext /endpoint: short description" \
  --description "..." \
  --label "certinext,vendor-bug" \
  --assignee @me
```

Use `--assignee @me` by default. Assign to someone else only if the issue involves infrastructure, credentials, or a system owned by a different team.

## When the vendor fixes these, update

- `README.md` — update the "List domains needing DCV" section if the server ever gains a way to express "not VERIFIED" as a single `dcvStatus` filter value
