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
other than VERIFIED*, which the server can't express, and `dcvStatus=EXPIRED`
still returns 400 (vendor #135290 open, probe R23) — an allow-list filter
would also silently drop unknown future statuses. Revisit when issue #6
settles the `DcvStatus` enum membership.

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

- `certinext/domains.py` — once `dcvStatus=EXPIRED` (or the full enum) stops 400ing, move the DCV-status half of `get_pending_dcv()` server-side too
- `README.md` — update the "List domains needing DCV" section
