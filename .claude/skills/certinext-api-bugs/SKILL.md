---
name: certinext-api-bugs
description: Known CertiNext vendor API bugs affecting domain listing and filtering. Use when editing certinext/domains.py, dcv_update.py, or README.md sections about listing or filtering domains.
---

The following CertiNext API bugs were confirmed by vendor support on 2026-05-20. Vendor will notify when fixed.

## Broken parameters

**`search` on `GET /api/certinext/v2/domains`**
Intended for exact or substring filtering by FQDN. Environment split
confirmed 2026-07-02 by probe R01 (GitLab issue #2): **sandbox** now matches
substrings correctly; **production** still returns 0 rows for any substring
(exact-FQDN works in both). Results are also capped at the ~50-row default
page. Workaround until prod is fixed: fetch all, filter client-side
(`get_list()`'s `pattern` regex). History: returned everything regardless of
value until ~2026-05; exact-FQDN fixed 2026-06-05.

**`domainStatus` + `dcvStatus` filters together on `GET /api/certinext/v2/domains`**
Originally returned HTTP 400 when both were used in one request (reported
2026-05-20). Probe R02 confirmed the combination now works in **both**
environments (2026-07-02, GitLab issue #6). `get_pending_dcv()` still fetches
all + filters client-side; the switch to server-side filtering is planned for
the 1.0 refactor (phase 1). Contested enum values remain (issue #6 / vendor
#135290): `dcvStatus=EXPIRED` still returns 400 in both envs (probe R23).

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

- `certinext/domains.py` — remove the `search` warning from the `get_list()` docstring; rewrite `get_pending_dcv()` to use server-side filtering instead of fetching all + client-side filter via `needs_dcv`
- `ums-certinext-scripts/dcv_update.py` — remove the comment noting search is broken
- `README.md` — update the "List all domains" and "List domains needing DCV" sections
