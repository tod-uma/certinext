---
name: certinext-api-bugs
description: Known CertiNext vendor API bugs affecting domain listing and filtering. Use when editing certinext/domains.py, dcv_update.py, or README.md sections about listing or filtering domains.
---

The following CertiNext API bugs were confirmed by vendor support on 2026-05-20. Vendor will notify when fixed.

## Broken parameters

**`search` on `GET /api/certinext/v2/domains`**
Intended for exact or substring filtering by FQDN. Returns all domains regardless of value passed. Workaround: fetch all, filter client-side.

**`domainStatus` + `dcvStatus` filters together on `GET /api/certinext/v2/domains`**
Returns HTTP 400 when both are used in the same request. Individual filter behavior untested.

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

- `certinext/domains.py` — remove the `search` warning from the `list()` docstring; rewrite `list_pending_dcv()` to use server-side filtering instead of fetching all + client-side filter via `needs_dcv`
- `ums-certinext-scripts/dcv_update.py` — remove the comment noting search is broken
- `README.md` — update the "List all domains" and "List domains needing DCV" sections
