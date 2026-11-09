---
name: certinext-api-bugs
description: Known CertiNext vendor API bugs and quirks in certificate ordering (SSL.com, X-Product-Code, EMS-1162) and in domain listing and filtering. Use when editing certinext/ssl_certificates.py, certinext/domains.py, certinext/cli/issue_cert.py, dcv_update.py, or README.md sections about ordering certificates or listing domains, or when an order fails with EMS-1162 Invalid Product Code.
---

## Ordering from SSL.com (GitLab #39, vendor #187868, ADR 0020 amendment)

**The API credential picks the CA, not the request.** A REST credential is
bound to one CA connector on the portal's API Credentials page. Nothing in
`POST /ssl-certificates` routes an order, so don't add a `ca=` argument that
pretends to.

**Send no `X-Product-Code` for SSL.com.** SSL.com codes (1011-1020, catalog
category `"SSL.com"`) in that header return 422 `[EMS-1162] Invalid Product
Code`, even on a credential bound to SSL.com. Without the header the same DV
order issued at once (sandbox, 2026-11-09). EMS-1162 on an emSign-bound
credential means a configuration problem: switch the credential, don't retry.
Still open with the vendor: how to choose a specific SSL.com product
(wildcard, UCC, OV) while the header rejects every SSL.com code.

**The catalog can't show a credential's CA.** It lists both categories
either way. `ProductCategory.ca` says which CA a *product* belongs to;
label orders by joining `OrderRecord.product_code` to
`catalog.ca_by_product_code()`. Don't use `issuer_ca` for that: emSign issues
from InCommon-branded intermediates whose names never say emSign.

**`validity_years` is not the lifetime.** The SSL.com staging cert lasted 90
days on `validityYears: 1`.

When the vendor answers #187868, update this section, README "More than one
CA", and close or retitle #39.

## Domain listing and filtering

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
is a documented `sortBy` value, so `DomainAccessor.get_list()` pages under
`sortBy=domainName&sortDir=asc` whenever it's asked for the whole account
(no `offset`/`limit` given). Only pass `offset`/`limit` explicitly when you
want one raw server page and can tolerate the default ordering.

**`domainName` stopped being unique in November 2026 (GitLab #38).** An
organization can now hold the same name once per CA (emSign + SSL.com, with
more CAs planned). Two rows tied on a name can swap across a page boundary
and one of them is silently skipped. `_get_all_domains()` therefore
re-fetches every name that sits on a page boundary with
`search=<name>&exactMatch=true` (in both prod and sandbox specs) and merges
the results by id. That costs one extra GET per 200 rows. Don't remove it as
redundant. The re-fetch itself pages until a short page (Codex review
of #38), so a name with more than 200 rows is still complete.

**`validatedBy` list filter** was in the sandbox spec only as of 2026-11-05.
`get_list(validated_by=...)` sends it and then filters again client-side,
because a prod that ignored it would return rows from every CA.

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
