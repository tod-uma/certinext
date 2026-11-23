---
name: certinext-api-bugs
description: Known CertiNext vendor API bugs and quirks in certificate ordering (SSL.com, X-Product-Code, EMS-1162) and in domain listing and filtering. Use when editing certinext/ssl_certificates.py, certinext/domains.py, certinext/cli/issue_cert.py, dcv_update.py, or README.md sections about ordering certificates or listing domains, or when an order fails with EMS-1162 Invalid Product Code. Also when creating SSL.com domain records or debugging dns-persist DCV (a 400 on create, a verify that 422s with MPIC failed, or `policy=wildcard`). Also for the v3 CLM paths (`/api/v3/certinext/` orders, audit-logs, users, roles, apis, discovery), their paging parameters, 404 on `orders/{id}`, 400 on `users/groups/members`, or when capturing fixtures with `scripts/capture_corpus.py` or probing a credential with `scripts/probe_access.py`.
---

## Ordering from SSL.com (GitLab #39, vendor #187868, ADR 0020 amendment)

**The API credential picks the CA, not the request.** A REST credential is
bound to one CA connector on the portal's API Credentials page. Nothing in
`POST /ssl-certificates` routes an order, so don't add a `ca=` argument that
pretends to.

**Never put an SSL.com code in `X-Product-Code`; send the InCommon code.**
SSL.com codes (1011-1020, catalog category `"SSL.com"`) in that header return
422 `[EMS-1162] Invalid Product Code`, even on a credential bound to SSL.com.
On that credential the vendor *translates* InCommon codes per product. In
sandbox on 2026-11-09, `970` (InCommon DV) issued SSL.com DV and was reported
as `1011`, and `971` (InCommon DV Wildcard) issued an SSL.com wildcard,
reported as `1012`. On 2026-11-10, `955` (InCommon OV) issued SSL.com OV,
reported as `1015`. No header gives the default DV. Don't "fix" a caller that
sends `970` to an SSL.com credential: that is the supported way to pick a
product. EMS-1162 on an emSign-bound credential means a configuration problem:
switch the credential, don't retry. Untested: the UCC and 30/45/90-day
codes, and what an InCommon code with no SSL.com equivalent does. The vendor
hasn't confirmed the translation yet.

**Prod uses different codes from sandbox (read and tested 2026-11-12).** The
examples above are sandbox codes. In prod the InCommon DV codes are `842` (DV),
`843` (wildcard), `844` (UCC) and `845` (wildcard UCC); OV is `846`-`849` and EV
`850`/`851` (plus 30/45/90-day variants). A prod order with `842` on an
SSL.com-bound credential issued SSL.com DV, reported as `1011`, in about 8 s
(`--ca SSLCOM` pre-flight passed). The prod SSL.com category lists **DV only,
`1011`-`1014`**: there is no SSL.com OV or EV in prod, so an OV/EV order has no
SSL.com equivalent there. Untested in prod: `843`/`844`/`845` → `1012`/`1013`/
`1014`. Don't copy a sandbox code into a prod command; list the prod catalog
first.

**The catalog can't show a credential's CA.** What it lists doesn't depend
on the credential (sandbox: both categories; prod: SSL.com only since
2026-11-15). `ProductCategory.ca` says which CA a *product* belongs to;
label orders by joining `OrderRecord.product_code` to
`catalog.ca_by_product_code()`. That still works for translated orders,
because the report records the SSL.com code. Don't read a code's catalog CA as
"where an order with it goes": `970` is in the emSign category but issues from
SSL.com on an SSL.com credential. Don't use `issuer_ca` either: emSign issues
from InCommon-branded intermediates whose names never say emSign.

**Prod dropped the emSign category (2026-11-15).** The prod catalog now lists
only `"SSL.com"` (`1011`-`1014`), so `ca_by_product_code()` falls back to
`LEGACY_EMSIGN_CODES` in `certinext/models/catalog.py` (prod: the 56 KB §5
profiles; sandbox: 57 codes copied from its catalog 2026-11-16). If an emSign
order shows up `unknown` with an "Orders with a product code the catalog does
not list" warning, its code is missing from those tables. Confirm it's emSign
(KB, cert chain) before adding it, and add it to the code-by-code list in
`test_legacy_code_sets_match_their_sources` too.

**`validity_years` is not the lifetime.** The SSL.com staging cert lasted 90
days on `validityYears: 1`.

### SSL.com domain records and dns-persist DCV (seen 2026-11-10, sandbox + prod)

- **An emSign domain record does not give you an SSL.com one.** Each apex
  needs its own SSL.com record:
  `certinext-domains create <apex> --ca SSLCOM organization_id=<numeric org id> dcv_method=dns-persist`.
  Without both `organization_id` and `dcv_method` the create returns 400. It
  comes back `PENDING` with `DNS-PERSIST` selected.
- **SSL.com validates on its own.** A PENDING record usually turns VERIFIED
  within minutes of `_validation-persist.<apex>` being public, before any
  `POST /dcv/verify`. A verify right after publishing can 422 with
  `caMessage: "Multi-perspective inspection (MPIC) check failed"` or "Expected
  DNS record not found". That's propagation, so re-run rather than debug it.
  Don't query public resolvers for the name before publishing it: the cached
  NXDOMAIN keeps it invisible there for the negative-cache TTL.
- **A record can come back with no `DNS-PERSIST` option**, offering only
  DNS-TXT and HTTP. ums-certinext-scripts then reports `no-persist-option`.
  Re-running doesn't help. Deleting the domain record and re-creating it with
  `dcv_method=dns-persist` (portal, or the create above) gave a working persist
  option, and the existing public TXT validated it at once (one prod apex,
  2026-11-10, during a prod API slowdown). The cause is unconfirmed; Tod
  suspects vendor overload at create time.
- **The persist `recordValue` has no `; policy=wildcard`**, and the option
  says `exactName: true`. draft-ietf-acme-dns-persist-01 §5.1/§6.2 reads that
  as exact-FQDN-only, with no subdomains and no wildcards. Subdomain issuance
  has worked in practice anyway (sandbox and prod, 2026-11-10), so don't add
  the parameter preemptively. If a subdomain or wildcard order ever fails DCV,
  appending it is the first thing to try. Ask #187868 why it's omitted.

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

## v3 CLM paths (`/api/v3/certinext/`, probed 2026-11-23, prod and sandbox)

These are the reads the Splunk ingest needs (audit logs, users, roles, API
credentials, orders). Fixtures are `tests/fixtures/corpus/{prod,sandbox}/v3-*.json`;
`scripts/probe_access.py` re-runs every probe below with any credential.

- **Envelope:** `totalResults`, `pageNumber`, `pageSize` plus a list key that
  differs per path (`orders`, `auditLogs`, `users`, `customRoles`,
  `credentials`, `certificates`, `members`). `users/detailed` and
  `audit-logs/modules` are bare arrays. Stop paging on `totalResults` and on a
  short page.
- **Page-size parameter differs.** `orders`, `audit-logs`, `apis` and
  `discovery/certificates` take `pageNumber`/`pageSize`; `users` and
  `users/roles` take `pageNumber`/**`recordLimit`** (per the spec). On `users`,
  `pageSize` is ignored and the page defaults to 20, which looks like a cap
  until you send `recordLimit`.
- **`orders/{id}` takes the row's `orderId`.** `orderNumber`, the key v2 uses,
  returns 404 "No such order.".
- **`orders/{id}` has no order history,** although the spec's description
  promises history, SANs, organization and contacts. Prod, 2026-11-23: two
  orders from each of all 20 (`orderStatus`, `certificateStatus`,
  `originator`) groups added only `certificate`, `issuerCA`, `requestor`,
  `orderedDate` and `renewalNotificationsEnabled` to the list row's keys, plus
  `revocationDate`/`revocationReason` on revoked orders and
  `additionalInformation` on cancelled ones. Don't model a history field;
  re-check with `probe_access.py --order-details N`. Some `certificateStatus`
  values are bare numeric codes (`14`, `15`, `24`), so keep it a string.
- **`users/groups/members` needs `groupId` or `userIds`.** With neither it
  returns 400. A v2 `groupNumber` as `groupId` returns 404 "No such group.", and
  no list returns a v3 group id. `userIds` (a user's `userId`) works.
- **`excludeIgnored` on `orders` must be `0` or `1`.** `true`/`false` return 400.
  It changed nothing on this account (no row has `ignored` set).
- **Audit logs:** `fromDate`/`toDate` are whole days, `YYYY-MM-DD`, and filter
  correctly (a ten-year window returns the unfiltered total).
- **v3 dates are display strings, `DD Mon YYYY (HH:MM)`**, not ISO 8601, **with
  no offset marker.** v3 **order** dates are UTC: on 2026-11-23 `requestedDate`
  and `expiresOn` equalled v2 `orderDate`/`certificateExpiryDate` (UTC per #20)
  to the minute for 1,533 prod and 151 sandbox orders, July to November, so
  across a DST change. Audit `timestamp` is UTC too (portal logins at a noted
  time, both environments). All v3 models use `_V3DisplayDatetimeUTC`.
  **`discovery/certificates` is different:** its
  `expiresOn` shows `16:59`/`17:59` (prod) and `05:29` (sandbox) for
  certificates that expire 23:59:59 UTC, so it is in some local zone; don't
  generalise from it. `users/profile` has no timezone field.
- **v2 `/reports/orders` and v3 `/orders` are different sets, neither a
  superset.** On 2026-11-23: v2 1,763, v3 1,694, 1,642 in both. v3 adds
  unsubmitted portal drafts ("Auto Save"); v2 adds "Order Accepted" orders with
  no product or certificate status (mostly ACME). Every issued certificate is in
  both.
- **`reports/certificates` answers 200 with only `{"status":"success"}`.** Why is
  unresolved (permission or a missing `X-Tenant-Context`; library #35).
- **Access is per credential and can change.** The same credential got 403 on
  these paths on 2026-10-21 and 200 on 2026-11-23, cause unknown, and v3 lists
  are scoped to the token's user, so a new credential can see less while still
  answering 200. Compare `totalResults` when switching credentials.

**Capturing v3 fixtures:** audit `activity` text embeds the names of users,
groups and API credentials, including deleted ones that no list returns.
`capture_corpus.py` scrubs known names, matches the known audit templates and
fails the run with `LEAK` lines if a raw value survives. A `LEAK` means a rule
is missing; fix the sanitizer, don't commit.

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
