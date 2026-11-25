# IDEA-014: Request read-only CLM (v3) API access

- **Status:** Proposed
- **Created:** 2026-10-21
- **Updated:** 2026-11-25 (read-only user exists; two items left with the
  vendor; see [Status](#status-2026-11-25))
- **Coordinating issue:** #35

This started as a request for the CLM certificate report alone, to give
`replacement-report` server-side key filtering. It now covers every v3 CLM read
path that a downstream Splunk ingest app (UMS_certinext) needs. The original
certificate-report reasoning below still holds; it is one part of the ask.

## Context

`certinext replacement-report` ([ADR 0018](../adr/0018-classify-replacement-on-configurable-signals.md))
has to download and parse every certificate to learn its key type, because the
public `/api/certinext/v2` API exposes no key-algorithm field. That is about two
requests per certificate (roughly 1,150 for 573 valid certificates on
2026-10-21).

The vendor's CLM module, which moved from `/api/v2/certinext/*` to
`/api/v3/certinext/*` in the 2026-10-21 spec refresh, has
`GET /api/v3/certinext/reports/certificates`. That endpoint takes
`filterKeyAlgorithm`, `filterIssuer`, `filterStatus`, and expiry-range
filters. When called read-only with our API account:

- `GET /api/v3/certinext/reports/certificates` returned only
  `{"status":"success"}`, with no rows.
- `GET /api/v3/certinext/orders` returned **403** ("Your account does not carry
  the permission required for this operation").

## The idea

Ask CertiNext whether an API-client account can be granted the permission
these CLM endpoints need. If so, add an accessor for the certificate report and
let `replacement-report` use its key and issuer filters for a cheap
key-type count, keeping local `--inspect` parsing for the chain signal and for
cross-checking.

## Scope widened (2026-11-20)

The UMS_certinext Splunk app (plan: `Splunk/apps-meta`
`docs/plans/ums-certinext-app.md`) needs to ingest audit logs, users and
roles, and API credentials, as well as orders and the certificate report. All
of these live under the v3 CLM API, which the current API account cannot read.
The current account can also issue and revoke certificates, so the ingest
should not reuse it.

The ask is therefore a **dedicated read-only API user** whose OAuth client
credential can `GET` these paths (from the 2026-11-16 prod spec snapshot, all
under `/api/v3/certinext/`):

- `audit-logs`, `audit-logs/modules`
- `users`, `users/detailed`, `users/roles`, `users/roles/{id}/permissions`,
  `users/groups/members`
- `apis` (the API-credentials list)
- `orders` and `orders/{id}` (v3, with history)
- `reports/certificates` (the original ask)

The same grant unblocks [IDEA-007](IDEA-007-users-roles-accessor.md) (#22) and
an audit-log accessor.

## Status (2026-11-25)

Most of the ask is done without a vendor grant:

- Since 2026-11-23 the existing credential reads the v3 audit-log, users,
  roles, API-credential and orders paths (they returned 403 on 2026-10-21).
- On 2026-11-24 Tod created a read-only user in the portal: a custom role
  with view permissions only, a service user in group All, and a REST
  credential. Its probe totals match the existing credential on every path
  except `apis`. The accessors shipped in 1.5.0rc1;
  [ADR 0030](../adr/0030-v3-accessors-beside-v2-verified-filters-utc-dates.md) records the v3 choices.
- `orders/{id}` returns no history, although the spec says it does.

Two items are with the vendor (ticket #191815, sent 2026-11-24, which
answered the same day that it is investigating):

1. **`apis` returns 0 for the read-only role.** The permissions that might
   allow it ("View … REST API keys") most likely also allow
   `GET /apis/{id}`, which returns credential secrets, so they are not
   granted. We asked for a list-only permission.
2. **`reports/certificates` is still empty.** It returns only
   `{"status":"success"}` for an Administrator user and for the read-only
   role, which holds "View All Certificates Report". That's true with and
   without the documented `pageNumber`/`recordLimit` parameters, and with
   no custom headers sent. On 2026-11-25 we sent the vendor the
   `x-correlation-id` of each call (see
   [IDEA-017](IDEA-017-vendor-correlation-id.md)).

## Why not now

CertiNext has its hands full with the eMudhra ECC distrust (October 2026), and
the local inspection already works: a full production run completed with 0
errors. This is an optimization, not a blocker. Pick it up once the incident
has settled, or if inspection becomes too slow or gets rate-limited as the
inventory grows.

## Pros

- No per-certificate downloads for key-type counts.
- A server-side key filter could also feed monitoring (certinext-zabbix) cheaply.

## Cons / costs

- A new accessor against an untyped (`{"type":"object"}`) response, which has to
  be validated against a live payload corpus per
  [ADR 0005](../adr/0005-lenient-models-validated-against-live-payload-corpus.md).
- Would not replace the chain signal: the report filters on key and issuer, not
  on the served chain.

## Effort

Small once access exists: an accessor, a model, corpus fixtures, and an option
in `build_report`.

## Open questions & caveats

- Is the empty payload a permission problem (like the 403), or does that
  endpoint need tenant or session headers (`X-Tenant-Context`) that API clients
  never send?
- Does the CLM report cover ACME-issued certificates as well as portal orders?

## Next steps

1. Wait for the vendor's answer on #191815 (both items in
   [Status](#status-2026-11-25)).
2. If `reports/certificates` starts returning rows, capture a corpus sample
   before modelling, then add the accessor and the `replacement-report`
   option described above.
3. If a list-only API-credentials permission appears, add it to the
   read-only role and re-probe `apis`.

## References

- Spec snapshot (internal): `certinext-spec-snapshots`, 2026-10-21 refresh.
- [Mozilla bug 2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)

---

> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Haiku 5.5,
> `claude-haiku-5-5`) from a conversation with Tod Detre. May contain inaccuracies
> or hallucinated details; verify specifics against current sources before relying
> on them.
