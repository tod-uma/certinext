# IDEA-014: Request CLM certificate-report API access for server-side key filtering

- **Status:** Proposed
- **Created:** 2026-10-21
- **Updated:** 2026-10-21
- **Coordinating issue:** #35

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

1. After the incident, ask the vendor about CLM permissions for API accounts.
2. If granted, capture a corpus sample and probe the filters before modelling.

## References

- Spec snapshot (internal): `certinext-spec-snapshots`, 2026-10-21 refresh.
- [Mozilla bug 2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)

---

> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Haiku 5.5,
> `claude-haiku-5-5`) from a conversation with Tod Detre. May contain inaccuracies
> or hallucinated details; verify specifics against current sources before relying
> on them.
