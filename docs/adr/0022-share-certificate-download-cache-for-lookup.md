---
status: accepted
date: 2026-11-16
---

# Share certificate downloads for SAN listing and exact certificate lookup

## Context and problem statement

The cert-users threads "Report modification request" and "How to extract
additional contact info from a cert" request SAN exports and access to
certificate contact information. Tod requested SAN listing and identifier
lookup using replacement-report's existing download cache.

ADR 0019 originally required a separate cache for each command. Sharing the
same immutable certificate payload avoids downloading every certificate again.

## Considered options

- Keep ADR 0019's separate per-command download caches.
- Share its existing download entries while reading status and contacts live.

## Decision outcome

Chosen: share the existing `replacement-inspect/{production,sandbox}` entries
among replacement-report, `list-certificates --sans`, and
`lookup-certificate`. This supersedes only ADR 0019's command-local ownership
rule; its opt-in, raw-payload, order-and-serial key, clean-result, privacy,
and failure rules still apply. ADR 0021's 30-day default still applies.

- Cache switches and prompting are shared. No flags in a noninteractive run
  means no cache. Explicit refresh, directory, or maximum age implies cache.
- Every list or lookup reads the orders report live, with its existing
  pagination behavior and account visibility limits. Lookup imposes no status
  or validity filter. No completeness claim extends beyond the returned report.
- SAN enrichment preserves every report row, represents unknown SANs as `null`,
  verifies the parsed leaf serial against the live row when available, and
  never caches a row without a serial. A bad cache entry falls back to live.
  SAN listing does not prune the shared cache; expiry still causes a miss.
- Listing remains fast unless `--sans` is selected. CSV encodes all SANs as
  a JSON array per cell, with no shortened `+N` representation.
- Lookup uses literal identifiers (SAN, CN, order, serial, request number),
  returns every match, and exposes unknown SANs and scan failures. SAN and auto
  scan all certificate-bearing rows; explicit report-field lookups skip downloads.
  Wildcard SANs are literal identifiers, not hostname-coverage rules.
- Matched order details are always fetched live. Raw detail fields are
  preserved rather than guessing delegation/contact response shapes from
  request schemas. Missing fields mean unknown availability, not no contacts.
- Lookup exits 1 for partial results and 3 for a no-match result with no known
  search failures. Listing exits 1 on inspection failures after emitting rows.
- The library operations are reusable independently of the CLI, keeping the
  future TUI and MCP ideas inexpensive. No general HTTP caching is introduced.

### Consequences

Warm SAN scans reuse replacement-report downloads. Cold scans are sequential,
which avoids introducing shared-session concurrency and can be slow. Mutable
contact information cannot be inferred from a cache hit or an issued certificate.
The live detail endpoint's inclusion of UI delegation fields remains unverified;
there is no UI scraping or inferred contact association fallback.

### Confirmation

Offline tests cover shared-cache reuse, serial mismatches, all SAN types,
report-field lookup, ambiguity, incomplete results, CSV output and live detail
reads. A live API check is still needed to establish contact field availability
for each vendor pipeline and account permission scope.

## More information

- [ADR 0019](0019-command-local-opt-in-inspection-cache.md)
- [ADR 0021](0021-replacement-report-defaults-to-ca-signal.md)
- [cryptography X.509 reference](https://cryptography.io/en/latest/x509/reference/)
- [Python CSV reference](https://docs.python.org/3/library/csv.html)

---
> **AI-assistant disclaimer:** Drafted by Codex (GPT-6) from a conversation with
> Tod Detre. May contain inaccuracies; verify specifics against current sources
> before relying on them.
