---
status: accepted
date: 2026-10-21
---

# Classify replacement need on configurable issuer, key, and chain signals; flag disagreement

## Context and problem statement

On 2026-10-20 Mozilla removed `emSign ECC Root CA - G3` from NSS (bug 2083449),
and Chrome is removing it too. That untrusts every certificate whose chain runs
through it. For InCommon certificates ordered through CertiNext, that means
ECDSA leaves issued by `InCommon Intermediate CA - OVG3C`. The ACME proxy's
certificates were already tracked elsewhere. Portal and API orders were not, and
CertiNext's own records are the only inventory that covers them.
`certinext replacement-report` answers "which currently valid certificates must
be replaced?" The question this ADR settles is **what to classify on**.

The incident brief framed it as "ECDSA key **or** issued by OVG3C". It also asked
for disagreements to be flagged rather than resolved silently, because CertiNext
said it might re-root ECC issuance onto `emSign Root CA - G1`. After such a
re-root, key type alone would be wrong.

What the API offers was checked read-only against production on 2026-10-21:

- No field gives the key algorithm. The OpenAPI spec types every order and
  certificate response as a bare `object`.
- Every orders-report row carries the issuing intermediate's name (`issuerCA`),
  so the issuer signal costs nothing.
- The chain served with a downloaded certificate includes the root. OVG3C chains
  end at `emSign ECC Root CA - G3`; OVG2C chains end at `emSign Root CA - G1`.
- The CLM endpoint `GET /api/v3/certinext/reports/certificates` has
  `filterKeyAlgorithm` and `filterIssuer` parameters, but our API account gets
  back only `{"status":"success"}`, and `GET /api/v3/certinext/orders` returns
  403. A server-side key filter is not available to us.

## Decision drivers

- Answer the real question ("does it chain to a distrusted CA?"), not a proxy
  for it.
- Never pick between conflicting evidence silently.
- The next distrust event should need a config change, not a code change.
- The library is public (GitHub, PyPI), so nothing account-specific can be
  hardcoded.
- The default run should be cheap. Downloading every certificate takes about two
  requests per certificate.

## Considered options

1. **Key type only** — classify ECDSA leaves as needing replacement.
2. **Issuer only** — classify on the report's `issuerCA`.
3. **Key or issuer, picking one when they disagree.**
4. **Server-side filtering** with the CLM report's `filterKeyAlgorithm` /
   `filterIssuer`.
5. **Three configurable signals (issuer, key, chain CA) with a `conflict`
   verdict.**

## Decision outcome

Chosen: **option 5**.

- **Signals.** Each signal is a list in `ReplacementCriteria`:
  - `issuers`: issuing-CA common names.
  - `key_types`: `EC`, `RSA`, `Ed25519`, `Ed448`, `DSA`.
  - `chain_cas`: CA common names anywhere in the served chain.

  An empty list, or `--disable-signal`, turns a signal off.
- **Verdicts.** A certificate is `replace` when *every* evaluated signal
  matches, `conflict` when evaluated signals disagree, `ok` when none match,
  and `unknown` when nothing could be evaluated.
- **Conflicts.** These are listed by default and counted **separately** from the
  "need replacing" headline. They are never folded in, and never hidden.
- **Cost.** The issuer signal is evaluated by default. Key and chain need
  `--inspect`, which downloads and parses each certificate locally.
- **Configuration.** Built-in defaults describe the eMudhra distrust. A
  top-level `[replacement]` table in `config.toml` overrides them, and per-run
  flags override that. Each layer *replaces* a signal's list rather than
  merging into it. An invalid table fails closed with exit 2, the same reasoning
  as [0017](0017-connection-destinations-fail-closed.md): silently dropping a
  criterion would under-report.

### Consequences

- Good: the full production inspection found **19 EC-key certificates issued by
  OVG2C** that chain to the trusted G1 root. They were ordered 2026-05-29 through
  2026-07-14, before the distrust. Option 1 (and any key-type-only view, such as
  the proxy's Splunk dashboard) counts them as needing replacement when they
  don't. This design surfaces them as `conflict`. Issuer and chain agreed on
  all 573 valid certificates.
- Good: a future distrust event is a `[replacement]` edit or a flag, not a code
  change.
- Good: the chain signal keeps giving the right answer through a re-root without
  any config change.
- Bad: an accurate key and chain answer costs about two requests per certificate
  and needs the `cryptography` package (the `csr` extra).
- Neutral: without `--inspect` the report is issuer-only and says so in its
  summary line.

### Confirmation

`tests/test_replacement.py` covers every verdict, including both directions of
disagreement, criteria layering, and the separate conflict count. The read-only
production verification is recorded in
[docs/plans/replacement-report.md](../plans/replacement-report.md).

## Pros and cons of the options

### 1. Key type only
- Good, because it matches how the distrust was first described ("ECC certs").
- Bad, because it is a proxy. It breaks on a re-root, and it was already wrong
  for 19 production certificates before any re-root.
- Bad, because it needs every certificate downloaded.

### 2. Issuer only
- Good, because it is free and was exact for every certificate checked.
- Bad, because it is still a proxy: it says which intermediate, not which root.
  Kept as the default *cheap* signal, not the only one.

### 3. Key or issuer, picking one on disagreement
- Bad, because a silent pick hides exactly the case the brief cared about. The
  brief rejected it explicitly.

### 4. Server-side CLM filters
- Good, because there would be no per-certificate downloads.
- Bad, because it is unavailable to our API account (empty payload / 403).
  Parked as a wishlist idea rather than chased with the vendor during the
  incident.

### 5. Configurable signals with a conflict verdict
- Good, because the chain signal answers the real question and the others
  cross-check it.
- Good, because disagreements are visible and counted.
- Bad, because there is more surface (three lists, flags, config) than a
  single-purpose check.

## More information

- [MADR](https://adr.github.io/madr/) — the format this record follows.
- [Mozilla bug 2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449) —
  the distrust that prompted this.
- [cryptography — X.509 reference](https://cryptography.io/en/latest/x509/reference/)
  and [asymmetric key types](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/)
  — how leaves and chains are parsed locally.
- [TOML v1.0.0 specification](https://toml.io/en/v1.0.0) — the `[replacement]`
  table's format.
- Related: [0017](0017-connection-destinations-fail-closed.md) (fail closed),
  [0005](0005-lenient-models-validated-against-live-payload-corpus.md) (the
  `issuerCA` field was added to `OrderRecord` under this policy), and
  [IDEA-014](../wishlist/IDEA-014-clm-certificate-report-access.md) (server-side
  filtering).

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Haiku 5.5,
> `claude-haiku-5-5`) from a conversation with Tod Detre; the design work it
> records was done earlier in the same session. May contain inaccuracies or
> hallucinated details; verify specifics against current sources before relying
> on them.
