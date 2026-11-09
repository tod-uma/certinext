---
status: accepted
date: 2026-11-06
---

# Branch on "is emSign?", fail closed on emSign-only writes, and never auto-recover a timed-out order

## Context and problem statement

In November 2026 CertiNext added SSL.com as a second CA beside emSign, and the
vendor says more will follow. One domain name can now have one record per CA.
A non-emSign record has a different DCV shape: a fully-qualified `recordName`
and `recordValue`, plus an `options[]` list, instead of emSign's rotating
token at a host prefix. The API reports the CA with `validatedBy`, which is
present only for SSL.com. An absent value means emSign.

The emSign-only write methods, `change_dcv_method()` and `reinitiate_dcv()`, are
unsafe on any other CA. The sandbox SSL.com payload showed that a naive
`host = recordName` would publish at `_pki-validation.maine.edu.maine.edu`.

In the same week the sandbox took more than 60 s to answer
`POST /ssl-certificates` while still creating, and even issuing, the order.
That happened twice, in the v1.4.0rc1 tag pipeline. The client raised a bare
`httpx.ReadTimeout` for a certificate that existed, and re-sending the CSR
fails as a duplicate (EMS-1099).

The question: **how does the library tell CAs apart and keep emSign-only
behaviour away from other CAs, and what does it do when an order create times
out?** Tod chose to record both decisions in one ADR, because they shipped
together in v1.4.0rc2 (#38).

## Decision drivers

- The vendor will add more CAs, and the library must not treat an unknown CA as
  safe.
- A wrong DCV write or a wrong adopted order affects production certificates.
  Refusing is better than guessing.
- Existing callers that catch `httpx.HTTPError` must keep working.

## Considered options

1. **Branching:** test "is SSL.com?", or test "is emSign?" so that every other
   value takes the non-emSign path.
2. **A null `validatedBy`:** reject it as malformed, which an external review
   suggested, or read it as absent and therefore emSign.
3. **A timed-out create:** recover automatically by finding and adopting the
   order, or raise and offer recovery only when the caller opts in.

## Decision outcome

- **Branch on `is_emsign`, never on "is SSL.com".**
  - `Domain.ca` and `DcvInfo.ca` are `EMSIGN` when `validatedBy` is absent.
    Otherwise they hold the wire value upper-cased.
  - CA parameters are plain `str`, so unknown future CAs pass through.
- **emSign-only writes fail closed.**
  - `change_dcv_method()` and `reinitiate_dcv()` raise `ValueError` for any CA
    that is not emSign.
  - Before writing, they re-read `GET /domains/{id}/dcv`. They refuse if either
    that payload or the `Domain` object names another CA.
- **Null means absent, blank means unknown.**
  - An absent `validatedBy` or a JSON null means emSign.
  - A present but blank value maps to `UNKNOWN_CA`. It is not emSign, so writes
    refuse it.
  - Rejecting null was turned down because serializers commonly emit an unset
    field as null.
- **`get(name)` prefers emSign.**
  - With several records for one name and no `validated_by`, it returns the
    emSign record and logs a warning.
  - With several records and no emSign one, it raises.
- **Order creation gets its own timeout.**
  - `create_timeout` sets a 180 s read timeout for `POST /ssl-certificates`
    only. Every other request keeps 10 s connect and 60 s read.
  - A read timeout on create raises `CertiNextCreateTimeoutError`, a subclass of
    `httpx.ReadTimeout` that carries the CN and send time.
  - Connect and write timeouts are not converted. The request never fully
    arrived, so no order exists.
- **Recovery is opt-in and never guesses.**
  - `ssl.find_created_orders()` only lists candidates.
  - `ssl.recover_timed_out_create()` adopts exactly one match. It raises
    `CertiNextOrderRecoveryError` with the candidates if there are zero or
    several.
  - `issue-cert` adopts only with `--recover-on-timeout`.

### Consequences

- Good: a CA the library has never seen gets the safe non-emSign path, with no
  code change.
- Good: a stale `Domain` object cannot slip an emSign write past a CA change.
- Good: a slow vendor no longer loses an issued certificate. The caller can
  find it and adopt it.
- Bad: each emSign-only write makes one extra GET.
- Bad: if the vendor ever sends null for a non-emSign domain, it is read as
  emSign. The pre-write re-read narrows the risk but does not remove it.
- Bad: `get(name)` defaulting to emSign may be the wrong default once most
  domains are SSL.com. Revisit after the prod cutover.
- Neutral: an unattended caller that wants recovery must ask for it.

### Confirmation

- `tests/test_domains_multi_ca.py` uses a real, scrubbed sandbox SSL.com DCV
  payload. It covers CA normalisation, the null/blank split, the per-CA
  duplicates in `get()` and `get_list()`, and the refused writes.
- The timeout and recovery tests cover the error type, candidate listing, and
  adopting on exactly one match.
- The v1.4.0rc2 tag pipeline issued a sandbox certificate end to end.
- An external review (GPT-6 via Codex, 2026-11-06) found the stale-row write and
  the null/blank gaps. Both are fixed, apart from the null decision above.

## Pros and cons of the options

### Branching
- Test "is emSign?": good, because it is the only CA with the token shape, and
  new CAs default to the safe path.
- Test "is SSL.com?": bad, because each new CA would fall into emSign
  behaviour.

### A null `validatedBy`
- Read null as emSign: good, because it matches how serializers emit unset
  fields. Bad, because it trusts the vendor here.
- Reject null: good, because it is the strictest reading. Bad, because it would
  refuse ordinary emSign payloads.

### A timed-out create
- Opt-in recovery: good, because two orders for the same CN in the same minute
  are indistinguishable, and only the caller knows whether the CN is unique.
  Bad, because the caller has to write the handler.
- Automatic recovery: good, because it is convenient. Bad, because it can adopt
  the wrong order.

## Amendment 2026-11-09: how an order reaches SSL.com

This section records a fact the original decision left open. It changes none
of the decisions above.

**The API credential picks the CA. The order request does not.**

- An API credential is bound to one CA connector, which is set on the portal's
  API Credentials page. InCommon's 2026-11-06 update to the cert-users list says
  the same thing.
- `POST /ssl-certificates` has no CA field. An order goes to whichever CA the
  calling credential is bound to.
- **Never send an SSL.com code in `X-Product-Code`. To choose a product, send
  the InCommon code for it, or send no header for the default DV.** This
  bullet first said to send no header at all. It was corrected later on
  2026-11-09, after a cert-users report led to the 970/971 test below.
  - On a credential switched to SSL.com, sending SSL.com DV code `1011` in the
    header still returned 422 `[EMS-1162] Invalid Product Code`.
  - The same DV request without the header was issued in the create response
    itself, by SSL.com TLS Issuing ECC CA R1 - STG.
  - With InCommon DV code `970`, it issued an SSL.com DV certificate, and the
    orders report recorded product code `1011`. With InCommon DV Wildcard code
    `971`, it issued an SSL.com wildcard certificate, recorded as `1012`. The
    vendor translates InCommon codes into SSL.com codes product by product.
  - All were sandbox requests on 2026-11-09. The OV, UCC and 30/45/90-day
    InCommon codes have not been tried.
- **The catalog cannot show a credential's CA.** After the switch,
  `GET /catalog/products` still listed the emSign products and the `SSL.com`
  category (codes 1011–1020). The category name is the only CA marker on a
  product. It names the CA a code belongs to, not where an order sent with
  that code goes: `970` sits in the emSign category but issued from SSL.com.
  Orders are still labelled correctly by product code, because the report
  records the translated code.
- **The 2026-11-06 EMS-1162 failures came from configuration.** Those requests
  ran on a credential still bound to emSign. Widening its group scope did not
  change its CA.
- **The staging certificate:**
  - It lasted 90 days, although the request asked for `validityYears: 1`. Callers
    must not treat `validity_years` as the lifetime.
  - Its EKU carried both serverAuth and clientAuth.
  - Its chain came back already in order, and `as_pem_chain()` handled it
    unchanged.

Still open with the vendor (#39):

- Whether the InCommon-code translation is intended and will stay. Whether
  every InCommon code has an SSL.com equivalent (OV, UCC, the 30/45/90-day
  variants), and what a code without one does.
- Whether one credential can ever issue from both CAs.
- Whether prod behaves the same once SSL.com issuance is enabled there.

What this means for later work:

- Choosing a CA means choosing a credential profile. A `ca=` argument on
  `create()` cannot route an order.
- The ordering design keeps its own future ADR. It needs the vendor's answers
  first.
- A CI issuance job issues from whichever CA its credential uses. eMudhra has
  announced that emSign is leaving certificate issuance, so no emSign issuance
  check is planned.
- The emSign branching above still matters. Existing emSign domain and DCV
  records stay in the API until they age out, and the fail-closed writes
  protect them until then.

## More information

- The 2026-11-09 amendment above answers how an order is routed. The original
  2026-11-06 text left that question open.
- [MADR](https://adr.github.io/madr/): the format this record follows.
- [httpx timeouts](https://www.python-httpx.org/advanced/timeouts/): the
  connect/read split and per-request timeouts.
- [CA/Browser Forum Baseline Requirements](https://cabforum.org/working-groups/server/baseline-requirements/requirements/):
  section 3.2.2.4 lists the DCV methods (`brMethod`) that SSL.com options cite.
- Related: [0005](0005-lenient-models-validated-against-live-payload-corpus.md)
  (lenient models), [0017](0017-connection-destinations-fail-closed.md) (fail
  closed where a guess could reach production). Tracking issue: #38.

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Haiku 5.5,
> `claude-haiku-5-5`) from a conversation with Tod Detre. The design it records
> was done in earlier sessions on 2026-11-05 and 2026-11-06. The 2026-11-09
> amendment records sandbox orders run in a later session (Claude Opus 5.5,
> `claude-opus-5-5`, then Claude Haiku 5.5). Claude Opus 5.5 corrected
> its product-code rule after further sandbox orders the same day. May contain
> inaccuracies or hallucinated details; verify specifics against current
> sources before relying on them.
