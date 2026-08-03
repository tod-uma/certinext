---
status: accepted
date: 2026-08-03
---

# DCV inheritance eligibility is org-scoped, not gated by DNS zone boundaries

## Context and problem statement

`Domain.dcv_covering_parent()` (and `filter_needs_dcv()`, which calls it) decides
whether a domain's DCV is already covered by a verified ancestor, so callers like
`dcv-update` and `certinext-top-domains` can skip domains that don't need direct
validation. The original implementation had two problems:

1. It matched ancestors by name against every domain in the account, without
   checking organization. CertiNext inheritance is scoped per organization, so a
   same-named domain registered under a *different* organization was wrongly
   treated as covering.
2. It treated a domain having its own NS records (a DNS zone boundary) as a hard
   block on inheritance, based on InCommon cert-users mailing list testimony from
   two other institutions (Cory Gekoski, University of Maryland, and Blake
   Bourgeois, Louisiana State University; 2026-06-01).

On 2026-08-03, after renewing a top-level account domain (`example.edu`) via
CertiNext's new `mode=renew` endpoint, an NS-delegated subdomain of it
(`sub.example.edu`) — its own DNS zone — was found to have inherited DCV from
`example.edu` since at least three weeks earlier. The CertiNext portal confirmed
it explicitly: "This domain was auto-verified from its parent domain
example.edu." The account's Auto-Inheritance setting (a per-domain, portal-only
toggle, not exposed via the API) was on, overriding the NS boundary entirely.

## Decision drivers

- For InCommon-affiliated CertiNext organizations, Auto-Inheritance is on by
  default — it is opt-out, not opt-in.
- The library isn't widely used yet, so there's no real backward-compatibility
  cost to changing the default; matching CertiNext's actual current behavior
  outweighs preserving the old (now-observed-wrong) default.

## Considered options

- Keep the NS-record check as a hard, always-applied default (the original
  behavior, consistent with the June cert-users testimony).
- Make ancestor matching org-scoped, and change the NS-record check from a hard
  default to an explicit opt-in (`check_ns=True`), matching CertiNext's observed
  opt-out Auto-Inheritance behavior for InCommon organizations.

## Decision outcome

Chosen the second option: `dcv_covering_parent()` now matches ancestors only
within the same `organization_id`, and no longer checks NS records unless the
caller explicitly passes `check_ns=True`. The NS check itself (`_has_ns_records()`)
is kept, not deleted — the June cert-users testimony may still hold for accounts
where Auto-Inheritance is disabled or unavailable, and this library may see use
beyond the one account it was built for.

### Consequences

- Good: matches the actually-observed CertiNext behavior for this account (and,
  per the decision drivers, likely for InCommon organizations generally).
- Good: closes a latent cross-organization false-positive in ancestor matching
  that existed independently of the NS-boundary question.
- Bad: any caller that relied on the old default (NS boundary as a hard block)
  now needs to pass `check_ns=True` explicitly — a breaking change to
  `dcv_covering_parent()`'s and `filter_needs_dcv()`'s default behavior. Judged
  acceptable now given the library's limited adoption; would warrant a changelog
  callout and a major-version bump if adoption grows before this is revisited.

## More information

- [CertiNext v2 OpenAPI spec](https://us-api.certinext.io/v3/api-docs/certinext-v2)
  (does not document the Auto-Inheritance toggle itself, which is portal-only;
  included as the closest available reference for the Domains API this code calls)

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Sonnet 5,
> `claude-sonnet-5`) from a conversation with Tod Detre. May contain inaccuracies
> or hallucinated details; verify specifics against current sources before
> relying on them.
