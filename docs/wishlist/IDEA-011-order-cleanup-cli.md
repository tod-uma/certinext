# IDEA-011: `orders cleanup` CLI command for cancelling stale orders

- **Status:** Proposed
- **Created:** 2026-08-07
- **Updated:** 2026-08-07

## Context

Both CertiNext accounts accumulate orders that were started and never
finished — submitted, then abandoned before the certificate was issued or
downloaded. A read-only measurement of the **production** account on
2026-08-07 found 24 orders in `Order Accepted` with no certificate
(median age 63 days, 18 of them older than 30 days) and 13 with a
certificate that was never downloaded.

This backlog is not cosmetic. It is currently the documented blocker on
enabling order-health notifications in `certinext-zabbix` (see that
repo's `docs/deployment.md`): the stuck-order triggers fire immediately
against it, so nothing can be alerted on until it is cleared. Clearing it
today means finding each order by hand in the portal.

The same measurement showed what the junk looks like: a single host
carried four orders placed within 13 minutes of each other — three
cancelled retries and one that succeeded — which is the signature of a
script retrying against a failing call.

Cleanup is a vendor-API operation, not a monitoring concern, so it
belongs in this library rather than in `certinext-zabbix`. That also
makes it useful to anyone using CertiNext without Zabbix, which is the
larger audience for this package.

## The idea

An `orders cleanup` command that finds stale orders from the orders
report and cancels them, with a dry-run default.

Feasibility is already confirmed against the live prod API (read-only
GETs, 2026-08-07):

- `OrderRecord.order_number` from `/reports/orders` **is** the `orderId`
  that `SslAccessor.get()` accepts — `sess.ssl.get(order.order_number)`
  returns a live order exposing `.cancel()` and `.revoke()`.
- `request_number` is **not** a lookup key; `sess.ssl.get()` returns 404
  for it.
- So the report row → cancellable order path needs no new endpoint work.
  `cancel()`, `reject()`, and `revoke()` already exist on the order model.

Sketch:

- Select candidates from the orders report by bucket and age — e.g.
  `Order Accepted` with no certificate, older than N days.
- Dry-run by default; print what would be cancelled and require an
  explicit flag to act.
- Filter by `originator` and/or common name, so a sweep can target one
  broken client's retry storm.

## Why not now

The session that surfaced this was scoped to settling trigger strategy in
`certinext-zabbix`, and this is a different repo and a materially larger
piece of work than it first appears — it is a destructive, hard-to-reverse
bulk operation against shared vendor state, which is design work, not a
quick command.

**What would change this:** a decision to clear the prod backlog
repeatably rather than once by hand — most likely when order-health
notifications are actually being enabled and the manual clear has to
happen anyway.

## Pros

- Turns "Tod clears the backlog by hand in the portal" into a repeatable,
  reviewable operation, and unblocks order-health alerting.
- No new API surface required — the primitives exist and the identifier
  mapping is verified.
- Useful to CertiNext users who don't run Zabbix.

## Cons / caveats

- **Destructive and hard to reverse.** A bulk cancel against prod is
  exactly the class of operation that needs a dry-run default, an
  explicit age threshold, and an explicit confirmation flag.
- **`cancel` and `revoke` must not share a command.** Cancelling a stale
  unissued order is low-risk; revoking an issued certificate breaks
  something in production. They should not be reachable by the same
  `--yes`.
- **Cancelling does not delete the row.** It flips `order_status` to
  `Order Cancelled`, which `certinext-zabbix` buckets as *failed*. Its
  `failed_recent` metric filters on `order_date` rather than cancellation
  date, so sweeping *old* junk will not spike it — that is exactly why a
  sandbox cleanup on 2026-08-07 left `failed_recent` at 0. Cancelling a
  *recent* stuck order would spike it.
- Cleanup does **not** improve `certinext.orders.expiring`; of the 68
  counted in prod, 55 are healthy current certificates and 10 are residue
  of successful renewals. See that repo's ADR 0008.

## References

- [CertiNext API — order cancel/reject/revoke](https://us-api.certinext.io)
  (endpoints `/ssl/{orderId}/cancel`, `/reject`, `/revoke`; see the
  vendor OpenAPI spec tracked in `certinext-spec-watch`)
- `certinext/models/ssl_certificates.py` — `cancel()`, `reject()`,
  `revoke()` on the order model
- `certinext-zabbix` `docs/deployment.md` — records the backlog as the
  prerequisite for order-health notifications
- [IDEA-008](IDEA-008-root-level-cli-option-set.md) — shared CLI option
  set; a new command should land after or alongside it

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Sonnet 5,
> `claude-sonnet-5`) from a conversation with Tod Detre on 2026-08-07.
> May contain inaccuracies or hallucinated details; verify specifics
> against current sources before relying on them.
