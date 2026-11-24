---
status: accepted
date: 2026-11-24
---

# v3 accessors sit beside v2, expose only live-verified filters, and parse dates as UTC

## Context and problem statement

1.5 added read-only accessors for the CertiNext v3 CLM API, for the planned
Splunk app: `session.audit`, `session.users`, `session.api_credentials` and
`session.v3_orders` (library !168, hardened in !169). Three questions came up
while building them, each answered from read-only probes of prod and sandbox
on 2026-11-23:

1. **v3 orders and v2 orders overlap.** Should `v3_orders` replace
   `session.orders` (the v2 `/reports/orders` report)?
2. **The spec lists more filters than anyone has tested.** Which should the
   accessors expose? This API has rejected filters its spec documents: v2
   `pending-*` status values return 422 (certinext-zabbix#3), and
   `orders/{id}` is documented with an order history it never returns.
3. **v3 dates are display strings** (`DD Mon YYYY (HH:MM)`) with no offset.
   What time zone are they in?

## Decision outcome

### 1. v3 orders sit beside v2, not in place of it

`session.v3_orders` is a separate accessor, and `session.orders` is unchanged.
The two endpoints return different order sets (prod, 2026-11-23: v2 1,763,
v3 1,694, 1,642 in both):

- v3-only rows are unsubmitted portal drafts (`orderStatus` "Auto Save");
- v2-only rows are "Order Accepted" orders with no product code, most of
  them ACME;
- every issued certificate is in both.

Neither is a superset, so the choice of source decides which incomplete
orders a caller sees. The caller picks by what it needs to see. The Splunk app
ingests both (apps-meta plan, decision D8). v3 rows are richer (requestor,
issuer, `expiresOn`, and the `orderId` that `get()` needs).

### 2. Only filters verified against the live API are exposed

A filter becomes a keyword argument only after a probe has confirmed that it
changes the result as documented. At 1.5.0rc1 that is:

- audit: `since`/`until` (`fromDate`/`toDate`, whole days);
- v3 orders: `exclude_ignored` (sent as `0`/`1`; the API answers `true`/`false`
  with 400).

Not exposed, although the spec lists them: the audit `module` filter, and v3
orders' `orderStatus`, `certificateStatusId` and `fromDate`. Callers filter
those client-side for now (`audit.list_modules()` lists the module names).
Each gets added once `scripts/probe_access.py` or a corpus capture confirms it.

### 3. v3 dates parse as UTC-aware datetimes

v3 display dates parse through `_V3DisplayDatetimeUTC` (`models/_base.py`)
into UTC-aware `datetime` values. Evidence, prod and sandbox, 2026-11-23:

- v3 order `requestedDate`/`expiresOn` matched v2 `orderDate`/
  `certificateExpiryDate` (UTC per library #20) to the minute for 1,684
  orders, July to November, across a DST change;
- portal logins at noted times appeared in the audit log at those UTC
  minutes;
- `users/profile` has no time-zone setting.

`discovery/certificates` is the exception: its `expiresOn` is in a local zone.
It has no model, and this decision does not cover it. User, role and
credential `createdDate` values had nothing independent to check against; they
are taken as UTC because orders and audit are.

### Consequences

- Good: existing `session.orders` callers (certinext-zabbix,
  ums-certinext-scripts) are untouched, and `session.orders` stays in the 1.x
  stable surface ([ADR 0028](0028-public-api-surface.md)).
- Good: every exposed filter is known to work, so a filtered call can't return
  a silently wrong result or an unexpected 422.
- Good: callers compare and store v3 timestamps without guessing a zone.
  The planned Splunk app sets `TZ = UTC` for these sourcetypes on the same
  evidence.
- Bad: two order accessors with overlapping data. The `V3OrderAccessor`
  docstring explains which to use.
- Bad: callers who need an unexposed filter filter client-side and fetch more
  rows than they need.
- Neutral: adding a verified filter later is a backward-compatible keyword
  argument. Removing one would not be, which is the reason to verify first.
- Risk: if the vendor ever adds a per-user or per-tenant zone, the UTC
  assumption breaks silently. The corpus tests would not catch it, because
  the fixtures carry no offset either.

### Confirmation

- `tests/test_corpus_models.py` validates every v3 model against the
  committed `v3-*` fixtures.
- A new filter's MR cites the probe output that verified it.

## More information

- Splunk/apps-meta `docs/plans/ums-certinext-app.md`: Phase 0 probe table,
  finding §5 (UTC evidence), decision D8 (order sources), Phase 1 item 4.
- The `certinext-api-bugs` skill records the v3 quirks (paging parameters,
  `orders/{id}` without history, `users/groups/members` parameters).
- [Python `datetime` — aware and naive objects](https://docs.python.org/3/library/datetime.html#aware-and-naive-objects)
- [Pydantic — field validators (`BeforeValidator`)](https://docs.pydantic.dev/latest/concepts/validators/)

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Opus 5.5,
> `claude-opus-5-5`) from a conversation with Tod Detre and the records of the
> sessions that built the v3 accessors. May contain inaccuracies or
> hallucinated details; verify specifics against current sources before
> relying on them.
