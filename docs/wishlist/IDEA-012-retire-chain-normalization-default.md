# IDEA-012: Revisit whether chain normalization should stay on by default

- **Status:** Proposed (coordinating issue: #30)
- **Created:** 2026-08-19
- **Updated:** 2026-08-19

## Context

Raised 2026-08-19 while fixing the R05 probe (#28). CertiNext used to return
the certificate chain with the root CA right after the leaf instead of last,
which breaks Windows Schannel / IIS validation — GitLab #4, vendor #134123.
`order_certificate_chain()` was added to normalize it, and MR !73 deliberately
made that sorting the default *regardless of vendor status*, with `--raw-chain`
/ `sort=False` as the opt-out.

**The vendor has since fixed the ordering.** Confirmed in both environments on
2026-07-14 (`f42427c`) and re-verified 2026-08-19: 8 of 8 sampled orders
already correctly ordered in sandbox *and* production, with production chains
three certificates deep — so this is not an artifact of trivially-short chains.

That makes the sorting, on current vendor behaviour, a no-op. The R05 probe's
own failure message proposed changing `order_certificate_chain`'s default as
part of responding to the fix. That was **declined** — see below — but the
underlying question is legitimate and worth not losing.

## The idea

Reconsider whether the default should flip from "always normalize" to
"pass through what the API returned", making sorting opt-in rather than
opt-out — or whether some middle option is better, e.g. normalizing only when
the chain is detectably out of order, or warning when normalization actually
changes something.

That last variant is the interesting one: it would turn a silent no-op into a
signal, giving a regression canary in library consumers rather than only in
this repo's probe suite.

## Why not now

Deliberately declined on 2026-08-19, for reasons that still hold:

- **Normalizing an already-correct chain costs nothing.** It is a no-op, so
  there is no bug, no wrong output, and no performance argument to answer.
- **One observed vendor fix is weak grounds for dropping a guard.** The failure
  mode it guards against is silent: a mis-ordered chain still looks like a valid
  PEM bundle and fails only later, in Windows Schannel / IIS validation, on
  someone else's server. The vendor already shipped this bug once.
- **Changing it is a behaviour change for every consumer**, not an internal
  refactor, and the current default is documented in the README and relied on by
  `--fullchain-out` / `--chain-out` / `download_chain()` / the stdout bundle.

**What would change this:** a sustained record of correct vendor ordering
(the R05 probe now guards exactly that, so the evidence accumulates on its own),
*plus* a concrete cost to the current default that does not exist today — e.g.
the `cryptography` dependency becoming genuinely unwanted for a consumer who
only needs the raw bytes, or a case where reordering actively loses information.

## Pros

- Drops a `cryptography` requirement from the default path; today sorting needs
  `certinext[csr]` and the library raises `ImportError` without it unless the
  caller uses the raw path.
- Returning exactly what the API sent is the more honest default for a client
  library, and easier to reason about when comparing against the portal.
- The warn-on-change variant would surface a vendor regression to every
  consumer, not just to this repo's sandbox probes.

## Cons / costs

- Removes a silent, free correctness guard against a bug the vendor has already
  shipped once, whose symptom appears far from this library.
- Behaviour change for existing consumers; needs a major-version or at least a
  loud deprecation, plus README and ADR updates.
- The warn-on-change variant needs a place to warn *to* that suits both library
  and CLI callers, which is more design than it first appears.

## Effort

The flip itself is small — `as_pem_chain`'s `sort` default, the CLI's
`sort = not opts.raw_chain` inversion, README, and tests. The cost is in the
decision and the migration story, not the code. The warn-on-change variant is
larger: it needs a comparison, a warning channel, and tests for both states.

## Open questions & caveats

- Would a warning-on-reorder actually be actionable for a library consumer, or
  just noise they cannot fix?
- Does any current consumer (`ums-certinext-scripts`, `certinext-zabbix`,
  Ansible-driven issuance) depend on the sorted default without saying so?
- If the default ever flips, does `--raw-chain` become redundant, or does it
  stay as the explicit spelling?

## Next steps

None. Revisit if the R05 probe shows a long clean record *and* a real cost to
the current default appears. If it is ever picked up, it needs an ADR — the
current default was a deliberate decision (MR !73), so reversing it should not
be a quiet default change.

## References

- [GitLab #4 — vendor bug: chain returned in wrong order](https://gitlab.its.maine.edu/sysadmin/python-libs/certinext/-/issues/4) (closed; vendor #134123)
- [GitLab #5 — sort chain into correct signing order, add `--raw-chain`](https://gitlab.its.maine.edu/sysadmin/python-libs/certinext/-/issues/5)
- [GitLab #28 — R05 probe canary](https://gitlab.its.maine.edu/sysadmin/python-libs/certinext/-/issues/28) (the fix that raised this)
- `certinext/_chain.py` — `order_certificate_chain()`
- `certinext/models/ssl_certificates.py` — `CertificateDownload.as_pem_chain(sort=True)`
- [Windows Schannel — certificate chain requirements](https://learn.microsoft.com/en-us/windows/win32/secauthn/certificate-chains)
- [RFC 8446 §4.4.2 — TLS 1.3 certificate_list ordering](https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.2)
- [`cryptography` — X.509 reference](https://cryptography.io/en/latest/x509/reference/)

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Opus 5,
> `claude-opus-5[1m]`) from a conversation with Tod Detre. May contain
> inaccuracies or hallucinated details; verify specifics against current
> sources before relying on them.
