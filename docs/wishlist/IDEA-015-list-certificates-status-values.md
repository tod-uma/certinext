# IDEA-015: `list-certificates --status` help advertises values that return 422

- **Status:** Proposed
- **Created:** 2026-10-21
- **Updated:** 2026-10-21
- **Coordinating issue:** #36

## Context

`certinext list-certificates --status` passes its value straight through to
`GET /api/certinext/v2/reports/orders?status=`. Its help text and the README's
examples suggest `pending-dcv` and `pending-csr`. Live probes (see the R-series
in `tests/test_probes.py`) show that the pending sub-statuses `pending-dcv`,
`pending-csr`, `pending-organization-verification`, `pending-documents` and
`pending-agreement` all return **422**. The spec's enum for this parameter is
only `issued`, `revoked`, `expired`, `cancelled`, `rejected`, and
`pending-approval`.

Found while building `replacement-report`, which uses `status=issued`.

## The idea

Make `--status` a choice limited to the values that work. That could be a typer
`Enum` like `domain-cert-count`'s, or a plain list in the help. Fix the README
examples to match.

## Why not now

It has no effect on the eMudhra replacement work, and the
`replacement-report` branch is scoped to that incident. It's also a small CLI
contract change (a free-form string becomes a closed choice), so it belongs
with a deliberate release note rather than slipped in.

## Pros

- A bad value fails at the command line with a clear message, not as a vendor 422.

## Cons / costs

- If the vendor ever fixes the pending sub-statuses, the choice has to widen
  again.

## Effort

Small: one option type, a README edit, and a regenerated help golden.

## Open questions & caveats

- Do the 422 sub-statuses still fail after the 2026-10-21 spec refresh? Re-probe
  before changing anything.

## Next steps

1. Re-run the pending-status probe.
2. Restrict the option and update the README.

## References

- [typer — Enum choices](https://typer.tiangolo.com/tutorial/parameter-types/enum/)

---

> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Haiku 5.5,
> `claude-haiku-5-5`) from a conversation with Tod Detre. May contain inaccuracies
> or hallucinated details; verify specifics against current sources before relying
> on them.
