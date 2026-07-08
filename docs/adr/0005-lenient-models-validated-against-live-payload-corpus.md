---
status: accepted
date: 2026-07-02
---

# Lenient response models, validated against a captured live-payload corpus

## Context and problem statement

The CertiNext API drifts silently and its own documentation disagrees with
itself: the OpenAPI spec omits enum values that the Postman collection and
the live API use (GitLab issue #6, vendor #135290); DCV payloads use
different key names across endpoints; list endpoints alternate between bare
arrays and wrapper objects; boolean flags arrive as the strings `"1"`/`"0"`.
The 0.3.x dict-and-property pattern tolerated all of this implicitly.
Pydantic's default fail-fast validation would convert every one of these
handled quirks into a production runtime crash. What is the validation
policy for 1.0's models, and what is their source of truth?

## Decision drivers

- Other institutions report different bugs; the vendor patches without
  notifying us — the contract observed today is not the contract next month.
- A model generated from the OpenAPI spec would bake known-wrong contracts
  into 1.0 (issue #6 proves the spec is not authoritative).
- Existing test fixtures are hand-anonymized approximations, not evidence.

## Considered options

- Lenient models + committed corpus of captured live payloads (sandbox +
  prod) as ground truth, spec/Postman as cross-checks
- Strict models generated from the OpenAPI spec
- Keep raw dicts (no models)

## Decision outcome

Chosen: **lenient models + live corpus**. Ratified 2026-07-02. Concretely:

- Models use `model_config = ConfigDict(extra="allow")`; unknown fields are
  retained, never fatal.
- Enum-like fields accept unknown values: typed to fall back to the raw
  string (with a logged warning), never `ValidationError`, while the known
  values keep their typed form. No enum value is added or removed on spec or
  Postman evidence alone (issue #6 stays open until the vendor answers).
- Key-name variance is modeled with
  [`AliasChoices`](https://docs.pydantic.dev/latest/concepts/alias/) fallback
  chains, mirroring the 0.3.x fallbacks (e.g. `txtToken`/`fileToken`/`token`).
- The raw payload stays reachable from every model (the `as_dict()` escape
  hatch survives).
- Ground truth is a **committed corpus of sanitized captured payloads** from
  both sandbox and production (read-only GETs), recaptured by a re-runnable
  probe suite (phase 0 plan). Every model must parse the entire corpus in
  unit tests. The probe suite doubles as the regression sentinel for future
  vendor drift.

### Consequences

- Good: vendor drift degrades into logged warnings and probe-suite failures
  instead of production crashes.
- Good: "did the vendor silently fix/break X?" becomes a probe run, not an
  archaeology session.
- Bad: leniency can mask real regressions — the probe suite and healthcheck
  are the compensating strictness; they, not the models, are where failures
  should surface loudly.
- Bad: corpus sanitization is a manual review gate before each commit of new
  fixtures (domain names, org identifiers).

### Confirmation

CI runs a corpus-parse test over every fixture; the probe suite exists and is
documented as re-runnable against both environments.

## Pros and cons of the options

### Lenient models + corpus (chosen)

- Good, because it encodes the observed reality of this vendor rather than a
  contract the vendor doesn't honor.
- Bad, because fixtures require sanitization discipline.

### Strict models from the OpenAPI spec

- Good, because zero-effort model generation.
- Bad, because the spec is demonstrably wrong (issue #6) — strictness against
  a wrong contract means crashing on valid live data.

### Keep raw dicts

- Good, because nothing can fail to validate.
- Bad, because it abandons the typing/validation goal of the 1.0 refactor
  entirely.

## More information

- [pydantic — `extra` behavior](https://docs.pydantic.dev/latest/concepts/models/#extra-data)
- [pydantic — alias & `AliasChoices`](https://docs.pydantic.dev/latest/concepts/alias/)
- GitLab issue #6 (enum discrepancies, vendor #135290); ADR 0002 (issue
  tracking convention)
- Plan: `docs/plans/pydantic-typer-refactor/phase-0-guardrails-and-probe-suite.md`

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Fable 5,
> `claude-fable-5`) from a conversation with Tod Detre. May contain
> inaccuracies or hallucinated details; verify specifics against current
> sources before relying on them.
