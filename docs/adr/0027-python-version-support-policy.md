---
status: accepted
date: 2026-11-20
---

# Python version support: deprecate before removing, on named triggers

## Context and problem statement

Python 3.10 reached upstream end of life in October 2026. certinext still
declares `requires-python = ">=3.10"` and tests 3.10 in CI. Python 3.15 is
final, and 3.16 is in alpha.

Dropping a Python version is a compatibility break, and the cost lands on
whoever deploys certinext, not on this repository. Raising
`requires-python` gives a host still on 3.10 (for example Ubuntu 22.04's
system Python) no warning: its next install or upgrade simply fails, or
quietly stays on an old release. We do not have a verified list of which
deploy hosts run which Python, so a hard drop would be a guess.

Keeping 3.10 costs little today: one CI job, the `tomli` fallback in
`_config.py`, mypy checking as 3.10, and avoiding 3.11+ features such as
`tomllib`, `enum.StrEnum` and `typing.Self`.

## Considered options

- **Drop 3.10 now.** Simplest code, but breaks unknown hosts without
  warning.
- **Keep 3.10 indefinitely.** No breakage, but the trade-off never gets
  revisited, and the cost grows as dependencies move on.
- **Deprecate now, remove on a named trigger.** Warn the people running
  it, and write down in advance what makes removal worth it.

## Decision outcome

Chosen: deprecate now, remove on a named trigger.

### Deprecation (from 1.5.0)

- 3.10 stays in `requires-python`, the classifiers and the CI matrix, and
  stays fully supported.
- Importing certinext on 3.10 emits a `FutureWarning`. Not a
  `DeprecationWarning`: Python hides those by default outside `__main__`,
  and the people who need to see this run scheduled jobs, not test suites.
  The warning lands in those jobs' logs, which is how an unknown 3.10 host
  shows up before removal breaks it. `tests/test_python_support.py` checks
  that it fires on 3.10 and nowhere else.
- The README and release notes say 3.10 is deprecated.

### Removal triggers

Remove 3.10 support when **any** of these holds:

1. **A dependency we need drops 3.10.** A security fix or a feature we
   want is only available in a release that requires 3.11+. Until then,
   installers keep 3.10 hosts on older dependency versions, which is
   acceptable only while those versions are not vulnerable.
2. **We want a 3.11+ feature** enough to remove compatibility code
   (`tomllib`, `StrEnum`, `Self`, `ExceptionGroup`/`except*`, and so on).
3. **No deploy host runs 3.10,** checked on the hosts themselves, not from
   inventory files or memory.
4. **CI can no longer test 3.10:** the `python:3.10-slim` image is
   withdrawn, or uv or a test dependency stops supporting it.

Removal is a minor release that says so in its release notes. It drops
3.10 from `requires-python`, the classifiers, both CI matrices
(`.gitlab-ci.yml`, `.github/workflows/ci.yml`), the `tomli` dependency and
fallback import, mypy's `python_version`, the warning and its test, and
the README note.

### Adding new versions

- The next Python release is tested early in an optional job: GitLab's
  `unit-test-next` on the `python:<next>-rc-slim` tag with
  `allow_failure: true`, and GitHub's matrix entry with
  `experimental: true` (`continue-on-error`). It is expected to fail until
  dependencies with compiled code (pydantic-core, cryptography) ship wheels
  for it, and never blocks a merge.
- Once that version is final and the job passes, move it into the required
  matrix and add its classifier. 3.15 went this way in this change.

### Consequences

- One more CI job per pipeline while 3.10 and the next release are both
  tested.
- 3.10 users see a warning in their logs on every run until they upgrade
  or support is removed. That is the intended effect.
- Removal becomes a check against this list, not a fresh debate.

## More information

- [PEP 619: Python 3.10 release schedule](https://peps.python.org/pep-0619/)
- [ADR 0006](0006-tomlkit-for-config-writes-tomllib-for-reads.md) (the
  `tomllib`/`tomli` read path that removal simplifies)

---
> **AI-assistant disclaimer:** Drafted by Claude (Haiku 5.5) from a conversation
> with Tod Detre. May contain inaccuracies; verify specifics against current
> sources before relying on them.
