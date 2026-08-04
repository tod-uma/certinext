# IDEA-010: Windows CI runner leg

- **Status:** Proposed (coordinating issue: #25)
- **Created:** 2026-08-04
- **Updated:** 2026-08-04

## Context

Raised 2026-08-04 while fixing a test-isolation bug in `test_setup_logging.py`
(the two new IDEA-009 tests silently depended on `INVOCATION_ID` being unset,
which held on GitLab's Docker-executor `python:3.12-slim` images and on local
Windows dev, but not on GitHub Actions' `ubuntu-latest` runner — its Actions
Runner process is itself launched as a systemd service, so `INVOCATION_ID`
leaks into every job's environment). The immediate bug is fixed by isolating
the tests properly, not by adding CI coverage.

While discussing that fix, adding an Ubuntu container to GitLab CI was
considered and rejected — the trigger was systemd process ancestry, not
Ubuntu-vs-slim-Debian, so a GitLab Ubuntu image wouldn't have caught it either
(GitLab's executor here runs job containers directly, no systemd in the tree).
That raised the adjacent question: both CI providers today
(`.github/workflows/ci.yml`'s `ubuntu-latest`, `.gitlab-ci.yml`'s
`python:*-slim` images) only test on Linux, while Tod's actual local dev
machine is Windows. No CI leg currently exercises Windows at all.

## The idea

Add a Windows CI leg — e.g. a `windows-latest` runner in the GitHub Actions
matrix — to catch Windows-specific bugs (path separator handling, filesystem
case-sensitivity, text encoding/line-ending differences, `keyring` backend
differences) that a Linux-only matrix can't surface, even though local dev
already runs on Windows day to day.

## Why not now

A passing idea raised alongside an unrelated bug fix, not something either
CI provider's gap is currently blocking. No known Windows-specific bug has
actually surfaced yet — this is preventive, not reactive.

## Pros

- Closes the one platform gap that's actually plausible here: local dev is
  Windows, but zero CI coverage tests that platform today.
- GitHub Actions makes this close to a one-line addition (`windows-latest` in
  the existing matrix), unlike the systemd-detection case which needed no OS
  change at all.

## Cons / costs

- Windows runners are slower and more resource-expensive on GitHub-hosted
  Actions than Linux runners.
- Unconfirmed whether GitLab's self-hosted runners at
  `gitlab.its.maine.edu` offer any Windows executor — if not, this is a
  GitHub-Actions-only leg, widening the existing gap where GitHub Actions
  already catches things GitLab CI doesn't.
- Expands the CI matrix (currently 5 Python versions × lint/typecheck/test on
  GitHub) with another dimension to maintain.

## Effort

Small on GitHub Actions if scoped to one Python version (add `windows-latest`
to the `test` job's matrix); larger if also chasing GitLab Windows runner
availability, which isn't confirmed to exist on this org's infrastructure.

## Open questions & caveats

- Does `gitlab.its.maine.edu` have any Windows-capable runner? If not, is a
  GitHub-Actions-only Windows leg still worth it on its own?
- Full matrix (all 5 Python versions × Windows) or just one representative
  version, given the cost concern above?

## Next steps

None yet — revisit if a Windows-specific bug actually surfaces, or if the
cost/benefit looks better once GitLab Windows-runner availability is known.

## References

- [GitHub Actions — using windows-latest runners](https://docs.github.com/en/actions/using-github-hosted-runners/using-github-hosted-runners/about-github-hosted-runners#supported-runners-and-hardware-resources)
- [GitLab Runner — supported executors](https://docs.gitlab.com/runner/executors/)
- [IDEA-009 — syslog/journald-aware logging mode](IDEA-009-syslog-aware-logging.md)

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Sonnet 5,
> `claude-sonnet-5`) from a conversation with Tod Detre. May contain
> inaccuracies or hallucinated details; verify specifics against current
> sources before relying on them.
