# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for a security problem.** The issue
tracker is public, and a report there discloses the flaw before there is a
fix.

Instead, use either of:

- **Email** <tod.detre@maine.edu> with `certinext security` in the subject
  line.
- **GitHub private vulnerability reporting** — the "Report a vulnerability"
  button on the
  [Security tab](https://github.com/tod-uma/certinext/security/advisories/new).
  This keeps the report private until a fix ships and lets you follow it.

Useful things to include, as far as you have them: the version (`certinext
--version`), what an attacker gains, and the smallest reproduction you can
manage. A CSR, a config file with the secrets removed, or the failing command
line is usually enough. Please redact client secrets, prevetting tokens, and
order numbers before sending.

## What to expect

This library is maintained by University of Maine System staff as part of
operational work, not by a dedicated security team. Reports are handled on a
**best-effort basis with no guaranteed response time**. You will get an
acknowledgement when the report is read, and an honest answer about whether
and when it will be fixed — including "not soon" if that is the truth.

Fixes land in the most recent release. Older versions are not backported;
if you are pinned to an older release, expect to upgrade to get the fix.

## Scope

In scope — anything in this repository:

- The `certinext` library and the `certinext` CLI.
- Credential handling: keyring storage, environment variables, the OAuth2
  client-credentials flow, and how secrets are (or are not) written to logs.
- Endpoint resolution — anything that causes a command to reach a different
  CertiNext environment than the operator intended.

Out of scope:

- **The CertiNext API itself.** Vulnerabilities in the vendor's service
  belong to the vendor; report them through your own CertiNext account team.
  This project only talks to that API.
- University of Maine System infrastructure, accounts, or issued
  certificates. Those go to UMS IT security, not here.

## A note on this repository

GitHub is a **push mirror**. Development happens in a University of Maine
System GitLab instance that is not publicly reachable, so a fix may appear
here as a single squashed commit with its discussion elsewhere. This does not
affect how you report — the addresses above are monitored — but it does mean
the public commit history is not the whole story.
