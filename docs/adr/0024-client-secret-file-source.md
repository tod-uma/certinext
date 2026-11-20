---
status: accepted
date: 2026-11-20
---

# Read the client secret from a file, ranked below the keyring

## Context and problem statement

Credentials came only from an explicit argument, the OS keyring, or the
`CERTINEXT_CLIENT_ID` / `CERTINEXT_CLIENT_SECRET` environment variables.
`CertiNextSettings` explicitly dropped pydantic's `file_secret_settings`.

Headless consumers have no keyring. The systemd services (certinext-zabbix,
ums-certinext-scripts) therefore get the secret through an `EnvironmentFile`,
and an environment variable is readable in `/proc/<pid>/environ` by the same
user and by root tooling. The planned Splunk modular input has a worse
choice: `storage/passwords` can be read back over REST by any user allowed
to use the stored password. A file only the service account can read, kept
outside the application's tree, closes both gaps. It is the `_FILE`
convention that Docker secrets and systemd `LoadCredential=` use.

## Considered options

- **Read the file in each consumer.** Every consumer would repeat the
  permission check and the newline handling, and they would drift.
- **pydantic's `secrets_dir`.** It expects a directory with one file per
  field name, which does not match one path set per input or per host, and
  it does no permission check.
- **A single-file source in the library**: `client_secret_file=` and
  `CERTINEXT_CLIENT_SECRET_FILE`.

## Decision outcome

Chosen: a single-file source in the library.

**Precedence for the secret** (highest first):

1. explicit `client_secret=` or `client_secret_file=` (both at once raises
   `ValueError`);
2. the OS keyring for the active profile;
3. the file named by `CERTINEXT_CLIENT_SECRET_FILE`;
4. `CERTINEXT_CLIENT_SECRET`.

The plan that asked for this listed "init, keyring, file, env". An explicit
path ranks with the other explicit arguments rather than below the keyring,
because an argument that a stored credential silently overrides is a
surprise. A path from the environment ranks below the keyring, matching the
existing rule that stored credentials outrank the environment. It ranks
above `CERTINEXT_CLIENT_SECRET` because naming a file is the more deliberate
choice.

`certinext.session(client_secret_file=...)` accepts the same path. It never
reads the keyring, so there it is simply an alternative to `client_secret`.

**The file:**

- is opened once, and every check runs on that open handle, so it cannot be
  swapped between the check and the read;
- must be a regular file (a FIFO is refused without blocking);
- on POSIX, must have no world read or write bit. Group access is allowed so
  a service group can share it; 0400 or 0440 is recommended. Windows mode
  bits mean nothing, so there the file's ACL is the operator's job;
- loses trailing CR/LF only. Other whitespace may be part of the secret;
- must be UTF-8 and non-empty.

**Failure is closed.** A file that this source would use but cannot raises
`CertiNextSecretFileError` (a `ValueError`). It never falls through to a
lower source, because quietly authenticating with a different credential
hides the misconfiguration. A file that a higher source supersedes is never
opened, so a stale `CERTINEXT_CLIENT_SECRET_FILE` cannot break a run that
does not use it. Error messages name the path and the problem, never the
content. The `certinext` CLI turns the error into one log line and exit 1.

After resolution, `CertiNextSettings.client_secret_file` names the file the
secret was actually read from, or is `None`. The environment source is
filtered so the field is never set merely because the variable is.

### Consequences

- Consumers that use `build_session` or `CertiNextSettings` get the
  variable with no code change. Moving a systemd unit from `EnvironmentFile`
  to `LoadCredential=` plus `CERTINEXT_CLIENT_SECRET_FILE=%d/<name>` is a
  deployment change only.
- The Splunk app passes the input's configured path to
  `certinext.session(client_secret_file=...)` and does not read the file
  itself.
- No `--client-secret-file` CLI option yet. The variable covers the
  services; add the option if an interactive need appears.

## More information

- [ADR 0003](0003-adopt-pydantic-typer-httpx-settings-rich-for-1.0.md):
  pydantic-settings and the nonstandard keyring-over-env order.
- [ADR 0017](0017-connection-destinations-fail-closed.md): the fail-closed
  precedent for misconfiguration.
- [systemd credentials](https://systemd.io/CREDENTIALS/)

---
> **AI-assistant disclaimer:** Drafted by Claude (Opus 5.5) from a conversation
> with Tod Detre. May contain inaccuracies; verify specifics against current
> sources before relying on them.
