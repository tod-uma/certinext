# Copyright 2026 University of Maine System
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Public CLI-support layer: connection resolution, session building, logging.

This module is the supported surface for scripts that build their own
CertiNext sessions with the same credential and endpoint resolution the
bundled ``certinext`` CLI uses (ADR 0004). It replaces the private
``certinext._cli`` argparse helpers; unlike those, nothing here depends on
argparse, typer, or any specific argument-parsing library.

Typical use::

    from certinext.cli_support import build_session, resolve_connection

    conn = resolve_connection(sandbox=True)
    sess = build_session(conn)

Resolution rules (unchanged from 0.3.x):

- **Endpoints** (:func:`resolve_connection`): explicit URL argument →
  ``--sandbox`` flag → the active profile's stored connection settings →
  built-in production endpoints.
- **Credentials** (:func:`build_session`): explicit argument → OS keyring →
  environment variable → interactive prompt (see
  :class:`certinext.settings.CertiNextSettings` for the first three).
"""

import getpass
import logging
import os
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, NoReturn

import structlog

import certinext
from certinext._config import ConfigError, connection_config
from certinext._keyring import keyring_available, no_keyring_help
from certinext.exceptions import CertiNextAPIError
from certinext.settings import CertiNextSettings

log = structlog.get_logger()


class CredentialsNotFoundError(RuntimeError):
    """Raised by :func:`build_session` when credentials are absent and prompting is suppressed.

    Callers that pass ``prompt=False`` should catch this to handle the
    no-credentials case without blocking on interactive input.
    """


def prompt_stderr(prompt: str) -> str:
    """Prompt on stderr and read a line from stdin.

    Built-in ``input()`` writes its prompt to stdout, which corrupts piped
    output for CLIs that print certificates or JSON to stdout. This writes
    the prompt to stderr instead, so ``certinext issue-cert ... > cert.pem``
    style redirection never captures prompt text.

    Args:
        prompt: Text to display, including any trailing punctuation/space
            (e.g. ``"Continue? [y/N]: "``).

    Returns:
        The line read from stdin with the trailing newline stripped.

    Raises:
        EOFError: If stdin is closed before a line is read.
    """
    print(prompt, end="", file=sys.stderr, flush=True)
    return input()


def require_credential(
    value: str | None,
    env_var: str,
    prompt: str,
    secret: bool = False,
    allow_prompt: bool = True,
) -> str:
    """Return an already-resolved credential, or fall back to an interactive prompt.

    The CLI-arg → keyring → env resolution happens in
    :class:`~certinext.settings.CertiNextSettings`; this handles the final
    step of the precedence order — prompting — plus the error paths when
    prompting is suppressed or impossible. Secrets are read with getpass so
    they are not echoed to the terminal.

    Args:
        value: The credential as resolved by settings, or None if absent.
        env_var: Environment variable name to mention in messages.
        prompt: Text shown when prompting interactively.
        secret: If True, use getpass so input is not echoed.
        allow_prompt: If False, raise :exc:`CredentialsNotFoundError` instead
            of prompting when the credential was not resolved. Use this in
            setup scripts that want to try the API but handle missing
            credentials gracefully.

    Returns:
        The resolved credential string.

    Raises:
        CredentialsNotFoundError: If ``allow_prompt`` is False and the
            credential was not resolved.
        RuntimeError: If the credential is unset and stdin is not a TTY, so
            no interactive prompt is possible.
    """
    if value:
        return value
    if not allow_prompt:
        raise CredentialsNotFoundError(
            f"{prompt} is not configured. "
            f"Set {env_var} or run 'certinext setup keyring' to store it."
        )
    if not sys.stdin.isatty():
        if keyring_available():
            raise RuntimeError(
                f"{prompt} is required but stdin is not a TTY. "
                f"Set {env_var} or store the credential in the keyring."
            )
        raise RuntimeError(
            f"{prompt} is required but stdin is not a TTY, and no usable "
            f"OS keyring backend was found. Set {env_var}.\n\n" + no_keyring_help()
        )
    if secret:
        return getpass.getpass(f"{prompt}: ")
    return prompt_stderr(f"{prompt}: ")


@dataclass(frozen=True)
class ResolvedConnection:
    """A fully resolved connection target for :func:`build_session`.

    Attributes:
        base_url: Concrete CertiNext API base URL.
        token_url: Concrete OAuth2 token endpoint URL.
        sandbox: The *effective* sandbox choice (CLI flag or profile config),
            so :attr:`certinext.session.CertiNextSession.sandbox` and portal
            hints are correct.
        profile: The credential profile for keyring lookups, or None for the
            default profile.
    """

    base_url: str
    token_url: str
    sandbox: bool
    profile: str | None


def resolve_connection(
    profile: str | None = None,
    sandbox: bool = False,
    base_url: str | None = None,
    token_url: str | None = None,
) -> ResolvedConnection:
    """Resolve the connection endpoint and effective profile from CLI-level inputs.

    Fills in the connection endpoint from (in priority order):

    1. An explicit ``base_url`` / ``token_url`` argument.
    2. The ``sandbox`` flag (the sandbox endpoints).
    3. The active profile's stored connection settings — an explicit
       ``base_url`` / ``token_url``, or ``sandbox = true`` — from the config
       file (see :func:`certinext._config.connection_config`).
    4. The built-in production endpoints.

    As in 0.3.x, the bare ``sandbox`` flag also defaults the profile to
    ``'sandbox'`` so keyring lookups find sandbox credentials; a profile
    configured with ``sandbox = true`` keeps its own name.

    Args:
        profile: Explicit profile name from the CLI, or None.
        sandbox: The ``--sandbox`` CLI flag.
        base_url: Explicit ``--base-url`` CLI value, or None.
        token_url: Explicit ``--token-url`` CLI value, or None.

    Returns:
        A :class:`ResolvedConnection` with concrete URLs and the effective
        sandbox flag and profile.
    """
    cli_sandbox = bool(sandbox)

    # Mirror build_session's profile precedence so the stored connection
    # settings are read for the profile that will actually be used.
    lookup_profile = profile
    if lookup_profile is None and cli_sandbox:
        lookup_profile = "sandbox"
    if lookup_profile is None:
        lookup_profile = os.environ.get("CERTINEXT_PROFILE") or None

    try:
        conn, warnings = connection_config(lookup_profile)
    except ConfigError as exc:
        # A broken config file should not silently send traffic to production;
        # surface it and fall back to no stored connection settings.
        log.warning("Ignoring connection settings", error=str(exc))
        conn, warnings = {}, []
    for warning in warnings:
        log.warning("certinext config", warning=warning)

    cfg_sandbox = bool(conn.get("sandbox", False))
    cfg_base = conn.get("base_url")
    cfg_token = conn.get("token_url")

    if base_url is not None:
        resolved_base = base_url  # explicit CLI value wins
    elif cli_sandbox:
        resolved_base = certinext.SANDBOX_BASE_URL
    elif cfg_base is not None:
        resolved_base = str(cfg_base)
    elif cfg_sandbox:
        resolved_base = certinext.SANDBOX_BASE_URL
    else:
        resolved_base = certinext.BASE_URL

    if token_url is not None:
        resolved_token = token_url  # explicit CLI value wins
    elif cli_sandbox:
        resolved_token = certinext.SANDBOX_TOKEN_URL
    elif cfg_token is not None:
        resolved_token = str(cfg_token)
    elif cfg_base is not None:
        # Custom base_url without a matching token_url — keep the production
        # token endpoint; setup defaults always writes the two together.
        resolved_token = certinext.TOKEN_URL
    elif cfg_sandbox:
        resolved_token = certinext.SANDBOX_TOKEN_URL
    else:
        resolved_token = certinext.TOKEN_URL

    # Only the bare CLI flag auto-selects the 'sandbox' keyring profile; a
    # named profile with sandbox = true keeps its own credentials.
    effective_profile = profile
    if cli_sandbox and profile is None:
        effective_profile = "sandbox"

    # Effective sandbox flag: a profile that targets sandbox counts even
    # without the CLI flag, so sess.sandbox and portal hints stay right.
    return ResolvedConnection(
        base_url=resolved_base,
        token_url=resolved_token,
        sandbox=cli_sandbox or cfg_sandbox,
        profile=effective_profile,
    )


def _reorder_log_keys_processor(extra_priority_keys: Sequence[str]) -> structlog.typing.Processor:
    """Build a processor that reorders event dict keys for consistent JSON output.

    Puts fixed fields first so every line reads: timestamp → level → event → logger
    (foreign only) → any extra priority keys → remaining fields.

    Args:
        extra_priority_keys: Caller-specific keys (e.g. ``correlation_id``, ``pid``)
            ordered right after the built-in priority keys.

    Returns:
        A structlog processor performing the reordering.
    """
    priority = ["timestamp", "level", "logger", "event", *extra_priority_keys]

    def _reorder(_logger: Any, _method: str, event_dict: structlog.typing.EventDict) -> structlog.typing.EventDict:
        reordered: dict[str, Any] = {k: event_dict[k] for k in priority if k in event_dict}
        reordered.update({k: v for k, v in event_dict.items() if k not in priority})
        return reordered

    return _reorder


def _drop_keys_processor(keys: Sequence[str]) -> structlog.typing.Processor:
    """Build a processor that removes the given keys from every event dict.

    Args:
        keys: Event dict keys to remove when present.

    Returns:
        A structlog processor performing the removal.
    """

    def _drop(_logger: Any, _method: str, event_dict: structlog.typing.EventDict) -> structlog.typing.EventDict:
        for key in keys:
            event_dict.pop(key, None)
        return event_dict

    return _drop


class LogFormat(str, Enum):
    """Non-interactive (cron/redirected) structlog output format.

    Interactive (TTY) output always uses :class:`structlog.dev.ConsoleRenderer`
    regardless of this setting — it only selects the machine-readable format
    used once stderr is redirected.
    """

    LOGFMT = "logfmt"
    """``key=value`` pairs (via :class:`structlog.processors.LogfmtRenderer`).

    The default: syslog forwarders and Splunk auto-extract ``key=value`` pairs
    out of the box (``kv_mode=auto``), even with a syslog header in front of
    the payload. JSON does not get that treatment unless the sourcetype is
    explicitly configured for it, because the *whole* event, header included,
    has to be valid JSON for auto-extraction to fire.
    """

    JSON = "json"
    """One JSON object per line, via :class:`structlog.processors.JSONRenderer`."""


class DebugLogFormat(str, Enum):
    """On-disk format for the ``debug_log_path`` sidecar file.

    Deliberately separate from :class:`LogFormat`: the two streams have
    different consumers and different correct defaults, so sharing one enum
    would leak console-only values into the machine-readable stderr stream's
    option surface (ADR 0012).
    """

    CONSOLE = "console"
    """Human-readable lines via :class:`structlog.dev.ConsoleRenderer`.

    The default. This file is not ingested into Splunk (ADR 0012) - its only
    reader is a person on an SSH session, and real multi-line tracebacks are
    the whole reason the file exists. Rendered with colors off and
    :func:`structlog.dev.plain_traceback` pinned; see :func:`setup_logging`.
    """

    JSON = "json"
    """One JSON object per line, via :class:`structlog.processors.JSONRenderer`.

    The pre-ADR-0012 default, retained so that turning on log ingestion later
    doesn't require re-litigating the format. Tracebacks embed as a single
    escaped ``exception`` string, which parses cleanly but reads badly.
    """


class LogMode(str, Enum):
    """Whether non-interactive output drops the redundant ``timestamp``/``pid`` fields.

    Journald/syslog already stamps every line it forwards with a timestamp
    and PID before it reaches Splunk (see ADR 0007's own example), so the
    structlog-level ``timestamp`` field and any ``pid`` bound via
    :func:`structlog.contextvars.bind_contextvars` duplicate that (IDEA-009).
    """

    AUTO = "auto"
    """Drop the fields when a systemd unit is detected (:func:`_systemd_invoked`); keep them otherwise."""

    SYSLOG = "syslog"
    """Always drop the fields - for cron output piped through ``logger(1)``, which has no detectable env signal."""

    VERBOSE = "verbose"
    """Always keep the fields, even under systemd - for interactively debugging a unit's output."""


def _systemd_invoked() -> bool:
    """Whether the current process was invoked by systemd.

    Checks the two env vars systemd sets: ``INVOCATION_ID`` (every
    systemd-invoked run) and ``JOURNAL_STREAM`` (set only when stdout/stderr
    feed journald directly). Either one is sufficient.

    Returns:
        True if either env var is present.
    """
    return bool(os.environ.get("INVOCATION_ID") or os.environ.get("JOURNAL_STREAM"))


def _effective_syslog_mode(log_mode: LogMode) -> bool:
    """Resolve a :class:`LogMode` to whether syslog-redundant fields should be dropped.

    Args:
        log_mode: The requested mode.

    Returns:
        True if ``timestamp``/``pid`` should be dropped from non-interactive output.
    """
    if log_mode is LogMode.SYSLOG:
        return True
    if log_mode is LogMode.VERBOSE:
        return False
    return _systemd_invoked()


def setup_logging(
    verbose: int,
    *,
    log_format: LogFormat = LogFormat.LOGFMT,
    log_mode: LogMode = LogMode.AUTO,
    debug_log_path: Path | None = None,
    debug_log_format: DebugLogFormat = DebugLogFormat.CONSOLE,
    extra_priority_keys: Sequence[str] = (),
    console_quiet_keys: Sequence[str] = (),
    quiet_loggers: Sequence[str] = (),
) -> None:
    """Route all output — structlog and third-party stdlib — through a shared renderer.

    Uses structlog.stdlib.ProcessorFormatter as the single stdlib handler formatter so
    native structlog calls and foreign stdlib records (httpx, httpcore, keyring) both
    pass through the same renderer.

    TTY (interactive): ConsoleRenderer with local HH:MM:SS timestamps.
    Non-TTY (cron/redirect): ``log_format`` (default logfmt) with full ISO UTC
    timestamps, consistent key order (timestamp → level → logger → event → ...).

    Args:
        verbose: Verbosity count from -v flags (0=INFO, 3+=DEBUG, 4+=third-party DEBUG).
        log_format: Non-interactive output format — see :class:`LogFormat`.
            Ignored when stderr is a TTY.
        log_mode: Whether to drop the ``timestamp``/``pid`` fields from
            non-interactive output as redundant with journald/syslog's own
            stamping — see :class:`LogMode`. Ignored when stderr is a TTY.
        debug_log_path: When set, append a DEBUG-level log to this path
            independent of ``verbose`` — every event, including full
            tracebacks, regardless of the visible verbosity level. No
            default (there is no library-level log directory); rotation is
            logrotate's job, not this function's. Callers should pass their
            own env-var-resolved path (e.g. ``CERTINEXT_ZABBIX_DEBUG_LOG``).
        debug_log_format: On-disk format for that file — see
            :class:`DebugLogFormat`. Defaults to human-readable console
            output, because the file is deliberately not ingested into Splunk
            (ADR 0012) and its only reader is a person over SSH. Ignored when
            ``debug_log_path`` is None.
        extra_priority_keys: Additional event dict keys (e.g. run-level
            ``correlation_id``/``pid`` contextvars) placed right after the built-in
            keys in non-interactive output, so cron log lines keep a stable field order.
        console_quiet_keys: Event dict keys suppressed from *interactive* (TTY)
            output at verbosity 0. Use for run-context fields that repeat
            unchanged on every line; ``-v`` and above shows them, and
            non-interactive output always carries them.
        quiet_loggers: Additional stdlib logger names capped at WARNING below
            ``-vvvv``, alongside the built-in httpx/httpcore/keyring set (e.g.
            ``filelock``, ``nm.wire``).
    """
    level = logging.DEBUG if verbose >= 3 else logging.INFO
    interactive = sys.stderr.isatty()

    ts_fmt = "%H:%M:%S" if interactive else "iso"
    pre_chain: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt=ts_fmt, utc=not interactive),
    ]
    foreign_pre_chain: list[Any] = [
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.contextvars.merge_contextvars,
        structlog.processors.TimeStamper(fmt=ts_fmt, utc=not interactive),
    ]

    if interactive:
        renderer: Any = structlog.dev.ConsoleRenderer()
        final_processors: list[Any] = [
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.format_exc_info,
        ]
        if console_quiet_keys and verbose < 1:
            final_processors.append(_drop_keys_processor(console_quiet_keys))
        final_processors.append(renderer)
    else:
        renderer = (
            structlog.processors.JSONRenderer()
            if LogFormat(log_format) is LogFormat.JSON
            else structlog.processors.LogfmtRenderer()
        )
        final_processors = [
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.format_exc_info,
        ]
        if _effective_syslog_mode(LogMode(log_mode)):
            final_processors.append(_drop_keys_processor(["timestamp", "pid"]))
        final_processors.append(_reorder_log_keys_processor(extra_priority_keys))
        final_processors.append(renderer)

    # A DEBUG-level debug-log file must receive every event regardless of
    # `verbose`, but structlog's filtering bound logger drops below-level
    # calls before any handler sees them — so the wrapper (and the root
    # logger passed to basicConfig) must open up to DEBUG whenever
    # debug_log_path is set. The stderr handler stays capped at `level`
    # via its own handler-level filter, so visible output is unaffected.
    wrapper_level = logging.DEBUG if debug_log_path is not None else level

    structlog.configure(
        processors=pre_chain + [structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        wrapper_class=structlog.make_filtering_bound_logger(wrapper_level),
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=foreign_pre_chain,
        processors=final_processors,
    )
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(formatter)
    handler.setLevel(level)
    handlers: list[logging.Handler] = [handler]

    if debug_log_path is not None:
        # ConsoleRenderer's default exception_formatter is
        # RichTracebackFormatter(show_locals=True, color_system="truecolor"),
        # which would write ANSI escapes into the file *and* dump every frame's
        # locals — including OAuth client secrets and tokens held during
        # session setup. Pinning plain_traceback does two things: it suppresses
        # the UserWarning structlog raises when a pretty formatter sits behind
        # format_exc_info ("Remove `format_exc_info` from your processor chain
        # if you want pretty exceptions"), and it keeps the rich formatter
        # unreachable if this chain is ever reordered. Today format_exc_info
        # already flattens exc_info to a plain string first, so rich never gets
        # the chance — only the reordering risk and the warning are live.
        debug_renderer: Any = (
            structlog.processors.JSONRenderer()
            if DebugLogFormat(debug_log_format) is DebugLogFormat.JSON
            else structlog.dev.ConsoleRenderer(
                colors=False,
                exception_formatter=structlog.dev.plain_traceback,
                # Keep extra_priority_keys' deliberate order instead of
                # re-sorting the extras alphabetically.
                sort_keys=False,
            )
        )
        debug_formatter = structlog.stdlib.ProcessorFormatter(
            foreign_pre_chain=foreign_pre_chain,
            processors=[
                structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                structlog.processors.format_exc_info,
                _reorder_log_keys_processor(extra_priority_keys),
                debug_renderer,
            ],
        )
        debug_handler = logging.FileHandler(debug_log_path)
        debug_handler.setFormatter(debug_formatter)
        debug_handler.setLevel(logging.DEBUG)
        handlers.append(debug_handler)

    logging.basicConfig(handlers=handlers, level=wrapper_level, force=True)

    if verbose < 4:
        # httpx logs one INFO line per request; keep it quiet unless -vvvv
        # (urllib3, its predecessor here, only logged at DEBUG).
        for name in ("httpx", "httpcore", "keyring", "jaraco", "win32ctypes", *quiet_loggers):
            logging.getLogger(name).setLevel(logging.WARNING)


def build_session(
    connection: ResolvedConnection,
    *,
    account_number: str | None = None,
    client_secret: str | None = None,
    scope: str = "",
    prompt: bool = True,
) -> certinext.CertiNextSession:
    """Resolve credentials and return a configured :class:`~certinext.CertiNextSession`.

    Reads credentials in priority order: explicit argument → keyring →
    environment variable → interactive prompt (the first three via
    :class:`~certinext.settings.CertiNextSettings`). When ``account_number``
    is provided explicitly the keyring is **not** consulted for the client
    secret, because the stored secret belongs to the previously configured
    account and would cause an authentication failure if used with a
    different client ID.

    Args:
        connection: The resolved endpoint/profile, from
            :func:`resolve_connection`.
        account_number: Explicit CertiNext account number (OAuth2 client_id),
            or None to resolve from keyring/env/prompt.
        client_secret: Explicit OAuth2 client secret, or None to resolve.
        scope: OAuth2 scope string (optional).
        prompt: If ``False``, raise :exc:`CredentialsNotFoundError` instead of
            prompting interactively when credentials are absent. Use this in
            setup scripts that want to attempt an API call but handle missing
            credentials gracefully without blocking on user input.

    Returns:
        An authenticated :class:`~certinext.CertiNextSession`.

    Raises:
        CredentialsNotFoundError: If ``prompt=False`` and credentials are not
            available from the keyring or environment.
    """
    # Only pass kwargs the caller actually set: an init value of None would
    # still outrank the keyring and env sources inside pydantic-settings.
    init_kwargs: dict[str, Any] = {}
    if connection.profile:
        init_kwargs["profile"] = connection.profile
    if account_number:
        init_kwargs["client_id"] = account_number
    if client_secret:
        init_kwargs["client_secret"] = client_secret
    settings = CertiNextSettings(**init_kwargs)

    client_id = require_credential(
        settings.client_id, "CERTINEXT_CLIENT_ID", "CertiNext account number",
        allow_prompt=prompt,
    )
    secret = require_credential(
        settings.client_secret.get_secret_value() if settings.client_secret else None,
        "CERTINEXT_CLIENT_SECRET", "CertiNext client secret", secret=True,
        allow_prompt=prompt,
    )
    if prompt:
        log.info("Connecting", url=connection.base_url, account=client_id,
                 profile=settings.profile or "default")
    return certinext.session(
        base_url=connection.base_url,
        token_url=connection.token_url,
        client_id=client_id,
        client_secret=secret,
        scope=scope,
        sandbox=connection.sandbox,
    )


def fatal_api_error(exc: CertiNextAPIError, message: str) -> NoReturn:
    """Log a CertiNext API error at ERROR level and exit with code 1.

    Logs ``message: exc`` at ERROR level, each field validation error at ERROR
    level, and the full response body at DEBUG level.

    Args:
        exc: The :class:`~certinext.exceptions.CertiNextAPIError` that was caught.
        message: Short description of the failed operation, e.g.
            ``"Error creating order"``.
    """
    log.error(message, error=str(exc))
    for field_err in exc.field_errors:
        log.error("Field error", field_error=str(field_err))
    log.debug("Full response body", body=exc.body)
    raise SystemExit(1) from exc
