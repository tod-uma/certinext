"""Shared CLI utilities for certinext command-line scripts.

Provides argument registration, sandbox URL overrides, and session construction
so each CLI entry point stays focused on its own logic rather than credential
plumbing.
"""

import argparse
import getpass
import logging
import os
import sys
from typing import Any, NoReturn

import structlog

import certinext
from certinext._keyring import keyring_available, keyring_get, keyring_service, no_keyring_help
from certinext.exceptions import CertiNextAPIError

log = structlog.get_logger()


def _resolve(
    arg_value: str | None,
    env_var: str,
    prompt: str,
    secret: bool = False,
    kr_service: str | None = None,
    kr_key: str | None = None,
) -> str:
    """Resolve a credential from CLI arg, keyring, environment variable, or interactive prompt.

    Checks in priority order: explicit argument → keyring → environment variable → prompt.
    Secrets are read with getpass so they are not echoed to the terminal.

    Args:
        arg_value: Value from a CLI argument, or None if not provided.
        env_var: Environment variable name to fall back to.
        prompt: Text shown when prompting interactively.
        secret: If True, use getpass so input is not echoed.
        kr_service: Keyring service name to check before the env var.
        kr_key: Keyring key (username) to look up under kr_service.

    Returns:
        The resolved credential string.

    Raises:
        RuntimeError: If the credential is unset and stdin is not a TTY, so
            no interactive prompt is possible.
    """
    if arg_value:
        return arg_value
    if kr_service and kr_key:
        kr_value = keyring_get(kr_service, kr_key)
        if kr_value:
            return kr_value
    env_value = os.environ.get(env_var)
    if env_value:
        return env_value
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
    return input(f"{prompt}: ")


def add_connection_args(target: Any, *, scope: bool = False) -> None:
    """Add standard connection arguments to a parser or argument group.

    Registers ``--profile``, ``--sandbox``, ``--base-url``, ``--token-url``,
    ``--account-number`` / ``--client-id``, and ``--client-secret``. Optionally
    also registers ``--scope`` when ``scope=True``.

    Args:
        target: An :class:`argparse.ArgumentParser` or argument group that
            accepts ``add_argument`` calls.
        scope: If ``True``, also add ``--scope`` for OAuth2 scope strings.
    """
    target.add_argument(
        "--profile", metavar="NAME", default=None,
        help="Credential profile for keyring lookup (env: CERTINEXT_PROFILE; default: use the default profile)",
    )
    target.add_argument(
        "--sandbox", action="store_true", default=False,
        help="Connect to the CertiNext sandbox API; implies --profile sandbox unless --profile is set",
    )
    target.add_argument(
        "--base-url", default=certinext.BASE_URL, metavar="URL",
        help=f"CertiNext base URL (default: {certinext.BASE_URL})",
    )
    target.add_argument(
        "--token-url", default=certinext.TOKEN_URL, metavar="URL",
        help=f"OAuth2 token endpoint URL (default: {certinext.TOKEN_URL})",
    )
    target.add_argument(
        "--account-number", "--client-id", dest="account_number", default=None, metavar="ACCT",
        help="CertiNext account number / OAuth2 client_id (env: CERTINEXT_CLIENT_ID)",
    )
    target.add_argument(
        "--client-secret", default=None, metavar="SECRET",
        help="OAuth2 client secret (env: CERTINEXT_CLIENT_SECRET)",
    )
    if scope:
        target.add_argument("--scope", default="", metavar="SCOPE", help="OAuth2 scope (optional)")


def apply_sandbox(args: argparse.Namespace) -> None:
    """Override base_url and token_url for the sandbox when ``--sandbox`` is set.

    Also sets ``args.profile`` to ``'sandbox'`` if no profile was explicitly
    provided, so keyring lookups automatically find sandbox credentials.

    Args:
        args: Parsed CLI arguments (modified in place).
    """
    if args.sandbox:
        args.base_url = certinext.SANDBOX_BASE_URL
        args.token_url = certinext.SANDBOX_TOKEN_URL
        if args.profile is None:
            args.profile = "sandbox"


def _reorder_log_keys(_logger: Any, _method: str, event_dict: structlog.typing.EventDict) -> structlog.typing.EventDict:
    """Reorder event dict keys for consistent JSON output regardless of log source.

    Puts fixed fields first so every line reads: timestamp → level → event → logger
    (foreign only) → remaining fields.

    Args:
        _logger: Unused — required by the structlog processor protocol.
        _method: Unused — required by the structlog processor protocol.
        event_dict: The current log event dictionary to reorder.

    Returns:
        A new dict with priority keys first, remaining keys appended in original order.
    """
    priority = ["timestamp", "level", "logger", "event"]
    reordered: dict[str, Any] = {k: event_dict[k] for k in priority if k in event_dict}
    reordered.update({k: v for k, v in event_dict.items() if k not in priority})
    return reordered


def _setup_logging(verbose: int) -> None:
    """Route all output — structlog and third-party stdlib — through a shared renderer.

    Uses structlog.stdlib.ProcessorFormatter as the single stdlib handler formatter so
    native structlog calls and foreign stdlib records (urllib3, requests, keyring) both
    pass through the same renderer.

    TTY (interactive): ConsoleRenderer with local HH:MM:SS timestamps.
    Non-TTY (cron/redirect): JSONRenderer with full ISO UTC timestamps, consistent
    key order (timestamp → level → logger → event → ...).

    Args:
        verbose: Verbosity count from -v flags (0=INFO, 3+=DEBUG, 4+=third-party DEBUG).
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
            renderer,
        ]
    else:
        renderer = structlog.processors.JSONRenderer()
        final_processors = [
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.format_exc_info,
            _reorder_log_keys,
            renderer,
        ]

    structlog.configure(
        processors=pre_chain + [structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        wrapper_class=structlog.make_filtering_bound_logger(level),
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
    logging.basicConfig(handlers=[handler], level=level, force=True)

    if verbose < 4:
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("keyring").setLevel(logging.WARNING)
        logging.getLogger("jaraco").setLevel(logging.WARNING)
        logging.getLogger("win32ctypes").setLevel(logging.WARNING)


def build_session(args: argparse.Namespace) -> certinext.CertiNextSession:
    """Resolve credentials and return a configured :class:`~certinext.CertiNextSession`.

    Reads credentials in priority order: explicit CLI argument → keyring →
    environment variable → interactive prompt.  When ``--account-number`` is
    provided explicitly the keyring is **not** consulted for the client secret,
    because the stored secret belongs to the previously configured account and
    would cause an authentication failure if used with a different client ID.

    Args:
        args: Parsed CLI arguments. Must have ``profile``, ``base_url``,
            ``token_url``, ``account_number``, and ``client_secret`` attributes.
            ``scope`` is optional (defaults to ``""`` when absent).

    Returns:
        An authenticated :class:`~certinext.CertiNextSession`.
    """
    profile = getattr(args, "profile", None) or os.environ.get("CERTINEXT_PROFILE")
    svc = keyring_service("certinext", profile)
    client_id = _resolve(
        args.account_number, "CERTINEXT_CLIENT_ID", "CertiNext account number",
        kr_service=svc, kr_key="CERTINEXT_CLIENT_ID",
    )
    # Skip keyring for secret when account number was explicitly overridden — the
    # stored secret belongs to a different account and would cause a 401.
    secret_kr_service = None if args.account_number else svc
    secret_kr_key = None if args.account_number else "CERTINEXT_CLIENT_SECRET"
    client_secret = _resolve(
        args.client_secret, "CERTINEXT_CLIENT_SECRET", "CertiNext client secret", secret=True,
        kr_service=secret_kr_service,
        kr_key=secret_kr_key,
    )
    log.info("Connecting", url=args.base_url, account=client_id, profile=profile or "default")
    return certinext.session(
        base_url=args.base_url,
        token_url=args.token_url,
        client_id=client_id,
        client_secret=client_secret,
        scope=getattr(args, "scope", ""),
        sandbox=getattr(args, "sandbox", False),
    )


def add_requestor_args(target: Any, config: dict[str, Any] | None = None) -> None:
    """Add standard certificate requestor arguments to a parser or argument group.

    Registers ``--requestor-name``, ``--requestor-email``, ``--requestor-phone``,
    ``--requestor-designation``, and ``--signer-place``. When not supplied on
    the command line, values fall back to the corresponding
    ``CERTINEXT_REQUESTOR_*`` environment variable, then to the stored config
    defaults (see :mod:`certinext._config`).

    Args:
        target: An :class:`argparse.ArgumentParser` or argument group that
            accepts ``add_argument`` calls.
        config: Stored defaults keyed by argparse dest name, as returned by
            :func:`certinext._config.config_defaults`. Optional.
    """
    cfg = config or {}

    def _default(env_var: str, dest: str) -> str:
        """Resolve a fallback value: environment variable, then stored config."""
        return os.environ.get(env_var, "") or str(cfg.get(dest, "") or "")

    _rname = _default("CERTINEXT_REQUESTOR_NAME", "requestor_name")
    _remail = _default("CERTINEXT_REQUESTOR_EMAIL", "requestor_email")
    _rphone = _default("CERTINEXT_REQUESTOR_PHONE", "requestor_phone")
    target.add_argument(
        "--requestor-name", metavar="NAME",
        default=_rname or None, required=not _rname,
        help="Full name of the certificate requestor (env: CERTINEXT_REQUESTOR_NAME)",
    )
    target.add_argument(
        "--requestor-email", metavar="EMAIL",
        default=_remail or None,
        help="Email address of the requestor (env: CERTINEXT_REQUESTOR_EMAIL)",
    )
    target.add_argument(
        "--requestor-phone", metavar="PHONE",
        default=_rphone or None, required=not _rphone,
        help="Phone in E.164 format, e.g. +12075551234 (env: CERTINEXT_REQUESTOR_PHONE)",
    )
    target.add_argument(
        "--requestor-designation", metavar="TITLE",
        default=_default("CERTINEXT_REQUESTOR_DESIGNATION", "requestor_designation"),
        help="Job title or designation of the requestor (env: CERTINEXT_REQUESTOR_DESIGNATION)",
    )
    target.add_argument(
        "--signer-place", metavar="PLACE",
        default=_default("CERTINEXT_SIGNER_PLACE", "signer_place"),
        help="City/location for the subscriber agreement signature (env: CERTINEXT_SIGNER_PLACE)",
    )


def add_json_output_arg(target: Any) -> None:
    """Add a ``--json`` flag to a parser or argument group.

    When set, the CLI writes its output as machine-readable JSON instead of
    human-readable text.

    Args:
        target: An :class:`argparse.ArgumentParser` or argument group that
            accepts ``add_argument`` calls.
    """
    target.add_argument(
        "--json", dest="output_json", action="store_true", default=False,
        help="Write output as JSON instead of human-readable text",
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
