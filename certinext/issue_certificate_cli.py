"""Submit a CSR to CertiNext and download the issued certificate.

This script is both a working CLI and a reference implementation showing how
to drive the full certificate lifecycle using :class:`~certinext.ssl_certificates.OrderWorkflow`.
The same pattern can be used directly in your own scripts::

    import certinext
    from certinext.ssl_certificates import OrderWorkflow
    from certinext.exceptions import CertiNextTimeoutError

    sess = certinext.session(client_id="YOUR_ACCOUNT", client_secret="YOUR_SECRET")

    # Create the order (domain and requestor come from your own data)
    order = sess.ssl.create_ov(
        "example.maine.edu",
        organization_id="2517111",
        requestor_name="Jane Doe",
        requestor_email="jane@maine.edu",
        requestor_phone="+12075551234",
        csr=open("example.csr").read(),
    )

    # Drive the order from creation to a PEM certificate in one call.
    # from_csr() fills signer_place from the CSR subject's L/ST fields.
    try:
        pem = (
            OrderWorkflow.from_csr(order, open("example.csr").read(), signer_name="Jane Doe")
            .on("status_change", lambda old, new: print(f"Status: {old} -> {new}"))
            .on("issued", lambda o: print(f"Issued! Order {o.order_id}"))
            .run(wait=300)
        )
        open("example.pem", "w").write(pem)
    except CertiNextTimeoutError as exc:
        print(f"Timed out. Resume with --order-id {exc.order_id}")

This CLI wraps the same workflow and adds argument parsing, credential loading
from the keyring, and sandbox switching.

The target domain must already have DCV completed in CertiNext. Use
``certinext-pending-dcv`` (or ``dcv-update``) to complete DCV first.

Requires the ``csr`` optional dependency::

    pip install certinext[csr]

Usage::

    certinext-issue-cert --csr example.com.csr --requestor-name "Jane Doe"
    certinext-issue-cert --csr example.com.csr --output example.com.pem
    certinext-issue-cert --csr example.com.csr --cert-out cert.pem --chain-out chain.pem
    certinext-issue-cert --csr example.com.csr --fullchain-out fullchain.pem
    certinext-issue-cert --csr example.com.csr --der-out cert.der
    certinext-issue-cert --csr example.com.csr --sandbox
    certinext-issue-cert < example.com.csr
    certinext-issue-cert --order-id <ID> --wait 300  # resume polling
"""

import argparse
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import structlog

from certinext._cli import (
    _setup_logging,
    add_connection_args,
    add_requestor_args,
    apply_sandbox,
    build_session,
    fatal_api_error,
    prompt_stderr,
)
from certinext._config import ConfigError, config_defaults, profile_from_argv, save_defaults
from certinext.csr import CsrInfo
from certinext.exceptions import CertiNextAPIError, CertiNextTimeoutError
from certinext.session import CertiNextSession
from certinext.ssl_certificates import DcvChallenge, OrderWorkflow, SslOrder

log = structlog.get_logger()


def build_parser(config: dict[str, Any] | None = None) -> argparse.ArgumentParser:
    """Return the argument parser for certinext-issue-cert.

    Args:
        config: Stored defaults keyed by argparse dest name, as returned by
            :func:`certinext._config.config_defaults`. Values become argparse
            defaults, so explicit CLI arguments always win.

    Returns:
        A configured ArgumentParser instance.
    """
    cfg = config or {}
    parser = argparse.ArgumentParser(
        description=(
            "Submit a CSR to CertiNext and download the issued certificate. "
            "Domain and SANs are extracted from the CSR automatically."
        ),
    )
    parser.add_argument(
        "-v", "--verbose", action="count", default=0,
        help="Increase verbosity (-vvv for debug logging)",
    )

    conn = parser.add_argument_group("connection")
    add_connection_args(conn)

    cert = parser.add_argument_group("certificate")
    cert.add_argument(
        "csr_file", nargs="?", metavar="CSR_FILE", default=argparse.SUPPRESS,
        help="PEM-encoded CSR file (default: stdin; not required with --order-id)",
    )
    cert.add_argument(
        "--csr", metavar="FILE", default=None, dest="csr_file",
        help="PEM-encoded CSR file (alternative to positional argument)",
    )
    cert.add_argument(
        "--domain", metavar="FQDN", default=None,
        help="Override the primary domain (default: extracted from CSR CN)",
    )
    cert.add_argument(
        "--san", action="append", dest="sans", metavar="FQDN", default=None,
        help="Override SANs (default: extracted from CSR SAN extension; repeatable)",
    )
    cert.add_argument(
        "--validity", type=int, default=cfg.get("validity", 1), metavar="YEARS", choices=[1, 2, 3],
        help="Certificate validity in years (1, 2, or 3; default: 1)",
    )
    cert.add_argument(
        "--type", dest="cert_type", choices=["dv", "ov", "ev"], default=cfg.get("cert_type", "dv"),
        help="Certificate validation type (default: dv)",
    )
    cert.add_argument(
        "--org-id", metavar="ID", default=cfg.get("org_id"),
        help="Organization ID, required for OV and EV certificates",
    )
    cert.add_argument(
        "--prevetting-token", metavar="TOKEN", default=None,
        help=(
            "Organization Consent Token for OV/EV orders. "
            "When provided, the CA auto-approves without a manual approver step. "
            "Retrieve from the CertiNext portal under Organization Management → "
            "Organization Consent / Consent Tokens for the target organization."
        ),
    )
    cert.add_argument(
        "--auto-secure-www", action="store_true", default=False,
        help=(
            "Request automatic www-redirect coverage from the CA "
            "(default: false; the API default is true if omitted)"
        ),
    )

    req = parser.add_argument_group("requestor")
    add_requestor_args(req, config=cfg)

    ctl = parser.add_argument_group("output")
    ctl.add_argument(
        "--output", "-o", metavar="FILE", default=None,
        help="Write certificate PEM to FILE instead of stdout",
    )
    ctl.add_argument(
        "--cert-out", metavar="FILE", default=None,
        help="Write only the end-entity (leaf) certificate PEM to FILE",
    )
    ctl.add_argument(
        "--chain-out", metavar="FILE", default=None,
        help="Write only the intermediate CA chain PEM to FILE",
    )
    ctl.add_argument(
        "--fullchain-out", metavar="FILE", default=None,
        help="Write the leaf-first fullchain PEM (certificate + intermediates) to FILE",
    )
    ctl.add_argument(
        "--der-out", metavar="FILE", default=None,
        help="Write the end-entity certificate in DER (binary) format to FILE",
    )
    ctl.add_argument(
        "--all-formats-out", metavar="DIR", default=None,
        help=(
            "Write all certificate formats to DIR: {domain}.pem (PEM bundle) "
            "and {domain}.der (DER). "
            "The domain stem comes from the order's CN."
        ),
    )
    ctl.add_argument(
        "--wait", type=int, default=300, metavar="SECONDS",
        help="Seconds to wait for issuance before giving up (0 = submit and exit; default: 300)",
    )
    ctl.add_argument(
        "--order-id", metavar="ID", default=None,
        help="Resume polling an existing order rather than creating a new one",
    )
    ctl.add_argument(
        "--save-defaults", action="store_true", default=False,
        help=(
            "Store the effective requestor/certificate values as defaults for "
            "future runs (in the config file; interactively confirms before "
            "the order is created)"
        ),
    )
    ctl.add_argument(
        "--no-domain-check", action="store_true", default=False,
        help=(
            "Skip the pre-creation check for existing orders on the same domain. "
            "By default the script queries issued and in-progress orders and "
            "prompts before creating a new one. Set this flag in automated pipelines."
        ),
    )
    return parser


def _read_csr(path: str | None) -> str:
    """Read a PEM-encoded CSR from a file path or stdin.

    When reading from an interactive TTY, reads line by line and stops
    automatically after ``-----END CERTIFICATE REQUEST-----`` so the user
    does not need to press Ctrl-D.  When stdin is a pipe the full stream is
    read until EOF as before.

    Args:
        path: File path to read, or None to read from stdin.

    Returns:
        The CSR as a PEM string.

    Raises:
        SystemExit: If the file cannot be read.
    """
    try:
        if path is None:
            if sys.stdin.isatty():
                print(
                    "Paste the PEM-encoded CSR below "
                    "(input stops automatically after '-----END CERTIFICATE REQUEST-----'):",
                    file=sys.stderr,
                )
                lines: list[str] = []
                for line in sys.stdin:
                    lines.append(line)
                    if line.rstrip() == "-----END CERTIFICATE REQUEST-----":
                        break
                return "".join(lines)
            return sys.stdin.read()
        with open(path) as f:
            return f.read()
    except OSError as exc:
        log.error("Error reading CSR", error=str(exc))
        raise SystemExit(1) from exc


def _parse_csr(pem: str) -> CsrInfo:
    """Parse a PEM-encoded CSR and return its subject fields and SANs.

    Thin wrapper around :func:`certinext.csr.parse_csr` that converts
    :exc:`ImportError` and :exc:`ValueError` to ``SystemExit(1)``.

    Args:
        pem: PEM-encoded certificate signing request string.

    Returns:
        :class:`~certinext.csr.CsrInfo` with CN, email, locality, state,
        organisation, and DNS SANs.

    Raises:
        SystemExit: If ``cryptography`` is not installed, the CSR cannot be
            parsed, or no CN is found in the subject.
    """
    from certinext.csr import parse_csr

    try:
        return parse_csr(pem)
    except (ImportError, ValueError) as exc:
        log.error(str(exc))
        raise SystemExit(1) from exc


def _check_existing_and_prompt(
    sess: CertiNextSession, args: argparse.Namespace
) -> SslOrder | None:
    """Check for existing orders on the same domain and prompt the user how to proceed.

    Skips immediately when ``args.no_domain_check`` is set. Otherwise fetches
    all orders (any status) whose CN matches ``args.domain`` and:

    - If an in-progress order is found (any ``pending-*`` status), logs a
      warning and prompts the user to resume it instead of creating a new one.
      Returns the fetched :class:`~certinext.ssl_certificates.SslOrder` if the
      user answers ``y``.
    - If an issued certificate is found, logs a warning and prompts the user to
      confirm creating a new one. Raises :exc:`SystemExit(0)` if the user
      declines.

    API errors during the check are logged at DEBUG level and ignored so they
    never block order creation.

    Args:
        sess: Active CertiNext session.
        args: Parsed CLI arguments. Reads ``args.domain`` and
            ``args.no_domain_check``.

    Returns:
        An :class:`~certinext.ssl_certificates.SslOrder` to resume, or ``None``
        to proceed with creating a new order.

    Raises:
        SystemExit: With code 0 if the user declines to create a new
            certificate over an existing issued one.
    """
    if args.no_domain_check:
        return None
    try:
        all_matches = sess.orders.find_by_domain(args.domain, status=None)
    except CertiNextAPIError as exc:
        log.debug("Domain existence check failed — skipping", status_code=exc.status_code)
        return None

    log.debug("Domain check: orders found", count=len(all_matches), domain=args.domain)
    for r in all_matches:
        log.debug("domain check order", order_number=r.order_number, status=r.certificate_status, cn=r.common_name)

    pending = next(
        (r for r in all_matches if (r.certificate_status or "").lower().startswith("pending")),
        None,
    )
    issued = next(
        (r for r in all_matches if (r.order_status or "").lower() == "order fulfilled"),
        None,
    )

    if pending and pending.order_number:
        pending_order = sess.ssl.get(pending.order_number)
        if pending_order.csr_submitted:
            log.warning(
                "In-progress order exists with CSR on file — resuming may work",
                domain=args.domain, order_id=pending.order_number, status=pending.certificate_status,
            )
        else:
            log.warning(
                "In-progress order exists without CSR — resuming will submit current CSR",
                domain=args.domain, order_id=pending.order_number, status=pending.certificate_status,
            )
        try:
            answer = prompt_stderr("Resume it instead of creating a new one? [y/N]: ").strip().lower()
        except EOFError:
            answer = ""
        if answer == "y":
            log.info("Resuming order", order_id=pending_order.order_id, status=pending_order.status)
            return pending_order

    if issued and issued.order_number:
        log.warning(
            "An issued certificate already exists",
            domain=args.domain, order_number=issued.order_number,
        )
        try:
            answer = prompt_stderr("Create a new certificate anyway? [y/N]: ").strip().lower()
        except EOFError:
            answer = ""
        if answer != "y":
            raise SystemExit(0)

    return None


def _create_order(sess: CertiNextSession, args: argparse.Namespace, csr: str = "") -> SslOrder:
    """Create a new SSL order.

    When ``csr`` is provided it is included in the initial order body, which
    may allow the CA to skip the ``pending-csr`` stage entirely.

    Args:
        sess: An authenticated CertiNextSession.
        args: Parsed CLI arguments with ``domain``, ``cert_type``, ``org_id``,
            ``sans``, ``validity``, ``prevetting_token``, and requestor fields.
        csr: PEM-encoded CSR to include with the initial order (optional).

    Returns:
        The created SslOrder.

    Raises:
        SystemExit: If OV/EV is requested without ``--org-id``, or on API error.
    """
    cert_type = args.cert_type
    sans: list[str] | None = args.sans or None
    csr_arg: str | None = csr.strip() or None
    requestor_name: str = args.requestor_name or ""
    requestor_email: str = args.requestor_email or ""
    requestor_phone: str = args.requestor_phone or ""
    requestor_designation: str = args.requestor_designation or ""
    signer_place: str = args.signer_place or ""
    auto_secure_www: bool = bool(args.auto_secure_www)
    prevetting_token: str | None = getattr(args, "prevetting_token", None)

    try:
        if cert_type == "dv":
            return sess.ssl.create_dv(
                args.domain,
                validity_years=args.validity,
                additional_domains=sans,
                auto_secure_www=auto_secure_www,
                csr=csr_arg,
                requestor_name=requestor_name,
                requestor_email=requestor_email,
                requestor_phone=requestor_phone,
                requestor_designation=requestor_designation,
                signer_name=requestor_name,
                signer_place=signer_place,
            )
        elif cert_type == "ov":
            return sess.ssl.create_ov(
                args.domain,
                organization_id=args.org_id,
                validity_years=args.validity,
                additional_domains=sans,
                auto_secure_www=auto_secure_www,
                prevetting_token=prevetting_token,
                csr=csr_arg,
                requestor_name=requestor_name,
                requestor_email=requestor_email,
                requestor_phone=requestor_phone,
                requestor_designation=requestor_designation,
                signer_name=requestor_name,
                signer_place=signer_place,
            )
        else:
            return sess.ssl.create_ev(
                args.domain,
                organization_id=args.org_id,
                validity_years=args.validity,
                additional_domains=sans,
                auto_secure_www=auto_secure_www,
                prevetting_token=prevetting_token,
                csr=csr_arg,
                requestor_name=requestor_name,
                requestor_email=requestor_email,
                requestor_phone=requestor_phone,
                requestor_designation=requestor_designation,
                signer_name=requestor_name,
                signer_place=signer_place,
            )
    except CertiNextAPIError as exc:
        fatal_api_error(exc, "Error creating order")


def _stem_from_domain(domain: str | None) -> str:
    """Return a filesystem-safe filename stem derived from a certificate domain.

    Replaces ``*`` (wildcard) with the literal string ``wildcard`` so that
    wildcard certificate filenames do not contain shell-glob characters.

    Args:
        domain: The primary domain (CN) of the certificate, or ``None``.

    Returns:
        A non-empty string safe to use as a filename stem.
    """
    return (domain or "certificate").replace("*", "wildcard")


def _write_file(path: str, content: str, label: str) -> None:
    """Write text to a file, exiting with an error log on failure.

    Args:
        path: Destination file path.
        content: Text to write.
        label: Human-readable description of the content for log messages,
            e.g. ``"certificate"`` or ``"fullchain"``.

    Raises:
        SystemExit: With code 1 if the file cannot be written.
    """
    try:
        with open(path, "w") as f:
            f.write(content)
    except OSError as exc:
        log.error("Error writing output", output=label, path=path, error=str(exc))
        raise SystemExit(1) from exc
    log.info("Output written", output=label, path=path)



def _try_download_write_binary(
    label: str,
    path: str,
    download_fn: Callable[[], bytes],
) -> bool:
    """Attempt to download and write a binary certificate format.

    Logs a warning and returns ``False`` on any download or write failure
    rather than exiting, so callers can continue writing other formats.

    Args:
        label: Human-readable description for log messages
            (e.g. ``"certificate (DER)"``).
        path: Destination file path.
        download_fn: Zero-argument callable that fetches the raw bytes.

    Returns:
        ``True`` if both the download and the write succeeded, ``False``
        otherwise.
    """
    try:
        data = download_fn()
    except CertiNextAPIError as exc:
        log.warning(
            "Skipping format — download failed",
            output=label, path=path, status_code=exc.status_code,
        )
        return False
    try:
        with open(path, "wb") as f:
            f.write(data)
    except OSError as exc:
        log.warning(
            "Skipping format — write failed",
            output=label, path=path, error=str(exc),
        )
        return False
    log.info("Output written", output=label, path=path)
    return True


def _write_outputs(order: SslOrder, args: argparse.Namespace, pem: str) -> None:
    """Write the issued certificate to the requested output destinations.

    ``--output`` receives the raw PEM bundle returned by the workflow
    (unchanged historical behavior); when no destination flag at all is given,
    that bundle is printed to stdout. ``--cert-out``, ``--chain-out``, and
    ``--fullchain-out`` are assembled from the JSON download
    (:meth:`~certinext.ssl_certificates.SslOrder.download_certificate`), which
    separates the end-entity certificate from its intermediates:

    - ``--cert-out``: the end-entity (leaf) certificate only
    - ``--chain-out``: the intermediate CA certificates only
    - ``--fullchain-out``: leaf followed by intermediates
      (:meth:`~certinext.ssl_certificates.CertificateDownload.as_pem_chain`)

    Each PEM file is normalised to end with exactly one trailing newline.
    The binary format ``--der-out`` writes a DER-encoded end-entity certificate
    and cannot be written to stdout.  ``--all-formats-out DIR`` writes
    ``{domain}.pem`` and ``{domain}.der`` to *DIR* in one call, deriving the
    stem from the order's CN via :func:`_stem_from_domain`.

    Args:
        order: The issued order to download certificate parts from.
        args: Parsed CLI arguments (reads ``output``, ``cert_out``,
            ``chain_out``, ``fullchain_out``, ``der_out``,
            and ``all_formats_out``).
        pem: Raw PEM bundle already downloaded by the workflow.

    Raises:
        SystemExit: With code 1 if any download fails, a requested part is
            missing from the download, or a file cannot be written. An empty
            intermediate chain with ``--chain-out`` is a warning, not an
            error, because a leaf signed directly by a root has no
            intermediates.
    """
    if args.cert_out or args.chain_out or args.fullchain_out:
        try:
            dl = order.download_certificate()
        except CertiNextAPIError as exc:
            fatal_api_error(exc, "Error downloading certificate parts")
        if args.cert_out:
            leaf = (dl.certificate_pem or "").strip()
            if not leaf:
                log.error("Download contained no end-entity certificate")
                raise SystemExit(1)
            _write_file(args.cert_out, leaf + "\n", "certificate")
        if args.chain_out:
            chain = [p.strip() for p in dl.chain_pem if p and p.strip()]
            if not chain:
                log.warning("Download contained no intermediate certificates")
            _write_file(args.chain_out, "\n".join(chain) + "\n" if chain else "", "chain")
        if args.fullchain_out:
            fullchain = dl.as_pem_chain()
            if not fullchain:
                log.error("Download contained no certificates for the fullchain")
                raise SystemExit(1)
            _write_file(args.fullchain_out, fullchain, "fullchain")

    if args.der_out:
        _try_download_write_binary("certificate (DER)", args.der_out, order.download_certificate_der)

    if args.all_formats_out:
        stem = _stem_from_domain(order.domain)
        out_dir = Path(args.all_formats_out)
        _write_file(str(out_dir / f"{stem}.pem"), pem, "certificate bundle (PEM)")
        _try_download_write_binary(
            "certificate (DER)", str(out_dir / f"{stem}.der"), order.download_certificate_der,
        )

    if args.output:
        _write_file(args.output, pem, "certificate bundle")
    elif not (args.cert_out or args.chain_out or args.fullchain_out
              or args.der_out or args.all_formats_out):
        print(pem, end="")


def _maybe_save_defaults(args: argparse.Namespace) -> None:
    """Store the effective requestor/certificate values as config defaults.

    Called before the order is created so a failed or timed-out issuance never
    loses the entered values. When stdin is a TTY, asks for confirmation first
    (prompt on stderr so piped stdout stays clean); in non-interactive runs the
    ``--save-defaults`` flag itself is the consent and the save happens
    silently. Only non-empty values are stored.

    Args:
        args: Parsed CLI arguments (after ``apply_sandbox``, so ``args.profile``
            reflects the active profile section to write).
    """
    values = {
        "requestor_name": args.requestor_name,
        "requestor_email": args.requestor_email,
        "requestor_phone": args.requestor_phone,
        "requestor_designation": args.requestor_designation,
        "signer_place": args.signer_place,
        "cert_type": args.cert_type,
        "org_id": args.org_id,
        "validity": args.validity,
    }
    section = f"profile {args.profile!r}" if args.profile else "the default profile"
    if sys.stdin.isatty():
        print(f"Save these values as defaults for {section}?", file=sys.stderr)
        for key, value in values.items():
            if value not in (None, ""):
                print(f"  {key} = {value}", file=sys.stderr)
        if prompt_stderr("Save? [Y/n]: ").strip().lower() in ("n", "no"):
            log.info("Defaults not saved")
            return
    try:
        path = save_defaults(values, args.profile)
    except ConfigError as exc:
        log.error("Error saving defaults", error=str(exc))
        raise SystemExit(1) from exc
    log.info("Defaults saved", path=str(path), profile=args.profile or "default")


def main() -> None:
    """Entry point for certinext-issue-cert.

    The function is structured in three phases:

    1. **Argument parsing and validation** — parse CLI flags, cross-validate
       required combinations (e.g. ``--org-id`` for OV/EV), and build an
       authenticated session from the keyring or environment.

    2. **Order acquisition** — either fetch an existing order by ``--order-id``
       (resume path) or create a new one. For new orders, missing fields are
       filled from the CSR subject: domain from CN, SANs from the SAN
       extension, ``requestor_email`` from ``emailAddress``, and
       ``signer_place`` from ``L`` + ``ST``.

    3. **Workflow execution** — an :class:`~certinext.ssl_certificates.OrderWorkflow`
       drives the order through all pending states (agreement acceptance, CSR
       submission, DCV) and polls until issuance. Event hooks wire up logging
       so status transitions and DCV challenges are visible at INFO/DEBUG
       level without any polling logic in this function.

    On any non-zero exit after an order has been created, the resume hint
    ``Re-run with --order-id <ID>`` is printed so the operator can continue
    from where the process left off.
    """
    # `order` is declared here so the except-SystemExit handler can reference
    # it even if the error occurs partway through order creation.
    order: SslOrder | None = None
    try:
        # ------------------------------------------------------------------
        # Phase 1: Argument parsing and validation
        # ------------------------------------------------------------------
        # The active profile must be known before parsing so stored config
        # defaults can seed the parser; explicit CLI arguments still win.
        try:
            cfg, cfg_warnings = config_defaults(profile_from_argv(sys.argv[1:]))
        except ConfigError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            raise SystemExit(2) from exc
        parser = build_parser(cfg)
        args = parser.parse_intermixed_args()

        _setup_logging(args.verbose)
        for warning in cfg_warnings:
            log.warning("Ignored config entry", detail=warning)

        # Cross-argument validation that argparse can't express natively.
        if args.cert_type in ("ov", "ev") and not args.org_id:
            parser.error(f"--org-id is required for {args.cert_type.upper()} certificates")

        if args.requestor_phone and not args.requestor_phone.startswith("+"):
            parser.error(
                f"--requestor-phone must be in E.164 format (e.g. +12075551234), "
                f"got: {args.requestor_phone!r}"
            )

        # apply_sandbox() rewrites base_url/token_url when --sandbox is set.
        # build_session() loads credentials from the keyring (or env vars) and
        # returns an authenticated CertiNextSession.
        apply_sandbox(args)

        # Save defaults before any network work so a failed issuance never
        # loses the entered values.
        if args.save_defaults:
            _maybe_save_defaults(args)

        sess = build_session(args)

        # Capture signer fields early; they may be overridden by CSR defaults.
        signer_name = args.requestor_name
        signer_place = args.signer_place

        # ------------------------------------------------------------------
        # Phase 2: Order acquisition
        # ------------------------------------------------------------------

        if args.order_id:
            # Resume path: fetch an existing order by its numeric ID.
            try:
                order = sess.ssl.get(args.order_id)
            except CertiNextAPIError as exc:
                log.error("Error fetching order", order_id=args.order_id, status_code=exc.status_code)
                raise SystemExit(1) from exc
            log.info("Resuming order", order_id=order.order_id, status=order.status)
            csr_path = getattr(args, "csr_file", None)
            csr = _read_csr(csr_path) if csr_path is not None else ""

        else:
            # New-order path: parse the CSR, fill any missing fields from its
            # subject, then POST to the ssl-certificates endpoint.
            csr_path = getattr(args, "csr_file", None)
            csr = _read_csr(csr_path)
            if not csr.strip():
                log.error("Empty CSR")
                raise SystemExit(1)

            # parse_csr() extracts CN, SANs, emailAddress, L, and ST.
            # Each field only overrides the CLI argument when the argument was
            # not supplied, so explicit flags always take precedence.
            csr_info = _parse_csr(csr)
            if not args.domain:
                args.domain = csr_info.common_name          # CN → primary domain
            if args.sans is None:
                args.sans = csr_info.sans                   # SAN extension
            if not args.requestor_email and csr_info.email:
                args.requestor_email = csr_info.email       # emailAddress OID
            if not args.signer_place and csr_info.signer_place:
                args.signer_place = csr_info.signer_place   # "Orono, Maine"
                signer_place = csr_info.signer_place

            order = _check_existing_and_prompt(sess, args)
            if order is None:
                log.info(
                    "Ordering certificate",
                    domain=args.domain,
                    sans_count=len(args.sans) if args.sans else 0,
                )
                order = _create_order(sess, args, csr=csr)
                log.info("Created order", order_id=order.order_id, status=order.status)

        # ------------------------------------------------------------------
        # Phase 3: Workflow execution
        # ------------------------------------------------------------------

        # DCV challenges are only logged once even if advance() fires the
        # dcv_available event on subsequent poll ticks.
        dcv_logged = False

        def _on_dcv(challenges: list[DcvChallenge]) -> None:
            nonlocal dcv_logged
            if not dcv_logged:
                for c in challenges:
                    log.info(
                        "DCV challenge",
                        domain=c.domain, method=c.method, host=c.host, token=c.token,
                    )
                dcv_logged = True

        # OrderWorkflow drives the order through every pending state and polls
        # until issuance. Event hooks replace explicit polling logic here —
        # the workflow emits events; this function just logs them.
        wf = (
            OrderWorkflow(order, signer_name=signer_name, signer_place=signer_place)
            .on("status_change", lambda old, new: log.debug(
                "Order status change", order_id=order.order_id, old_status=old, new_status=new,
            ))
            .on("poll", lambda o: log.debug(
                "Polling order", order_id=o.order_id, status=o.status,
            ))
            .on("dcv_available", _on_dcv)
            .on("issued", lambda o: log.info("Order issued", order_id=o.order_id))
        )

        if args.wait == 0:
            # Non-blocking mode: submit the CSR and advance one step, then
            # exit so the caller can schedule a later resume run.
            wf.submit_csr(csr, force=True)
            wf.advance(csr)
            log.info("Order submitted", order_id=order.order_id, status=order.status)
            log.info("Re-run with --order-id to resume polling", order_id=order.order_id)
            return

        # wf.run() submits the CSR (force=True), drives all state transitions,
        # polls until issued, and downloads the PEM with automatic 422 retry.
        # It raises CertiNextTimeoutError if wait seconds elapse without issuance.
        try:
            pem = wf.run(csr=csr, wait=args.wait)
        except CertiNextTimeoutError as exc:
            log.error(
                "Timed out waiting for issuance",
                wait_seconds=exc.wait, order_id=order.order_id, status=order.status,
            )
            raise SystemExit(1) from exc

        if order.status != "issued":
            log.error(
                "Order ended without issuance",
                order_id=order.order_id, status=order.status,
            )
            raise SystemExit(1)

        # ------------------------------------------------------------------
        # Output: write the PEM to files and/or stdout
        # ------------------------------------------------------------------
        _write_outputs(order, args, pem)

    except SystemExit as exc:
        # If we have an order that can be resumed, always print the hint so
        # the operator knows how to continue after any unexpected failure.
        if exc.code not in (0, 130) and order is not None and order.order_id:
            if order.status not in ("cancelled", "rejected", "revoked"):
                log.error("Re-run with --order-id to resume", order_id=order.order_id)
        raise
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        raise SystemExit(130)


if __name__ == "__main__":
    main()
