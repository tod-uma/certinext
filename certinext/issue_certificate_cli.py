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
    certinext-issue-cert --csr example.com.csr --sandbox
    certinext-issue-cert < example.com.csr
    certinext-issue-cert --order-id <ID> --wait 300  # resume polling
"""

import argparse
import logging
import sys

from certinext._cli import (
    _setup_logging,
    add_connection_args,
    add_requestor_args,
    apply_sandbox,
    build_session,
    fatal_api_error,
)
from certinext.csr import CsrInfo
from certinext.exceptions import CertiNextAPIError, CertiNextTimeoutError
from certinext.session import CertiNextSession
from certinext.ssl_certificates import DcvChallenge, OrderWorkflow, SslOrder

log = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    """Return the argument parser for certinext-issue-cert.

    Returns:
        A configured ArgumentParser instance.
    """
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
        "--validity", type=int, default=1, metavar="YEARS", choices=[1, 2, 3],
        help="Certificate validity in years (1, 2, or 3; default: 1)",
    )
    cert.add_argument(
        "--type", dest="cert_type", choices=["dv", "ov", "ev"], default="dv",
        help="Certificate validation type (default: dv)",
    )
    cert.add_argument(
        "--org-id", metavar="ID", default=None,
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
    add_requestor_args(req)

    ctl = parser.add_argument_group("output")
    ctl.add_argument(
        "--output", "-o", metavar="FILE", default=None,
        help="Write certificate PEM to FILE instead of stdout",
    )
    ctl.add_argument(
        "--wait", type=int, default=300, metavar="SECONDS",
        help="Seconds to wait for issuance before giving up (0 = submit and exit; default: 300)",
    )
    ctl.add_argument(
        "--order-id", metavar="ID", default=None,
        help="Resume polling an existing order rather than creating a new one",
    )
    return parser


def _read_csr(path: str | None) -> str:
    """Read a PEM-encoded CSR from a file path or stdin.

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
                print("Reading CSR from stdin (paste PEM, then Ctrl-D):", file=sys.stderr)
            return sys.stdin.read()
        with open(path) as f:
            return f.read()
    except OSError as exc:
        log.error("Error reading CSR: %s", exc)
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
        log.error("%s", exc)
        raise SystemExit(1) from exc


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
        parser = build_parser()
        args = parser.parse_intermixed_args()

        _setup_logging(args.verbose)

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
                log.error("Error fetching order %s: HTTP %s", args.order_id, exc.status_code)
                raise SystemExit(1) from exc
            log.info("Resuming order %s (status: %s)", order.order_id, order.status)
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
            if not signer_place and csr_info.signer_place:
                signer_place = csr_info.signer_place        # "Orono, Maine"

            log.info(
                "Ordering certificate for %s%s",
                args.domain,
                f" + {len(args.sans)} SAN(s)" if args.sans else "",
            )
            order = _create_order(sess, args, csr=csr)
            log.info("Created order %s (status: %s)", order.order_id, order.status)

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
                        "DCV challenge for %s: %s %s = %s",
                        c.domain, c.method, c.host, c.token,
                    )
                dcv_logged = True

        # OrderWorkflow drives the order through every pending state and polls
        # until issuance. Event hooks replace explicit polling logic here —
        # the workflow emits events; this function just logs them.
        wf = (
            OrderWorkflow(order, signer_name=signer_name, signer_place=signer_place)
            .on("status_change", lambda old, new: log.debug(
                "Order %s: %s -> %s", order.order_id, old, new,
            ))
            .on("poll", lambda o: log.debug(
                "Order %s status: %s (polling)", o.order_id, o.status,
            ))
            .on("dcv_available", _on_dcv)
            .on("issued", lambda o: log.info("Order %s issued.", o.order_id))
        )

        if args.wait == 0:
            # Non-blocking mode: submit the CSR and advance one step, then
            # exit so the caller can schedule a later resume run.
            wf.submit_csr(csr, force=True)
            wf.advance(csr)
            log.info("Order %s submitted (status: %s)", order.order_id, order.status)
            log.info("Re-run with --order-id %s to resume polling.", order.order_id)
            return

        # wf.run() submits the CSR (force=True), drives all state transitions,
        # polls until issued, and downloads the PEM with automatic 422 retry.
        # It raises CertiNextTimeoutError if wait seconds elapse without issuance.
        try:
            pem = wf.run(csr=csr, wait=args.wait)
        except CertiNextTimeoutError as exc:
            log.error(
                "Timed out after %ds waiting for issuance (order %s, status: %s).",
                exc.wait, order.order_id, order.status,
            )
            raise SystemExit(1) from exc

        if order.status != "issued":
            log.error(
                "Order %s ended with status '%s' — certificate was not issued.",
                order.order_id, order.status,
            )
            raise SystemExit(1)

        # ------------------------------------------------------------------
        # Output: write the PEM to a file or print to stdout
        # ------------------------------------------------------------------
        if args.output:
            try:
                with open(args.output, "w") as f:
                    f.write(pem)
                log.info("Certificate written to %s", args.output)
            except OSError as exc:
                log.error("Error writing certificate: %s", exc)
                raise SystemExit(1) from exc
        else:
            print(pem, end="")

    except SystemExit as exc:
        # If we have an order that can be resumed, always print the hint so
        # the operator knows how to continue after any unexpected failure.
        if exc.code not in (0, 130) and order is not None and order.order_id:
            if order.status not in ("cancelled", "rejected", "revoked"):
                log.error("Re-run with --order-id %s to resume.", order.order_id)
        raise
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        raise SystemExit(130)


if __name__ == "__main__":
    main()
