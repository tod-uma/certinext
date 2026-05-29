"""Submit a CSR to CertiNext and download the issued certificate.

Reads a PEM-encoded CSR from a file or stdin, extracts the domain and SANs
from the CSR itself, creates a certificate order, submits the CSR, and writes
the issued PEM certificate to stdout or a file once the CA has signed it.

The target domain must already have DCV completed in CertiNext.  Use
``certinext-pending-dcv`` (or ``dcv-update``) to complete DCV first.

Requires the ``csr`` optional dependency::

    pip install certinext[csr]

Usage::

    certinext-issue-cert example.com.csr --requestor-name "John Doe" ...
    certinext-issue-cert --csr example.com.csr --output example.com.pem
    certinext-issue-cert --csr example.com.csr --sandbox
    certinext-issue-cert < example.com.csr
    certinext-issue-cert --order-id <ID> --wait 300  # resume polling an existing order
"""

import argparse
import logging
import sys
import time

from certinext._cli import (
    _setup_logging,
    add_connection_args,
    add_requestor_args,
    apply_sandbox,
    build_session,
    fatal_api_error,
)
from certinext.exceptions import CertiNextAPIError
from certinext.session import CertiNextSession
from certinext.ssl_certificates import DcvChallenge, SslOrder

log = logging.getLogger(__name__)

_TERMINAL_STATUSES = frozenset({"issued", "revoked", "cancelled", "rejected", "expired"})
_POLL_INTERVAL = 5


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


def _parse_csr(pem: str) -> tuple[str, list[str]]:
    """Extract the CN and DNS SANs from a PEM-encoded CSR.

    Thin wrapper around :func:`certinext.csr.parse_csr` that converts
    :exc:`ImportError` and :exc:`ValueError` to ``SystemExit(1)``.

    Args:
        pem: PEM-encoded certificate signing request string.

    Returns:
        A tuple of ``(cn, sans)`` where ``cn`` is the Common Name from the
        subject and ``sans`` is a list of DNS SANs from the SAN extension,
        excluding the CN.

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

    requestor_kwargs = dict(
        requestor_name=args.requestor_name or "",
        requestor_email=args.requestor_email or "",
        requestor_phone=args.requestor_phone or "",
        requestor_designation=args.requestor_designation or "",
        signer_name=args.requestor_name or "",
        signer_place=args.signer_place or "",
    )
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
                **requestor_kwargs,
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
                **requestor_kwargs,
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
                **requestor_kwargs,
            )
    except CertiNextAPIError as exc:
        fatal_api_error(exc, "Error creating order")


def _submit_csr(order: SslOrder, csr: str, *, force: bool = False) -> bool:
    """Submit the CSR for this order unless it is in a terminal state.

    Refreshes the order first. If the status is not terminal (or ``force`` is
    set), attempts CSR submission regardless of the exact status — some API
    environments (e.g. the sandbox) skip ``pending-csr`` and return a later
    status directly from order creation. Failure is fatal only when the order
    was in ``pending-csr``; for other statuses the error is logged as a debug
    message and processing continues, since the order may not need a CSR at
    that stage.

    Set ``force=True`` when the caller explicitly provided a CSR and wants
    submission attempted even if the order appears to be in a terminal state
    (e.g. ``"issued"`` without an actual signed certificate yet).

    Args:
        order: The SslOrder to submit the CSR for.
        csr: PEM-encoded Certificate Signing Request string.
        force: If ``True``, bypass the terminal-status early-exit.

    Returns:
        ``True`` if the CSR was accepted by the API; ``False`` if submission
        was skipped (terminal state without ``force``) or the API rejected it
        non-fatally.
    """
    order.refresh()
    if not force and order.status in _TERMINAL_STATUSES:
        return False
    log.debug("Submitting CSR for order %s (status: %s)", order.order_id, order.status)
    needed = order.status == "pending-csr"
    try:
        order.submit_csr(csr)
        order.refresh()
        return True
    except CertiNextAPIError as exc:
        if needed:
            fatal_api_error(exc, f"Error submitting CSR for order {order.order_id}")
        log.debug(
            "CSR submission returned HTTP %s for order %s in status %r — "
            "order may not require a CSR at this stage",
            exc.status_code, order.order_id, order.status,
        )
        return False


def _advance_order(
    order: SslOrder,
    signer_name: str,
    signer_place: str,
    csr: str = "",
    *,
    _dcv_logged: set[str] | None = None,
) -> None:
    """Accept the subscriber agreement, handle DCV, or submit the CSR as needed.

    Refreshes the order state first, then performs the appropriate action:

    - ``pending-agreement``: accepts the subscriber agreement.
    - ``pending-dcv``: logs challenge details and triggers a verify call.
      In UMS environments, pre-validated domains should auto-resolve without
      any manual intervention; this code path may never produce visible output
      in normal UMS operation.
    - ``pending-csr``: submits the provided CSR. Exits with code 1 if
      submission fails or if no CSR was provided.

    Args:
        order: The SslOrder to advance.
        signer_name: Full name of the person accepting the agreement.
        signer_place: City or location of the signer.
        csr: PEM-encoded CSR string. Required when the order reaches
            ``pending-csr``; ignored for other states.
        _dcv_logged: Mutable set tracking order IDs whose DCV challenges have
            already been logged at INFO level. Pass the same set on every call
            to suppress repeat log messages during polling.
    """
    order.refresh()
    if order.status == "pending-agreement":
        log.debug("Accepting subscriber agreement for order %s", order.order_id)
        try:
            order.accept_agreement(signer_name, signer_place)
            order.refresh()
        except CertiNextAPIError as exc:
            log.debug(
                "accept_agreement returned HTTP %s — order may advance on its own",
                exc.status_code,
            )
    elif order.status == "pending-dcv":
        challenges: list[DcvChallenge] = []
        try:
            challenges = order.get_dcv()
            if challenges and (_dcv_logged is None or order.order_id not in _dcv_logged):
                for c in challenges:
                    log.info(
                        "DCV challenge for %s: %s %s = %s",
                        c.domain, c.method, c.host, c.token,
                    )
                if _dcv_logged is not None and order.order_id is not None:
                    _dcv_logged.add(order.order_id)
        except CertiNextAPIError as exc:
            log.debug(
                "get_dcv returned HTTP %s for order %s",
                exc.status_code, order.order_id,
            )
        for c in challenges:
            if c.domain and c.method:
                try:
                    order.verify_dcv(c.domain, c.method)
                except CertiNextAPIError as exc:
                    log.debug(
                        "verify_dcv returned HTTP %s for %s on order %s — will retry on next poll",
                        exc.status_code, c.domain, order.order_id,
                    )
        order.refresh()
    elif order.status == "pending-csr":
        if not csr.strip():
            log.error(
                "Order %s requires a CSR — re-run with --order-id %s --csr <file>",
                order.order_id, order.order_id,
            )
            raise SystemExit(1)
        log.debug("Submitting CSR for order %s (status: pending-csr)", order.order_id)
        try:
            order.submit_csr(csr)
            order.refresh()
        except CertiNextAPIError as exc:
            fatal_api_error(exc, f"CSR submission failed for order {order.order_id}")


def main() -> None:
    """Entry point for certinext-issue-cert."""
    try:
        parser = build_parser()
        args = parser.parse_intermixed_args()

        _setup_logging(args.verbose)

        if args.cert_type in ("ov", "ev") and not args.org_id:
            parser.error(f"--org-id is required for {args.cert_type.upper()} certificates")

        if args.requestor_phone and not args.requestor_phone.startswith("+"):
            parser.error(
                f"--requestor-phone must be in E.164 format (e.g. +12075551234), "
                f"got: {args.requestor_phone!r}"
            )

        apply_sandbox(args)
        sess = build_session(args)

        signer_name = args.requestor_name
        signer_place = args.signer_place

        if args.order_id:
            try:
                order = sess.ssl.get(args.order_id)
            except CertiNextAPIError as exc:
                log.error("Error fetching order %s: HTTP %s", args.order_id, exc.status_code)
                raise SystemExit(1) from exc
            log.info("Resuming order %s (status: %s)", order.order_id, order.status)

            csr_path = getattr(args, "csr_file", None)
            csr = _read_csr(csr_path) if csr_path is not None else ""
            # Immediate attempt when a file is provided — force=True so we try
            # even if the current status is not pending-csr (e.g. the CA may
            # have already advanced the order). If this fails non-fatally,
            # _advance_order will retry when the order reaches pending-csr.
            if csr.strip():
                if _submit_csr(order, csr, force=True):
                    log.info("CSR submitted, order status: %s", order.status)
        else:
            csr_path = getattr(args, "csr_file", None)
            csr = _read_csr(csr_path)
            if not csr.strip():
                log.error("Empty CSR")
                raise SystemExit(1)

            # Fill in domain and SANs from the CSR unless explicitly overridden.
            if not args.domain or args.sans is None:
                cn, csr_sans = _parse_csr(csr)
                if not args.domain:
                    args.domain = cn
                if args.sans is None:
                    args.sans = csr_sans

            log.info(
                "Ordering certificate for %s%s",
                args.domain,
                f" + {len(args.sans)} SAN(s)" if args.sans else "",
            )
            order = _create_order(sess, args, csr=csr)
            log.info("Created order %s (status: %s)", order.order_id, order.status)

            # If the CSR was accepted upfront the order may have already advanced
            # past pending-csr. _submit_csr is a best-effort fallback for APIs
            # or environments that don't accept an upfront CSR.
            if order.status not in _TERMINAL_STATUSES:
                _submit_csr(order, csr)
                log.info("Order %s status after CSR: %s", order.order_id, order.status)

        dcv_logged: set[str] = set()
        _advance_order(order, signer_name, signer_place, csr, _dcv_logged=dcv_logged)

        if args.wait == 0:
            log.info("Order %s submitted (status: %s)", order.order_id, order.status)
            log.info("Re-run with --order-id %s to resume polling.", order.order_id)
            return

        deadline = time.monotonic() + args.wait
        while order.status not in _TERMINAL_STATUSES:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                log.error(
                    "Timed out after %ds waiting for issuance "
                    "(order %s, status: %s). Re-run with --order-id %s to resume.",
                    args.wait, order.order_id, order.status, order.order_id,
                )
                raise SystemExit(1)
            log.debug(
                "Order %s status: %s (polling, %ds remaining)",
                order.order_id, order.status, int(remaining),
            )
            time.sleep(min(_POLL_INTERVAL, remaining))
            _advance_order(order, signer_name, signer_place, csr, _dcv_logged=dcv_logged)

        if order.status != "issued":
            log.error(
                "Order %s ended with status '%s' — certificate was not issued.",
                order.order_id, order.status,
            )
            raise SystemExit(1)

        log.info("Order %s issued.", order.order_id)
        try:
            pem = order.download_certificate_pem()
        except CertiNextAPIError as exc:
            log.error("Error downloading certificate for order %s: %s", order.order_id, exc)
            log.debug("  Full response body: %s", exc.body)
            raise SystemExit(1) from exc

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

    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        raise SystemExit(130)


if __name__ == "__main__":
    main()
