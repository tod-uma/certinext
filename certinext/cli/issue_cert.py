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

"""``certinext issue-cert`` — submit a CSR and download the issued certificate.

This command is both a working CLI and a reference for driving the full
certificate lifecycle with :class:`~certinext.ssl_certificates.OrderWorkflow`;
see that class for the library-level pattern. The command adds argument
handling, credential loading from the keyring, sandbox switching, and the
output-file plumbing.

The target domain must already have DCV completed in CertiNext. Use
``certinext pending-dcv`` (or ``dcv-update``) to complete DCV first.

Requires the ``csr`` optional dependency (``pip install certinext[csr]``).

Where the 0.3.x argparse script seeded parser *defaults* from the config file
(so required-ness itself depended on the config), this port keeps every option
optional at parse time and resolves the explicit-CLI → environment → stored
config precedence in :func:`resolve_order_defaults`, erroring with exit code 2
when a required value is still missing — same observable contract, testable as
a pure function.
"""

import os
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, NoReturn, Optional

import structlog
import typer
from rich.progress import Progress

from certinext._config import ConfigError, config_defaults, save_defaults
from certinext._keyring import keyring_get, keyring_service
from certinext.cli._app import app
from certinext.cli._shared import (
    AccountNumberOption,
    BaseUrlOption,
    ClientSecretOption,
    ProfileOption,
    SandboxOption,
    TokenUrlOption,
    VerboseOption,
    connect,
    err_console,
    progress_disabled,
)
from certinext.cli_support import fatal_api_error, prompt_stderr, setup_logging
from certinext.csr import CsrInfo
from certinext.exceptions import CertiNextAPIError, CertiNextTimeoutError
from certinext.session import CertiNextSession
from certinext.ssl_certificates import (
    CertificateDownload,
    DcvChallenge,
    OrderWorkflow,
    SslOrder,
)

log = structlog.get_logger()


class _CertType(str, Enum):
    """The certificate validation types ``--type`` accepts."""

    dv = "dv"
    ov = "ov"
    ev = "ev"


@dataclass
class OrderDefaults:
    """Effective order values after CLI → env → stored-config resolution.

    Produced by :func:`resolve_order_defaults`; consumed by the command body
    and :func:`_create_order`.

    Attributes:
        requestor_name: Full name of the certificate requestor.
        requestor_email: Requestor email ("" when unset; may be filled from
            the CSR emailAddress field later).
        requestor_phone: Requestor phone in E.164 format.
        requestor_designation: Requestor job title ("" when unset).
        signer_place: Subscriber-agreement signing location ("" when unset;
            may be filled from the CSR L/ST fields later).
        cert_type: ``"dv"``, ``"ov"``, or ``"ev"``.
        org_id: Organization ID for OV/EV orders, or None.
        validity: Certificate validity in years (1, 2, or 3).
        product: CERTInext product code, or None for the API default.
    """

    requestor_name: str
    requestor_email: str
    requestor_phone: str
    requestor_designation: str
    signer_place: str
    cert_type: str
    org_id: str | None
    validity: int
    product: str | None


def resolve_order_defaults(
    cfg: Mapping[str, Any],
    *,
    requestor_name: str | None = None,
    requestor_email: str | None = None,
    requestor_phone: str | None = None,
    requestor_designation: str | None = None,
    signer_place: str | None = None,
    cert_type: str | None = None,
    org_id: str | None = None,
    validity: int | None = None,
    product: str | None = None,
) -> OrderDefaults:
    """Resolve order values with the 0.3.x precedence: CLI > environment > config.

    The requestor fields fall back to their ``CERTINEXT_REQUESTOR_*`` /
    ``CERTINEXT_SIGNER_PLACE`` environment variables and then the stored
    config defaults; the certificate fields (``type``, ``org_id``,
    ``validity``, ``product``) fall back to config only, exactly as the
    argparse parser's config-seeded defaults did.

    Args:
        cfg: Stored defaults keyed by dest name, as returned by
            :func:`certinext._config.config_defaults`.
        requestor_name: Explicit ``--requestor-name`` value, or None.
        requestor_email: Explicit ``--requestor-email`` value, or None.
        requestor_phone: Explicit ``--requestor-phone`` value, or None.
        requestor_designation: Explicit ``--requestor-designation``, or None.
        signer_place: Explicit ``--signer-place`` value, or None.
        cert_type: Explicit ``--type`` value, or None.
        org_id: Explicit ``--org-id`` value, or None.
        validity: Explicit ``--validity`` value, or None.
        product: Explicit ``--product`` value, or None.

    Returns:
        The resolved :class:`OrderDefaults`.

    Raises:
        ValueError: When a required value (``--requestor-name`` or
            ``--requestor-phone``) is missing from every source. The message
            names the missing flags.
    """
    def _requestor(cli_value: str | None, env_var: str, key: str) -> str:
        """Resolve one requestor field: CLI, then env, then stored config."""
        return cli_value or os.environ.get(env_var, "") or str(cfg.get(key, "") or "")

    resolved = OrderDefaults(
        requestor_name=_requestor(requestor_name, "CERTINEXT_REQUESTOR_NAME", "requestor_name"),
        requestor_email=_requestor(requestor_email, "CERTINEXT_REQUESTOR_EMAIL", "requestor_email"),
        requestor_phone=_requestor(requestor_phone, "CERTINEXT_REQUESTOR_PHONE", "requestor_phone"),
        requestor_designation=_requestor(
            requestor_designation, "CERTINEXT_REQUESTOR_DESIGNATION", "requestor_designation"
        ),
        signer_place=_requestor(signer_place, "CERTINEXT_SIGNER_PLACE", "signer_place"),
        cert_type=cert_type or str(cfg.get("cert_type") or "dv"),
        org_id=org_id or (str(cfg["org_id"]) if cfg.get("org_id") else None),
        validity=validity if validity is not None else int(cfg.get("validity") or 1),
        product=product or (str(cfg["product"]) if cfg.get("product") else None),
    )

    missing = [
        flag
        for flag, value in (
            ("--requestor-name", resolved.requestor_name),
            ("--requestor-phone", resolved.requestor_phone),
        )
        if not value
    ]
    if missing:
        raise ValueError(f"the following arguments are required: {', '.join(missing)}")
    return resolved


@dataclass
class OutputOptions:
    """The output-destination flags of ``certinext issue-cert``.

    Mirrors the 0.3.x flag set; all destinations default to None (stdout
    bundle) and :func:`_write_outputs` interprets the combination.

    Attributes:
        output: ``--output`` path for the full PEM bundle, or None.
        cert_out: ``--cert-out`` path for the leaf certificate, or None.
        chain_out: ``--chain-out`` path for the intermediates, or None.
        fullchain_out: ``--fullchain-out`` path, or None.
        der_out: ``--der-out`` path for the DER leaf, or None.
        all_formats_out: ``--all-formats-out`` directory, or None.
        raw_chain: ``--raw-chain`` — emit the chain in raw API order.
    """

    output: str | None = None
    cert_out: str | None = None
    chain_out: str | None = None
    fullchain_out: str | None = None
    der_out: str | None = None
    all_formats_out: str | None = None
    raw_chain: bool = False


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
    sess: CertiNextSession, domain: str, no_domain_check: bool
) -> SslOrder | None:
    """Check for existing orders on the same domain and prompt the user how to proceed.

    Skips immediately when ``no_domain_check`` is set. Otherwise fetches
    all orders (any status) whose CN matches ``domain`` and:

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
        domain: The primary domain of the order about to be created.
        no_domain_check: The ``--no-domain-check`` flag.

    Returns:
        An :class:`~certinext.ssl_certificates.SslOrder` to resume, or ``None``
        to proceed with creating a new order.

    Raises:
        SystemExit: With code 0 if the user declines to create a new
            certificate over an existing issued one.
    """
    if no_domain_check:
        return None
    try:
        all_matches = sess.orders.find_by_domain(domain, status=None)
    except CertiNextAPIError as exc:
        log.debug("Domain existence check failed - skipping", status_code=exc.status_code)
        return None

    log.debug("Domain check: orders found", count=len(all_matches), domain=domain)
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
                "In-progress order exists with CSR on file - resuming may work",
                domain=domain, order_id=pending.order_number, status=pending.certificate_status,
            )
        else:
            log.warning(
                "In-progress order exists without CSR - resuming will submit current CSR",
                domain=domain, order_id=pending.order_number, status=pending.certificate_status,
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
            domain=domain, order_number=issued.order_number,
        )
        try:
            answer = prompt_stderr("Create a new certificate anyway? [y/N]: ").strip().lower()
        except EOFError:
            answer = ""
        if answer != "y":
            raise SystemExit(0)

    return None


def _create_order(
    sess: CertiNextSession,
    values: OrderDefaults,
    *,
    domain: str,
    sans: list[str] | None,
    auto_secure_www: bool,
    prevetting_token: str | None,
    csr: str = "",
) -> SslOrder:
    """Create a new SSL order.

    When ``csr`` is provided it is included in the initial order body, which
    may allow the CA to skip the ``pending-csr`` stage entirely.

    Args:
        sess: An authenticated CertiNextSession.
        values: The resolved order values (type, validity, org, requestor).
        domain: The primary domain for the order.
        sans: Additional domains, or None.
        auto_secure_www: The ``--auto-secure-www`` flag.
        prevetting_token: Organization consent token for OV/EV, or None.
        csr: PEM-encoded CSR to include with the initial order (optional).

    Returns:
        The created SslOrder.

    Raises:
        SystemExit: On API error.
    """
    csr_arg: str | None = csr.strip() or None

    try:
        if values.cert_type == "dv":
            return sess.ssl.create_dv(
                domain,
                validity_years=values.validity,
                additional_domains=sans,
                auto_secure_www=auto_secure_www,
                csr=csr_arg,
                requestor_name=values.requestor_name,
                requestor_email=values.requestor_email,
                requestor_phone=values.requestor_phone,
                requestor_designation=values.requestor_designation,
                signer_name=values.requestor_name,
                signer_place=values.signer_place,
                product_code=values.product,
            )
        elif values.cert_type == "ov":
            if values.org_id is None:  # validated by the command; guards direct calls
                raise SystemExit("--org-id is required for OV certificates")
            return sess.ssl.create_ov(
                domain,
                organization_id=values.org_id,
                validity_years=values.validity,
                additional_domains=sans,
                auto_secure_www=auto_secure_www,
                prevetting_token=prevetting_token,
                csr=csr_arg,
                requestor_name=values.requestor_name,
                requestor_email=values.requestor_email,
                requestor_phone=values.requestor_phone,
                requestor_designation=values.requestor_designation,
                signer_name=values.requestor_name,
                signer_place=values.signer_place,
                product_code=values.product,
            )
        else:
            if values.org_id is None:  # validated by the command; guards direct calls
                raise SystemExit("--org-id is required for EV certificates")
            return sess.ssl.create_ev(
                domain,
                organization_id=values.org_id,
                validity_years=values.validity,
                additional_domains=sans,
                auto_secure_www=auto_secure_www,
                prevetting_token=prevetting_token,
                csr=csr_arg,
                requestor_name=values.requestor_name,
                requestor_email=values.requestor_email,
                requestor_phone=values.requestor_phone,
                requestor_designation=values.requestor_designation,
                signer_name=values.requestor_name,
                signer_place=values.signer_place,
                product_code=values.product,
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
            "Skipping format - download failed",
            output=label, path=path, status_code=exc.status_code,
        )
        return False
    try:
        with open(path, "wb") as f:
            f.write(data)
    except OSError as exc:
        log.warning(
            "Skipping format - write failed",
            output=label, path=path, error=str(exc),
        )
        return False
    log.info("Output written", output=label, path=path)
    return True


def _fail_chain_sort(exc: ImportError) -> NoReturn:
    """Report that chain sorting needs ``cryptography`` and exit.

    Called when sorting was requested (``--raw-chain`` not set) but the
    ``cryptography`` package is unavailable. Points the user at the install
    extra and the ``--raw-chain`` escape hatch, then exits non-zero.

    Args:
        exc: The :class:`ImportError` raised by the sorting helper.

    Raises:
        SystemExit: Always, with code 1.
    """
    log.error(
        "Chain sorting requires the 'cryptography' package",
        install="pip install certinext[csr]",
        alternative="pass --raw-chain to emit the raw (unsorted) API order",
    )
    raise SystemExit(1) from exc


def _ordered_intermediates(dl: CertificateDownload) -> list[str]:
    """Return the intermediate certificates in leaf-first signing order.

    Sorts the full chain (leaf + intermediates) and drops the leaf, so the
    result is the intermediates ordered issuer-after-subject up to the root.

    Args:
        dl: The JSON certificate download to read leaf and intermediates from.

    Returns:
        Intermediate PEM strings in signing order; empty if there are none.

    Raises:
        ImportError: If the ``cryptography`` package is not installed.
    """
    from certinext._chain import order_certificate_chain

    ordered = order_certificate_chain(dl.chain_pem, leaf_pem=dl.certificate_pem)
    return ordered[1:] if len(ordered) > 1 else []


def _sort_pem_bundle(pem: str) -> str:
    """Return *pem* re-sorted into leaf-first signing order.

    Splits the bundle into individual certificates and re-orders them. If the
    bundle contains no parseable certificates the original text is returned
    unchanged.

    Args:
        pem: A PEM bundle (leaf plus chain), typically the raw download.

    Returns:
        The re-sorted PEM bundle ending in a single newline, or *pem* unchanged
        if nothing could be ordered.

    Raises:
        ImportError: If the ``cryptography`` package is not installed.
    """
    from certinext._chain import order_certificate_chain, split_pem_certificates

    ordered = order_certificate_chain(split_pem_certificates(pem))
    return "\n".join(ordered) + "\n" if ordered else pem


def _write_outputs(order: SslOrder, opts: OutputOptions, pem: str) -> None:
    """Write the issued certificate to the requested output destinations.

    ``--output`` (and the stdout default) receive the raw PEM bundle returned
    by the workflow, re-sorted into leaf-first signing order. ``--cert-out``,
    ``--chain-out``, and ``--fullchain-out`` are assembled from the JSON download
    (:meth:`~certinext.ssl_certificates.SslOrder.download_certificate`), which
    separates the end-entity certificate from its intermediates:

    - ``--cert-out``: the end-entity (leaf) certificate only
    - ``--chain-out``: the intermediate CA certificates only, in signing order
    - ``--fullchain-out``: leaf followed by intermediates, in signing order
      (:meth:`~certinext.ssl_certificates.CertificateDownload.as_pem_chain`)

    CertiNext returns the chain in a non-standard order that breaks IIS/Schannel
    (GitLab #4), so every chain-bearing output is sorted by default. ``--raw-chain``
    disables sorting and emits the exact API order; it is also the escape hatch
    when ``cryptography`` is not installed.

    Each PEM file is normalised to end with exactly one trailing newline.
    The binary format ``--der-out`` writes a DER-encoded end-entity certificate
    and cannot be written to stdout.  ``--all-formats-out DIR`` writes
    ``{domain}.pem`` (PEM bundle) and ``{domain}.der`` (DER) to *DIR* in one
    call, deriving the stem from the order's CN via :func:`_stem_from_domain`.

    Args:
        order: The issued order to download certificate parts from.
        opts: The output-destination flags.
        pem: Raw PEM bundle already downloaded by the workflow.

    Raises:
        SystemExit: With code 1 if any download fails, a requested part is
            missing from the download, a file cannot be written, or chain
            sorting is required but ``cryptography`` is not installed. An empty
            intermediate chain with ``--chain-out`` is a warning, not an
            error, because a leaf signed directly by a root has no
            intermediates.
    """
    sort = not opts.raw_chain

    # The raw bundle is used by --output, --all-formats-out, and the stdout
    # default; sort it once (and only if one of those will consume it).
    need_bundle = bool(opts.output or opts.all_formats_out) or not (
        opts.cert_out or opts.chain_out or opts.fullchain_out
        or opts.der_out or opts.all_formats_out or opts.output
    )
    pem_out = pem
    if need_bundle and sort:
        try:
            pem_out = _sort_pem_bundle(pem)
        except ImportError as exc:
            _fail_chain_sort(exc)

    if opts.cert_out or opts.chain_out or opts.fullchain_out:
        try:
            dl = order.download_certificate()
        except CertiNextAPIError as exc:
            fatal_api_error(exc, "Error downloading certificate parts")
        if opts.cert_out:
            leaf = (dl.certificate_pem or "").strip()
            if not leaf:
                log.error("Download contained no end-entity certificate")
                raise SystemExit(1)
            _write_file(opts.cert_out, leaf + "\n", "certificate")
        if opts.chain_out:
            try:
                chain = (
                    _ordered_intermediates(dl)
                    if sort
                    else [p.strip() for p in dl.chain_pem if p and p.strip()]
                )
            except ImportError as exc:
                _fail_chain_sort(exc)
            if not chain:
                log.warning("Download contained no intermediate certificates")
            _write_file(opts.chain_out, "\n".join(chain) + "\n" if chain else "", "chain")
        if opts.fullchain_out:
            try:
                fullchain = dl.as_pem_chain(sort=sort)
            except ImportError as exc:
                _fail_chain_sort(exc)
            if not fullchain:
                log.error("Download contained no certificates for the fullchain")
                raise SystemExit(1)
            _write_file(opts.fullchain_out, fullchain, "fullchain")

    if opts.der_out:
        _try_download_write_binary("certificate (DER)", opts.der_out, order.download_certificate_der)

    if opts.all_formats_out:
        stem = _stem_from_domain(order.domain)
        out_dir = Path(opts.all_formats_out)
        _write_file(str(out_dir / f"{stem}.pem"), pem_out, "certificate bundle (PEM)")
        _try_download_write_binary(
            "certificate (DER)", str(out_dir / f"{stem}.der"), order.download_certificate_der,
        )

    if opts.output:
        _write_file(opts.output, pem_out, "certificate bundle")
    elif not (opts.cert_out or opts.chain_out or opts.fullchain_out
              or opts.der_out or opts.all_formats_out):
        print(pem_out, end="")


def _maybe_save_defaults(values: OrderDefaults, profile: str | None) -> None:
    """Store the effective requestor/certificate values as config defaults.

    Called before the order is created so a failed or timed-out issuance never
    loses the entered values. When stdin is a TTY, asks for confirmation first
    (prompt on stderr so piped stdout stays clean); in non-interactive runs the
    ``--save-defaults`` flag itself is the consent and the save happens
    silently. Only non-empty values are stored.

    Args:
        values: The resolved order values to store.
        profile: The active profile section to write (the resolved profile,
            so ``--sandbox`` has become ``'sandbox'``).
    """
    to_store: dict[str, Any] = {
        "requestor_name": values.requestor_name,
        "requestor_email": values.requestor_email,
        "requestor_phone": values.requestor_phone,
        "requestor_designation": values.requestor_designation,
        "signer_place": values.signer_place,
        "cert_type": values.cert_type,
        "org_id": values.org_id,
        "validity": values.validity,
        "product": values.product,
    }
    section = f"profile {profile!r}" if profile else "the default profile"
    if sys.stdin.isatty():
        print(f"Save these values as defaults for {section}?", file=sys.stderr)
        for key, value in to_store.items():
            if value not in (None, ""):
                print(f"  {key} = {value}", file=sys.stderr)
        if prompt_stderr("Save? [Y/n]: ").strip().lower() in ("n", "no"):
            log.info("Defaults not saved")
            return
    try:
        path = save_defaults(to_store, profile)
    except ConfigError as exc:
        log.error("Error saving defaults", error=str(exc))
        raise SystemExit(1) from exc
    log.info("Defaults saved", path=str(path), profile=profile or "default")


@app.command("issue-cert")
def issue_cert(
    ctx: typer.Context,
    csr_file: Optional[str] = typer.Argument(
        None, metavar="[CSR_FILE]",
        help="PEM-encoded CSR file (default: stdin; not required with --order-id)",
    ),
    csr_opt: Optional[str] = typer.Option(
        None, "--csr", metavar="FILE",
        help="PEM-encoded CSR file (alternative to positional argument)",
    ),
    domain: Optional[str] = typer.Option(
        None, "--domain", metavar="FQDN",
        help="Override the primary domain (default: extracted from CSR CN)",
    ),
    san: list[str] = typer.Option(
        [], "--san", metavar="FQDN",
        help="Override SANs (default: extracted from CSR SAN extension; repeatable)",
    ),
    validity: Optional[int] = typer.Option(
        None, "--validity", metavar="YEARS", min=1, max=3,
        help="Certificate validity in years (1, 2, or 3; default: 1)",
    ),
    cert_type: Optional[_CertType] = typer.Option(
        None, "--type",
        help="Certificate validation type (default: dv)",
    ),
    org_id: Optional[str] = typer.Option(
        None, "--org-id", metavar="ID",
        help="Organization ID, required for OV and EV certificates",
    ),
    product: Optional[str] = typer.Option(
        None, "--product", metavar="CODE",
        help=(
            "CERTInext product code (X-Product-Code) selecting a specific catalog "
            "product; list codes with 'certinext setup defaults'. "
            "Default: the API's default product for the --type."
        ),
    ),
    prevetting_token: Optional[str] = typer.Option(
        None, "--prevetting-token", metavar="TOKEN",
        help=(
            "Organization Consent Token for OV/EV orders. "
            "When provided, the CA auto-approves without a manual approver step. "
            "Retrieve from the CertiNext portal under Organization Management > "
            "Organization Consent / Consent Tokens for the target organization."
        ),
    ),
    auto_secure_www: bool = typer.Option(
        False, "--auto-secure-www",
        help=(
            "Request automatic www-redirect coverage from the CA "
            "(default: false; the API default is true if omitted)"
        ),
    ),
    requestor_name: Optional[str] = typer.Option(
        None, "--requestor-name", metavar="NAME",
        help="Full name of the certificate requestor (env: CERTINEXT_REQUESTOR_NAME)",
    ),
    requestor_email: Optional[str] = typer.Option(
        None, "--requestor-email", metavar="EMAIL",
        help="Email address of the requestor (env: CERTINEXT_REQUESTOR_EMAIL)",
    ),
    requestor_phone: Optional[str] = typer.Option(
        None, "--requestor-phone", metavar="PHONE",
        help="Phone in E.164 format, e.g. +12075551234 (env: CERTINEXT_REQUESTOR_PHONE)",
    ),
    requestor_designation: Optional[str] = typer.Option(
        None, "--requestor-designation", metavar="TITLE",
        help="Job title or designation of the requestor (env: CERTINEXT_REQUESTOR_DESIGNATION)",
    ),
    signer_place_opt: Optional[str] = typer.Option(
        None, "--signer-place", metavar="PLACE",
        help="City/location for the subscriber agreement signature (env: CERTINEXT_SIGNER_PLACE)",
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", metavar="FILE",
        help="Write certificate PEM to FILE instead of stdout",
    ),
    cert_out: Optional[str] = typer.Option(
        None, "--cert-out", metavar="FILE",
        help="Write only the end-entity (leaf) certificate PEM to FILE",
    ),
    chain_out: Optional[str] = typer.Option(
        None, "--chain-out", metavar="FILE",
        help="Write only the intermediate CA chain PEM to FILE",
    ),
    fullchain_out: Optional[str] = typer.Option(
        None, "--fullchain-out", metavar="FILE",
        help="Write the leaf-first fullchain PEM (certificate + intermediates) to FILE",
    ),
    der_out: Optional[str] = typer.Option(
        None, "--der-out", metavar="FILE",
        help="Write the end-entity certificate in DER (binary) format to FILE",
    ),
    all_formats_out: Optional[str] = typer.Option(
        None, "--all-formats-out", metavar="DIR",
        help=(
            "Write all certificate formats to DIR: {domain}.pem (PEM bundle) "
            "and {domain}.der (DER). "
            "The domain stem comes from the order's CN."
        ),
    ),
    raw_chain: bool = typer.Option(
        False, "--raw-chain",
        help=(
            "Emit the certificate chain exactly as the API returns it, without "
            "re-sorting into leaf-first signing order. By default the chain is "
            "sorted (correct for IIS/Schannel); use this only for debugging or "
            "if you cannot install the 'cryptography' package."
        ),
    ),
    wait: int = typer.Option(
        300, "--wait", metavar="SECONDS",
        help="Seconds to wait for issuance before giving up (0 = submit and exit; default: 300)",
    ),
    order_id: Optional[str] = typer.Option(
        None, "--order-id", metavar="ID",
        help="Resume polling an existing order rather than creating a new one",
    ),
    save_defaults_flag: bool = typer.Option(
        False, "--save-defaults",
        help=(
            "Store the effective requestor/certificate values as defaults for "
            "future runs (in the config file; interactively confirms before "
            "the order is created)"
        ),
    ),
    no_domain_check: bool = typer.Option(
        False, "--no-domain-check",
        help=(
            "Skip the pre-creation check for existing orders on the same domain. "
            "By default the command queries issued and in-progress orders and "
            "prompts before creating a new one. Set this flag in automated pipelines."
        ),
    ),
    verbose: VerboseOption = 0,
    profile: ProfileOption = None,
    sandbox: SandboxOption = False,
    base_url: BaseUrlOption = None,
    token_url: TokenUrlOption = None,
    account_number: AccountNumberOption = None,
    client_secret: ClientSecretOption = None,
) -> None:
    """Submit a CSR to CertiNext and download the issued certificate.

    Domain and SANs are extracted from the CSR automatically.
    """
    # `order` is declared here so the except-SystemExit handler can reference
    # it even if the error occurs partway through order creation.
    order: SslOrder | None = None
    try:
        # ------------------------------------------------------------------
        # Phase 1: Option resolution and validation
        # ------------------------------------------------------------------
        # Config profile precedence matches 0.3.x profile_from_argv():
        # --profile, then --sandbox (implies 'sandbox'), then the env var.
        config_profile = profile or ("sandbox" if sandbox else None) or os.environ.get("CERTINEXT_PROFILE") or None
        try:
            cfg, cfg_warnings = config_defaults(config_profile)
        except ConfigError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            raise SystemExit(2) from exc

        setup_logging(verbose)
        for warning in cfg_warnings:
            log.warning("Ignored config entry", detail=warning)

        try:
            values = resolve_order_defaults(
                cfg,
                requestor_name=requestor_name,
                requestor_email=requestor_email,
                requestor_phone=requestor_phone,
                requestor_designation=requestor_designation,
                signer_place=signer_place_opt,
                cert_type=cert_type.value if cert_type else None,
                org_id=org_id,
                validity=validity,
                product=product,
            )
        except ValueError as exc:
            ctx.fail(str(exc))

        # Cross-argument validation the parser can't express natively.
        if values.cert_type in ("ov", "ev") and not values.org_id:
            ctx.fail(f"--org-id is required for {values.cert_type.upper()} certificates")

        if values.requestor_phone and not values.requestor_phone.startswith("+"):
            ctx.fail(
                f"--requestor-phone must be in E.164 format (e.g. +12075551234), "
                f"got: {values.requestor_phone!r}"
            )

        conn_profile = profile or ("sandbox" if sandbox else None)

        # Save defaults before any network work so a failed issuance never
        # loses the entered values.
        if save_defaults_flag:
            _maybe_save_defaults(values, conn_profile)

        sess = connect(
            profile=profile, sandbox=sandbox, base_url=base_url, token_url=token_url,
            account_number=account_number, client_secret=client_secret,
        )

        # Resolve the prevetting token: flag, then keyring, then environment.
        resolved_token = prevetting_token
        if not resolved_token:
            svc = keyring_service("certinext", conn_profile)
            resolved_token = (
                keyring_get(svc, "CERTINEXT_PREVETTING_TOKEN")
                or os.environ.get("CERTINEXT_PREVETTING_TOKEN")
                or None
            )

        # Capture signer fields early; they may be overridden by CSR defaults.
        signer_name = values.requestor_name
        signer_place = values.signer_place

        # The effective domain/SANs (CLI flags, falling back to the CSR below).
        effective_domain = domain
        sans: list[str] | None = list(san) or None
        csr_path = csr_opt if csr_opt is not None else csr_file

        # ------------------------------------------------------------------
        # Phase 2: Order acquisition
        # ------------------------------------------------------------------

        if order_id:
            # Resume path: fetch an existing order by its numeric ID.
            try:
                order = sess.ssl.get(order_id)
            except CertiNextAPIError as exc:
                log.error("Error fetching order", order_id=order_id, status_code=exc.status_code)
                raise SystemExit(1) from exc
            log.info("Resuming order", order_id=order.order_id, status=order.status)
            csr = _read_csr(csr_path) if csr_path is not None else ""

        else:
            # New-order path: parse the CSR, fill any missing fields from its
            # subject, then POST to the ssl-certificates endpoint.
            csr = _read_csr(csr_path)
            if not csr.strip():
                log.error("Empty CSR")
                raise SystemExit(1)

            # parse_csr() extracts CN, SANs, emailAddress, L, and ST.
            # Each field only overrides the CLI argument when the argument was
            # not supplied, so explicit flags always take precedence.
            csr_info = _parse_csr(csr)
            if not effective_domain:
                effective_domain = csr_info.common_name      # CN -> primary domain
            if not effective_domain:
                # _parse_csr exits when the CSR has no CN, so this is only
                # reachable if that guarantee ever weakens.
                log.error("No domain: CSR has no CN and --domain was not given")
                raise SystemExit(1)
            if sans is None:
                sans = csr_info.sans                         # SAN extension
            if not values.requestor_email and csr_info.email:
                values.requestor_email = csr_info.email      # emailAddress OID
            if not values.signer_place and csr_info.signer_place:
                values.signer_place = csr_info.signer_place  # "Orono, Maine"
                signer_place = csr_info.signer_place

            order = _check_existing_and_prompt(sess, effective_domain, no_domain_check)
            if order is None:
                log.info(
                    "Ordering certificate",
                    domain=effective_domain,
                    sans_count=len(sans) if sans else 0,
                )
                order = _create_order(
                    sess, values,
                    domain=effective_domain, sans=sans,
                    auto_secure_www=auto_secure_www,
                    prevetting_token=resolved_token, csr=csr,
                )
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

        # "poll" only fires once the order reaches a generic waiting state
        # (e.g. pending-approval) — agreement/CSR/DCV steps advance without
        # it — so the bar tracks wall-clock time against the wait budget
        # rather than counting ticks, and jumps forward once polling starts.
        poll_start = time.monotonic()

        def _on_poll(o: SslOrder) -> None:
            log.debug("Polling order", order_id=o.order_id, status=o.status)
            elapsed = min(int(time.monotonic() - poll_start), wait)
            progress.update(poll_task, completed=elapsed)

        # OrderWorkflow drives the order through every pending state and polls
        # until issuance. Event hooks replace explicit polling logic here —
        # the workflow emits events; this function just logs them.
        wf = (
            OrderWorkflow(order, signer_name=signer_name, signer_place=signer_place)
            .on("status_change", lambda old, new: log.debug(
                "Order status change", order_id=order.order_id, old_status=old, new_status=new,
            ))
            .on("poll", _on_poll)
            .on("dcv_available", _on_dcv)
            .on("issued", lambda o: log.info("Order issued", order_id=o.order_id))
        )

        if wait == 0:
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
            with Progress(console=err_console, disable=progress_disabled(verbose)) as progress:
                poll_task = progress.add_task("Waiting for issuance", total=wait)
                pem = wf.run(csr=csr, wait=wait)
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
        _write_outputs(
            order,
            OutputOptions(
                output=output, cert_out=cert_out, chain_out=chain_out,
                fullchain_out=fullchain_out, der_out=der_out,
                all_formats_out=all_formats_out, raw_chain=raw_chain,
            ),
            pem,
        )

    except SystemExit as exc:
        # If we have an order that can be resumed, always print the hint so
        # the operator knows how to continue after any unexpected failure.
        if exc.code not in (0, 130) and order is not None and order.order_id:
            if order.status not in ("cancelled", "rejected", "revoked"):
                log.error("Re-run with --order-id to resume", order_id=order.order_id)
        raise
