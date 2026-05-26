#!/usr/bin/env python3
"""Example: automate DNS-TXT DCV verification for CertiNext domains.

Walks through the DNS-TXT DCV pipeline for all pending domains, advancing
each as far as possible in a single run. Re-run after DNS propagation to
progress to the next step.

Pipeline per domain:
  1. Publish the DCV TXT token via your DNS provider (set_dns_txt_record).
  2. Wait for the token to appear on authoritative nameservers.
  3. Wait for the token to appear on public resolvers (8.8.8.8 / 1.1.1.1).
  4. Call domain.verify() to trigger CertiNext's DCV check.

To adapt this script to your environment, implement the two stub functions
near the top of the file: ``set_dns_txt_record`` and ``has_dns_txt_record``.
Both stubs include inline examples using dnspython and AWS Route 53.

Usage::

    export CERTINEXT_CLIENT_ID="your-account-number"
    export CERTINEXT_CLIENT_SECRET="your-client-secret"

    python dns_txt_dcv.py
    python dns_txt_dcv.py --dry-run
    python dns_txt_dcv.py --pattern r".*\\.example\\.com"
    python dns_txt_dcv.py example.com sub.example.com

Verbosity levels (cumulative):
  -v      Show configuration details (nameserver overrides, domain filter).
  -vvv    Enable script-level DEBUG logging.
  -vvvv   Also enable third-party DEBUG logging (urllib3).
"""

import argparse
import getpass
import logging
import os
import re
import sys
import uuid
from typing import Any

import certinext
from certinext.exceptions import CertiNextAPIError

log = logging.getLogger(__name__)

# Comma-separated authoritative nameservers to check before triggering verify().
# Leave empty to skip the authoritative propagation check and rely only on
# public resolvers (or proceed directly to verify if both are empty).
_DEFAULT_AUTH_NAMESERVERS = ""

# Comma-separated public resolvers for a final propagation check.
# Set to an empty string to skip this check.
_DEFAULT_PUBLIC_NAMESERVERS = "8.8.8.8,1.1.1.1"


# ---------------------------------------------------------------------------
# DNS provider stubs — implement these for your environment
# ---------------------------------------------------------------------------


def set_dns_txt_record(fqdn: str, value: str, dry_run: bool) -> None:
    """Publish a DNS TXT record via your DNS provider API.

    Replace the body of this function with a call to your DNS provider.
    The operation should be an idempotent upsert: safe to call multiple times
    with the same arguments.

    Args:
        fqdn: Fully-qualified domain name for the TXT record
              (e.g. ``_emudhra-challenge.example.com`` or ``example.com``).
        value: TXT record content (the CertiNext DCV token).
        dry_run: If True, log what would happen without making any changes.

    Example (using dnspython nsupdate with TSIG)::

        # pip install dnspython
        import dns.query
        import dns.tsigkeyring
        import dns.update

        if dry_run:
            log.info("[dry-run] would publish TXT %r at %s", value, fqdn)
            return
        keyring = dns.tsigkeyring.from_text({"keyname": "your-base64-key=="})
        update = dns.update.Update("example.com", keyring=keyring)
        update.replace(fqdn, 300, "TXT", value)
        dns.query.tcp(update, "ns1.example.com")

    Example (AWS Route 53 via boto3)::

        # pip install boto3
        import boto3

        if dry_run:
            log.info("[dry-run] would publish TXT %r at %s", value, fqdn)
            return
        client = boto3.client("route53")
        client.change_resource_record_sets(
            HostedZoneId="Z1234EXAMPLE",
            ChangeBatch={
                "Changes": [{
                    "Action": "UPSERT",
                    "ResourceRecordSet": {
                        "Name": fqdn,
                        "Type": "TXT",
                        "TTL": 300,
                        "ResourceRecords": [{"Value": f'"{value}"'}],
                    },
                }]
            },
        )
    """
    raise NotImplementedError(
        f"Implement set_dns_txt_record — publish TXT {value!r} at {fqdn!r} via your DNS provider"
    )


def has_dns_txt_record(fqdn: str, value: str, nameserver: str) -> bool:
    """Return True if nameserver resolves fqdn with the expected TXT value.

    Query the nameserver directly (not the system resolver) so propagation
    can be verified before triggering domain.verify().

    Args:
        fqdn: Fully-qualified domain name to query.
        value: Expected TXT record content.
        nameserver: IP address or hostname of the nameserver to query.

    Returns:
        True if the TXT record is present and contains the expected value.

    Example (using dnspython)::

        # pip install dnspython
        import socket
        import dns.exception
        import dns.resolver

        def _to_ip(host: str) -> str:
            try:
                socket.inet_aton(host)
                return host
            except OSError:
                return socket.gethostbyname(host)

        r = dns.resolver.Resolver(configure=False)
        r.nameservers = [_to_ip(nameserver)]
        r.timeout = 5
        r.lifetime = 10
        try:
            for rdata in r.resolve(fqdn, "TXT"):
                if any(s.decode() == value for s in rdata.strings):
                    return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
            pass
        return False
    """
    raise NotImplementedError(
        f"Implement has_dns_txt_record — check TXT {value!r} at {fqdn!r} against {nameserver!r}"
    )


# ---------------------------------------------------------------------------
# Nameserver utilities
# ---------------------------------------------------------------------------


def _parse_nameservers(raw: str) -> list[str]:
    """Parse a comma- or space-separated nameserver string into individual entries.

    Args:
        raw: Comma- or space-separated string of nameserver hostnames or IPs.

    Returns:
        Deduplicated list preserving original order. Empty string returns ``[]``.
    """
    seen: set[str] = set()
    result: list[str] = []
    for ns in re.split(r"[,\s]+", raw.strip()):
        if ns and ns not in seen:
            seen.add(ns)
            result.append(ns)
    return result


def _all_see_txt(fqdn: str, value: str, nameservers: list[str]) -> bool:
    """Return True if every nameserver in the list returns the expected TXT value.

    Args:
        fqdn: Fully-qualified domain name to query.
        value: Expected TXT record content.
        nameservers: Nameservers to query. Empty list returns True (vacuously).

    Returns:
        True if every nameserver reports the expected TXT value.
    """
    return all(has_dns_txt_record(fqdn, value, ns) for ns in nameservers)


# ---------------------------------------------------------------------------
# Domain filtering
# ---------------------------------------------------------------------------


def _covered_by_parent(name: str, all_domain_names: set[str]) -> str | None:
    """Return the closest ancestor domain in all_domain_names that covers name, or None.

    CertiNext propagates DCV coverage down the domain tree: verifying
    ``example.com`` also covers ``sub.example.com``. This function identifies
    domains in the pending list that will be covered by a parent processed in
    the same run, so the child can be skipped.

    Stops before bare TLDs: requires at least two labels in the candidate
    parent, so ``example.com`` may be covered by ``com`` is never matched.

    Args:
        name: The domain name to check (e.g. ``sub.example.com``).
        all_domain_names: Set of all domain names in this run (verified + pending).

    Returns:
        The covering ancestor domain name, or None if no ancestor is present.
    """
    labels = name.split(".")
    for i in range(1, len(labels) - 1):
        parent = ".".join(labels[i:])
        if parent in all_domain_names:
            return parent
    return None


def _filter_pending(domains: list[Any], pending: list[Any]) -> list[Any]:
    """Remove subdomains covered by a parent domain from the pending list.

    Args:
        domains: Full domain list (verified + pending), used to build the
            set of names that count as covering parents.
        pending: Domains that need DCV processing.

    Returns:
        Filtered pending list with covered subdomains removed.
    """
    all_domain_names = {d.name for d in domains if d.name}
    covered: list[tuple[str, str]] = []
    filtered: list[Any] = []
    for d in pending:
        parent = _covered_by_parent(d.name or "", all_domain_names)
        if parent:
            covered.append((d.name or "(unknown)", parent))
        else:
            filtered.append(d)
    for name, parent in covered:
        log.debug(
            "%s: covered by parent domain %s — skipping (use --include-subdomains to override)",
            name,
            parent,
        )
    if covered:
        log.info("Skipped %d subdomain(s) covered by parent domain(s)", len(covered))
    return filtered


# ---------------------------------------------------------------------------
# Per-domain DCV pipeline
# ---------------------------------------------------------------------------


def process_domain(
    domain: Any,
    dry_run: bool,
    correlation_id: str,
    auth_nameservers: list[str],
    public_nameservers: list[str],
) -> None:
    """Advance one CertiNext domain through the DNS-TXT DCV pipeline as far as possible.

    Steps attempted in order:
      1. Publish the DCV TXT token if not yet visible on any configured nameserver.
      2. Verify the token appears on all authoritative nameservers.
      3. Verify the token appears on all public resolvers.
      4. Trigger CertiNext DCV verification via domain.verify().

    Returns early (without error) at any step that is not yet complete. Re-run
    after DNS propagation to advance to the next step.

    Args:
        domain: A CertiNext Domain object with get_dcv() and verify() methods.
        dry_run: If True, log what would happen without making any changes.
        correlation_id: Run-level UUID included in warning messages for correlation.
        auth_nameservers: Authoritative nameservers to check for propagation.
            Empty list skips the authoritative check.
        public_nameservers: Public resolvers to check. Empty list skips this step.
    """
    name: str = domain.name or "(unknown)"
    dcv_status: str = domain.dcv_status or ""

    dcv = domain.get_dcv()
    if dcv.method != "DNS-TXT":
        log.debug("%s: skipping — DCV method is %r (not DNS-TXT)", name, dcv.method or "unset")
        return

    token: str = dcv.token
    if not token:
        log.warning("%s: no DCV token in response, skipping correlation_id=%s", name, correlation_id)
        return

    # dcv.host is the subdomain label returned by the CertiNext API (e.g. "_emudhra-challenge").
    # When set, the challenge record goes at <host>.<domain>; otherwise at the apex.
    dns_fqdn: str = f"{dcv.host}.{name}" if dcv.host else name

    log.info("%s: dcv_status=%s  challenge=%s", name, dcv_status, dns_fqdn)

    # Step 1 — publish the TXT record if not yet visible.
    # Use the first available nameserver as a proxy for "record has been published".
    # If visible there, skip publishing (the record was set in a previous run).
    check_ns = auth_nameservers[:1] or public_nameservers[:1]
    if check_ns:
        if not has_dns_txt_record(dns_fqdn, token, check_ns[0]):
            log.info("%s: TXT not yet visible — publishing", name)
            set_dns_txt_record(dns_fqdn, token, dry_run)
            if not dry_run:
                log.info("%s: record published — DNS propagation takes time, run again later", name)
            return
        log.info("%s: TXT record visible — checking full propagation", name)
    else:
        # No nameservers configured: publish unconditionally and proceed to verify.
        # set_dns_txt_record should be idempotent (UPSERT).
        set_dns_txt_record(dns_fqdn, token, dry_run)
        if dry_run:
            log.info("[dry-run] %s: would call domain.verify()", name)
            return
        log.info("%s: no propagation check configured — proceeding directly to verify", name)

    # Step 2 — wait for all authoritative nameservers.
    if auth_nameservers and not _all_see_txt(dns_fqdn, token, auth_nameservers):
        log.info("%s: not yet visible on all authoritative nameservers, run again later", name)
        return

    if auth_nameservers:
        log.info("%s: visible on authoritative nameservers", name)

    # Step 3 — wait for public resolvers (optional).
    if public_nameservers and not _all_see_txt(dns_fqdn, token, public_nameservers):
        log.info("%s: not yet visible on public resolvers, run again later", name)
        return

    log.info("%s: fully propagated — triggering DCV verification", name)

    # Step 4 — trigger CertiNext DCV verification.
    if dry_run:
        log.info("[dry-run] %s: would call domain.verify()", name)
        return

    try:
        result = domain.verify()
        log.info("%s: verify response: %s", name, result)
    except CertiNextAPIError as exc:
        log.warning("%s: DCV verification returned HTTP %s: %s", name, exc.status_code, exc.body)


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------


def _resolve(
    arg_value: str | None,
    env_var: str,
    prompt: str,
    secret: bool = False,
) -> str:
    """Return the first non-empty value from: CLI arg, environment variable, interactive prompt.

    In non-interactive mode (no controlling terminal, e.g. cron), fails immediately
    with a clear error rather than hanging on a prompt that will never be answered.

    Args:
        arg_value: Value from a CLI argument, or None if not provided.
        env_var: Environment variable name to fall back to.
        prompt: Text shown when prompting interactively.
        secret: If True, use getpass so input is not echoed.

    Returns:
        The resolved credential string.
    """
    if arg_value:
        return arg_value
    env_value = os.environ.get(env_var)
    if env_value:
        return env_value
    if not sys.stdin.isatty():
        sys.exit(
            f"ERROR: {prompt} not found in CLI args or env var {env_var!r} — "
            f"cannot prompt in non-interactive mode"
        )
    try:
        if secret:
            return getpass.getpass(f"{prompt}: ")
        return input(f"{prompt}: ")
    except EOFError:
        sys.exit(
            f"ERROR: {prompt} not found in CLI args or env var {env_var!r} — "
            f"stdin is not interactive"
        )


def _setup_logging(verbose: int) -> None:
    """Configure logging level and format based on verbosity count.

    Args:
        verbose: Verbosity count from -v flags (0=INFO, 3+=DEBUG, 4+=third-party DEBUG).
    """
    interactive = sys.stderr.isatty()
    logging.basicConfig(
        level=logging.DEBUG if verbose >= 3 else logging.INFO,
        format="%(message)s" if interactive else "%(asctime)s %(levelname)-8s %(message)s",
    )
    if verbose < 4:
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("keyring").setLevel(logging.WARNING)


def build_parser() -> argparse.ArgumentParser:
    """Return the argument parser for this script.

    Returns:
        A configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        description="Automate DNS-TXT DCV verification for CertiNext domains",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Credentials are read from CLI flags, then environment variables,\n"
            "then an interactive prompt (if stdin is a terminal).\n\n"
            "Implement set_dns_txt_record() and has_dns_txt_record() in this\n"
            "script before running it."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would happen without publishing DNS records or calling verify()",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help=(
            "Increase verbosity: -v shows config details, "
            "-vvv enables script debug logging, "
            "-vvvv also enables third-party debug logging (urllib3)"
        ),
    )
    parser.add_argument(
        "--certinext-client-id",
        metavar="ID",
        help="CertiNext client ID / account number (env: CERTINEXT_CLIENT_ID)",
    )
    parser.add_argument(
        "--certinext-client-secret",
        metavar="SECRET",
        help="CertiNext client secret (env: CERTINEXT_CLIENT_SECRET)",
    )
    parser.add_argument(
        "--include-subdomains",
        action="store_true",
        default=False,
        help=(
            "Process all domains even if a parent domain is also in the list. "
            "By default, subdomains are skipped when a parent will be validated "
            "in the same run (CertiNext propagates DCV coverage down the tree)."
        ),
    )
    parser.add_argument(
        "domain",
        nargs="*",
        metavar="DOMAIN",
        help="Limit to these exact domain names (default: all pending domains)",
    )
    parser.add_argument(
        "--pattern",
        metavar="REGEX",
        help="Filter domains by regex pattern (re.fullmatch, case-insensitive)",
    )
    parser.add_argument(
        "--auth-nameservers",
        metavar="NS1,NS2",
        default=None,
        help=(
            f"Comma-separated authoritative nameservers to check for propagation "
            f"(env: AUTH_NAMESERVERS; default: {_DEFAULT_AUTH_NAMESERVERS!r})"
        ),
    )
    parser.add_argument(
        "--public-nameservers",
        metavar="NS1,NS2",
        default=None,
        help=(
            f"Comma-separated public resolvers to check; "
            f"empty string disables the check "
            f"(env: PUBLIC_NAMESERVERS; default: {_DEFAULT_PUBLIC_NAMESERVERS!r})"
        ),
    )
    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the DNS-TXT DCV automation script."""
    parser = build_parser()
    args = parser.parse_args()

    effective_pattern = args.pattern or os.environ.get("DOMAIN_PATTERN")
    if args.domain and effective_pattern:
        parser.error("DOMAIN positional args and --pattern/DOMAIN_PATTERN are mutually exclusive")

    _setup_logging(args.verbose)

    client_id = _resolve(args.certinext_client_id, "CERTINEXT_CLIENT_ID", "CertiNext client ID")
    client_secret = _resolve(
        args.certinext_client_secret,
        "CERTINEXT_CLIENT_SECRET",
        "CertiNext client secret",
        secret=True,
    )

    sess = certinext.session(client_id=client_id, client_secret=client_secret)
    correlation_id = str(uuid.uuid4())
    log.info("Starting run pid=%d correlation_id=%s", os.getpid(), correlation_id)

    interrupted = False
    had_errors = False
    try:
        auth_ns_raw = args.auth_nameservers or os.environ.get("AUTH_NAMESERVERS") or _DEFAULT_AUTH_NAMESERVERS
        if args.public_nameservers is not None:
            pub_ns_raw = args.public_nameservers
        elif "PUBLIC_NAMESERVERS" in os.environ:
            pub_ns_raw = os.environ["PUBLIC_NAMESERVERS"]
        else:
            pub_ns_raw = _DEFAULT_PUBLIC_NAMESERVERS
        auth_nameservers = _parse_nameservers(auth_ns_raw)
        public_nameservers = _parse_nameservers(pub_ns_raw)

        if args.verbose:
            if auth_nameservers:
                log.info("Authoritative nameservers: %s", ", ".join(auth_nameservers))
            else:
                log.info("No authoritative nameserver check configured")
            if not public_nameservers:
                log.info("Public nameserver check disabled")
            elif pub_ns_raw != _DEFAULT_PUBLIC_NAMESERVERS:
                log.info("Public nameservers overridden: %s", pub_ns_raw)
            if args.domain:
                log.info("Domain filter: exact match on %s", ", ".join(args.domain))
            elif effective_pattern:
                log.info("Domain filter: pattern %s", effective_pattern)

        if args.dry_run:
            log.info("DRY RUN — no changes will be made")

        # NOTE: The API search parameter is a confirmed vendor bug — all domains are
        # returned regardless of the value passed. Use pattern for client-side filtering.
        if args.domain:
            domains = sess.domain.get_list(pattern="|".join(re.escape(d) for d in args.domain))
        else:
            domains = sess.domain.get_list(pattern=effective_pattern)

        pending = [d for d in domains if d.needs_dcv]
        already_verified = [d for d in domains if d.status == "ACTIVE" and not d.needs_dcv]
        for d in already_verified:
            log.debug("%s: already verified, skipping", d.name)
        log.info(
            "Found %d active domain(s) needing DCV (%d already verified)",
            len(pending),
            len(already_verified),
        )

        if not args.include_subdomains:
            pending = _filter_pending(domains, pending)

        for domain in pending:
            try:
                process_domain(domain, args.dry_run, correlation_id, auth_nameservers, public_nameservers)
            except NotImplementedError as exc:
                log.error("DNS stub not implemented: %s", exc)
                log.error("Edit this script and implement set_dns_txt_record / has_dns_txt_record before running")
                had_errors = True
                break
            except Exception:
                log.exception("Unexpected error processing %s", domain.name)
                had_errors = True

    except KeyboardInterrupt:
        sys.stderr.write("\n")
        interrupted = True
    except Exception:
        had_errors = True
        raise
    finally:
        if interrupted:
            log.warning("Interrupted correlation_id=%s", correlation_id)
        elif had_errors:
            log.warning("Ending run with errors correlation_id=%s", correlation_id)
        else:
            log.info("Ending run correlation_id=%s", correlation_id)

    if interrupted:
        sys.exit(130)
    if had_errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
