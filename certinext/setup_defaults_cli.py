#!/usr/bin/env python3
"""Store issue-cert defaults in the certinext config file.

Interactively prompts for the values that ``certinext-issue-cert`` would
otherwise need on every run (requestor identity, certificate type, org ID,
validity) and stores them in the config file. After this, issuing a
certificate is just::

    certinext-issue-cert new.csr

The default profile writes the ``[defaults]`` section. Named profiles write a
``[profiles.NAME]`` section that overrides ``[defaults]`` when that profile is
active (``--profile`` / ``CERTINEXT_PROFILE`` / ``--sandbox``).

If API credentials are already stored in the keyring (or can be set up first),
organization IDs for OV/EV orders are fetched from the API and presented as a
numbered menu rather than requiring the user to look them up manually.

Secrets (client secret, prevetting token) are NOT stored here — use
``certinext-setup-keyring`` for credentials.

Usage:
    certinext-setup-defaults                  # default profile
    certinext-setup-defaults --profile prod   # named profile
    certinext-setup-defaults --sandbox        # sandbox profile shortcut
"""
import argparse
import sys
from typing import Any

from certinext._cli import (
    CredentialsNotFoundError,
    add_connection_args,
    apply_sandbox,
    build_session,
)
from certinext._config import ConfigError, config_path, load_config, save_defaults
from certinext._keyring import keyring_available, keyring_get, keyring_service
from certinext.accounts import Organization
from certinext.exceptions import CertiNextAPIError

# Post-type fields in display order:
# (TOML key, base label, required for DV, required for OV/EV, note when optional)
_POST_TYPE_FIELDS: list[tuple[str, str, bool, bool, str]] = [
    ("requestor_name",
     "Requestor full name",
     True, True, ""),
    ("requestor_email",
     "Requestor email",
     False, False, "read from CSR emailAddress field when present"),
    ("requestor_phone",
     "Requestor phone (E.164, e.g. +12075551234)",
     True, True, ""),
    ("requestor_designation",
     "Requestor job title/designation",
     False, False, ""),
    ("signer_place",
     "Signer place (city/location, e.g. 'Orono, ME')",
     False, False, "read from CSR L and ST fields when present"),
    ("org_id",
     "Organization ID (from certinext-accounts)",
     False, True, "not needed for DV"),
    ("validity",
     "Validity in years (1/2/3)",
     False, False, "defaults to 1 year"),
]


def _prompt(label: str, current: Any) -> Any | None:
    """Prompt for one field, returning the new value, None to keep, or '' to clear.

    Shows the currently stored value (if any) in brackets; pressing Enter
    keeps it. Entering ``-`` clears the stored value.

    Args:
        label: Human-readable field label.
        current: Currently stored value, or None.

    Returns:
        The entered value as a string, ``''`` when the user cleared the field
        with ``-``, or None when the user kept the current value.
    """
    hint = f" [{current}]" if current not in (None, "") else ""
    value = input(f"{label}{hint}: ").strip()
    if not value:
        return None
    if value == "-":
        return ""
    return value


def _validated(key: str, value: str) -> Any:
    """Validate and coerce one entered value for its config key.

    Args:
        key: TOML config key being set.
        value: Raw string the user entered.

    Returns:
        The value to store (int for ``validity``, str otherwise).

    Raises:
        ValueError: If the value is not acceptable for the key.
    """
    if key == "validity":
        if value not in ("1", "2", "3"):
            raise ValueError("validity must be 1, 2, or 3")
        return int(value)
    if key == "type":
        if value not in ("dv", "ov", "ev"):
            raise ValueError("type must be dv, ov, or ev")
        return value
    if key == "requestor_phone" and not value.startswith("+"):
        raise ValueError("phone must be in E.164 format (start with '+')")
    return value


def _maybe_setup_keyring(args: argparse.Namespace) -> None:
    """Offer to run certinext-setup-keyring when no credentials are stored for this profile.

    Silently returns when credentials are already present or when no usable
    keyring backend is available.  Otherwise prompts the user and either runs
    ``certinext-setup-keyring`` (forwarding ``--sandbox`` or ``--profile``) or
    prints the manual command.

    Args:
        args: Parsed CLI arguments.  Reads ``args.profile`` and ``args.sandbox``.
    """
    import subprocess

    service = keyring_service("certinext", args.profile)
    if keyring_get(service, "CERTINEXT_CLIENT_ID") is not None:
        return  # credentials already configured

    if not keyring_available():
        return  # no usable backend — don't offer what can't work

    cmd = ["certinext-setup-keyring"]
    if args.sandbox:
        cmd.append("--sandbox")
    elif args.profile:
        cmd.extend(["--profile", args.profile])
    cmd_str = " ".join(cmd)

    profile_label = f"the {args.profile!r} profile" if args.profile else "the default profile"
    print(f"No API credentials are stored in the keyring for {profile_label}.")
    print("Credentials are needed to look up valid organization IDs for OV/EV orders.")
    try:
        answer = input(f"Run '{cmd_str}' now? [Y/n]: ").strip().lower()
    except EOFError:
        answer = "n"
    if answer in ("", "y", "yes"):
        subprocess.run(cmd, check=False)
    else:
        print(f"\nWhen you're ready:\n  {cmd_str}")
    print()


def _pick_org(
    orgs: list[Organization],
    cert_type: str,
    current_org_id: Any,
) -> str | None:
    """Present a numbered organization menu and return the chosen org number.

    Filters to pre-vetted organizations for OV/EV orders. Auto-selects when
    only one option is available. Returns ``None`` when the list is empty so
    the caller falls back to free-text entry.

    Args:
        orgs: Organizations returned by the accounts API.
        cert_type: ``"dv"``, ``"ov"``, or ``"ev"``.
        current_org_id: Currently configured org_id value, or None.

    Returns:
        The chosen organization number as a string, or None if the list is
        empty after filtering.
    """
    if cert_type in ("ov", "ev"):
        orgs = [o for o in orgs if o.is_pre_vetting_org == "1"]
    if not orgs:
        return None

    def _org_detail(org: Organization) -> str:
        """Return a parenthesised detail string for display."""
        parts = [f"#{org.organization_number}"]
        if org.locality:
            loc = org.locality
            if org.state_code:
                loc += f", {org.state_code}"
            parts.append(loc)
        if org.validation_for:
            parts.append(org.validation_for)
        if org.validation_status:
            parts.append(org.validation_status)
        return ", ".join(parts)

    if len(orgs) == 1:
        org = orgs[0]
        print(f"  Auto-selected: {org.organization_name} ({_org_detail(org)})")
        return str(org.organization_number)

    current_str = str(current_org_id) if current_org_id not in (None, "") else None
    print("Available organizations:")
    for i, org in enumerate(orgs, 1):
        marker = " [current]" if current_str and str(org.organization_number) == current_str else ""
        print(f"  {i}. {org.organization_name} ({_org_detail(org)}){marker}")

    default_idx = next(
        (i for i, o in enumerate(orgs, 1) if current_str and str(o.organization_number) == current_str),
        1,
    )
    while True:
        choice = input(f"Choose organization [{default_idx}]: ").strip()
        if not choice:
            choice = str(default_idx)
        if choice.isdigit() and 1 <= int(choice) <= len(orgs):
            return str(orgs[int(choice) - 1].organization_number)
        print(f"  Enter a number between 1 and {len(orgs)}", file=sys.stderr)


def main() -> None:
    """Interactively store issue-cert defaults in the config file."""
    try:
        parser = argparse.ArgumentParser(
            description=__doc__,
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        add_connection_args(parser)
        args = parser.parse_args()
        apply_sandbox(args)

        path = config_path()
        section_label = f"[profiles.{args.profile}]" if args.profile else "[defaults]"
        print(f"Store certinext-issue-cert defaults in {path}")
        print(f"Section: {section_label}")
        print()
        print("The domain and SANs are always read from the CSR and are not stored here.")
        print("Press Enter to keep a shown value, or enter '-' to clear it.")
        print()

        # Offer keyring setup first — credentials are needed for the org picker.
        _maybe_setup_keyring(args)

        # Try to build a session for API-assisted lookups (org picker).
        # prompt=False means we fall back silently rather than blocking.
        sess = None
        orgs: list[Organization] = []
        try:
            sess = build_session(args, prompt=False)
            orgs = sess.accounts.list_organizations()
        except (CredentialsNotFoundError, CertiNextAPIError, Exception):
            pass

        try:
            doc = load_config(path)
        except ConfigError as exc:
            sys.exit(f"Error: {exc}")
        if args.profile:
            current = doc.get("profiles", {}).get(args.profile, {})
        else:
            current = doc.get("defaults", {})
        if not isinstance(current, dict):
            current = {}

        values: dict[str, Any] = {}
        cleared: list[str] = []

        # Ask certificate type first — determines which remaining fields are required.
        while True:
            entered = _prompt("Certificate type [required] (dv/ov/ev)", current.get("type"))
            if entered is None:
                cert_type = str(current.get("type", "dv"))
                break
            if entered == "":
                cleared.append("type")
                cert_type = "dv"
                break
            try:
                values["type"] = _validated("type", entered)
                cert_type = values["type"]
                break
            except ValueError as exc:
                print(f"  {exc}", file=sys.stderr)
        print()

        is_ov_ev = cert_type in ("ov", "ev")

        for key, base_label, req_dv, req_ov_ev, note in _POST_TYPE_FIELDS:
            required = req_ov_ev if is_ov_ev else req_dv
            tag = "[required]" if required else "[optional]"
            label = f"{base_label} {tag}"
            if note:
                label += f" — {note}"

            # For org_id on OV/EV orders, use the API picker when available.
            if key == "org_id" and is_ov_ev and orgs:
                print(f"{label}:")
                chosen = _pick_org(orgs, cert_type, current.get("org_id"))
                if chosen is not None:
                    if chosen != str(current.get("org_id", "")):
                        values["org_id"] = chosen
                    continue
                # Fall through to free-text if picker returned nothing.

            while True:
                entered = _prompt(label, current.get(key))
                if entered is None:
                    break
                if entered == "":
                    cleared.append(key)
                    break
                try:
                    values[key] = _validated(key, entered)
                    break
                except ValueError as exc:
                    print(f"  {exc}", file=sys.stderr)

        if not values and not cleared:
            print("\nNothing to change.")
        else:
            try:
                save_defaults(values, args.profile, path, remove=tuple(cleared))
            except ConfigError as exc:
                sys.exit(f"Error: {exc}")

            print(f"\nStored in {section_label}:")
            for key, value in values.items():
                print(f"  {key} = {value}")
            for key in cleared:
                print(f"  {key} (cleared)")
            print(f"\nConfig file: {path}")
            print("Precedence: CLI argument > environment variable > profile section > [defaults].")

    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        raise SystemExit(130)


if __name__ == "__main__":
    main()
