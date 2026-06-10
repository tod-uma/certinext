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

from certinext._config import ConfigError, config_path, load_config, save_defaults

#: Prompted keys in display order: (TOML key, prompt label).
_FIELDS: list[tuple[str, str]] = [
    ("requestor_name", "Requestor full name"),
    ("requestor_email", "Requestor email"),
    ("requestor_phone", "Requestor phone (E.164, e.g. +12075551234)"),
    ("requestor_designation", "Requestor job title/designation"),
    ("signer_place", "Signer place (city/location, e.g. 'Orono, ME')"),
    ("type", "Certificate type (dv/ov/ev)"),
    ("org_id", "Organization ID (required for OV/EV)"),
    ("validity", "Validity in years (1/2/3)"),
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


def main() -> None:
    """Interactively store issue-cert defaults in the config file."""
    try:
        parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
        parser.add_argument('--profile', metavar='NAME', default=None,
                            help='Profile section to edit (default: the [defaults] section)')
        parser.add_argument('--sandbox', action='store_true', default=False,
                            help='Edit the sandbox profile (shortcut for --profile sandbox)')
        args = parser.parse_args()
        if args.sandbox and args.profile is None:
            args.profile = "sandbox"

        path = config_path()
        section_label = f"[profiles.{args.profile}]" if args.profile else "[defaults]"
        print(f"Store certinext-issue-cert defaults in {path}")
        print(f"Section: {section_label}")
        print("Press Enter to keep a shown value, or enter '-' to clear it.\n")

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
        for key, label in _FIELDS:
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
            return

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
