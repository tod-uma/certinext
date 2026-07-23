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

"""``certinext setup defaults`` — store issue-cert defaults in the config file.

Interactively prompts for the values that ``certinext issue-cert`` would
otherwise need on every run (requestor identity, certificate type, org ID,
validity) and stores them in the config file.

The default profile writes the ``[defaults]`` section. Named profiles write a
``[profiles.NAME]`` section that overrides ``[defaults]`` when that profile is
active (``--profile`` / ``CERTINEXT_PROFILE`` / ``--sandbox``).

If API credentials are already stored in the keyring (or can be set up first),
organization IDs for OV/EV orders are fetched from the API and presented as a
numbered menu rather than requiring the user to look them up manually.

Secrets (client secret, prevetting token) are NOT stored here — use
``certinext setup keyring`` for credentials.

The profile's API endpoint is stored too: ``--sandbox`` records
``sandbox = true``, ``--base-url`` (with optional ``--token-url``) records a
custom endpoint for non-US regions, and with no flag the tool prompts for it.
"""

import dataclasses
import sys
from typing import Any

import certinext
from certinext._config import ConfigError, config_path, load_config, save_defaults
from certinext._keyring import keyring_available, keyring_get, keyring_service
from certinext.accounts import Organization
from certinext.catalog import Product, ProductCategory
from certinext.cli._app import setup_app
from certinext.cli._shared import (
    AccountNumberOption,
    BaseUrlOption,
    ClientSecretOption,
    LogFormatOption,
    ProfileOption,
    SandboxOption,
    TokenUrlOption,
    VerboseOption,
)
from certinext.cli_support import (
    CredentialsNotFoundError,
    LogFormat,
    build_session,
    resolve_connection,
    setup_logging,
)
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
    # org_id comes before signer_place so the chosen org's location can be
    # offered as the signer_place default (see setup_defaults()).
    ("org_id",
     "Organization ID (from certinext accounts)",
     False, True, "not needed for DV"),
    ("signer_place",
     "Signer place (city/location, e.g. 'Orono, ME')",
     False, False, "read from CSR L and ST fields when present"),
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


def _present(current: dict[str, Any], *keys: str) -> list[str]:
    """Return the subset of keys actually stored in the current section.

    Used so a re-selected, unchanged endpoint never looks like an edit (we only
    ever clear keys that are really there).

    Args:
        current: The currently stored section dict for this profile.
        keys: Candidate keys to clear.

    Returns:
        The keys from ``keys`` that are present in ``current``.
    """
    return [k for k in keys if k in current]


def _endpoint_default(current: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Return (values, cleared) for the production-US default (clear all endpoint keys)."""
    return {}, _present(current, "sandbox", "base_url", "token_url")


def _endpoint_sandbox(current: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Return (values, cleared) for the US sandbox (the ``sandbox = true`` shorthand)."""
    values: dict[str, Any] = {} if current.get("sandbox") else {"sandbox": True}
    return values, _present(current, "base_url", "token_url")


def _endpoint_url(
    base: str, token: str | None, current: dict[str, Any]
) -> tuple[dict[str, Any], list[str]]:
    """Return (values, cleared) for an explicit endpoint URL.

    Args:
        base: Base URL (a trailing slash is stripped).
        token: Token URL, or None to derive ``<base>/oauth/token``.
        current: The currently stored section dict for this profile.

    Returns:
        A ``(values, cleared)`` tuple; only changed keys appear in ``values``,
        and a stored ``sandbox`` flag is cleared (an explicit URL supersedes it).
    """
    base = base.rstrip("/")
    token = token or f"{base}/oauth/token"
    values: dict[str, Any] = {}
    for key, val in (("base_url", base), ("token_url", token)):
        if val != current.get(key):
            values[key] = val
    return values, _present(current, "sandbox")


def _endpoint_from_flags(
    cli_sandbox: bool,
    cli_base_url: str | None,
    cli_token_url: str | None,
    current: dict[str, Any],
) -> tuple[dict[str, Any], list[str], list[str]] | None:
    """Resolve endpoint persistence from explicit connection flags (no prompts).

    Lets the connection flags on a ``certinext setup defaults`` run persist to
    the profile: ``--sandbox`` stores ``sandbox = true``; ``--base-url`` (with
    an optional ``--token-url``, otherwise derived as ``<base_url>/oauth/token``)
    stores a custom endpoint — useful for non-US regions with their own API
    hosts. The two are mutually exclusive: a custom URL clears any stored
    ``sandbox`` flag, and ``--sandbox`` clears any stored custom URL.

    Args:
        cli_sandbox: Whether ``--sandbox`` was given on this run.
        cli_base_url: Explicit ``--base-url`` value, or None if not given.
        cli_token_url: Explicit ``--token-url`` value, or None if not given.
        current: The currently stored section dict for this profile.

    Returns:
        A ``(values, cleared, messages)`` tuple to fold into the caller's
        :func:`save_defaults` call, or ``None`` when no connection flag was
        given (the caller should prompt interactively instead). ``messages``
        are lines to print for the user.
    """
    if cli_sandbox:
        values, cleared = _endpoint_sandbox(current)
        messages = (
            []
            if current.get("sandbox")
            else [f"This profile will default to the sandbox endpoint ({certinext.SANDBOX_BASE_URL})."]
        )
        return values, cleared, messages
    if cli_base_url is not None or cli_token_url is not None:
        if cli_base_url is not None:
            values, cleared = _endpoint_url(cli_base_url, cli_token_url, current)
            messages = [f"This profile will default to {cli_base_url.rstrip('/')}."]
        else:
            # --token-url alone: store just the token endpoint.
            values, cleared = {}, _present(current, "sandbox")
            if cli_token_url != current.get("token_url"):
                values["token_url"] = cli_token_url
            messages = []
        return values, cleared, messages
    return None


def _prompt_endpoint(
    current: dict[str, Any],
) -> tuple[dict[str, Any], list[str], tuple[str, str, bool] | None]:
    """Present a numbered menu of known API endpoints and return the selection.

    Lists the production-US default, the US sandbox, every region in
    :data:`certinext.KNOWN_API_ENDPOINTS` (India, QA, Demo, ...), and a
    custom-URL option. The current selection is marked and used as the default
    choice. A custom base URL derives its token URL as ``<base_url>/oauth/token``.

    Args:
        current: The currently stored section dict for this profile.

    Returns:
        A ``(values, cleared, live)`` tuple. ``values``/``cleared`` fold into
        the caller's :func:`save_defaults` call. ``live`` is the chosen
        ``(base_url, token_url, sandbox)`` so the caller can point the live
        session (used for the org picker) at the selected endpoint; it is
        ``None`` when the selection is unchanged or the custom URL was invalid,
        meaning the caller should leave the session as-is.
    """
    # Build the option list: default + sandbox + known regions + custom. Each
    # option is (label, base_url_or_None, kind) where kind drives persistence.
    options: list[tuple[str, str | None, str]] = [
        ("Production - US (default)", certinext.BASE_URL, "default"),
        ("Sandbox - US", certinext.SANDBOX_BASE_URL, "sandbox"),
    ]
    for region_label, region_url in certinext.KNOWN_API_ENDPOINTS:
        if region_url == certinext.BASE_URL:
            continue  # already shown as the default option
        options.append((region_label, region_url, "url"))
    options.append(("Custom URL...", None, "custom"))

    # Mark the option matching the current config as the default choice.
    cur_base = current.get("base_url")
    if cur_base:
        default_idx = next(
            (i for i, (_, u, _) in enumerate(options, 1) if u == cur_base),
            len(options),  # an unrecognised stored URL maps to "Custom URL…"
        )
    elif current.get("sandbox"):
        default_idx = 2
    else:
        default_idx = 1

    print("Which CERTInext API endpoint should this profile use?")
    for i, (label, url, _kind) in enumerate(options, 1):
        suffix = f"  {url}" if url else ""
        marker = "  [current]" if i == default_idx else ""
        print(f"  {i}. {label}{suffix}{marker}")

    while True:
        choice = input(f"Endpoint [{default_idx}]: ").strip() or str(default_idx)
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            _label, url, kind = options[int(choice) - 1]
            break
        print(f"  Enter a number between 1 and {len(options)}", file=sys.stderr)

    if kind == "default":
        values, cleared = _endpoint_default(current)
        return values, cleared, (certinext.BASE_URL, certinext.TOKEN_URL, False)
    if kind == "sandbox":
        values, cleared = _endpoint_sandbox(current)
        return values, cleared, (certinext.SANDBOX_BASE_URL, certinext.SANDBOX_TOKEN_URL, True)
    if kind == "url":
        assert url is not None  # non-custom options always carry a URL
        values, cleared = _endpoint_url(url, None, current)
        base = url.rstrip("/")
        return values, cleared, (base, f"{base}/oauth/token", False)
    # Custom URL: offer the current stored URL (if any) as the default.
    cur_custom = str(cur_base) if cur_base else ""
    hint = f" [{cur_custom}]" if cur_custom else ""
    entered = input(f"Custom base URL{hint}: ").strip() or cur_custom
    if not entered:
        return {}, [], None
    if not entered.startswith(("http://", "https://")):
        print("  Must be an http(s) URL; keeping current.", file=sys.stderr)
        return {}, [], None
    values, cleared = _endpoint_url(entered, None, current)
    base = entered.rstrip("/")
    return values, cleared, (base, f"{base}/oauth/token", False)


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


def _maybe_setup_keyring(profile: str | None) -> None:
    """Offer to run the keyring setup when no credentials are stored for this profile.

    Silently returns when credentials are already present or when no usable
    keyring backend is available. Otherwise prompts the user and either runs
    ``certinext-setup-keyring`` for the active profile or prints the manual
    command.

    Args:
        profile: The resolved profile (``--sandbox`` has already become
            profile ``'sandbox'`` when no other profile was given).
    """
    import subprocess

    service = keyring_service("certinext", profile)
    if keyring_get(service, "CERTINEXT_CLIENT_ID") is not None:
        return  # credentials already configured

    if not keyring_available():
        return  # no usable backend — don't offer what can't work

    # Forward the resolved profile (not --sandbox) so credentials land under
    # the same service the lookup above checked.
    cmd = ["certinext-setup-keyring"]
    if profile:
        cmd.extend(["--profile", profile])
    cmd_str = " ".join(cmd)

    profile_label = f"the {profile!r} profile" if profile else "the default profile"
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


def _filter_products(categories: list[ProductCategory], cert_type: str) -> list[Product]:
    """Flatten catalog categories to the products matching a validation level.

    CERTInext groups all SSL products in one category, so the validation level
    is matched against the product name (e.g. ``"OV"`` in ``"InCommon OV SSL
    Certificate"``). Falls back to every product when nothing matches, so a
    naming scheme this heuristic doesn't recognise never hides the list.

    The result is sorted with wildcard products last and alphabetical within
    each group, so the long, similar names are easier to scan in the menu.

    Args:
        categories: Product categories from :meth:`CatalogAccessor.list_products`.
        cert_type: ``"dv"``, ``"ov"``, or ``"ev"``.

    Returns:
        The matching :class:`~certinext.catalog.Product` objects (wildcards
        last), or all of them when the filter matches none.
    """
    level = cert_type.upper()
    everything = [p for cat in categories for p in cat.products]
    matched = [
        p for p in everything
        if p.product_name and level in p.product_name.upper().replace("-", " ").split()
    ]

    def _sort_key(p: Product) -> tuple[bool, str]:
        """Sort non-wildcard products first, then alphabetically by name."""
        name = (p.product_name or "").lower()
        return ("wildcard" in name, name)

    return sorted(matched or everything, key=_sort_key)


def _prompt_product(products: list[Product], current_product: Any) -> tuple[dict[str, Any], list[str]]:
    """Present a numbered menu of products and return ``(values, cleared)``.

    Each option shows the product name and code; an extra option clears any
    stored product so the API picks its default. The stored product (if still
    in the list) is marked and used as the default choice.

    Args:
        products: Products to offer (already filtered to the chosen type).
        current_product: Currently stored product code, or None.

    Returns:
        A ``(values, cleared)`` tuple to fold into the caller's
        :func:`save_defaults` call; both empty when the selection is unchanged.
    """
    current = str(current_product) if current_product not in (None, "") else None
    # Option 0 is always "API default" (no specific product).
    print("Which product should this profile default to?")
    print(f"  0. API default (no specific product){'  [current]' if not current else ''}")
    default_idx = 0
    for i, prod in enumerate(products, 1):
        marker = "  [current]" if current and str(prod.product_code) == current else ""
        if marker:
            default_idx = i
        price = f", {prod.price}" if prod.price else ""
        print(f"  {i}. {prod.product_name} (code {prod.product_code}{price}){marker}")

    while True:
        choice = input(f"Product [{default_idx}]: ").strip() or str(default_idx)
        if choice.isdigit() and 0 <= int(choice) <= len(products):
            idx = int(choice)
            break
        print(f"  Enter a number between 0 and {len(products)}", file=sys.stderr)

    if idx == 0:
        return {}, (["product"] if current else [])
    code = str(products[idx - 1].product_code)
    if code == current:
        return {}, []
    return {"product": code}, []


def _org_location(org: Organization) -> str:
    """Return a chosen org's location as a ``"City, ST"`` string (or ``""``).

    Used to offer the organization's locality as the default ``signer_place``.

    Args:
        org: The organization the user selected.

    Returns:
        ``"City, ST"`` when both are present, ``"City"`` when only the locality
        is known, or ``""`` when no locality is available.
    """
    if not org.locality:
        return ""
    return f"{org.locality}, {org.state_code}" if org.state_code else org.locality


def _pick_org(
    orgs: list[Organization],
    cert_type: str,
    current_org_id: Any,
    sandbox: bool = False,
) -> str | None:
    """Present a numbered organization menu and return the chosen org number.

    Filters to pre-vetted organizations for OV/EV orders. Auto-selects when
    only one option is available. Returns ``None`` when the list is empty so
    the caller falls back to free-text entry.

    Args:
        orgs: Organizations returned by the accounts API.
        cert_type: ``"dv"``, ``"ov"``, or ``"ev"``.
        current_org_id: Currently configured org_id value, or None.
        sandbox: If ``True``, the portal hint links to the sandbox site.

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

    portal = "sandbox-us.certinext.io" if sandbox else "us.certinext.io"
    print(f"Available organizations (the default is marked with a 'D' badge at {portal}):")
    current_str = str(current_org_id) if current_org_id not in (None, "") else None
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


@setup_app.command("defaults")
def setup_defaults(
    verbose: VerboseOption = 0,
    log_format: LogFormatOption = LogFormat.LOGFMT,
    profile: ProfileOption = None,
    sandbox: SandboxOption = False,
    base_url: BaseUrlOption = None,
    token_url: TokenUrlOption = None,
    account_number: AccountNumberOption = None,
    client_secret: ClientSecretOption = None,
) -> None:
    """Interactively store issue-cert defaults in the config file."""
    setup_logging(verbose, log_format=log_format)
    # The raw flags (before resolution folds profile config in) decide what
    # persists — only values explicit on *this* run should be stored.
    cli_sandbox = bool(sandbox)
    cli_base_url = base_url
    cli_token_url = token_url
    conn = resolve_connection(profile=profile, sandbox=sandbox, base_url=base_url, token_url=token_url)

    path = config_path()
    section_label = f"[profiles.{conn.profile}]" if conn.profile else "[defaults]"
    print(f"Store certinext issue-cert defaults in {path}")
    print(f"Section: {section_label}")
    print()
    print("The domain and SANs are always read from the CSR and are not stored here.")
    print("Press Enter to keep a shown value, or enter '-' to clear it.")
    print()

    try:
        doc = load_config(path)
    except ConfigError as exc:
        raise SystemExit(f"Error: {exc}")
    if conn.profile:
        current = doc.get("profiles", {}).get(conn.profile, {})
    else:
        current = doc.get("defaults", {})
    if not isinstance(current, dict):
        current = {}

    values: dict[str, Any] = {}
    cleared: list[str] = []

    # Endpoint selection FIRST: the org picker below calls the API, so the
    # live session must point at the chosen endpoint before we build it.
    # Explicit flags (--sandbox / --base-url) persist directly; otherwise
    # prompt with a menu and apply the choice to the connection for this run.
    from_flags = _endpoint_from_flags(cli_sandbox, cli_base_url, cli_token_url, current)
    if from_flags is not None:
        ep_values, ep_cleared, ep_messages = from_flags
        for message in ep_messages:
            print(message)
    else:
        ep_values, ep_cleared, live = _prompt_endpoint(current)
        if live is not None:
            conn = dataclasses.replace(conn, base_url=live[0], token_url=live[1], sandbox=live[2])
    values.update(ep_values)
    cleared.extend(ep_cleared)
    print()

    # Offer keyring setup next — credentials are needed for the org picker.
    _maybe_setup_keyring(conn.profile)

    # Try to build a session for API-assisted lookups (org and product
    # pickers), now that the endpoint is settled. prompt=False means we fall
    # back silently rather than blocking when credentials are absent.
    sess = None
    orgs: list[Organization] = []
    product_categories: list[ProductCategory] = []
    try:
        sess = build_session(
            conn, account_number=account_number, client_secret=client_secret, prompt=False,
        )
    except (CredentialsNotFoundError, CertiNextAPIError, Exception):
        sess = None
    if sess is not None:
        # Fetch each list independently so one failing endpoint doesn't
        # suppress the other picker.
        try:
            orgs = sess.accounts.list_organizations()
        except (CertiNextAPIError, Exception):
            pass
        try:
            product_categories = sess.catalog.list_products()
        except (CertiNextAPIError, Exception):
            pass

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

    # Product selection, filtered to the chosen type. Skipped silently when
    # the catalog couldn't be fetched (no credentials / API error).
    if product_categories:
        products = _filter_products(product_categories, cert_type)
        if products:
            prod_values, prod_cleared = _prompt_product(products, current.get("product"))
            values.update(prod_values)
            cleared.extend(prod_cleared)
            print()

    is_ov_ev = cert_type in ("ov", "ev")
    chosen_org: Organization | None = None

    for key, base_label, req_dv, req_ov_ev, note in _POST_TYPE_FIELDS:
        required = req_ov_ev if is_ov_ev else req_dv
        tag = "[required]" if required else "[optional]"
        label = f"{base_label} {tag}"
        if note:
            label += f" - {note}"

        # For org_id on OV/EV orders, use the API picker when available.
        if key == "org_id" and is_ov_ev and orgs:
            print(f"{label}:")
            chosen = _pick_org(orgs, cert_type, current.get("org_id"), sandbox=conn.sandbox)
            if chosen is not None:
                # Remember the org so signer_place (asked next) can default
                # to its location.
                chosen_org = next(
                    (o for o in orgs if str(o.organization_number) == chosen), None
                )
                if chosen != str(current.get("org_id", "")):
                    values["org_id"] = chosen
                continue
            # Fall through to free-text if picker returned nothing.

        # For signer_place, offer the chosen org's location as the default
        # when nothing is stored yet — Enter accepts it.
        if (
            key == "signer_place"
            and chosen_org is not None
            and not current.get("signer_place")
            and _org_location(chosen_org)
        ):
            org_loc = _org_location(chosen_org)
            raw = input(f"{label} [{org_loc}] (from chosen org): ").strip()
            if raw != "-":
                values[key] = raw or org_loc
            continue

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
        print(f"\nNothing to change. Config file: {path}")
    else:
        try:
            saved_path = save_defaults(values, conn.profile, path, remove=tuple(cleared))
        except ConfigError as exc:
            raise SystemExit(f"Error: {exc}")

        print(f"\nSaved to {saved_path}")
        print(f"Section {section_label}:")
        for key, value in values.items():
            print(f"  {key} = {value}")
        for key in cleared:
            print(f"  {key} (cleared)")
        print("Precedence: CLI argument > environment variable > profile section > [defaults].")
