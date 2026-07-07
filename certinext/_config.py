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

"""Stored defaults for certificate issuance.

Reads and writes ``config.toml``, which holds per-user defaults for
``certinext-issue-cert`` (requestor identity, certificate type, org ID,
validity, ...) plus optional per-profile *connection* settings (which API
endpoint a profile targets). The file has a ``[defaults]`` section plus
optional ``[profiles.NAME]`` sections that override it, mirroring the keyring
profile concept:

.. code-block:: toml

    [defaults]
    requestor_name  = "Jane Doe"
    requestor_email = "jane@maine.edu"
    type            = "ov"
    org_id          = "12345"

    [profiles.sandbox]
    type    = "dv"
    sandbox = true                       # this profile targets the sandbox API

    [profiles.staging]
    base_url  = "https://staging-api.certinext.io"
    token_url = "https://staging-api.certinext.io/oauth/token"

Two key families live side by side, each defined by a pydantic model in
:mod:`certinext.settings`. Issue-cert defaults
(:class:`~certinext.settings.IssuanceDefaults`) are read by
:func:`config_defaults`; connection settings
(:class:`~certinext.settings.ConnectionSettings`) are read by
:func:`connection_config`. Each reader ignores the other family's keys, so a
``sandbox``/``base_url`` entry never trips an "unknown key" warning during
certificate issuance. Values are validated one key at a time, so a bad entry
degrades into a warning while the rest of the file still applies.

Resolution precedence (highest first): explicit CLI argument, environment
variable, ``[profiles.NAME]`` value, ``[defaults]`` value, built-in default.

Writes go through tomlkit, so comments and formatting in a hand-edited file
survive ``certinext-setup-defaults`` / ``--save-defaults`` round trips.

Secrets (client secret, prevetting token) must never be stored here — use
the OS keyring via ``certinext-setup-keyring``.
"""
import os
import sys
from pathlib import Path
from typing import Any

import tomlkit
import tomlkit.exceptions
from pydantic import BaseModel, ValidationError

from certinext.settings import ConnectionSettings, IssuanceDefaults, family_keys

if sys.version_info >= (3, 11):
    import tomllib
else:  # Python 3.10
    import tomli as tomllib

#: TOML keys accepted in [defaults] / [profiles.NAME], mapped to the argparse
#: dest they feed. Derived from the IssuanceDefaults model (the TOML key is
#: the field's alias where one is set, e.g. ``type`` -> ``cert_type``).
CONFIG_KEYS: dict[str, str] = family_keys(IssuanceDefaults)

#: Reverse map: argparse dest -> TOML key (for saving).
DEST_TO_KEY: dict[str, str] = {dest: key for key, dest in CONFIG_KEYS.items()}

#: Per-profile connection settings, mapped to their field name (always the
#: TOML key itself). These live in the same [defaults]/[profiles.NAME]
#: sections as the issue-cert defaults but are read by
#: :func:`connection_config`, not :func:`config_defaults`.
CONNECTION_KEYS: dict[str, str] = family_keys(ConnectionSettings)


class ConfigError(Exception):
    """Raised when the config file exists but cannot be parsed or is invalid."""


def config_path() -> Path:
    """Return the path of the certinext config file.

    The ``CERTINEXT_CONFIG`` environment variable overrides the default
    location, which is ``%APPDATA%\\certinext\\config.toml`` on Windows and
    ``$XDG_CONFIG_HOME/certinext/config.toml`` (defaulting to
    ``~/.config/certinext/config.toml``) elsewhere.

    Returns:
        Absolute path to the config file (which may not exist yet).
    """
    override = os.environ.get("CERTINEXT_CONFIG")
    if override:
        return Path(override)
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / "certinext" / "config.toml"


def load_config(path: Path | None = None) -> dict[str, Any]:
    """Parse the config file and return its raw contents.

    Args:
        path: File to read; defaults to :func:`config_path`.

    Returns:
        The parsed TOML document as a dict, or an empty dict when the file
        does not exist.

    Raises:
        ConfigError: If the file exists but is not valid TOML.
    """
    path = path or config_path()
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise ConfigError(f"Cannot read {path}: {exc}") from exc
    try:
        doc: dict[str, Any] = tomllib.loads(raw.decode("utf-8"))
        return doc
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError(f"Invalid TOML in {path}: {exc}") from exc


def _sections(doc: dict[str, Any], profile: str | None) -> list[tuple[str, Any]]:
    """Return the (label, section) pairs a profile's settings merge from.

    Always ``[defaults]``, plus ``[profiles.NAME]`` when a profile is active
    (profile values override).

    Args:
        doc: The parsed config document.
        profile: Profile name, or None for the default profile only.

    Returns:
        List of ``(section label, raw section value)`` pairs in merge order.
    """
    sections: list[tuple[str, Any]] = [("[defaults]", doc.get("defaults", {}))]
    if profile:
        profiles = doc.get("profiles")
        section = profiles.get(profile, {}) if isinstance(profiles, dict) else {}
        sections.append((f"[profiles.{profile}]", section))
    return sections


def _checked(
    model_cls: type[BaseModel], key: str, value: Any, label: str, warnings: list[str]
) -> Any | None:
    """Validate a single config value through its family model.

    Validates ``{key: value}`` alone, so one bad entry never blocks the rest
    of the section.

    Args:
        model_cls: The family model declaring the key.
        key: TOML key name.
        value: Raw value from the parsed file.
        label: Section label for warning messages (e.g. ``'[defaults]'``).
        warnings: List that invalid-value messages are appended to.

    Returns:
        The validated value, or None (with a warning recorded) when the
        value is invalid and should be ignored.
    """
    try:
        probe = model_cls.model_validate({key: value})
    except ValidationError as exc:
        detail = "; ".join(err["msg"] for err in exc.errors())
        warnings.append(f"{label}: {key}: {detail} (got {value!r}); ignoring")
        return None
    return getattr(probe, family_keys(model_cls)[key])


def issuance_defaults(profile: str | None, path: Path | None = None) -> tuple[IssuanceDefaults, list[str]]:
    """Return stored issue-cert defaults for a profile as a validated model.

    Merges the ``[defaults]`` section with the matching ``[profiles.NAME]``
    section (profile values win). Unknown or invalid keys are skipped and
    reported via the warnings list rather than raising, so a typo in the
    config file never blocks issuance.

    Args:
        profile: Profile name, or None for the default profile only.
        path: Config file to read; defaults to :func:`config_path`.

    Returns:
        An ``(IssuanceDefaults, warnings)`` tuple.

    Raises:
        ConfigError: If the config file exists but cannot be parsed.
    """
    doc = load_config(path)
    warnings: list[str] = []
    merged: dict[str, Any] = {}

    for label, section in _sections(doc, profile):
        if not isinstance(section, dict):
            warnings.append(f"{label} is not a table; ignoring")
            continue
        for key, value in section.items():
            if key in CONNECTION_KEYS:
                continue  # connection settings are read by connection_config()
            if key not in CONFIG_KEYS:
                warnings.append(f"{label}: unknown key {key!r}; ignoring")
                continue
            checked = _checked(IssuanceDefaults, key, value, label, warnings)
            if checked is not None:
                merged[CONFIG_KEYS[key]] = checked
    return IssuanceDefaults.model_validate(merged), warnings


def config_defaults(profile: str | None, path: Path | None = None) -> tuple[dict[str, Any], list[str]]:
    """Return stored defaults for a profile, keyed by argparse dest name.

    Dict view of :func:`issuance_defaults` for the argparse-based CLIs
    (values feed ``build_parser`` defaults).

    Args:
        profile: Profile name, or None for the default profile only.
        path: Config file to read; defaults to :func:`config_path`.

    Returns:
        A ``(defaults, warnings)`` tuple: dest-keyed values to feed argparse,
        and human-readable warnings about ignored entries.

    Raises:
        ConfigError: If the config file exists but cannot be parsed.
    """
    model, warnings = issuance_defaults(profile, path)
    return model.model_dump(exclude_none=True), warnings


def connection_settings(profile: str | None, path: Path | None = None) -> tuple[ConnectionSettings, list[str]]:
    """Return stored connection settings for a profile as a validated model.

    Merges the ``[defaults]`` section with the matching ``[profiles.NAME]``
    section (profile values win), keeping only the
    :class:`~certinext.settings.ConnectionSettings` keys. Values of the wrong
    type are skipped and reported via the warnings list rather than raising,
    so a typo never blocks a CLI from connecting (it just falls back to the
    production default).

    Args:
        profile: Profile name, or None for the default profile only.
        path: Config file to read; defaults to :func:`config_path`.

    Returns:
        A ``(ConnectionSettings, warnings)`` tuple.

    Raises:
        ConfigError: If the config file exists but cannot be parsed.
    """
    doc = load_config(path)
    warnings: list[str] = []
    merged: dict[str, Any] = {}

    for label, section in _sections(doc, profile):
        if not isinstance(section, dict):
            continue  # config_defaults() already warns about a non-table section
        for key, value in section.items():
            if key not in CONNECTION_KEYS:
                continue  # issue-cert defaults are read by config_defaults()
            checked = _checked(ConnectionSettings, key, value, label, warnings)
            if checked is not None:
                merged[key] = checked
    return ConnectionSettings.model_validate(merged), warnings


def connection_config(profile: str | None, path: Path | None = None) -> tuple[dict[str, Any], list[str]]:
    """Return stored connection settings for a profile (endpoint selection).

    Dict view of :func:`connection_settings` for the argparse-based CLIs.

    Args:
        profile: Profile name, or None for the default profile only.
        path: Config file to read; defaults to :func:`config_path`.

    Returns:
        A ``(settings, warnings)`` tuple. ``settings`` may contain ``sandbox``
        (bool), ``base_url`` (str), and/or ``token_url`` (str).

    Raises:
        ConfigError: If the config file exists but cannot be parsed.
    """
    model, warnings = connection_settings(profile, path)
    return model.model_dump(exclude_none=True), warnings


def profile_from_argv(argv: list[str]) -> str | None:
    """Pre-scan argv for the active profile before full argparse parsing.

    Replicates the precedence used by ``apply_sandbox``: an explicit
    ``--profile`` wins, then ``--sandbox`` (implies profile ``'sandbox'``),
    then the ``CERTINEXT_PROFILE`` environment variable.

    Args:
        argv: Command-line arguments (without the program name).

    Returns:
        The profile name, or None for the default profile.
    """
    profile: str | None = None
    sandbox = False
    for i, arg in enumerate(argv):
        if arg == "--profile" and i + 1 < len(argv):
            profile = argv[i + 1]
        elif arg.startswith("--profile="):
            profile = arg.split("=", 1)[1]
        elif arg == "--sandbox":
            sandbox = True
    if profile:
        return profile
    if sandbox:
        return "sandbox"
    return os.environ.get("CERTINEXT_PROFILE") or None


def _parse_for_update(path: Path) -> tomlkit.TOMLDocument:
    """Read the config file as a comment-preserving tomlkit document.

    A missing file yields a fresh document with a short header comment; an
    existing file is parsed so comments and formatting round-trip.

    Args:
        path: Config file to read.

    Returns:
        The tomlkit document to update and write back.

    Raises:
        ConfigError: If the file exists but cannot be read or parsed (an
            unparseable file is never blindly overwritten).
    """
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        doc = tomlkit.document()
        doc.add(tomlkit.comment("CertiNext stored defaults - see the certinext README."))
        doc.add(tomlkit.comment("Managed by certinext-setup-defaults / --save-defaults."))
        doc.add(tomlkit.nl())
        return doc
    except OSError as exc:
        raise ConfigError(f"Cannot read {path}: {exc}") from exc
    try:
        return tomlkit.parse(raw.decode("utf-8"))
    except (tomlkit.exceptions.ParseError, UnicodeDecodeError) as exc:
        raise ConfigError(f"Invalid TOML in {path}: {exc}") from exc


def save_defaults(
    values: dict[str, Any],
    profile: str | None,
    path: Path | None = None,
    *,
    remove: tuple[str, ...] = (),
) -> Path:
    """Write defaults into the config file, creating it if needed.

    Values land in ``[defaults]`` (no profile) or ``[profiles.NAME]``. Both
    issue-cert defaults (:data:`CONFIG_KEYS`) and connection settings
    (:data:`CONNECTION_KEYS`) are accepted, by argparse dest name or TOML key
    name; ``None`` and empty-string values are skipped so a blank prompt answer
    never writes an empty default. Existing sections and keys not mentioned in
    ``values`` are preserved, and so are comments and formatting in a
    hand-written file (tomlkit round-trip).

    Args:
        values: Defaults to store, keyed by dest or TOML key name.
        profile: Profile name, or None for the ``[defaults]`` section.
        path: Config file to write; defaults to :func:`config_path`.
        remove: Keys (dest or TOML name) to delete from the section.

    Returns:
        The path written.

    Raises:
        ConfigError: If an existing file cannot be parsed (it is never
            overwritten blindly), if a key is not a recognised default, or
            if the file cannot be written.
    """
    path = path or config_path()
    doc = _parse_for_update(path)

    if profile:
        if "profiles" not in doc:
            doc["profiles"] = tomlkit.table(is_super_table=True)
        profiles = doc["profiles"]
        if not isinstance(profiles, dict):
            raise ConfigError(f"[profiles] in {path} is not a table")
        if profile not in profiles:
            profiles[profile] = tomlkit.table()
        section = profiles[profile]
    else:
        if "defaults" not in doc:
            doc["defaults"] = tomlkit.table()
        section = doc["defaults"]
    if not isinstance(section, dict):
        raise ConfigError(f"Target section in {path} is not a table")

    for name, value in values.items():
        key = DEST_TO_KEY.get(name, name)
        if key not in CONFIG_KEYS and key not in CONNECTION_KEYS:
            raise ConfigError(f"Not a recognised default: {name!r}")
        if value in (None, ""):
            continue
        section[key] = value
    for name in remove:
        key = DEST_TO_KEY.get(name, name)
        if key in section:
            del section[key]

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # newline="" disables \n -> \r\n translation: tomlkit's output already
        # carries the file's own line endings (preserved from parse), and
        # translating them again would corrupt \r\n into \r\r\n on Windows.
        path.write_text(tomlkit.dumps(doc), encoding="utf-8", newline="")
    except OSError as exc:
        raise ConfigError(f"Cannot write {path}: {exc}") from exc
    return path
