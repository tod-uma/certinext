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

Two key families live side by side. Issue-cert defaults (see
:data:`CONFIG_KEYS`) are read by :func:`config_defaults`; connection settings
(see :data:`CONNECTION_KEYS`) are read by :func:`connection_config`. Each
reader ignores the other family's keys, so a ``sandbox``/``base_url`` entry
never trips an "unknown key" warning during certificate issuance.

Resolution precedence (highest first): explicit CLI argument, environment
variable, ``[profiles.NAME]`` value, ``[defaults]`` value, built-in default.

Secrets (client secret, prevetting token) must never be stored here — use
the OS keyring via ``certinext-setup-keyring``.
"""
import os
import sys
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:  # Python 3.10
    import tomli as tomllib

#: TOML keys accepted in [defaults] / [profiles.NAME], mapped to the argparse
#: dest they feed. Keys equal to their dest are listed with an identity value.
CONFIG_KEYS: dict[str, str] = {
    "requestor_name": "requestor_name",
    "requestor_email": "requestor_email",
    "requestor_phone": "requestor_phone",
    "requestor_designation": "requestor_designation",
    "signer_place": "signer_place",
    "type": "cert_type",
    "org_id": "org_id",
    "validity": "validity",
    "product": "product",
}

#: Reverse map: argparse dest -> TOML key (for saving).
DEST_TO_KEY: dict[str, str] = {dest: key for key, dest in CONFIG_KEYS.items()}

#: Per-profile connection settings, mapped to their expected Python type. These
#: live in the same [defaults]/[profiles.NAME] sections as the issue-cert
#: defaults but are read by :func:`connection_config`, not :func:`config_defaults`.
#: ``sandbox`` is a boolean shorthand for the sandbox endpoints; ``base_url`` /
#: ``token_url`` point a profile at an arbitrary endpoint.
CONNECTION_KEYS: dict[str, type] = {
    "sandbox": bool,
    "base_url": str,
    "token_url": str,
}


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


def _validate(key: str, value: Any, source: str, warnings: list[str]) -> Any | None:
    """Validate a single config value, returning it (coerced) or None to skip.

    Args:
        key: TOML key name.
        value: Raw value from the parsed file.
        source: Section label for warning messages (e.g. ``'[defaults]'``).
        warnings: List that invalid-value messages are appended to.

    Returns:
        The validated value, or None when the value should be ignored.
    """
    if key == "validity":
        if not isinstance(value, int) or value not in (1, 2, 3):
            warnings.append(f"{source}: validity must be 1, 2, or 3 (got {value!r}); ignoring")
            return None
        return value
    if key == "type":
        if value not in ("dv", "ov", "ev"):
            warnings.append(f"{source}: type must be dv, ov, or ev (got {value!r}); ignoring")
            return None
        return value
    if not isinstance(value, str):
        warnings.append(f"{source}: {key} must be a string (got {value!r}); ignoring")
        return None
    return value


def config_defaults(profile: str | None, path: Path | None = None) -> tuple[dict[str, Any], list[str]]:
    """Return stored defaults for a profile, keyed by argparse dest name.

    Merges the ``[defaults]`` section with the matching ``[profiles.NAME]``
    section (profile values win). Unknown or invalid keys are skipped and
    reported via the warnings list rather than raising, so a typo in the
    config file never blocks issuance.

    Args:
        profile: Profile name, or None for the default profile only.
        path: Config file to read; defaults to :func:`config_path`.

    Returns:
        A ``(defaults, warnings)`` tuple: dest-keyed values to feed argparse,
        and human-readable warnings about ignored entries.

    Raises:
        ConfigError: If the config file exists but cannot be parsed.
    """
    doc = load_config(path)
    warnings: list[str] = []
    merged: dict[str, Any] = {}

    sections: list[tuple[str, Any]] = [("[defaults]", doc.get("defaults", {}))]
    if profile:
        sections.append((f"[profiles.{profile}]", doc.get("profiles", {}).get(profile, {})))

    for label, section in sections:
        if not isinstance(section, dict):
            warnings.append(f"{label} is not a table; ignoring")
            continue
        for key, value in section.items():
            if key in CONNECTION_KEYS:
                continue  # connection settings are read by connection_config()
            if key not in CONFIG_KEYS:
                warnings.append(f"{label}: unknown key {key!r}; ignoring")
                continue
            checked = _validate(key, value, label, warnings)
            if checked is not None:
                merged[CONFIG_KEYS[key]] = checked
    return merged, warnings


def connection_config(profile: str | None, path: Path | None = None) -> tuple[dict[str, Any], list[str]]:
    """Return stored connection settings for a profile (endpoint selection).

    Merges the ``[defaults]`` section with the matching ``[profiles.NAME]``
    section (profile values win), keeping only the keys in
    :data:`CONNECTION_KEYS`. Values of the wrong type are skipped and reported
    via the warnings list rather than raising, so a typo never blocks a CLI
    from connecting (it just falls back to the production default).

    Args:
        profile: Profile name, or None for the default profile only.
        path: Config file to read; defaults to :func:`config_path`.

    Returns:
        A ``(settings, warnings)`` tuple. ``settings`` may contain ``sandbox``
        (bool), ``base_url`` (str), and/or ``token_url`` (str).

    Raises:
        ConfigError: If the config file exists but cannot be parsed.
    """
    doc = load_config(path)
    warnings: list[str] = []
    merged: dict[str, Any] = {}

    sections: list[tuple[str, Any]] = [("[defaults]", doc.get("defaults", {}))]
    if profile:
        sections.append((f"[profiles.{profile}]", doc.get("profiles", {}).get(profile, {})))

    for label, section in sections:
        if not isinstance(section, dict):
            continue  # config_defaults() already warns about a non-table section
        for key, value in section.items():
            if key not in CONNECTION_KEYS:
                continue  # issue-cert defaults are read by config_defaults()
            expected = CONNECTION_KEYS[key]
            # bool is a subclass of int, so a stray "base_url = true" must not
            # pass the str check — reject any bool where a string is expected.
            if not isinstance(value, expected) or (expected is str and isinstance(value, bool)):
                warnings.append(f"{label}: {key} must be {expected.__name__} (got {value!r}); ignoring")
                continue
            merged[key] = value
    return merged, warnings


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


def _toml_literal(value: Any) -> str:
    """Render a scalar as a TOML literal (string, int, or bool)."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _render(doc: dict[str, Any]) -> str:
    """Render the config document back to TOML text.

    Emits ``[defaults]`` first, then ``[profiles.NAME]`` sections in sorted
    order, then any other top-level tables. Comments from a previous file
    are not preserved.

    Args:
        doc: Parsed config document (nested dicts of scalars).

    Returns:
        TOML text ending in a newline.
    """
    chunks: list[str] = [
        "# CertiNext stored defaults — see the certinext README.",
        "# Managed by certinext-setup-defaults / --save-defaults; comments are not preserved.",
        "",
    ]

    def emit(header: str, table: dict[str, Any]) -> None:
        """Append one [section] with its key/value lines to chunks."""
        chunks.append(f"[{header}]")
        for key in sorted(table):
            chunks.append(f"{key} = {_toml_literal(table[key])}")
        chunks.append("")

    if isinstance(doc.get("defaults"), dict):
        emit("defaults", doc["defaults"])
    profiles = doc.get("profiles")
    if isinstance(profiles, dict):
        for name in sorted(profiles):
            if isinstance(profiles[name], dict):
                emit(f"profiles.{name}", profiles[name])
    for name, table in doc.items():
        if name in ("defaults", "profiles"):
            continue
        if isinstance(table, dict):
            emit(name, table)
    return "\n".join(chunks)


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
    ``values`` are preserved; comments in a hand-written file are not.

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
    doc = load_config(path)

    section: dict[str, Any]
    if profile:
        profiles = doc.setdefault("profiles", {})
        if not isinstance(profiles, dict):
            raise ConfigError(f"[profiles] in {path} is not a table")
        section = profiles.setdefault(profile, {})
    else:
        section = doc.setdefault("defaults", {})
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
        section.pop(DEST_TO_KEY.get(name, name), None)

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(_render(doc), encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Cannot write {path}: {exc}") from exc
    return path
