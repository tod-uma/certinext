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

"""Tests for stored issue-cert defaults (certinext._config) and CLI precedence."""

from pathlib import Path

import pytest

import certinext
from certinext._config import (
    ConfigError,
    config_defaults,
    config_path,
    connection_config,
    load_config,
    profile_from_argv,
    save_defaults,
)
from certinext.cli.issue_cert import resolve_order_defaults
from certinext.cli_support import ResolvedConnection, resolve_connection


def _resolved_args(
    profile: str | None = None,
    sandbox: bool = False,
    base_url: str | None = None,
    token_url: str | None = None,
) -> ResolvedConnection:
    """Resolve connection inputs the way every CLI command does."""
    return resolve_connection(
        profile=profile, sandbox=sandbox, base_url=base_url, token_url=token_url,
    )


@pytest.fixture
def cfg_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point CERTINEXT_CONFIG at a temp file and return its path."""
    path = tmp_path / "config.toml"
    monkeypatch.setenv("CERTINEXT_CONFIG", str(path))
    return path


@pytest.fixture(autouse=True)
def _no_requestor_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Clear requestor/profile env vars so the host environment can't leak in."""
    for var in (
        "CERTINEXT_REQUESTOR_NAME",
        "CERTINEXT_REQUESTOR_EMAIL",
        "CERTINEXT_REQUESTOR_PHONE",
        "CERTINEXT_REQUESTOR_DESIGNATION",
        "CERTINEXT_SIGNER_PLACE",
        "CERTINEXT_PROFILE",
    ):
        monkeypatch.delenv(var, raising=False)


def test_config_path_env_override(cfg_file: Path) -> None:
    """CERTINEXT_CONFIG overrides the platform default location."""
    assert config_path() == cfg_file


def test_load_config_missing_file(cfg_file: Path) -> None:
    """A missing config file is an empty document, not an error."""
    assert load_config() == {}


def test_load_config_invalid_toml(cfg_file: Path) -> None:
    """Invalid TOML raises ConfigError with the path in the message."""
    cfg_file.write_text("not [valid toml", encoding="utf-8")
    with pytest.raises(ConfigError, match="Invalid TOML"):
        load_config()


def test_config_defaults_merges_profile_over_defaults(cfg_file: Path) -> None:
    """[profiles.NAME] values override [defaults]; dest names are mapped."""
    cfg_file.write_text(
        '[defaults]\nrequestor_name = "Jane"\ntype = "ov"\n\n'
        '[profiles.sandbox]\ntype = "dv"\n',
        encoding="utf-8",
    )
    merged, warnings = config_defaults("sandbox")
    assert merged == {"requestor_name": "Jane", "cert_type": "dv"}
    assert warnings == []


def test_config_defaults_without_profile(cfg_file: Path) -> None:
    """With no profile, [profiles.*] sections are ignored entirely."""
    cfg_file.write_text(
        '[defaults]\ntype = "ov"\n\n[profiles.sandbox]\ntype = "dv"\n',
        encoding="utf-8",
    )
    merged, _ = config_defaults(None)
    assert merged == {"cert_type": "ov"}


def test_config_defaults_warns_on_unknown_and_invalid(cfg_file: Path) -> None:
    """Unknown keys and out-of-range values are skipped with warnings."""
    cfg_file.write_text(
        '[defaults]\nbogus = "x"\nvalidity = 7\ntype = "xx"\nrequestor_name = "Jane"\n',
        encoding="utf-8",
    )
    merged, warnings = config_defaults(None)
    assert merged == {"requestor_name": "Jane"}
    assert len(warnings) == 3


def test_profile_from_argv_explicit_profile() -> None:
    """--profile wins over --sandbox."""
    assert profile_from_argv(["--sandbox", "--profile", "prod"]) == "prod"


def test_profile_from_argv_equals_form() -> None:
    """--profile=NAME is recognised."""
    assert profile_from_argv(["--profile=prod"]) == "prod"


def test_profile_from_argv_sandbox() -> None:
    """--sandbox implies the sandbox profile."""
    assert profile_from_argv(["--sandbox"]) == "sandbox"


def test_profile_from_argv_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """CERTINEXT_PROFILE is the fallback when no flag is present."""
    monkeypatch.setenv("CERTINEXT_PROFILE", "prod")
    assert profile_from_argv([]) == "prod"


def test_profile_from_argv_none() -> None:
    """No flags and no env var means the default profile."""
    assert profile_from_argv(["new.csr"]) is None


def test_save_defaults_roundtrip(cfg_file: Path) -> None:
    """Saved values (including dest-name mapping) load back identically."""
    save_defaults({"requestor_name": "Jane", "cert_type": "ov", "validity": 2}, None)
    merged, warnings = config_defaults(None)
    assert merged == {"requestor_name": "Jane", "cert_type": "ov", "validity": 2}
    assert warnings == []


def test_save_defaults_profile_section(cfg_file: Path) -> None:
    """A profile save writes [profiles.NAME] and leaves [defaults] alone."""
    save_defaults({"requestor_name": "Jane"}, None)
    save_defaults({"cert_type": "dv"}, "sandbox")
    doc = load_config()
    assert doc["defaults"] == {"requestor_name": "Jane"}
    assert doc["profiles"]["sandbox"] == {"type": "dv"}


def test_save_defaults_skips_empty_and_preserves_existing(cfg_file: Path) -> None:
    """Empty values are not written; keys not mentioned survive a re-save."""
    save_defaults({"requestor_name": "Jane", "org_id": ""}, None)
    save_defaults({"requestor_phone": "+12075551234", "requestor_email": None}, None)
    merged, _ = config_defaults(None)
    assert merged == {"requestor_name": "Jane", "requestor_phone": "+12075551234"}


def test_save_defaults_remove(cfg_file: Path) -> None:
    """The remove parameter deletes stored keys."""
    save_defaults({"requestor_name": "Jane", "org_id": "123"}, None)
    save_defaults({}, None, remove=("org_id",))
    merged, _ = config_defaults(None)
    assert merged == {"requestor_name": "Jane"}


def test_save_defaults_preserves_comments(cfg_file: Path) -> None:
    """Comments and existing keys in a hand-written file survive a save (tomlkit)."""
    cfg_file.write_text(
        "# my hand-written notes\n"
        '[defaults]\ntype = "ov"  # OV is what we usually want\n',
        encoding="utf-8",
    )
    save_defaults({"requestor_name": "Jane"}, None)
    text = cfg_file.read_text(encoding="utf-8")
    assert "# my hand-written notes" in text
    assert "# OV is what we usually want" in text
    merged, _ = config_defaults(None)
    assert merged == {"cert_type": "ov", "requestor_name": "Jane"}


def test_save_defaults_rejects_unknown_key(cfg_file: Path) -> None:
    """Saving an unrecognised key raises ConfigError."""
    with pytest.raises(ConfigError, match="Not a recognised default"):
        save_defaults({"client_secret": "nope"}, None)


def test_save_defaults_refuses_corrupt_file(cfg_file: Path) -> None:
    """An unparseable existing file is never blindly overwritten."""
    cfg_file.write_text("not [valid toml", encoding="utf-8")
    with pytest.raises(ConfigError, match="Invalid TOML"):
        save_defaults({"requestor_name": "Jane"}, None)


def test_parser_uses_config_defaults() -> None:
    """Config values seed the resolved order defaults for cert and requestor fields."""
    cfg = {
        "requestor_name": "Jane",
        "requestor_phone": "+12075551234",
        "cert_type": "ov",
        "org_id": "123",
        "validity": 3,
        "signer_place": "Orono, ME",
    }
    values = resolve_order_defaults(cfg)
    assert values.requestor_name == "Jane"
    assert values.requestor_phone == "+12075551234"
    assert values.cert_type == "ov"
    assert values.org_id == "123"
    assert values.validity == 3
    assert values.signer_place == "Orono, ME"


def test_parser_cli_overrides_config() -> None:
    """Explicit CLI arguments beat stored config defaults."""
    cfg = {"requestor_name": "Jane", "requestor_phone": "+12075551234", "cert_type": "ov"}
    values = resolve_order_defaults(cfg, cert_type="dv", requestor_name="Bob")
    assert values.cert_type == "dv"
    assert values.requestor_name == "Bob"


def test_parser_env_overrides_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """Environment variables beat stored config defaults for requestor args."""
    monkeypatch.setenv("CERTINEXT_REQUESTOR_NAME", "EnvName")
    cfg = {"requestor_name": "Jane", "requestor_phone": "+12075551234"}
    values = resolve_order_defaults(cfg)
    assert values.requestor_name == "EnvName"


def test_parser_still_requires_missing_values() -> None:
    """Without CLI, env, or config values, required requestor args still fail."""
    with pytest.raises(ValueError, match="--requestor-name"):
        resolve_order_defaults({})


def test_config_defaults_includes_product(cfg_file: Path) -> None:
    """A stored product code is returned under the 'product' dest."""
    cfg_file.write_text('[defaults]\nproduct = "842"\n', encoding="utf-8")
    merged, warnings = config_defaults(None)
    assert merged == {"product": "842"}
    assert warnings == []


def test_save_defaults_product_roundtrip(cfg_file: Path) -> None:
    """A product code saves and loads back under a profile."""
    save_defaults({"product": "1057"}, "prod")
    merged, _ = config_defaults("prod")
    assert merged["product"] == "1057"


# --- connection settings (sandbox / base_url / token_url) -------------------


def test_connection_config_sandbox_bool(cfg_file: Path) -> None:
    """A profile's sandbox = true is read back as a boolean."""
    cfg_file.write_text("[profiles.srv]\nsandbox = true\n", encoding="utf-8")
    conn, warnings = connection_config("srv")
    assert conn == {"sandbox": True}
    assert warnings == []


def test_connection_config_custom_urls(cfg_file: Path) -> None:
    """Explicit base_url/token_url are read back verbatim."""
    cfg_file.write_text(
        '[profiles.staging]\nbase_url = "https://s-api"\ntoken_url = "https://s-api/oauth/token"\n',
        encoding="utf-8",
    )
    conn, _ = connection_config("staging")
    assert conn == {"base_url": "https://s-api", "token_url": "https://s-api/oauth/token"}


def test_connection_config_profile_over_defaults(cfg_file: Path) -> None:
    """[profiles.NAME] connection keys merge over [defaults] connection keys."""
    cfg_file.write_text(
        '[defaults]\nsandbox = true\n\n[profiles.prod]\nbase_url = "https://p-api"\n',
        encoding="utf-8",
    )
    conn, _ = connection_config("prod")
    assert conn == {"sandbox": True, "base_url": "https://p-api"}


def test_connection_config_wrong_types_warn(cfg_file: Path) -> None:
    """A non-bool sandbox and a bool base_url are skipped with warnings."""
    cfg_file.write_text('[profiles.x]\nsandbox = "yes"\nbase_url = true\n', encoding="utf-8")
    conn, warnings = connection_config("x")
    assert conn == {}
    assert len(warnings) == 2


def test_config_defaults_ignores_connection_keys(cfg_file: Path) -> None:
    """Connection keys don't trip config_defaults' unknown-key warning."""
    cfg_file.write_text(
        '[defaults]\nsandbox = true\nbase_url = "https://x"\ntype = "dv"\n',
        encoding="utf-8",
    )
    merged, warnings = config_defaults(None)
    assert merged == {"cert_type": "dv"}
    assert warnings == []


def test_save_defaults_writes_connection_keys(cfg_file: Path) -> None:
    """save_defaults accepts and round-trips connection keys."""
    save_defaults({"sandbox": True}, "srv")
    conn, warnings = connection_config("srv")
    assert conn == {"sandbox": True}
    assert warnings == []


def test_save_defaults_custom_url_roundtrip(cfg_file: Path) -> None:
    """A custom base/token URL pair saves and loads identically."""
    save_defaults(
        {"base_url": "https://s-api", "token_url": "https://s-api/oauth/token"}, "staging"
    )
    conn, _ = connection_config("staging")
    assert conn == {"base_url": "https://s-api", "token_url": "https://s-api/oauth/token"}


# --- apply_sandbox endpoint resolution --------------------------------------


def test_apply_sandbox_default_is_production(cfg_file: Path) -> None:
    """No flags and no config resolve to the production endpoints."""
    args = _resolved_args()
    assert args.base_url == certinext.BASE_URL
    assert args.token_url == certinext.TOKEN_URL
    assert args.sandbox is False
    assert args.profile is None


def test_apply_sandbox_cli_flag(cfg_file: Path) -> None:
    """--sandbox resolves to sandbox endpoints and the sandbox profile."""
    args = _resolved_args(sandbox=True)
    assert args.base_url == certinext.SANDBOX_BASE_URL
    assert args.token_url == certinext.SANDBOX_TOKEN_URL
    assert args.sandbox is True
    assert args.profile == "sandbox"


def test_apply_sandbox_explicit_base_url_wins(cfg_file: Path) -> None:
    """An explicit --base-url is kept and does not flip the sandbox flag."""
    args = _resolved_args(base_url="https://custom-api")
    assert args.base_url == "https://custom-api"
    assert args.sandbox is False


def test_apply_sandbox_profile_sandbox_true(cfg_file: Path) -> None:
    """A profile with sandbox = true targets sandbox without the CLI flag."""
    cfg_file.write_text("[profiles.srv]\nsandbox = true\n", encoding="utf-8")
    args = _resolved_args(profile="srv")
    assert args.base_url == certinext.SANDBOX_BASE_URL
    assert args.token_url == certinext.SANDBOX_TOKEN_URL
    assert args.sandbox is True
    assert args.profile == "srv"  # named profile keeps its own name


def test_apply_sandbox_profile_custom_url(cfg_file: Path) -> None:
    """A profile with base_url/token_url targets that endpoint."""
    cfg_file.write_text(
        '[profiles.staging]\nbase_url = "https://s-api"\ntoken_url = "https://s-api/oauth/token"\n',
        encoding="utf-8",
    )
    args = _resolved_args(profile="staging")
    assert args.base_url == "https://s-api"
    assert args.token_url == "https://s-api/oauth/token"
    assert args.sandbox is False


def test_apply_sandbox_cli_flag_overrides_profile_url(cfg_file: Path) -> None:
    """CLI --sandbox beats a profile's stored custom base_url for that run."""
    cfg_file.write_text('[profiles.staging]\nbase_url = "https://s-api"\n', encoding="utf-8")
    args = _resolved_args(profile="staging", sandbox=True)
    assert args.base_url == certinext.SANDBOX_BASE_URL


def test_apply_sandbox_cli_base_url_overrides_profile(cfg_file: Path) -> None:
    """An explicit --base-url beats a profile's sandbox = true."""
    cfg_file.write_text("[profiles.srv]\nsandbox = true\n", encoding="utf-8")
    args = _resolved_args(profile="srv", base_url="https://custom-api")
    assert args.base_url == "https://custom-api"


def test_apply_sandbox_reads_env_profile(cfg_file: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """CERTINEXT_PROFILE selects the profile whose connection config is applied."""
    cfg_file.write_text("[profiles.srv]\nsandbox = true\n", encoding="utf-8")
    monkeypatch.setenv("CERTINEXT_PROFILE", "srv")
    args = _resolved_args()
    assert args.base_url == certinext.SANDBOX_BASE_URL
    assert args.sandbox is True


def test_broken_config_does_not_fall_back_to_production(cfg_file: Path) -> None:
    """An unparseable config fails closed instead of silently selecting production."""
    cfg_file.write_text("not [valid toml", encoding="utf-8")
    with pytest.raises(ConfigError, match="Invalid TOML"):
        _resolved_args()


def test_broken_config_with_explicit_profile_raises(cfg_file: Path) -> None:
    """A named profile plus a broken config raises rather than guessing production."""
    cfg_file.write_text("not [valid toml", encoding="utf-8")
    with pytest.raises(ConfigError, match="Invalid TOML"):
        _resolved_args(profile="staging")


def test_broken_config_with_env_profile_raises(
    cfg_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CERTINEXT_PROFILE is no escape hatch: a broken config still fails closed."""
    cfg_file.write_text("not [valid toml", encoding="utf-8")
    monkeypatch.setenv("CERTINEXT_PROFILE", "srv")
    with pytest.raises(ConfigError, match="Invalid TOML"):
        _resolved_args()


def test_broken_config_with_sandbox_flag_still_resolves(cfg_file: Path) -> None:
    """--sandbox pins the endpoint, so a broken config cannot select production."""
    cfg_file.write_text("not [valid toml", encoding="utf-8")
    args = _resolved_args(sandbox=True)
    assert args.base_url == certinext.SANDBOX_BASE_URL
    assert args.token_url == certinext.SANDBOX_TOKEN_URL
    assert args.sandbox is True


def test_broken_config_with_explicit_base_url_still_resolves(cfg_file: Path) -> None:
    """An explicit --base-url pins the endpoint, so a broken config is only a warning."""
    cfg_file.write_text("not [valid toml", encoding="utf-8")
    args = _resolved_args(base_url="https://custom-api")
    assert args.base_url == "https://custom-api"


def test_profile_without_config_section_still_resolves(cfg_file: Path) -> None:
    """A keyring-only profile has no config section and must still reach production.

    ``certinext setup keyring --profile prod`` stores credentials without
    writing a ``[profiles.prod]`` section, so an absent section is a supported
    configuration, not an error (see README 'Named profiles').
    """
    cfg_file.write_text('[defaults]\ntype = "ov"\n', encoding="utf-8")
    args = _resolved_args(profile="prod")
    assert args.base_url == certinext.BASE_URL
    assert args.token_url == certinext.TOKEN_URL
    assert args.profile == "prod"
