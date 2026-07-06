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

"""Tests for CertiNextSettings credential precedence (certinext.settings).

The certinext order is nonstandard — explicit argument -> OS keyring ->
environment variable — with the keyring *outranking* env. These tests pin
that order so a pydantic-settings upgrade or source reshuffle can never
silently revert to the library default (env above everything but init).
"""

from collections.abc import Iterator

import pytest
from pydantic import SecretStr

from certinext.settings import CertiNextSettings

#: Fake keyring backing store: (service, key) -> value.
_FakeStore = dict[tuple[str, str], str]


@pytest.fixture(autouse=True)
def fake_keyring(monkeypatch: pytest.MonkeyPatch) -> Iterator[_FakeStore]:
    """Replace keyring lookups with an in-memory store and clear certinext env vars.

    Isolation matters twice over: the dev machine has real certinext keyring
    entries and may have CERTINEXT_* set, and neither may leak into these
    precedence assertions.

    Yields:
        The mutable store; tests populate it with (service, key) entries.
    """
    store: _FakeStore = {}
    monkeypatch.setattr(
        "certinext.settings.keyring_get",
        lambda service, key: store.get((service, key)),
    )
    for var in ("CERTINEXT_CLIENT_ID", "CERTINEXT_CLIENT_SECRET", "CERTINEXT_PROFILE"):
        monkeypatch.delenv(var, raising=False)
    yield store


def test_keyring_outranks_env(fake_keyring: _FakeStore, monkeypatch: pytest.MonkeyPatch) -> None:
    """Stored keyring credentials win over environment variables."""
    fake_keyring[("certinext", "CERTINEXT_CLIENT_ID")] = "kr-id"
    fake_keyring[("certinext", "CERTINEXT_CLIENT_SECRET")] = "kr-secret"
    monkeypatch.setenv("CERTINEXT_CLIENT_ID", "env-id")
    monkeypatch.setenv("CERTINEXT_CLIENT_SECRET", "env-secret")

    settings = CertiNextSettings()
    assert settings.client_id == "kr-id"
    assert settings.client_secret is not None
    assert settings.client_secret.get_secret_value() == "kr-secret"


def test_env_used_when_keyring_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    """Environment variables resolve when nothing is stored in the keyring."""
    monkeypatch.setenv("CERTINEXT_CLIENT_ID", "env-id")
    monkeypatch.setenv("CERTINEXT_CLIENT_SECRET", "env-secret")

    settings = CertiNextSettings()
    assert settings.client_id == "env-id"
    assert settings.client_secret is not None
    assert settings.client_secret.get_secret_value() == "env-secret"


def test_explicit_args_outrank_keyring(fake_keyring: _FakeStore) -> None:
    """Constructor (CLI) values win over stored keyring credentials."""
    fake_keyring[("certinext", "CERTINEXT_CLIENT_ID")] = "kr-id"
    fake_keyring[("certinext", "CERTINEXT_CLIENT_SECRET")] = "kr-secret"

    settings = CertiNextSettings(client_id="cli-id", client_secret=SecretStr("cli-secret"))
    assert settings.client_id == "cli-id"
    assert settings.client_secret is not None
    assert settings.client_secret.get_secret_value() == "cli-secret"


def test_explicit_client_id_skips_keyring_secret(
    fake_keyring: _FakeStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An explicit client ID disables the keyring lookup for the secret.

    The stored secret belongs to the previously configured account; using it
    with a different client ID would only produce a 401. The env fallback
    still applies.
    """
    fake_keyring[("certinext", "CERTINEXT_CLIENT_SECRET")] = "kr-secret"

    settings = CertiNextSettings(client_id="other-account")
    assert settings.client_secret is None

    monkeypatch.setenv("CERTINEXT_CLIENT_SECRET", "env-secret")
    settings = CertiNextSettings(client_id="other-account")
    assert settings.client_secret is not None
    assert settings.client_secret.get_secret_value() == "env-secret"


def test_profile_selects_keyring_service(fake_keyring: _FakeStore) -> None:
    """A named profile reads from the certinext-<profile> keyring service."""
    fake_keyring[("certinext", "CERTINEXT_CLIENT_ID")] = "default-id"
    fake_keyring[("certinext-sandbox", "CERTINEXT_CLIENT_ID")] = "sandbox-id"

    assert CertiNextSettings().client_id == "default-id"
    assert CertiNextSettings(profile="sandbox").client_id == "sandbox-id"


def test_env_profile_selects_keyring_service(
    fake_keyring: _FakeStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CERTINEXT_PROFILE picks the keyring service when no explicit profile is given."""
    fake_keyring[("certinext-prod", "CERTINEXT_CLIENT_ID")] = "prod-id"
    monkeypatch.setenv("CERTINEXT_PROFILE", "prod")

    settings = CertiNextSettings()
    assert settings.profile == "prod"
    assert settings.client_id == "prod-id"


def test_explicit_profile_outranks_env_profile(
    fake_keyring: _FakeStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An explicit profile beats CERTINEXT_PROFILE for the keyring service too."""
    fake_keyring[("certinext-a", "CERTINEXT_CLIENT_ID")] = "a-id"
    fake_keyring[("certinext-b", "CERTINEXT_CLIENT_ID")] = "b-id"
    monkeypatch.setenv("CERTINEXT_PROFILE", "b")

    settings = CertiNextSettings(profile="a")
    assert settings.profile == "a"
    assert settings.client_id == "a-id"


def test_empty_env_string_is_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """Empty-string env vars count as absent, matching the old `or None` idiom."""
    monkeypatch.setenv("CERTINEXT_CLIENT_ID", "")
    monkeypatch.setenv("CERTINEXT_PROFILE", "")

    settings = CertiNextSettings()
    assert settings.client_id is None
    assert settings.profile is None


def test_no_sources_resolve_to_none() -> None:
    """With nothing anywhere, fields are None (the caller prompts or errors)."""
    settings = CertiNextSettings()
    assert settings.client_id is None
    assert settings.client_secret is None
    assert settings.profile is None
