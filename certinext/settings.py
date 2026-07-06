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

"""pydantic-settings configuration models for certinext (ADR 0003).

Three pieces live here:

- :class:`IssuanceDefaults` and :class:`ConnectionSettings` — the two key
  families stored side by side in ``config.toml``'s ``[defaults]`` and
  ``[profiles.NAME]`` sections. Fields use strict types so a wrong-typed
  entry (e.g. ``sandbox = "yes"``) fails per-field validation and degrades
  into a warning in :mod:`certinext._config`, never a crash and never a
  silent coercion.
- :class:`KeyringSettingsSource` — a custom settings source exposing the OS
  keyring to pydantic-settings.
- :class:`CertiNextSettings` — API credential and profile resolution with
  the certinext precedence order, which is **nonstandard**: explicit
  argument -> OS keyring -> environment variable. The keyring *outranks*
  the environment (pydantic-settings' default puts env above everything
  but init args), which is why :meth:`~CertiNextSettings.settings_customise_sources`
  splices :class:`KeyringSettingsSource` in between the init and env sources.

Interactive prompting (the final fallback of the credential order) is not a
settings source; it stays in :mod:`certinext._cli` where TTY handling lives.

File loading, profile-overlay merging, and warning collection live in
:mod:`certinext._config`, which validates each stored key through these
models one field at a time.
"""

import os
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, StrictBool, StrictStr, field_validator
from pydantic.fields import FieldInfo
from pydantic_settings import (
    BaseSettings,
    InitSettingsSource,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

from certinext._keyring import keyring_get, keyring_service


class IssuanceDefaults(BaseModel):
    """Stored ``certinext-issue-cert`` defaults (one of the two config-file key families).

    Field names match the argparse dest they feed; where the TOML key differs
    (``type`` -> ``cert_type``) the TOML key is the field's alias. All fields
    are optional — the config file may set any subset.
    """

    model_config = ConfigDict(populate_by_name=True)

    requestor_name: StrictStr | None = None
    requestor_email: StrictStr | None = None
    requestor_phone: StrictStr | None = None
    requestor_designation: StrictStr | None = None
    signer_place: StrictStr | None = None
    cert_type: Literal["dv", "ov", "ev"] | None = Field(default=None, alias="type")
    org_id: StrictStr | None = None
    validity: Literal[1, 2, 3] | None = None
    product: StrictStr | None = None


class ConnectionSettings(BaseModel):
    """Per-profile connection settings (the other config-file key family).

    ``sandbox`` is a boolean shorthand for the sandbox endpoints;
    ``base_url``/``token_url`` point a profile at an arbitrary endpoint.
    Strict types are load-bearing: pydantic's lax mode would coerce
    ``sandbox = "yes"`` to ``True``, but the deployed contract is that a
    wrong-typed value is skipped with a warning.
    """

    sandbox: StrictBool | None = None
    base_url: StrictStr | None = None
    token_url: StrictStr | None = None


def family_keys(model_cls: type[BaseModel]) -> dict[str, str]:
    """Map a family model's TOML keys to its field (argparse dest) names.

    The TOML key is the field's alias when one is set (``type``), otherwise
    the field name itself.

    Args:
        model_cls: One of the config-family models
            (:class:`IssuanceDefaults` or :class:`ConnectionSettings`).

    Returns:
        Dict of TOML key -> field name, in field-declaration order.
    """
    return {(field.alias or name): name for name, field in model_cls.model_fields.items()}


class KeyringSettingsSource(PydanticBaseSettingsSource):
    """Settings source reading API credentials from the OS keyring.

    Looks up ``CERTINEXT_CLIENT_ID`` / ``CERTINEXT_CLIENT_SECRET`` under the
    keyring service for the active profile (``certinext`` or
    ``certinext-<profile>``). Placed *above* the env source so stored
    credentials outrank environment variables — the certinext precedence
    rule pydantic-settings does not provide out of the box.

    When ``client_id`` was passed explicitly (an ``--account-number`` CLI
    argument), the keyring is not consulted at all: the stored secret
    belongs to the previously configured account and would only produce an
    authentication failure with a different client ID.

    Degrades to an empty result when keyring is unavailable
    (:func:`certinext._keyring.keyring_get` swallows backend errors).
    """

    def __init__(self, settings_cls: type[BaseSettings], init_kwargs: dict[str, Any]) -> None:
        """Capture the init kwargs the settings object was constructed with.

        Args:
            settings_cls: The settings class being populated.
            init_kwargs: Keyword arguments passed to the settings
                constructor (explicit CLI values), used for the active
                profile and the explicit-client-id rule.
        """
        super().__init__(settings_cls)
        self._init_kwargs = init_kwargs

    def get_field_value(self, field: FieldInfo, field_name: str) -> tuple[Any, str, bool]:
        """Unused per-field hook required by the source ABC (``__call__`` does the work).

        Args:
            field: The field being populated.
            field_name: The field's name.

        Returns:
            A "no value" triple.
        """
        return None, field_name, False

    def __call__(self) -> dict[str, Any]:
        """Return credentials found in the keyring for the active profile.

        The profile mirrors the init -> env precedence of the settings class
        itself: an explicit ``profile`` kwarg wins, then ``CERTINEXT_PROFILE``.

        Returns:
            A dict with ``client_id`` and/or ``client_secret`` when stored,
            empty when nothing is stored, keyring is unavailable, or an
            explicit client ID disables the lookup.
        """
        if self._init_kwargs.get("client_id"):
            return {}
        profile = self._init_kwargs.get("profile") or os.environ.get("CERTINEXT_PROFILE") or None
        service = keyring_service("certinext", profile)
        values: dict[str, Any] = {}
        client_id = keyring_get(service, "CERTINEXT_CLIENT_ID")
        if client_id:
            values["client_id"] = client_id
        client_secret = keyring_get(service, "CERTINEXT_CLIENT_SECRET")
        if client_secret:
            values["client_secret"] = client_secret
        return values


class CertiNextSettings(BaseSettings):
    """Resolved API credentials and profile selection.

    Resolution order per field (highest first): explicit constructor
    argument (CLI), OS keyring, environment variable
    (``CERTINEXT_CLIENT_ID`` / ``CERTINEXT_CLIENT_SECRET`` /
    ``CERTINEXT_PROFILE``). The interactive prompt that follows when
    nothing resolves is the caller's job (see
    :func:`certinext._cli.build_session`).

    Usage::

        settings = CertiNextSettings(profile="sandbox")   # CLI values as kwargs
        settings.client_id                                # keyring beats env

    Empty strings from the environment count as unset, matching the
    ``os.environ.get(...) or ...`` idiom this class replaces.
    """

    model_config = SettingsConfigDict(env_prefix="CERTINEXT_", extra="ignore")

    profile: str | None = None
    client_id: str | None = None
    client_secret: SecretStr | None = None

    @field_validator("profile", "client_id", "client_secret", mode="before")
    @classmethod
    def _empty_string_is_unset(cls, value: Any) -> Any:
        """Treat an empty or whitespace-only string as an absent value.

        Args:
            value: The raw value from any source.

        Returns:
            None for empty strings, the value unchanged otherwise.
        """
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Order the sources as init -> keyring -> env (keyring outranks env).

        Args:
            settings_cls: The settings class being populated.
            init_settings: Source for explicit constructor arguments.
            env_settings: Source for environment variables.
            dotenv_settings: Unused (no dotenv support; dropped).
            file_secret_settings: Unused (no file secrets; dropped).

        Returns:
            The source tuple in certinext precedence order.
        """
        init_kwargs = init_settings.init_kwargs if isinstance(init_settings, InitSettingsSource) else {}
        return (init_settings, KeyringSettingsSource(settings_cls, init_kwargs), env_settings)
