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

"""Pydantic model for the v3 CLM API-credentials list (``/api/v3/certinext/apis``)."""

from typing import Any

from pydantic import Field

from ._base import CertiNextModel, _V3DisplayDatetimeUTC


class ApiCredential(CertiNextModel):
    """One API credential (metadata only; the list never returns a secret).

    Instances are returned by
    :class:`~certinext.api_credentials.ApiCredentialAccessor`.
    """

    credential_id: str | None = Field(default=None, alias="credentialId", description="Opaque credential id.")
    description: str | None = Field(
        default=None, alias="description", description="The label the credential was created with."
    )
    api_type: str | None = Field(default=None, alias="apiType", description="API type, e.g. REST or ACME.")
    ca_connector: str | None = Field(default=None, alias="caConnector", description="CA connector, when bound.")
    group: str | None = Field(default=None, alias="group", description="Group the credential is scoped to.")
    products: str | None = Field(default=None, alias="products", description="Products it may order, when limited.")
    status: str | None = Field(default=None, alias="status", description='e.g. ``"Active"``.')
    user: str | None = Field(default=None, alias="user", description="User the credential acts as.")
    created_date: _V3DisplayDatetimeUTC = Field(
        default=None, alias="createdDate", description="When it was created (UTC)."
    )
    tags: list[Any] = Field(default_factory=list, alias="tags", description="Tags; empty on every captured row.")

    def __repr__(self) -> str:
        """Return a concise developer representation."""
        return (
            f"ApiCredential(credential_id={self.credential_id!r}, "
            f"api_type={self.api_type!r}, status={self.status!r})"
        )
