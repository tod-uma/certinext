from datetime import datetime
from typing import Any
from .client import CertiNextClient

_BASE = "/api/certinext/v2/domains"


class Domain:
    def __init__(self, client: CertiNextClient, data: dict[str, Any]) -> None:
        self._client = client
        self._data: dict[str, Any] = data

    # --- properties ---

    @property
    def id(self) -> str | None:
        return self._data.get("domainId")

    @property
    def name(self) -> str | None:
        return self._data.get("domainName")

    @name.setter
    def name(self, value: str) -> None:
        self._data["domainName"] = value

    @property
    def organization_id(self) -> str | None:
        return self._data.get("organizationId")

    @property
    def organization_name(self) -> str | None:
        return self._data.get("organizationName")

    @property
    def status(self) -> str | None:
        return self._data.get("status")

    @property
    def dcv_status(self) -> str | None:
        return self._data.get("dcvStatus")

    @property
    def created_at(self) -> datetime | None:
        raw = self._data.get("createdAt")
        if not raw:
            return None
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))

    # --- dunder methods ---

    def __str__(self) -> str:
        def row(label: str, value: Any) -> str:
            return f"  {label:<16} {value or ''}"
        lines = [f"Domain: {self.name or '(unknown)'}"]
        lines.append(row("id:", self.id))
        lines.append(row("status:", self.status))
        lines.append(row("dcv_status:", self.dcv_status))
        lines.append(row("organization:", self.organization_name))
        if self.created_at:
            lines.append(row("created:", self.created_at))
        return "\n".join(lines)

    def __repr__(self) -> str:
        return f"Domain(id={self.id!r}, name={self.name!r}, status={self.status!r}, dcv_status={self.dcv_status!r})"

    # --- public helpers ---

    def as_dict(self) -> dict[str, Any]:
        return self._data

    def to_row(self) -> dict[str, str]:
        return {
            "name": self.name or "",
            "status": self.status or "",
            "dcv_status": self.dcv_status or "",
            "organization": self.organization_name or "",
            "created_at": self.created_at.isoformat() if self.created_at else "",
            "id": self.id or "",
        }

    # --- API methods ---

    def refresh(self) -> "Domain":
        result = self._client.get(f"{_BASE}/{self.id}")
        if isinstance(result, dict):
            self._data = result
        return self

    def deactivate(self) -> "Domain":
        self._data = self._client.post(f"{_BASE}/{self.id}/deactivate")
        return self

    def get_dcv(self) -> dict[str, Any]:
        result = self._client.get(f"{_BASE}/{self.id}/dcv")
        return result if isinstance(result, dict) else {}

    def verify(self) -> dict[str, Any]:
        return self._client.post(f"{_BASE}/{self.id}/dcv/verify")

    def change_dcv_method(self, method: str) -> dict[str, Any]:
        return self._client.post(
            f"{_BASE}/{self.id}/dcv/change-method", json={"method": method}
        )

    def last_dcv_attempt(self) -> dict[str, Any]:
        result = self._client.get(f"{_BASE}/{self.id}/dcv/last-attempt")
        return result if isinstance(result, dict) else {}

    def dcv_attempt_history(self) -> dict[str, Any] | list[Any]:
        return self._client.get(f"{_BASE}/{self.id}/dcv/attempt-history")


class DomainAccessor:
    def __init__(self, client: CertiNextClient) -> None:
        self._client = client

    def list(self, offset: int | None = None, limit: int | None = None) -> list[Domain]:
        params: dict[str, Any] = {}
        if offset is not None:
            params["offset"] = offset
        if limit is not None:
            params["limit"] = limit
        result = self._client.get(_BASE, params=params or None)
        raw: list[Any]
        if isinstance(result, list):
            raw = result
        else:
            raw = []
            for val in result.values():
                if isinstance(val, list):
                    raw = val  # type: ignore[assignment]
                    break
        return [Domain(self._client, item) for item in raw]

    def get(self, domain_id_or_name: str) -> Domain:
        """Get a domain by ID or by name (e.g. 'maine.edu')."""
        if "." in domain_id_or_name:
            name = domain_id_or_name.lower()
            for domain in self.list():
                if (domain.name or "").lower() == name:
                    return domain
            raise KeyError(f"No domain found with name {domain_id_or_name!r}")
        result = self._client.get(f"{_BASE}/{domain_id_or_name}")
        if not isinstance(result, dict):
            raise ValueError(f"Unexpected list response for domain {domain_id_or_name!r}")
        return Domain(self._client, result)

    def create(self, name: str, **fields: Any) -> Domain:
        return Domain(self._client, self._client.post(_BASE, json={"name": name, **fields}))
