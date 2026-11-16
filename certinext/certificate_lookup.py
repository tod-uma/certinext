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

"""Certificate inventory enrichment and exact lookup, independent of the CLI.

Orders are always read live. Only immutable certificate downloads use the
replacement-report cache; mutable order details are fetched for every match.
"""

from dataclasses import dataclass, field
from typing import Any, Literal

import httpx

from certinext._chain import split_pem_certificates
from certinext._inspection_cache import InspectionCache
from certinext.exceptions import CertiNextAPIError
from certinext.models.orders import OrderRecord
from certinext.models.ssl_certificates import CertificateDownload
from certinext.replacement import inspect_download
from certinext.session import CertiNextSession

LookupField = Literal["auto", "san", "cn", "order", "serial", "request", "requestor"]


def normalize_serial(value: str) -> str:
    """Normalize a hexadecimal serial, including colon separators and zero padding.

    No decimal interpretation is attempted. Invalid hex remains an exact string.
    """
    compact = value.strip().lower().replace(":", "")
    if compact.startswith("0x"):
        compact = compact[2:]
    if compact and all(c in "0123456789abcdef" for c in compact):
        return compact.lstrip("0") or "0"
    return value.strip().casefold()


def _name(value: str) -> str:
    """Normalize DNS spelling for literal matching, without wildcard expansion."""
    return value.strip().rstrip(".").casefold()


@dataclass
class CertificateEntry:
    """One live report record, optional certificate SANs, and per-row errors."""

    record: OrderRecord
    sans: list[str] | None = None
    from_cache: bool = False
    error: str | None = None
    details: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        """Return report data plus explicit SAN provenance and live detail payload."""
        return {
            **self.record.as_dict(),
            "sans": self.sans,
            "sans_source": "cache" if self.from_cache else "download" if self.sans is not None else None,
            "error": self.error,
            "details": self.details,
        }


def _parse(download: CertificateDownload, record: OrderRecord) -> list[str]:
    """Read every SAN type from the leaf, verifying it against the live serial.

    Raises ValueError for a missing leaf or a different issued certificate.
    """
    try:
        from cryptography import x509
    except ImportError as exc:
        raise ImportError("SAN inspection requires cryptography; install certinext[csr]") from exc

    blocks = split_pem_certificates(download.certificate_pem or "")
    if not blocks:
        raise ValueError("download contains no leaf certificate")
    leaf = x509.load_pem_x509_certificate(blocks[0].encode("ascii"))
    if record.certificate_serial_number and normalize_serial(record.certificate_serial_number) != format(
        leaf.serial_number, "x"
    ):
        raise ValueError("download serial differs from the live orders report")
    try:
        names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    except x509.DuplicateExtension as exc:
        raise ValueError("leaf has duplicate SAN extensions") from exc
    return [str(name.value) for name in names]


def enrich_sans(
    sess: CertiNextSession,
    entries: list[CertificateEntry],
    cache: InspectionCache | None = None,
) -> None:
    """Fill SANs sequentially, keeping every report row and recording failures.

    A cache hit is re-parsed and checked against the live report serial.
    No-serial rows are not cached. Rows without a certificate expiry or serial
    have unknown SANs (typically pending orders); no certificate is fabricated.
    Only downloads accepted by replacement-report's parser with a chain are
    written, keeping the shared cache contract intact (ADR 0022).
    """
    for entry in entries:
        record = entry.record
        if not record.certificate_serial_number and not record.certificate_expiry_date:
            continue
        if not record.order_number:
            entry.error = "orders report omitted the order number"
            continue
        if cache is not None and record.certificate_serial_number:
            hit = cache.get(record.order_number, record.certificate_serial_number)
            if hit is not None:
                try:
                    download = CertificateDownload.model_validate(hit.download)
                    sans = _parse(download, record)
                    if inspect_download(download).chain_cas:
                        entry.sans, entry.from_cache = sans, True
                        continue
                except ValueError:
                    pass  # An invalid cache entry is a miss; try live.
        try:
            order = sess.ssl.get(record.order_number)
            download = order.download_certificate()
            entry.sans = _parse(download, record)
            if cache is not None and record.certificate_serial_number:
                inspection = inspect_download(download)
                if inspection.chain_cas:
                    detail = order.as_dict()
                    who = detail.get("orderedBy") or detail.get("requestor") or {}
                    cache.put(
                        record.order_number,
                        record.certificate_serial_number,
                        download.as_dict(),
                        who if isinstance(who, dict) else {},
                    )
        except (CertiNextAPIError, httpx.HTTPError, ValueError) as exc:
            entry.error = f"SAN inspection failed ({type(exc).__name__})"


def _matches(entry: CertificateEntry, query: str, field: LookupField) -> bool:
    """Match one identifier literally; auto checks every supported identifier."""
    r = entry.record
    matches = {
        "cn": bool(r.common_name and _name(r.common_name) == _name(query)),
        "san": any(_name(s) == _name(query) for s in entry.sans or []),
        "order": bool(r.order_number and r.order_number.casefold() == query.casefold()),
        "serial": bool(
            r.certificate_serial_number and normalize_serial(r.certificate_serial_number) == normalize_serial(query)
        ),
        "request": bool(r.request_number and r.request_number.casefold() == query.casefold()),
    }
    return any(matches.values()) if field == "auto" else matches[field]


def _requestor_match(details: dict[str, Any], query: str) -> bool | None:
    """Match a requestor's full name or email; None means unavailable fields.

    The requestor.name/email shape is captured in both prod and sandbox corpus
    fixtures. orderedBy is deliberately not substituted: an order's submitter
    is not necessarily its requestor. No substring or wildcard matching is used.
    """
    who = details.get("requestor")
    if not isinstance(who, dict):
        return None
    values = [who.get(key) for key in ("name", "email")]
    known = [v.strip().casefold() for v in values if isinstance(v, str) and v.strip()]
    return query.casefold() in known if known else None


def _read_details(sess: CertiNextSession, entry: CertificateEntry) -> None:
    """Read current order details once, recording errors without dropping rows."""
    if entry.details is not None:
        return
    try:
        if not entry.record.order_number:
            raise ValueError("orders report omitted the order number")
        entry.details = sess.ssl.get(entry.record.order_number).as_dict()
    except (CertiNextAPIError, httpx.HTTPError, ValueError) as exc:
        entry.error = f"detail lookup failed ({type(exc).__name__})"


@dataclass
class LookupResult:
    """All matching orders and inspection failures that limit search completeness."""

    matches: list[CertificateEntry] = field(default_factory=list)
    errors: list[CertificateEntry] = field(default_factory=list)
    unknown_sans: int = 0
    unknown_requestors: int = 0
    cache_hits: int = 0
    cache_misses: int = 0


def lookup_certificates(
    sess: CertiNextSession,
    query: str,
    *,
    field: LookupField = "auto",
    cache: InspectionCache | None = None,
) -> LookupResult:
    """Find all literal matches in the live report, then fetch their current details.

    SAN and auto searches inspect every issued certificate, including expired
    ones; other fields need only the report. Contact field shapes are passed
    through as returned by the detail endpoint, never inferred from request
    schemas. Missing delegation data does not establish that no delegate exists.
    Explicit requestor search reads each row's current detail response once,
    matching a full name or email. It never downloads certificates and is not
    included in auto. Missing requestor fields limit completeness.
    """
    query = query.strip()
    if not query:
        raise ValueError("a non-empty certificate identifier is required")
    if field not in ("auto", "san", "cn", "order", "serial", "request", "requestor"):
        raise ValueError(f"unsupported lookup field: {field}")
    entries = [CertificateEntry(r) for r in sess.orders.get_list()]
    if field in ("auto", "san"):
        enrich_sans(sess, entries, cache)
    result = LookupResult(
        errors=[e for e in entries if e.error],
        cache_hits=sum(e.from_cache for e in entries),
        cache_misses=sum(not e.from_cache and bool(e.sans is not None or e.error) for e in entries),
        unknown_sans=sum(e.sans is None for e in entries) if field in ("auto", "san") else 0,
    )
    for entry in entries:
        if field == "requestor":
            _read_details(sess, entry)
            match = _requestor_match(entry.details, query) if entry.details is not None else None
            if match is None:
                result.unknown_requestors += 1
            if entry.error:
                result.errors.append(entry)
            if match is not True:
                continue
        elif not _matches(entry, query, field):
            continue
        result.matches.append(entry)
        _read_details(sess, entry)
        if entry.error and entry not in result.errors:
            result.errors.append(entry)
    return result
