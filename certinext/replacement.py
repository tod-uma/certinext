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

"""Find currently valid certificates that need replacing after a CA distrust.

When a root or intermediate CA loses browser trust, every certificate still
chaining to it has to be reissued. This module inventories the account's
valid certificates from the orders report and classifies each one against
:class:`ReplacementCriteria`, which names three independent signals:

- **issuer** — the issuing intermediate's common name. Free: every orders
  report row carries it (``issuerCA``).
- **key** — the leaf's public-key algorithm (``EC``, ``RSA``, ...). The API
  exposes no key-type field, so this needs the certificate downloaded and
  parsed (``inspect=True``).
- **chain** — a CA common name anywhere in the chain the API serves. Also
  needs ``inspect=True``. This is the most direct "does it chain to the
  distrusted root?" test, and keeps working if the CA re-roots an
  intermediate.

A certificate needs replacing when every evaluated signal matches. When the
evaluated signals disagree the verdict is :attr:`Verdict.CONFLICT` rather than
a silent pick, listed and counted separately for review. That disagreement
is what a CA re-rooting its issuance looks like, and also what an EC key
issued under an RSA-rooted intermediate looks like (key type matches, chain
is trusted) — such certificates exist, so key type alone is not trusted.

The defaults describe the October 2026 eMudhra ECC distrust (Mozilla bug
2083449: ``emSign ECC Root CA - G3`` removed from NSS, which untrusts ECDSA
certificates from ``InCommon Intermediate CA - OVG3C``). Override them in the
``[replacement]`` table of ``config.toml`` or per call when the situation
changes.

Example::

    from certinext.replacement import ReplacementCriteria, build_report

    report = build_report(sess, ReplacementCriteria(), inspect=True)
    for row in report.select():
        print(row.facts.common_name, row.verdict.value)
"""

import datetime as dt
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any, Callable, Literal, get_args

import httpx
import structlog
from pydantic import BaseModel, ConfigDict, Field, field_validator

from certinext._chain import split_pem_certificates
from certinext.exceptions import CertiNextAPIError, CertiNextRateLimitError

if TYPE_CHECKING:  # pragma: no cover - typing only
    from cryptography.x509 import Certificate, Name

    from certinext.models.orders import OrderRecord
    from certinext.models.ssl_certificates import CertificateDownload, SslOrder
    from certinext.session import CertiNextSession

log = structlog.get_logger(__name__)

Signal = Literal["issuer", "key", "chain"]
"""Names of the replacement signals, in evaluation order."""

SIGNALS: tuple[Signal, ...] = ("issuer", "key", "chain")

KeyType = Literal["EC", "RSA", "Ed25519", "Ed448", "DSA"]
"""Public-key algorithm families the ``key`` signal can match."""

_KEY_TYPES_BY_FOLDED: dict[str, KeyType] = {k.casefold(): k for k in get_args(KeyType)}

#: Defaults for the October 2026 eMudhra ECC distrust (Mozilla bug 2083449).
DEFAULT_ISSUERS: tuple[str, ...] = ("InCommon Intermediate CA - OVG3C",)
DEFAULT_KEY_TYPES: tuple[KeyType, ...] = ("EC",)
DEFAULT_CHAIN_CAS: tuple[str, ...] = ("emSign ECC Root CA - G3",)

# Wait used when a 429 carries no Retry-After header.
_DEFAULT_RETRY_AFTER = 5.0

# Friendly names for the curves CertiNext issues on; anything else shows the
# curve's own name.
_CURVE_LABELS = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}


def _utcnow() -> dt.datetime:
    """Return the current time as a timezone-aware UTC datetime.

    A module-level seam so tests can pin "now".

    Returns:
        ``datetime.now(timezone.utc)``.
    """
    return dt.datetime.now(dt.timezone.utc)


class ReplacementCriteria(BaseModel):
    """Which certificates count as needing replacement.

    Each list feeds one signal; an empty list, or naming the signal in
    :attr:`disabled`, turns that signal off. Matching is case-insensitive and
    exact on common names.

    Built from (lowest precedence first) the module defaults, the
    ``[replacement]`` table of ``config.toml`` (:meth:`from_config`), and
    per-run overrides (:meth:`with_overrides`). A higher layer *replaces* a
    signal's list rather than merging into it, so ``--issuer X`` means
    exactly ``X``.

    Example::

        criteria = ReplacementCriteria().with_overrides(disable=["key"])
    """

    model_config = ConfigDict(extra="forbid")

    issuers: list[str] = Field(
        default_factory=lambda: list(DEFAULT_ISSUERS),
        description="Issuing-intermediate common names that need replacing.",
    )
    key_types: list[KeyType] = Field(
        default_factory=lambda: list(DEFAULT_KEY_TYPES),
        description="Leaf public-key algorithms that need replacing.",
    )
    chain_cas: list[str] = Field(
        default_factory=lambda: list(DEFAULT_CHAIN_CAS),
        description="CA common names that must not appear in the served chain.",
    )
    disabled: list[Signal] = Field(
        default_factory=list,
        description="Signals switched off regardless of their lists.",
    )

    @field_validator("key_types", mode="before")
    @classmethod
    def _canonical_key_types(cls, value: Any) -> Any:
        """Accept key-type names in any case (``ec`` -> ``EC``).

        Args:
            value: The raw ``key_types`` value.

        Returns:
            The list with recognized names in canonical case; unrecognized
            entries pass through for the ``Literal`` check to reject.
        """
        if not isinstance(value, list):
            return value
        return [
            _KEY_TYPES_BY_FOLDED.get(item.casefold(), item) if isinstance(item, str) else item
            for item in value
        ]

    @classmethod
    def from_config(cls, doc: dict[str, Any]) -> "ReplacementCriteria":
        """Build criteria from a parsed ``config.toml`` document.

        Keys absent from the ``[replacement]`` table keep their defaults.

        Args:
            doc: The parsed TOML document (see
                :func:`certinext._config.load_config`).

        Returns:
            The configured criteria, or the defaults when the table is absent.

        Raises:
            ValueError: If ``replacement`` is not a table.
            pydantic.ValidationError: If a key is unknown or a value invalid.
        """
        section = doc.get("replacement")
        if section is None:
            return cls()
        if not isinstance(section, dict):
            raise ValueError("[replacement] must be a table")
        return cls.model_validate(section)

    def with_overrides(
        self,
        *,
        issuers: list[str] | None = None,
        key_types: list[str] | None = None,
        chain_cas: list[str] | None = None,
        disable: list[str] | None = None,
    ) -> "ReplacementCriteria":
        """Return a copy with per-run overrides applied.

        Args:
            issuers: Replaces :attr:`issuers` when not ``None``.
            key_types: Replaces :attr:`key_types` when not ``None``.
            chain_cas: Replaces :attr:`chain_cas` when not ``None``.
            disable: Signals to add to :attr:`disabled`.

        Returns:
            A new, validated :class:`ReplacementCriteria`.

        Raises:
            pydantic.ValidationError: If an override value is invalid.
        """
        data = self.model_dump()
        if issuers is not None:
            data["issuers"] = issuers
        if key_types is not None:
            data["key_types"] = key_types
        if chain_cas is not None:
            data["chain_cas"] = chain_cas
        if disable:
            data["disabled"] = sorted(set(data["disabled"]) | set(disable), key=SIGNALS.index)
        return type(self).model_validate(data)

    def active_signals(self) -> list[Signal]:
        """Return the signals that will be evaluated, in evaluation order.

        Returns:
            Signals that are not disabled and have a non-empty list.
        """
        lists: dict[Signal, list[Any]] = {
            "issuer": self.issuers, "key": list(self.key_types), "chain": self.chain_cas,
        }
        return [s for s in SIGNALS if s not in self.disabled and lists[s]]


class Verdict(str, Enum):
    """Outcome of classifying one certificate against the criteria."""

    REPLACE = "replace"
    """Every evaluated signal matched."""
    CONFLICT = "conflict"
    """Some evaluated signals matched and others did not."""
    OK = "ok"
    """No evaluated signal matched."""
    UNKNOWN = "unknown"
    """No signal could be evaluated (e.g. no issuer recorded, not inspected)."""

    @property
    def needs_replacing(self) -> bool:
        """Whether this verdict counts toward "needs replacing".

        Only :attr:`REPLACE` does. A conflict is counted separately ("to
        review") rather than folded in: in practice certificates exist whose
        key type matches but whose chain is trusted (an EC key issued under
        an RSA-rooted intermediate), and counting those would overstate the
        work. Conflicts are still listed by default, never hidden.
        """
        return self is Verdict.REPLACE


@dataclass
class Inspection:
    """What parsing a downloaded certificate and its chain revealed.

    Attributes:
        key_type: Public-key family, one of :data:`KeyType`, or the key
            class name for anything unrecognized.
        key_size: Key size in bits, or ``None`` for fixed-size keys (Ed25519).
        key_label: Human label, e.g. ``EC P-384`` or ``RSA 2048``.
        sans: DNS subject alternative names on the leaf.
        leaf_issuer: Common name of the leaf's issuer.
        chain_cas: Common names of every certificate in the served chain.
    """

    key_type: str
    key_size: int | None
    key_label: str
    sans: list[str]
    leaf_issuer: str | None
    chain_cas: list[str]


@dataclass
class CertificateFacts:
    """Everything known about one valid certificate.

    Report fields are always present; inspection fields are filled only when
    the certificate was downloaded and parsed.

    Attributes:
        order_number: CertiNext order number.
        common_name: Primary domain from the orders report.
        issuer: Issuing intermediate CN from the orders report (``issuerCA``).
        valid_to: Certificate expiry (UTC).
        order_date: Order creation time (UTC), if reported.
        originator: Channel that placed the order (``ACME``, ``CERTInext``,
            ``CERTInext API``).
        group_number: Account sub-group number.
        group_name: Account sub-group name, when it could be resolved.
        product_code: CertiNext product code.
        serial_number: Certificate serial number.
        inspection: Parsed certificate details, or ``None`` if not inspected.
        ordered_by_name: Who placed the order (order detail), if inspected.
        ordered_by_email: Their email address, if inspected.
        error: Why inspection failed, if it did.
    """

    order_number: str
    common_name: str | None
    issuer: str | None
    valid_to: dt.datetime
    order_date: dt.datetime | None = None
    originator: str | None = None
    group_number: str | None = None
    group_name: str | None = None
    product_code: str | None = None
    serial_number: str | None = None
    inspection: Inspection | None = None
    ordered_by_name: str | None = None
    ordered_by_email: str | None = None
    error: str | None = None

    def names(self) -> frozenset[str]:
        """Return the lower-cased name set used to detect superseded copies.

        Returns:
            The leaf's SANs when inspected, else the common name alone (empty
            if there is none).
        """
        if self.inspection and self.inspection.sans:
            return frozenset(n.lower() for n in self.inspection.sans)
        return frozenset({self.common_name.lower()}) if self.common_name else frozenset()


@dataclass
class Classification:
    """A verdict plus the signal detail that produced it.

    Attributes:
        verdict: The overall :class:`Verdict`.
        matched: Evaluated signals that matched.
        evaluated: Every signal that could be evaluated.
        unevaluated: Active signals that could not be evaluated (typically
            ``key``/``chain`` without inspection).
    """

    verdict: Verdict
    matched: list[Signal]
    evaluated: list[Signal]
    unevaluated: list[Signal]


@dataclass
class ReportRow:
    """One certificate's facts, classification, and superseded flag.

    Attributes:
        facts: The certificate's :class:`CertificateFacts`.
        classification: How it scored against the criteria.
        superseded: Whether a newer valid certificate covers all its names.
    """

    facts: CertificateFacts
    classification: Classification
    superseded: bool = False

    @property
    def verdict(self) -> Verdict:
        """Shortcut for ``classification.verdict``."""
        return self.classification.verdict

    def days_left(self, now: dt.datetime) -> int:
        """Return whole days until expiry.

        Args:
            now: The reference time (UTC-aware).

        Returns:
            ``(valid_to - now).days``.
        """
        return (self.facts.valid_to - now).days

    def to_dict(self, now: dt.datetime) -> dict[str, Any]:
        """Return a JSON-ready dict of every field.

        Args:
            now: Reference time for ``days_left``.

        Returns:
            A flat dict; lists stay lists, datetimes become ISO strings.
        """
        f, i = self.facts, self.facts.inspection
        return {
            "verdict": self.verdict.value,
            "needs_replacing": self.verdict.needs_replacing,
            "matched_signals": list(self.classification.matched),
            "unevaluated_signals": list(self.classification.unevaluated),
            "common_name": f.common_name,
            "sans": list(i.sans) if i else None,
            "key_type": i.key_type if i else None,
            "key_size": i.key_size if i else None,
            "issuer": f.issuer,
            "leaf_issuer": i.leaf_issuer if i else None,
            "chain_cas": list(i.chain_cas) if i else None,
            "valid_to": f.valid_to.isoformat(),
            "days_left": self.days_left(now),
            "order_number": f.order_number,
            "order_date": f.order_date.isoformat() if f.order_date else None,
            "originator": f.originator,
            "group_number": f.group_number,
            "group_name": f.group_name,
            "product_code": f.product_code,
            "serial_number": f.serial_number,
            "superseded": self.superseded,
            "ordered_by_name": f.ordered_by_name,
            "ordered_by_email": f.ordered_by_email,
            "error": f.error,
        }


GroupBy = Literal["originator", "group", "issuer"]
"""Dimensions :meth:`ReplacementReport.breakdown` can group by."""


@dataclass
class ReplacementReport:
    """The classified inventory, with selection and summary helpers.

    Attributes:
        criteria: The criteria the rows were classified with.
        rows: Every valid certificate, soonest expiry first.
        inspected: Whether certificates were downloaded and parsed.
        generated_at: The reference "now" used for validity and days left.
    """

    criteria: ReplacementCriteria
    rows: list[ReportRow]
    inspected: bool
    generated_at: dt.datetime

    def population(
        self, *, latest_only: bool = False, expiring_within: int | None = None
    ) -> list[ReportRow]:
        """Return the rows a summary should count.

        Args:
            latest_only: Drop superseded rows.
            expiring_within: Keep only rows expiring within this many days.

        Returns:
            Matching rows, soonest expiry first.
        """
        rows = self.rows
        if latest_only:
            rows = [r for r in rows if not r.superseded]
        if expiring_within is not None:
            rows = [r for r in rows if r.days_left(self.generated_at) < expiring_within]
        return rows

    def select(
        self,
        *,
        include_ok: bool = False,
        latest_only: bool = False,
        expiring_within: int | None = None,
    ) -> list[ReportRow]:
        """Return the rows to display.

        Args:
            include_ok: Also return rows that do not need replacing (to
                measure migration progress).
            latest_only: Drop superseded rows.
            expiring_within: Keep only rows expiring within this many days.

        Returns:
            Matching rows, soonest expiry first.
        """
        rows = self.population(latest_only=latest_only, expiring_within=expiring_within)
        if include_ok:
            return rows
        return [r for r in rows if r.verdict is not Verdict.OK]

    @staticmethod
    def summarize(rows: list[ReportRow]) -> dict[str, int]:
        """Count verdicts, superseded copies, and inspection errors.

        Args:
            rows: The population to count (usually :meth:`population`).

        Returns:
            Counts keyed ``valid``, ``needs_replacing``, one key per
            :class:`Verdict` value, ``superseded``, and ``errors``.
        """
        verdicts = Counter(r.verdict for r in rows)
        summary = {
            "valid": len(rows),
            "needs_replacing": sum(n for v, n in verdicts.items() if v.needs_replacing),
        }
        summary.update({v.value: verdicts.get(v, 0) for v in Verdict})
        summary["superseded"] = sum(1 for r in rows if r.superseded)
        summary["errors"] = sum(1 for r in rows if r.facts.error)
        return summary

    @staticmethod
    def breakdown(rows: list[ReportRow], by: GroupBy) -> list[dict[str, Any]]:
        """Count verdicts per originator, group, or issuer.

        Useful for spotting which groups hold automated (ACME) issuance
        without hardcoding any account's group numbers.

        Args:
            rows: The population to count.
            by: The dimension to group on.

        Returns:
            One dict per distinct value, largest first, with the key, the
            ``valid``/``needs_replacing`` counts, and per-verdict counts.
        """
        def key(row: ReportRow) -> str:
            f = row.facts
            if by == "originator":
                return f.originator or ""
            if by == "group":
                return f.group_name or f.group_number or ""
            return f.issuer or ""

        buckets: dict[str, list[ReportRow]] = defaultdict(list)
        for row in rows:
            buckets[key(row)].append(row)
        out: list[dict[str, Any]] = [
            {by: k, **ReplacementReport.summarize(v)} for k, v in buckets.items()
        ]
        out.sort(key=lambda d: (-d["valid"], d[by]))
        for item in out:
            del item["superseded"], item["errors"]
        return out


def _common_name(name: "Name") -> str | None:
    """Return the first common name in an X.509 name, if any.

    Args:
        name: A :class:`cryptography.x509.Name`.

    Returns:
        The CN string, or ``None``.
    """
    from cryptography.x509.oid import NameOID

    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(attrs[0].value) if attrs else None


def _load_pem(pem: str) -> "Certificate":
    """Parse one PEM certificate block.

    Args:
        pem: A single PEM certificate.

    Returns:
        The parsed certificate.

    Raises:
        ValueError: If the block cannot be parsed.
    """
    from cryptography import x509

    return x509.load_pem_x509_certificate(pem.encode("ascii"))


def describe_key(cert: "Certificate") -> tuple[str, int | None, str]:
    """Classify a certificate's public key.

    Args:
        cert: The parsed certificate.

    Returns:
        ``(key_type, key_size, key_label)``, e.g. ``("EC", 384, "EC P-384")``.
    """
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

    key = cert.public_key()
    if isinstance(key, ec.EllipticCurvePublicKey):
        curve = key.curve
        return "EC", curve.key_size, f"EC {_CURVE_LABELS.get(curve.name, curve.name)}"
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA", key.key_size, f"RSA {key.key_size}"
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519", None, "Ed25519"
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448", None, "Ed448"
    if isinstance(key, dsa.DSAPublicKey):
        return "DSA", key.key_size, f"DSA {key.key_size}"
    name = type(key).__name__
    return name, None, name


def inspect_download(download: "CertificateDownload") -> Inspection:
    """Parse a downloaded certificate and its chain.

    Args:
        download: The JSON download for an issued order.

    Returns:
        The leaf's key, SANs, and issuer, plus every chain CA's common name.

    Raises:
        ImportError: If the ``cryptography`` package is not installed
            (``pip install certinext[csr]``).
        ValueError: If the download holds no parseable leaf certificate.
    """
    try:
        from cryptography import x509
    except ImportError as exc:
        raise ImportError(
            "The 'cryptography' package is required to inspect certificates. "
            "Install it with: pip install certinext[csr] "
            "(or drop --inspect to classify on issuer alone)."
        ) from exc

    leaf_blocks = split_pem_certificates(download.certificate_pem or "")
    if not leaf_blocks:
        raise ValueError("download contains no leaf certificate")
    leaf = _load_pem(leaf_blocks[0])
    key_type, key_size, key_label = describe_key(leaf)

    try:
        sans = leaf.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []

    chain_cas: list[str] = []
    for item in download.chain_pem:
        for block in split_pem_certificates(item):
            cn = _common_name(_load_pem(block).subject)
            if cn and cn not in chain_cas:
                chain_cas.append(cn)

    return Inspection(
        key_type=key_type, key_size=key_size, key_label=key_label, sans=list(sans),
        leaf_issuer=_common_name(leaf.issuer), chain_cas=chain_cas,
    )


def classify(facts: CertificateFacts, criteria: ReplacementCriteria) -> Classification:
    """Score one certificate against the criteria.

    The issuer signal uses the leaf's own issuer when inspected, else the
    orders report's ``issuerCA``. Key and chain signals need inspection.

    Args:
        facts: What is known about the certificate.
        criteria: The replacement criteria.

    Returns:
        The verdict with the signals that matched, were evaluated, and could
        not be evaluated.
    """
    results: dict[Signal, bool] = {}
    active = criteria.active_signals()
    insp = facts.inspection

    if "issuer" in active:
        issuer = (insp.leaf_issuer if insp and insp.leaf_issuer else facts.issuer) or ""
        if issuer:
            results["issuer"] = issuer.casefold() in {i.casefold() for i in criteria.issuers}
    if "key" in active and insp:
        results["key"] = insp.key_type in criteria.key_types
    if "chain" in active and insp:
        wanted = {c.casefold() for c in criteria.chain_cas}
        results["chain"] = any(ca.casefold() in wanted for ca in insp.chain_cas)

    evaluated: list[Signal] = [s for s in SIGNALS if s in results]
    matched: list[Signal] = [s for s in evaluated if results.get(s)]
    unevaluated: list[Signal] = [s for s in active if s not in results]
    if not evaluated:
        verdict = Verdict.UNKNOWN
    elif not matched:
        verdict = Verdict.OK
    elif len(matched) < len(evaluated):
        verdict = Verdict.CONFLICT
    else:
        verdict = Verdict.REPLACE
    return Classification(verdict=verdict, matched=matched, evaluated=evaluated, unevaluated=unevaluated)


def mark_superseded(rows: list[ReportRow]) -> None:
    """Flag rows whose names are all covered by a newer valid certificate.

    "Newer" compares ``(order_date, valid_to)``. A row with no names is never
    superseded. Flags are set in place.

    Args:
        rows: The report rows to flag.
    """
    def recency(row: ReportRow) -> tuple[dt.datetime, dt.datetime]:
        f = row.facts
        return (f.order_date or dt.datetime.min.replace(tzinfo=dt.timezone.utc), f.valid_to)

    by_name: dict[str, list[ReportRow]] = defaultdict(list)
    for row in rows:
        for name in row.facts.names():
            by_name[name].append(row)

    for row in rows:
        names = row.facts.names()
        if not names:
            continue
        mine = recency(row)
        first = next(iter(names))
        row.superseded = any(
            other is not row and recency(other) > mine and names <= other.facts.names()
            for other in by_name[first]
        )


def _facts_from_record(record: "OrderRecord", group_names: dict[str, str]) -> CertificateFacts:
    """Build report-level facts from one orders report row.

    Args:
        record: A row whose ``order_number`` and expiry are set.
        group_names: Group number to group name.

    Returns:
        Facts with no inspection data.
    """
    assert record.order_number and record.certificate_expiry_date  # filtered by caller
    return CertificateFacts(
        order_number=record.order_number,
        common_name=record.common_name,
        issuer=record.issuer_ca or None,
        valid_to=record.certificate_expiry_date,
        order_date=record.order_date,
        originator=record.originator,
        group_number=record.group_number,
        group_name=group_names.get(record.group_number or ""),
        product_code=record.product_code,
        serial_number=record.certificate_serial_number,
    )


def _inspect_into(
    sess: "CertiNextSession", facts: CertificateFacts, sleep: Callable[[float], None]
) -> None:
    """Download, parse, and record one certificate's details on ``facts``.

    Retries once after a 429. Any API, transport, or parse failure is
    recorded on :attr:`CertificateFacts.error` rather than raised, so one bad
    order never aborts a full inventory.

    Args:
        sess: An authenticated session.
        facts: The facts to fill in (mutated).
        sleep: Called with the Retry-After delay before the retry.

    Raises:
        ImportError: If ``cryptography`` is missing (fatal for every row).
    """
    order: "SslOrder | None" = None
    download: "CertificateDownload | None" = None
    for attempt in (1, 2):
        try:
            order = sess.ssl.get(facts.order_number)
            download = order.download_certificate()
            break
        except CertiNextRateLimitError as exc:
            if attempt == 2:
                facts.error = f"rate limited: {exc}"
                return
            delay = exc.retry_after or _DEFAULT_RETRY_AFTER
            log.warning("Rate limited; retrying", order=facts.order_number, wait_seconds=delay)
            sleep(delay)
        except (CertiNextAPIError, httpx.HTTPError) as exc:
            facts.error = str(exc) or type(exc).__name__
            return
    if order is None or download is None:  # pragma: no cover - the loop breaks or returns
        return

    detail = order.as_dict()
    who = detail.get("orderedBy") or detail.get("requestor") or {}
    if isinstance(who, dict):
        facts.ordered_by_name = who.get("name") or None
        facts.ordered_by_email = who.get("email") or None
    try:
        facts.inspection = inspect_download(download)
    except ValueError as exc:
        facts.error = f"unparseable certificate: {exc}"


def build_report(
    sess: "CertiNextSession",
    criteria: ReplacementCriteria,
    *,
    inspect: bool = False,
    originators: list[str] | None = None,
    groups: list[str] | None = None,
    now: dt.datetime | None = None,
    on_progress: Callable[[CertificateFacts], None] | None = None,
    on_total: Callable[[int], None] | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> ReplacementReport:
    """Inventory valid certificates and classify each against the criteria.

    Read-only: issues only GET requests. "Valid" means the orders report
    lists it under ``status=issued`` (which excludes revoked, expired, and
    cancelled orders) and its expiry is still in the future.

    Args:
        sess: An authenticated session.
        criteria: The replacement criteria.
        inspect: Download and parse every certificate, enabling the key and
            chain signals plus SANs and who ordered it (one order-detail and
            one download request per certificate).
        originators: Keep only these originators (case-insensitive).
        groups: Keep only these groups, by number or name (case-insensitive).
        now: Reference time; defaults to the current UTC time.
        on_progress: Called after each certificate is inspected.
        on_total: Called once with the number of certificates to inspect.
        sleep: Delay function used for rate-limit backoff.

    Returns:
        The classified :class:`ReplacementReport`.

    Raises:
        ImportError: If ``inspect`` is set and ``cryptography`` is missing.
        CertiNextAPIError: If the orders report itself cannot be read.
    """
    now = now or _utcnow()
    try:
        group_names = {
            g.group_number: g.group_name for g in sess.accounts.list_groups()
            if g.group_number and g.group_name
        }
    except (CertiNextAPIError, httpx.HTTPError) as exc:
        log.warning("Could not resolve group names; showing numbers", error=str(exc))
        group_names = {}

    records = sess.orders.get_list(status="issued")
    facts = [
        _facts_from_record(r, group_names)
        for r in records
        if r.order_number and r.certificate_expiry_date and r.certificate_expiry_date > now
    ]
    if originators:
        wanted = {o.casefold() for o in originators}
        facts = [f for f in facts if (f.originator or "").casefold() in wanted]
    if groups:
        wanted = {g.casefold() for g in groups}
        facts = [
            f for f in facts
            if (f.group_number or "").casefold() in wanted or (f.group_name or "").casefold() in wanted
        ]
    log.info("Valid certificates found", count=len(facts), issued_rows=len(records))

    if inspect:
        if on_total:
            on_total(len(facts))
        for f in facts:
            _inspect_into(sess, f, sleep)
            if on_progress:
                on_progress(f)

    rows = [ReportRow(facts=f, classification=classify(f, criteria)) for f in facts]
    mark_superseded(rows)
    rows.sort(key=lambda r: (r.facts.valid_to, r.facts.order_number))
    return ReplacementReport(criteria=criteria, rows=rows, inspected=inspect, generated_at=now)


__all__ = [
    "DEFAULT_CHAIN_CAS",
    "DEFAULT_ISSUERS",
    "DEFAULT_KEY_TYPES",
    "SIGNALS",
    "CertificateFacts",
    "Classification",
    "GroupBy",
    "Inspection",
    "KeyType",
    "ReplacementCriteria",
    "ReplacementReport",
    "ReportRow",
    "Signal",
    "Verdict",
    "build_report",
    "classify",
    "describe_key",
    "inspect_download",
    "mark_superseded",
]
