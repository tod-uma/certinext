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

"""Certificate-chain ordering utilities.

CertiNext's certificate download endpoint returns chain certificates in a
non-standard order — the root CA appears immediately after the leaf instead of
last — which breaks chain validation in Windows Schannel / IIS (GitLab #4,
CertiNext support #134123). The helpers here re-sort a set of PEM certificates
into RFC 5246 §7.4.2 leaf-first signing order (end-entity, then each issuer up
to the root) so that ``--fullchain-out`` / ``--output`` produce a fullchain a
server will accept.

Sorting requires parsing X.509 certificates, which needs the optional
``cryptography`` dependency::

    pip install certinext[csr]

When ``cryptography`` is unavailable, :func:`order_certificate_chain` raises
:class:`ImportError`; callers that want the unmodified API order should not call
it (e.g. ``certinext-issue-cert --raw-chain`` / ``as_pem_chain(sort=False)``).
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:  # pragma: no cover - typing only
    from cryptography.x509 import Certificate

log = structlog.get_logger(__name__)

# Matches a single PEM certificate block, including the BEGIN/END markers.
# DOTALL so the base64 body (which contains newlines) is captured; non-greedy
# so adjacent blocks in a bundle are matched individually.
_PEM_CERT_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)


def split_pem_certificates(text: str) -> list[str]:
    """Split a PEM bundle into individual certificate blocks.

    Extracts each ``-----BEGIN CERTIFICATE----- … -----END CERTIFICATE-----``
    block from *text*, ignoring surrounding whitespace and any non-certificate
    content (for example a private key in a combined PEM file). Each returned
    block is stripped of leading and trailing whitespace.

    Args:
        text: Concatenated PEM text containing zero or more certificates.

    Returns:
        Individual PEM certificate strings in the order they appear in *text*.
        Empty if *text* contains no certificate blocks.
    """
    if not text:
        return []
    return [m.group(0).strip() for m in _PEM_CERT_RE.finditer(text)]


class _CertNode:
    """A parsed certificate paired with its original PEM text.

    Holds the precomputed identity fields used to link certificates into a
    chain: subject/issuer distinguished names (as DER bytes for exact
    comparison), the Subject Key Identifier (SKI), the Authority Key Identifier
    (AKI), and whether the certificate is self-signed. The original (stripped)
    PEM text is preserved verbatim so re-ordering never alters the bytes the API
    returned.
    """

    def __init__(self, original: str, cert: "Certificate") -> None:
        """
        Args:
            original: The stripped PEM text this node was parsed from.
            cert: The parsed :class:`cryptography.x509.Certificate`.
        """
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes

        self.original = original
        self.cert = cert
        self.fingerprint: bytes = cert.fingerprint(hashes.SHA256())
        self.subject_dn: bytes = cert.subject.public_bytes()
        self.issuer_dn: bytes = cert.issuer.public_bytes()
        self.self_signed: bool = self.subject_dn == self.issuer_dn

        self.ski: bytes | None = None
        try:
            self.ski = cert.extensions.get_extension_for_class(
                x509.SubjectKeyIdentifier
            ).value.digest
        except x509.ExtensionNotFound:
            pass

        self.aki: bytes | None = None
        try:
            self.aki = cert.extensions.get_extension_for_class(
                x509.AuthorityKeyIdentifier
            ).value.key_identifier
        except x509.ExtensionNotFound:
            pass

        self.is_ca: bool | None = None
        try:
            self.is_ca = cert.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value.ca
        except x509.ExtensionNotFound:
            pass

    def __repr__(self) -> str:
        """Return a concise developer representation."""
        return f"_CertNode(self_signed={self.self_signed}, is_ca={self.is_ca})"


def _find_issuer(
    node: _CertNode,
    by_ski: dict[bytes, list[_CertNode]],
    by_subject: dict[bytes, list[_CertNode]],
    used: set[bytes],
) -> _CertNode | None:
    """Return the certificate that issued *node*, or ``None`` if not present.

    Prefers an Authority-Key-Identifier → Subject-Key-Identifier match (precise,
    survives issuer renames and cross-signing), then falls back to matching
    *node*'s issuer distinguished name against candidate subject DNs. Never
    returns *node* itself or a certificate already placed in the chain (*used*),
    which terminates the walk cleanly at a self-signed root.

    Args:
        node: The certificate whose issuer is sought.
        by_ski: Index of SKI bytes to the certificates carrying that SKI.
        by_subject: Index of subject-DN bytes to the certificates with that DN.
        used: Fingerprints of certificates already placed in the chain.

    Returns:
        The issuing :class:`_CertNode`, or ``None`` if no unused candidate is
        found.
    """
    if node.aki is not None:
        for cand in by_ski.get(node.aki, []):
            if cand.fingerprint != node.fingerprint and cand.fingerprint not in used:
                return cand
    for cand in by_subject.get(node.issuer_dn, []):
        if cand.fingerprint != node.fingerprint and cand.fingerprint not in used:
            return cand
    return None


def _select_leaf(nodes: list[_CertNode]) -> _CertNode:
    """Pick the end-entity certificate from an unordered set.

    The leaf is a certificate that nothing else in the set is issued by: its SKI
    is referenced by no other certificate's AKI, and its subject DN matches no
    other certificate's issuer DN. Among candidates, prefers a non-CA leaf, then
    a non-self-signed one; falls back to the first non-self-signed node, then the
    first node, so a result is always returned for a non-empty set.

    Args:
        nodes: Parsed certificates to choose from (must be non-empty).

    Returns:
        The chosen leaf :class:`_CertNode`.
    """
    all_akis = {n.aki for n in nodes if n.aki is not None}
    all_issuer_dns = {n.issuer_dn for n in nodes}

    candidates = [
        n
        for n in nodes
        if (n.ski is None or n.ski not in all_akis) and n.subject_dn not in all_issuer_dns
    ]
    if candidates:
        # Prefer a non-CA end-entity, then a non-self-signed cert, keeping the
        # original order stable within each preference tier.
        candidates.sort(key=lambda n: (n.is_ca is True, n.self_signed))
        return candidates[0]
    for n in nodes:
        if not n.self_signed:
            return n
    return nodes[0]


def order_certificate_chain(
    pems: list[str], *, leaf_pem: str | None = None
) -> list[str]:
    """Re-order PEM certificates into leaf-first signing order.

    Parses every certificate in *pems* (and *leaf_pem*, if given), removes exact
    duplicates, then returns them ordered end-entity first followed by each
    issuer up to the root — the layout servers expect and that CertiNext's
    download endpoint fails to produce (GitLab #4). Certificates that cannot be
    linked into the chain (cross-signed alternates, stray certs) and any blocks
    that fail to parse are appended at the end so no data is silently dropped.

    The returned strings are the *original* stripped PEM blocks, reordered — the
    certificate bytes are never re-encoded.

    Args:
        pems: PEM certificate strings to order. May be individual certificates
            or bundles (each is split into its constituent blocks).
        leaf_pem: The known end-entity certificate, when the caller has it
            separately (the JSON download path). When given it anchors the chain
            and leaf auto-detection is skipped; when ``None`` the leaf is
            detected from *pems*.

    Returns:
        Ordered list of PEM certificate strings (leaf first, root last). Empty
        if no certificate blocks are present.

    Raises:
        ImportError: If the ``cryptography`` package is not installed. Install
            it with ``pip install certinext[csr]``; or avoid sorting entirely
            via ``as_pem_chain(sort=False)`` / ``certinext-issue-cert
            --raw-chain``.
    """
    try:
        from cryptography import x509
    except ImportError as exc:
        raise ImportError(
            "The 'cryptography' package is required to sort certificate chains. "
            "Install it with: pip install certinext[csr] "
            "(or use --raw-chain / sort=False to emit the unsorted API order)."
        ) from exc

    # Collect candidate blocks, leaf first so it wins as the chain anchor.
    raw_blocks: list[str] = []
    if leaf_pem and leaf_pem.strip():
        raw_blocks.extend(split_pem_certificates(leaf_pem) or [leaf_pem.strip()])
    leaf_block_count = len(raw_blocks)
    for pem in pems:
        if pem and pem.strip():
            raw_blocks.extend(split_pem_certificates(pem) or [pem.strip()])

    nodes: list[_CertNode] = []
    unparseable: list[str] = []
    seen: set[bytes] = set()
    leaf_fingerprint: bytes | None = None

    for index, block in enumerate(raw_blocks):
        try:
            cert = x509.load_pem_x509_certificate(block.encode())
        except Exception:  # noqa: BLE001 - any parse failure is treated the same
            log.debug("certinext.chain.unparseable_block")
            if block not in unparseable:
                unparseable.append(block)
            continue
        node = _CertNode(block, cert)
        if leaf_pem and index < leaf_block_count and leaf_fingerprint is None:
            leaf_fingerprint = node.fingerprint
        if node.fingerprint in seen:
            continue
        seen.add(node.fingerprint)
        nodes.append(node)

    if not nodes:
        return unparseable

    by_ski: dict[bytes, list[_CertNode]] = {}
    by_subject: dict[bytes, list[_CertNode]] = {}
    for node in nodes:
        if node.ski is not None:
            by_ski.setdefault(node.ski, []).append(node)
        by_subject.setdefault(node.subject_dn, []).append(node)

    leaf: _CertNode | None = None
    if leaf_fingerprint is not None:
        leaf = next((n for n in nodes if n.fingerprint == leaf_fingerprint), None)
    if leaf is None:
        leaf = _select_leaf(nodes)

    ordered: list[_CertNode] = [leaf]
    used: set[bytes] = {leaf.fingerprint}
    current = leaf
    while True:
        parent = _find_issuer(current, by_ski, by_subject, used)
        if parent is None:
            break
        ordered.append(parent)
        used.add(parent.fingerprint)
        current = parent

    leftovers = [n for n in nodes if n.fingerprint not in used]
    if leftovers:
        log.warning(
            "certinext.chain.unlinked_certificates",
            count=len(leftovers),
            ordered=len(ordered),
        )

    return [n.original for n in ordered] + [n.original for n in leftovers] + unparseable
