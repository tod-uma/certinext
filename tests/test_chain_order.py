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

"""Tests for certinext._chain certificate-chain ordering.

Builds real certificate chains with the ``cryptography`` library so the
issuer→subject linking exercised by
:func:`certinext._chain.order_certificate_chain` runs against genuine X.509
structures. Two chains are generated: one carrying Subject/Authority Key
Identifier extensions (the AKI→SKI fast path) and one without them (the
issuer/subject distinguished-name fallback path), so both linking strategies
are covered.
"""

import builtins
import datetime
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from certinext._chain import order_certificate_chain, split_pem_certificates
from certinext.ssl_certificates import CertificateDownload

_NB = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
_NA = datetime.datetime(2027, 1, 1, tzinfo=datetime.timezone.utc)


def _pem(cert: x509.Certificate) -> str:
    """Return a certificate as a stripped PEM string."""
    return cert.public_bytes(serialization.Encoding.PEM).decode().strip()


def _build_cert(
    subject_cn: str,
    subject_key: ec.EllipticCurvePrivateKey,
    issuer_cn: str,
    issuer_key: ec.EllipticCurvePrivateKey,
    *,
    ca: bool,
    with_key_ids: bool,
) -> x509.Certificate:
    """Build a signed certificate for use in test chains.

    Args:
        subject_cn: Common Name for the certificate subject.
        subject_key: Key whose public half is certified.
        issuer_cn: Common Name of the issuing certificate's subject.
        issuer_key: Private key that signs (set equal to ``subject_key`` for a
            self-signed root).
        ca: Whether to mark the certificate as a CA via BasicConstraints.
        with_key_ids: Whether to add SubjectKeyIdentifier and
            AuthorityKeyIdentifier extensions.

    Returns:
        The signed :class:`cryptography.x509.Certificate`.
    """
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)]))
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NB)
        .not_valid_after(_NA)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if with_key_ids:
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()),
            critical=False,
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False,
        )
    return builder.sign(issuer_key, hashes.SHA256())


def _make_chain(with_key_ids: bool) -> tuple[str, str, str, str]:
    """Build a 4-level chain: root → TLS CA → OV CA → leaf.

    Args:
        with_key_ids: Whether the certificates carry SKI/AKI extensions.

    Returns:
        Tuple of stripped PEM strings ``(leaf, ov_ca, tls_ca, root)`` in correct
        leaf-first signing order.
    """
    root_key = ec.generate_private_key(ec.SECP256R1())
    tls_key = ec.generate_private_key(ec.SECP256R1())
    ov_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())

    root = _build_cert("Root CA", root_key, "Root CA", root_key, ca=True, with_key_ids=with_key_ids)
    tls = _build_cert("TLS CA", tls_key, "Root CA", root_key, ca=True, with_key_ids=with_key_ids)
    ov = _build_cert("OV CA", ov_key, "TLS CA", tls_key, ca=True, with_key_ids=with_key_ids)
    leaf = _build_cert(
        "leaf.example.com", leaf_key, "OV CA", ov_key, ca=False, with_key_ids=with_key_ids
    )
    return _pem(leaf), _pem(ov), _pem(tls), _pem(root)


# Chains in correct order: (leaf, ov, tls, root).
_LEAF_K, _OV_K, _TLS_K, _ROOT_K = _make_chain(with_key_ids=True)
_LEAF_N, _OV_N, _TLS_N, _ROOT_N = _make_chain(with_key_ids=False)

# The wrong order CertiNext returns: root jumps to position 2 (GitLab #4).
_BUG_ORDER_K = [_LEAF_K, _ROOT_K, _OV_K, _TLS_K]
_CORRECT_K = [_LEAF_K, _OV_K, _TLS_K, _ROOT_K]
_BUG_ORDER_N = [_LEAF_N, _ROOT_N, _OV_N, _TLS_N]
_CORRECT_N = [_LEAF_N, _OV_N, _TLS_N, _ROOT_N]


# ---------------------------------------------------------------------------
# split_pem_certificates
# ---------------------------------------------------------------------------


def test_split_extracts_each_block() -> None:
    """A concatenated bundle is split into its individual stripped blocks."""
    bundle = "\n".join(_CORRECT_K) + "\n"
    assert split_pem_certificates(bundle) == _CORRECT_K


def test_split_ignores_non_certificate_content() -> None:
    """Surrounding noise and a private-key block are not returned as certs."""
    text = "garbage\n" + _LEAF_K + "\n-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n"
    assert split_pem_certificates(text) == [_LEAF_K]


def test_split_empty_string() -> None:
    """Empty input yields no blocks."""
    assert split_pem_certificates("") == []


# ---------------------------------------------------------------------------
# order_certificate_chain — the core fix
# ---------------------------------------------------------------------------


def test_orders_bug_order_via_key_ids() -> None:
    """The scrambled API order is corrected using AKI/SKI matching."""
    assert order_certificate_chain(_BUG_ORDER_K) == _CORRECT_K


def test_orders_bug_order_via_dn_fallback() -> None:
    """The scrambled API order is corrected with no SKI/AKI (DN fallback)."""
    assert order_certificate_chain(_BUG_ORDER_N) == _CORRECT_N


def test_already_correct_order_is_stable() -> None:
    """A correctly ordered chain is returned unchanged."""
    assert order_certificate_chain(_CORRECT_K) == _CORRECT_K


def test_orders_with_explicit_leaf() -> None:
    """When the leaf is supplied separately it anchors the chain (JSON path)."""
    # Intermediates+root in scrambled order, leaf passed separately.
    result = order_certificate_chain([_ROOT_K, _OV_K, _TLS_K], leaf_pem=_LEAF_K)
    assert result == _CORRECT_K


def test_deduplicates_identical_certs() -> None:
    """Exact duplicate certificates are collapsed to one."""
    result = order_certificate_chain([_LEAF_K, _OV_K, _OV_K, _TLS_K, _ROOT_K, _LEAF_K])
    assert result == _CORRECT_K


def test_leaf_only_returns_single_cert() -> None:
    """A lone leaf certificate is returned as-is."""
    assert order_certificate_chain([_LEAF_K]) == [_LEAF_K]


def test_empty_input_returns_empty() -> None:
    """No certificates in, no certificates out."""
    assert order_certificate_chain([]) == []


def test_unlinked_cert_appended_at_end() -> None:
    """A cert that does not chain to the leaf is preserved at the end."""
    # A foreign self-signed root unrelated to the leaf's chain.
    other_key = ec.generate_private_key(ec.SECP256R1())
    other = _pem(
        _build_cert("Other Root", other_key, "Other Root", other_key, ca=True, with_key_ids=True)
    )
    result = order_certificate_chain([_LEAF_K, _OV_K, _TLS_K, _ROOT_K, other])
    assert result[:4] == _CORRECT_K
    assert result[4] == other


def test_unparseable_block_appended_at_end() -> None:
    """A block that is not a real certificate is kept at the end, never dropped."""
    junk = "-----BEGIN CERTIFICATE-----\nNOTBASE64\n-----END CERTIFICATE-----"
    result = order_certificate_chain([_LEAF_K, _OV_K, _TLS_K, _ROOT_K, junk])
    assert result[:4] == _CORRECT_K
    assert result[-1] == junk


def test_all_unparseable_preserves_order() -> None:
    """If nothing parses, the input order is preserved (graceful degradation)."""
    a = "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----"
    b = "-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----"
    assert order_certificate_chain([a, b]) == [a, b]


def test_requires_cryptography(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without cryptography, sorting raises ImportError pointing at the extra."""
    real_import = builtins.__import__

    def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "cryptography" or name.startswith("cryptography."):
            raise ImportError("simulated missing cryptography")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(ImportError, match=r"certinext\[csr\]"):
        order_certificate_chain(_CORRECT_K)


# ---------------------------------------------------------------------------
# CertificateDownload.as_pem_chain — integration with the sorter
# ---------------------------------------------------------------------------


def test_as_pem_chain_sorts_by_default() -> None:
    """as_pem_chain() re-orders a scrambled JSON chain into signing order."""
    dl = CertificateDownload.model_validate({"certificatePem": _LEAF_K, "chainPem": [_ROOT_K, _OV_K, _TLS_K]})
    assert dl.as_pem_chain() == "\n".join(_CORRECT_K) + "\n"


def test_as_pem_chain_raw_preserves_api_order() -> None:
    """as_pem_chain(sort=False) concatenates the fields in API order, unsorted."""
    dl = CertificateDownload.model_validate({"certificatePem": _LEAF_K, "chainPem": [_ROOT_K, _OV_K, _TLS_K]})
    assert dl.as_pem_chain(sort=False) == "\n".join(_BUG_ORDER_K) + "\n"
