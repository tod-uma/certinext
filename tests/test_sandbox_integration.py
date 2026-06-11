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

"""End-to-end sandbox integration tests for the CertiNext library.

Covers the full API surface against the live sandbox: authentication, domain
management, order reporting, organization lookup, and OV certificate issuance.
All tests skip automatically when the required credentials are absent, so this
file is safe to include in every pipeline — only those that have the right
environment variables will actually exercise the API.

Required environment variables (base access):

    CERTINEXT_SANDBOX_CLIENT_ID       CertiNext account number
    CERTINEXT_SANDBOX_CLIENT_SECRET   OAuth client secret

Required additionally for cert-issuance tests:

    CERTINEXT_SANDBOX_ORG_ID          Organisation ID for OV orders
    CERTINEXT_SANDBOX_PREVETTING_TOKEN Prevetting token for sandbox auto-approval

Alternatively, store the base credentials in the OS keychain under the
``sandbox`` profile::

    certinext-setup-keyring --sandbox

Run all integration tests explicitly::

    pytest -m integration tests/test_sandbox_integration.py
"""

import os
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import pkcs7 as pkcs7_mod
from cryptography.x509.oid import NameOID

import certinext
from certinext._keyring import keyring_get, keyring_service
from certinext.accounts import Organization
from certinext.domains import Domain
from certinext.exceptions import CertiNextTimeoutError
from certinext.orders import OrderRecord
from certinext.ssl_certificates import OrderWorkflow, SslOrder

# ---------------------------------------------------------------------------
# Session-scoped fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def sandbox_session() -> certinext.CertiNextSession:
    """Return an authenticated sandbox session, or skip.

    Looks up credentials from the ``sandbox`` keyring profile first, then
    falls back to ``CERTINEXT_SANDBOX_CLIENT_ID`` / ``CERTINEXT_SANDBOX_CLIENT_SECRET``.

    Returns:
        An authenticated :class:`~certinext.CertiNextSession` using the sandbox
        base URL and token URL.
    """
    svc = keyring_service("certinext", "sandbox")
    client_id = (
        keyring_get(svc, "CERTINEXT_CLIENT_ID")
        or os.environ.get("CERTINEXT_SANDBOX_CLIENT_ID", "")
    )
    client_secret = (
        keyring_get(svc, "CERTINEXT_CLIENT_SECRET")
        or os.environ.get("CERTINEXT_SANDBOX_CLIENT_SECRET", "")
    )
    if not client_id or not client_secret:
        pytest.skip(
            "sandbox credentials not available — run: certinext-setup-keyring --sandbox "
            "or set CERTINEXT_SANDBOX_CLIENT_ID / CERTINEXT_SANDBOX_CLIENT_SECRET"
        )
    return certinext.session(
        base_url=certinext.SANDBOX_BASE_URL,
        token_url=certinext.SANDBOX_TOKEN_URL,
        client_id=client_id,
        client_secret=client_secret,
    )


@pytest.fixture(scope="session")
def sandbox_ov_creds() -> dict[str, str]:
    """Return OV-specific credentials, or skip if not configured.

    These are only required for the cert-issuance tests.  All other tests in
    this file depend only on ``sandbox_session`` and skip independently.

    Returns:
        Dict with ``org_id`` and ``prevetting_token`` keys.
    """
    org_id = os.environ.get("CERTINEXT_SANDBOX_ORG_ID", "")
    prevetting_token = os.environ.get("CERTINEXT_SANDBOX_PREVETTING_TOKEN", "")
    if not org_id or not prevetting_token:
        pytest.skip(
            "OV issuance credentials not set — "
            "add CERTINEXT_SANDBOX_ORG_ID and CERTINEXT_SANDBOX_PREVETTING_TOKEN"
        )
    return {"org_id": org_id, "prevetting_token": prevetting_token}


# ---------------------------------------------------------------------------
# CSR helper
# ---------------------------------------------------------------------------

def _parse_chain(pem: str) -> list[x509.Certificate]:
    """Parse all PEM certificates from a chain string.

    Splits on ``-----END CERTIFICATE-----`` boundaries and loads each block as
    an :class:`~cryptography.x509.Certificate`.  The first entry is the leaf;
    subsequent entries are the issuing CA certs in order.

    Args:
        pem: PEM string containing one or more concatenated certificates.

    Returns:
        List of parsed :class:`~cryptography.x509.Certificate` objects.
    """
    certs: list[x509.Certificate] = []
    marker = "-----END CERTIFICATE-----"
    remaining = pem
    while "-----BEGIN CERTIFICATE-----" in remaining:
        end = remaining.index(marker) + len(marker)
        certs.append(x509.load_pem_x509_certificate(remaining[:end].encode()))
        remaining = remaining[end:]
    return certs


def _generate_csr(cn: str) -> str:
    """Return a fresh EC P-256 CSR PEM for the given CN.

    Includes ``emailAddress``, ``ST``, and ``L`` subject attributes so the
    library can extract requestor email and signer place automatically.

    Args:
        cn: The Common Name for the CSR subject.

    Returns:
        PEM-encoded certificate signing request as a string.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Maine"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Orono"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "University of Maine System"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "ITS"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, "tod.detre@maine.edu"),
        ]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(Encoding.PEM).decode()


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestAuth:
    """Verify that OAuth token acquisition and account lookup succeed."""

    def test_session_authenticates(self, sandbox_session: certinext.CertiNextSession) -> None:
        """session() successfully obtains an OAuth token and returns a session."""
        assert sandbox_session is not None

    def test_account_me_returns_account_number(self, sandbox_session: certinext.CertiNextSession) -> None:
        """accounts.me() returns an AccountInfo with a non-None account_number."""
        info = sandbox_session.accounts.me()
        assert info.account_number is not None, "account_number is None after auth"


# ---------------------------------------------------------------------------
# Domains
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestDomains:
    """Verify that the Domains API returns usable data."""

    def test_domain_list_is_non_empty(self, sandbox_session: certinext.CertiNextSession) -> None:
        """domain.get_list() returns at least one registered domain."""
        domains = sandbox_session.domain.get_list()
        assert len(domains) > 0, "no domains returned from sandbox"

    def test_domain_list_returns_domain_objects(self, sandbox_session: certinext.CertiNextSession) -> None:
        """Every item from get_list() is a Domain instance with id and name."""
        domains = sandbox_session.domain.get_list()
        for d in domains:
            assert isinstance(d, Domain)
            assert d.id is not None, f"domain missing id: {d!r}"
            assert d.name is not None, f"domain missing name: {d!r}"

    def test_domain_status_values_are_known(self, sandbox_session: certinext.CertiNextSession) -> None:
        """Every domain's status is one of the documented values."""
        valid = {"ACTIVE", "INACTIVE", "EXPIRED", "REVOKED"}
        for d in sandbox_session.domain.get_list():
            assert d.status in valid, f"unexpected status {d.status!r} on {d.name}"


# ---------------------------------------------------------------------------
# Orders report
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestOrders:
    """Verify that the Orders Report API returns usable data."""

    def test_orders_list_returns_order_records(self, sandbox_session: certinext.CertiNextSession) -> None:
        """orders.get_list() returns a list of OrderRecord objects."""
        orders = sandbox_session.orders.get_list()
        assert isinstance(orders, list)
        assert all(isinstance(o, OrderRecord) for o in orders)

    def test_order_records_have_order_numbers(self, sandbox_session: certinext.CertiNextSession) -> None:
        """Every OrderRecord has a non-None order_number."""
        for o in sandbox_session.orders.get_list():
            assert o.order_number is not None, f"order missing order_number: {o!r}"

    def test_ssl_get_by_order_number(self, sandbox_session: certinext.CertiNextSession) -> None:
        """ssl.get() returns an SslOrder for the first order in the report."""
        orders = sandbox_session.orders.get_list()
        if not orders or orders[0].order_number is None:
            pytest.skip("no orders with order_number in sandbox")
        order = sandbox_session.ssl.get(orders[0].order_number)
        assert isinstance(order, SslOrder)
        assert order.order_id == orders[0].order_number


# ---------------------------------------------------------------------------
# Organisations
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestOrganisations:
    """Verify that the Accounts / Organisations API returns usable data."""

    def test_list_organisations_returns_list(self, sandbox_session: certinext.CertiNextSession) -> None:
        """accounts.list_organizations() returns a non-empty list."""
        orgs = sandbox_session.accounts.list_organizations()
        assert isinstance(orgs, list)
        assert len(orgs) > 0, "no organizations returned from sandbox"

    def test_organisations_have_numbers(self, sandbox_session: certinext.CertiNextSession) -> None:
        """Every Organization has a non-None organization_number."""
        for org in sandbox_session.accounts.list_organizations():
            assert isinstance(org, Organization)
            assert org.organization_number is not None, f"org missing number: {org!r}"


# ---------------------------------------------------------------------------
# OV certificate issuance
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestCertIssuance:
    """End-to-end OV certificate issuance against the sandbox.

    These tests consume a sandbox certificate slot and may take up to five
    minutes.  They are only attempted when ``CERTINEXT_SANDBOX_ORG_ID`` and
    ``CERTINEXT_SANDBOX_PREVETTING_TOKEN`` are set.

    In GitLab CI, the ``integration-cert-issuance`` job provides all required
    variables and runs only on release-candidate and stable tag pipelines.
    """

    def test_issue_ov_cert(
        self,
        sandbox_session: certinext.CertiNextSession,
        sandbox_ov_creds: dict[str, str],
        tmp_path: Path,
    ) -> None:
        """Issue an OV certificate end-to-end and verify all download formats.

        Generates a fresh EC P-256 CSR with a CI-job-unique CN, creates an OV
        order with the prevetting token so the sandbox auto-approves it, drives
        the order to issuance via :class:`~certinext.ssl_certificates.OrderWorkflow`,
        then verifies:

        - The returned PEM bundle contains a parseable cert chain whose leaf CN
          matches the CSR.
        - :meth:`~certinext.ssl_certificates.SslOrder.download_certificate_der`
          returns valid DER for the leaf certificate with a matching CN.
        - :meth:`~certinext.ssl_certificates.SslOrder.download_certificate_pkcs7`
          returns a valid PKCS#7 bundle containing at least one certificate.
        - ``--all-formats-out`` writes all three formats to a directory and each
          file is parseable.

        Args:
            sandbox_session: Authenticated sandbox session fixture.
            sandbox_ov_creds: OV org ID and prevetting token fixture.
            tmp_path: Pytest temporary directory for ``--all-formats-out`` output.
        """
        job_id = os.environ.get("CI_JOB_ID", str(int(time.time())))
        cn = f"certinext-ci-{job_id}.maine.edu"
        csr_pem = _generate_csr(cn)

        order = sandbox_session.ssl.create_ov(
            cn,
            organization_id=sandbox_ov_creds["org_id"],
            prevetting_token=sandbox_ov_creds["prevetting_token"],
            requestor_name="CertiNext CI",
            requestor_email="tod.detre@maine.edu",
            requestor_phone="+12073708630",
            signer_name="CertiNext CI",
            signer_place="Orono, Maine",
            csr=csr_pem,
        )

        try:
            pem = OrderWorkflow(
                order, signer_name="CertiNext CI", signer_place="Orono, Maine"
            ).run(csr=csr_pem, wait=300)
        except CertiNextTimeoutError as exc:
            pytest.fail(
                f"Timed out waiting for order {exc.order_id} to issue after 300 s"
            )

        assert "-----BEGIN CERTIFICATE-----" in pem, (
            "Response does not contain a PEM certificate"
        )

        chain = _parse_chain(pem)
        assert len(chain) >= 1, "Response contains no parseable certificates"
        leaf = chain[0]

        # Verify chain signatures for every link whose issuer cert is present.
        # The CA may omit intermediate certs from the returned chain; we verify
        # whatever links we can find by matching issuer/subject, rather than
        # assuming consecutive ordering.
        for cert in chain:
            if cert.issuer == cert.subject:
                continue  # self-signed root — no parent to verify against
            issuer = next((c for c in chain if c.subject == cert.issuer), None)
            if issuer is None:
                continue  # issuer not in chain; CA omitted it
            try:
                cert.verify_directly_issued_by(issuer)
            except Exception as exc:
                pytest.fail(
                    f"Signature verification failed: "
                    f"{cert.subject.rfc4514_string()!r} not correctly signed by "
                    f"{issuer.subject.rfc4514_string()!r}: {exc}"
                )

        # When the intermediate is absent we fall back to an issuer-name check:
        # assert the leaf's issuer looks like a CertiNext/InCommon/emSign CA cert.
        leaf_issuer_cn_attrs = leaf.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert leaf_issuer_cn_attrs, "Leaf cert has no issuer CN"
        raw = leaf_issuer_cn_attrs[0].value
        leaf_issuer_cn = raw.decode() if isinstance(raw, bytes) else raw
        known_ca_keywords = ("InCommon", "emSign", "Staging", "CertiNext")
        assert any(kw in leaf_issuer_cn for kw in known_ca_keywords), (
            f"Leaf cert issuer {leaf_issuer_cn!r} does not look like a CertiNext sandbox CA"
        )

        # Leaf must not be expired.
        now = datetime.now(timezone.utc)
        assert leaf.not_valid_after_utc > now, (
            f"Issued certificate expired at {leaf.not_valid_after_utc}"
        )

        # Leaf CN must match the CSR.
        cn_attrs = leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert cn_attrs, "Issued certificate has no CN attribute"
        assert cn_attrs[0].value == cn, (
            f"CN mismatch: expected {cn!r}, got {cn_attrs[0].value!r}"
        )

        # ------------------------------------------------------------------
        # DER download — single end-entity cert
        # ------------------------------------------------------------------
        der = order.download_certificate_der()
        assert isinstance(der, bytes) and len(der) > 0, "DER download returned empty bytes"
        der_cert = x509.load_der_x509_certificate(der)
        der_cn_attrs = der_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert der_cn_attrs, "DER certificate has no CN attribute"
        assert der_cn_attrs[0].value == cn, (
            f"DER CN mismatch: expected {cn!r}, got {der_cn_attrs[0].value!r}"
        )
        assert der_cert.not_valid_after_utc > now, (
            f"DER certificate expired at {der_cert.not_valid_after_utc}"
        )

        # ------------------------------------------------------------------
        # PKCS#7 download — full bundle; verify chain signatures
        # ------------------------------------------------------------------
        p7b = order.download_certificate_pkcs7()
        assert isinstance(p7b, bytes) and len(p7b) > 0, "PKCS#7 download returned empty bytes"
        p7b_certs = pkcs7_mod.load_der_pkcs7_certificates(p7b)
        assert len(p7b_certs) >= 1, "PKCS#7 bundle contains no certificates"
        # Verify chain signatures using the same logic applied to the PEM bundle above.
        for p7b_cert in p7b_certs:
            if p7b_cert.issuer == p7b_cert.subject:
                continue  # self-signed root
            issuer = next((c for c in p7b_certs if c.subject == p7b_cert.issuer), None)
            if issuer is None:
                continue  # issuer not included in bundle
            try:
                p7b_cert.verify_directly_issued_by(issuer)
            except Exception as exc:
                pytest.fail(
                    f"PKCS#7 signature verification failed: "
                    f"{p7b_cert.subject.rfc4514_string()!r} not signed by "
                    f"{issuer.subject.rfc4514_string()!r}: {exc}"
                )

        # ------------------------------------------------------------------
        # --all-formats-out: three files written and parseable
        # ------------------------------------------------------------------
        from certinext.issue_certificate_cli import _stem_from_domain, _write_outputs

        _write_outputs(order, type("_Args", (), {  # type: ignore[arg-type]
            "cert_out": None, "chain_out": None, "fullchain_out": None,
            "der_out": None, "pkcs7_out": None,
            "all_formats_out": str(tmp_path), "output": None,
        })(), pem)

        stem = _stem_from_domain(order.domain)
        pem_file = tmp_path / f"{stem}.pem"
        der_file = tmp_path / f"{stem}.der"
        p7b_file = tmp_path / f"{stem}.p7b"

        assert pem_file.exists(), f"--all-formats-out did not write {pem_file.name}"
        assert der_file.exists(), f"--all-formats-out did not write {der_file.name}"
        assert p7b_file.exists(), f"--all-formats-out did not write {p7b_file.name}"

        x509.load_der_x509_certificate(der_file.read_bytes())
        assert len(pkcs7_mod.load_der_pkcs7_certificates(p7b_file.read_bytes())) >= 1
