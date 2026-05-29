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

"""CSR parsing utilities.

Requires the ``csr`` optional dependency::

    pip install certinext[csr]
"""


def parse_csr(pem: str) -> tuple[str, list[str]]:
    """Extract the CN and DNS SANs from a PEM-encoded CSR.

    Args:
        pem: PEM-encoded certificate signing request string.

    Returns:
        A tuple of ``(cn, sans)`` where ``cn`` is the Common Name from the
        subject and ``sans`` is a list of DNS SANs from the SAN extension,
        excluding the CN (CertiNext takes the primary domain separately from
        additional domains).

    Raises:
        ImportError: If the ``cryptography`` package is not installed. Install
            it with ``pip install certinext[csr]``.
        ValueError: If the PEM cannot be parsed as a CSR, or the CSR subject
            contains no Common Name.
    """
    try:
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID, NameOID
    except ImportError as exc:
        raise ImportError(
            "The 'cryptography' package is required to parse CSRs. "
            "Install it with: pip install certinext[csr]"
        ) from exc

    try:
        csr = x509.load_pem_x509_csr(pem.encode())
    except Exception as exc:
        raise ValueError(f"Failed to parse CSR: {exc}") from exc

    cn_attrs = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not cn_attrs:
        raise ValueError(
            "CSR subject has no Common Name — use --domain to specify the primary domain"
        )
    cn = str(cn_attrs[0].value)

    try:
        san_ext = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_value = san_ext.value
        if isinstance(san_value, x509.SubjectAlternativeName):
            dns_names = [
                name
                for name in san_value.get_values_for_type(x509.DNSName)
                if name != cn
            ]
        else:
            dns_names = []
    except x509.ExtensionNotFound:
        dns_names = []

    return cn, dns_names
