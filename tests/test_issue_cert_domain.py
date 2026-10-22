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

"""Tests for how `certinext issue-cert` picks the primary domain and SANs."""

import pytest

from certinext.cli.issue_cert import _resolve_domain_and_sans
from certinext.csr import CsrInfo


def _info(cn: str | None, sans: list[str]) -> CsrInfo:
    """Build a CsrInfo with only the fields domain resolution reads.

    Args:
        cn: Common Name, or ``None`` for a CN-less CSR.
        sans: DNS SANs as :func:`~certinext.csr.parse_csr` would return them.

    Returns:
        A :class:`CsrInfo`.
    """
    return CsrInfo(common_name=cn, email=None, locality=None, state=None,
                   organization=None, sans=sans)


def test_cn_is_primary_without_domain() -> None:
    """The CSR's CN is the primary domain when --domain is absent."""
    assert _resolve_domain_and_sans(_info("a.example.edu", ["b.example.edu"]), None, None) == (
        "a.example.edu", ["b.example.edu"],
    )


def test_no_cn_with_domain_drops_primary_from_sans() -> None:
    """A CN-less CSR works with --domain, and the primary is not repeated as a SAN."""
    info = _info(None, ["a.example.edu", "b.example.net"])
    assert _resolve_domain_and_sans(info, "A.example.edu", None) == (
        "A.example.edu", ["b.example.net"],
    )


def test_no_cn_without_domain_exits() -> None:
    """A CN-less CSR without --domain is a usage error."""
    with pytest.raises(SystemExit):
        _resolve_domain_and_sans(_info(None, ["a.example.edu"]), None, None)


def test_explicit_sans_are_kept() -> None:
    """Explicit --san values are used as given."""
    info = _info(None, ["a.example.edu", "b.example.net"])
    assert _resolve_domain_and_sans(info, "a.example.edu", ["c.example.org"]) == (
        "a.example.edu", ["c.example.org"],
    )
