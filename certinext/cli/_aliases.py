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

"""Alias entry points keeping the 0.3.x script names working (ADR 0004).

Each ``certinext-<name>`` console script maps to a shim that invokes the
consolidated app with its subcommand pre-selected, so flags, behavior, and
exit codes are identical to ``certinext <name>``. Removal of the aliases is
planned no earlier than 2.0.
"""

import sys


def _invoke(*subcommand: str) -> int:
    """Run the app with ``subcommand`` prepended to the process arguments.

    Args:
        subcommand: The subcommand path to pre-select (one element, or two
            for nested commands like ``setup keyring``).

    Returns:
        The process exit code from :func:`certinext.cli.main`.
    """
    from certinext.cli import main

    return main([*subcommand, *sys.argv[1:]])


def healthcheck() -> int:
    """Entry point for the ``certinext-healthcheck`` alias."""
    return _invoke("healthcheck")


def accounts() -> int:
    """Entry point for the ``certinext-accounts`` alias."""
    return _invoke("accounts")


def ledger() -> int:
    """Entry point for the ``certinext-ledger`` alias."""
    return _invoke("ledger")


def list_certificates() -> int:
    """Entry point for the ``certinext-list-certificates`` alias."""
    return _invoke("list-certificates")


def pending_dcv() -> int:
    """Entry point for the ``certinext-pending-dcv`` alias."""
    return _invoke("pending-dcv")


def domain_cert_count() -> int:
    """Entry point for the ``certinext-domain-cert-count`` alias."""
    return _invoke("domain-cert-count")


def parent_dcv_status() -> int:
    """Entry point for the ``certinext-parent-dcv-status`` alias."""
    return _invoke("parent-dcv-status")


def domains() -> int:
    """Entry point for the ``certinext-domains`` alias."""
    return _invoke("domains")


def setup_keyring() -> int:
    """Entry point for the ``certinext-setup-keyring`` alias."""
    return _invoke("setup", "keyring")


def setup_defaults() -> int:
    """Entry point for the ``certinext-setup-defaults`` alias."""
    return _invoke("setup", "defaults")
