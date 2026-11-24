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

"""Certificate serial-number comparison shared by the lookup and replacement paths.

Kept in its own module because :mod:`certinext.certificate_lookup` imports
:mod:`certinext.replacement`, and both need the same check.
"""


def normalize_serial(value: str) -> str:
    """Normalize a hexadecimal serial, including colon separators and zero padding.

    No decimal interpretation is attempted. Invalid hex remains an exact string.

    Args:
        value: A serial as written in a report or by an operator.

    Returns:
        Lower-case hex without separators or leading zeros, or the stripped,
        case-folded input when it is not hex.
    """
    compact = value.strip().lower().replace(":", "")
    if compact.startswith("0x"):
        compact = compact[2:]
    if compact and all(c in "0123456789abcdef" for c in compact):
        return compact.lstrip("0") or "0"
    return value.strip().casefold()


def serial_matches_leaf(report_serial: str, leaf_serial: int) -> bool:
    """Return whether a report's serial names the parsed leaf certificate.

    Accepts the report's hex serial or its observed decimal emSign form.

    Args:
        report_serial: The serial the orders report gives.
        leaf_serial: The serial parsed from the downloaded leaf.

    Returns:
        True when they denote the same serial.
    """
    if normalize_serial(report_serial) == format(leaf_serial, "x"):
        return True
    compact = report_serial.strip()
    return compact.isascii() and compact.isdecimal() and int(compact, 10) == leaf_serial
