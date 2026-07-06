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

"""Pydantic response models for the CertiNext API (ADR 0003/0005).

Models live in per-API-area modules mirroring the accessor modules
(``models.catalog`` ↔ ``certinext.catalog``, ...). The legacy modules
re-export them, so both import paths work; the legacy paths remain the
documented public API for 1.0.
"""

from ._base import CertiNextModel, coerce_flag, lenient_enum
from .catalog import CustomField, Product, ProductCategory

__all__ = [
    "CertiNextModel",
    "coerce_flag",
    "lenient_enum",
    "CustomField",
    "Product",
    "ProductCategory",
]
