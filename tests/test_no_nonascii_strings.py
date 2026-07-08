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

"""Guard against non-ASCII characters in printed string literals.

Strings that reach stdout/stderr (``help=`` text, ``print()`` output, log
events) crash with :exc:`UnicodeEncodeError` when the console encoding cannot
represent them — for example a U+2192 arrow on a Windows cp1252 pipe, or any
non-ASCII character under a ``C``/``POSIX`` locale. This test fails if any
non-docstring string literal in the shipped package contains a non-ASCII
character, so such characters cannot be reintroduced unnoticed.

Docstrings and comments are intentionally exempt: they are never written to a
console, so they cannot trigger the crash.
"""

import ast
import pathlib
from typing import cast

import certinext

_PACKAGE_DIR = pathlib.Path(certinext.__file__).parent


def _docstring_node_ids(tree: ast.AST) -> set[int]:
    """Return the ``id()`` of every docstring Constant node in *tree*.

    A docstring is the first statement of a module, class, or function when that
    statement is a bare string expression.

    Args:
        tree: A parsed module AST.

    Returns:
        Set of ``id()`` values for the docstring string-constant nodes.
    """
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = getattr(node, "body", [])
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(getattr(body[0], "value", None), ast.Constant)
            ):
                const_node = cast(ast.Constant, body[0].value)
                if isinstance(const_node.value, str):
                    ids.add(id(const_node))
    return ids


def _offending_literals(path: pathlib.Path) -> list[tuple[int, str]]:
    """Return ``(lineno, snippet)`` for non-docstring string literals with non-ASCII.

    Args:
        path: Python source file to scan.

    Returns:
        A list of offending literals; empty when the file is clean.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstrings = _docstring_node_ids(tree)
    hits: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and id(node) not in docstrings
            and not node.value.isascii()
        ):
            hits.append((node.lineno, node.value.strip()[:60]))
    return hits


def test_no_nonascii_in_printed_strings() -> None:
    """No shipped module may carry non-ASCII in a non-docstring string literal."""
    problems: list[str] = []
    for py in sorted(_PACKAGE_DIR.rglob("*.py")):
        for lineno, snippet in _offending_literals(py):
            problems.append(f"{py.name}:{lineno}  {snippet!r}")
    assert not problems, (
        "Non-ASCII characters found in printed string literals (use ASCII; "
        "these crash on non-UTF-8 consoles):\n" + "\n".join(problems)
    )
