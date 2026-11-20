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

"""Python-version support policy (ADR 0027).

Python 3.10 is deprecated: importing certinext on it emits a FutureWarning,
and on 3.11+ it must not. The import runs in a fresh interpreter because the
warning fires once, at first import, which this test session has long since
done. Each CI matrix job checks its own interpreter's branch.
"""

import subprocess
import sys


def _import_with_future_warnings_as_errors() -> subprocess.CompletedProcess[str]:
    """Import certinext in a fresh interpreter with FutureWarning made fatal.

    Returns:
        The completed process; a non-zero return code means the import warned.
    """
    return subprocess.run(
        [sys.executable, "-W", "error::FutureWarning", "-c", "import certinext"],
        capture_output=True,
        text=True,
        check=False,
    )


def test_import_warns_only_on_python_310() -> None:
    """3.10 gets the deprecation warning; newer versions import silently."""
    proc = _import_with_future_warnings_as_errors()
    if sys.version_info < (3, 11):
        assert proc.returncode != 0
        assert "Python 3.10 is deprecated" in proc.stderr
    else:
        assert proc.returncode == 0, proc.stderr
