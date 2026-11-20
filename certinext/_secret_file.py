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

"""Read an OAuth client secret from a file (ADR 0024).

The ``_FILE`` convention: instead of putting the secret itself in an
environment variable (visible in ``/proc/<pid>/environ``) or a store readable
over an API, the caller names a file that only the service account can read,
for example one placed by configuration management at mode 0400, or a
systemd ``LoadCredential=`` file.
"""

import os
import stat
import sys
from pathlib import Path

from certinext.exceptions import CertiNextSecretFileError

#: Permission bits that make a secret file unsafe: readable or writable by
#: users other than the owner and group.
_WORLD_BITS = stat.S_IROTH | stat.S_IWOTH


def read_secret_file(path: str | os.PathLike[str]) -> str:
    """Return the client secret stored in ``path``.

    The file is opened once, and every check runs against that open handle,
    so the file cannot be swapped between the check and the read. On POSIX
    the file must be a regular file with no world read or write bit; group
    access is allowed so a service group can share it. Windows has no
    meaningful mode bits, so the permission check is skipped there and the
    file's ACL is the caller's responsibility.

    Trailing carriage returns and newlines are stripped, since editors and
    ``echo`` add them. Other whitespace is kept: it may be part of the secret.

    Args:
        path: Path to the secret file. ``~`` is expanded.

    Returns:
        The secret, without its trailing newline.

    Raises:
        CertiNextSecretFileError: If the file is missing, unreadable, not a
            regular file, world-readable or world-writable, not UTF-8 text,
            or empty after stripping the newline. The message names the path
            and the problem, never the content.
    """
    shown = os.fspath(path)
    resolved = Path(shown).expanduser()
    # O_NONBLOCK keeps a FIFO from blocking the open; the S_ISREG check below
    # then refuses it. Harmless on regular files, absent on Windows.
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(resolved, flags)
    except FileNotFoundError:
        raise CertiNextSecretFileError(shown, "file not found") from None
    except PermissionError:
        raise CertiNextSecretFileError(shown, "permission denied") from None
    except IsADirectoryError:
        raise CertiNextSecretFileError(shown, "not a regular file") from None
    except OSError as exc:
        raise CertiNextSecretFileError(shown, f"cannot open ({exc.strerror or type(exc).__name__})") from None
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise CertiNextSecretFileError(shown, "not a regular file")
        if sys.platform != "win32" and info.st_mode & _WORLD_BITS:
            mode = stat.S_IMODE(info.st_mode)
            raise CertiNextSecretFileError(
                shown, f"mode {mode:04o} is accessible to other users; chmod o-rwx (0400 or 0440 recommended)"
            )
        try:
            raw = handle.read()
        except OSError as exc:
            raise CertiNextSecretFileError(shown, f"cannot read ({exc.strerror or type(exc).__name__})") from None
    # A UnicodeDecodeError carries the whole input in ``.object``. Raising
    # inside the ``except`` block would chain it as ``__context__`` (``from
    # None`` only hides it from the printed traceback), so the error is raised
    # after the block ends. ``raw`` is deleted first so the bytes are not left
    # in this frame's locals, which error collectors such as Sentry record.
    text: str | None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    del raw
    if text is None:
        raise CertiNextSecretFileError(shown, "not UTF-8 text")
    secret = text.rstrip("\r\n")
    if not secret.strip():
        raise CertiNextSecretFileError(shown, "file is empty")
    return secret
