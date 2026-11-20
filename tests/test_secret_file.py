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

"""Tests for the client-secret file reader (certinext._secret_file, ADR 0024)."""

import os
import sys
from pathlib import Path

import pytest

import certinext
from certinext import CertiNextSecretFileError
from certinext._secret_file import read_secret_file

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits")


def _secret(tmp_path: Path, content: bytes, mode: int = 0o400) -> Path:
    """Write a secret file with the given content and mode.

    Args:
        tmp_path: pytest's per-test directory.
        content: Raw bytes to store.
        mode: File mode to apply (ignored by Windows).

    Returns:
        The file's path.
    """
    path = tmp_path / "client.secret"
    path.write_bytes(content)
    path.chmod(mode)
    return path


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        (b"s3cret", "s3cret"),
        (b"s3cret\n", "s3cret"),
        (b"s3cret\r\n", "s3cret"),
        (b"s3cret\n\n", "s3cret"),
        (b" s3 cret \n", " s3 cret "),
    ],
)
def test_reads_secret_and_strips_trailing_newline_only(tmp_path: Path, content: bytes, expected: str) -> None:
    """Trailing CR/LF is stripped; other whitespace is part of the secret."""
    assert read_secret_file(_secret(tmp_path, content)) == expected


def test_expands_user(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A ``~`` path resolves against the home directory."""
    _secret(tmp_path, b"s3cret\n")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    assert read_secret_file("~/client.secret") == "s3cret"


def test_missing_file(tmp_path: Path) -> None:
    """A missing file names the path and the problem."""
    with pytest.raises(CertiNextSecretFileError, match="file not found") as info:
        read_secret_file(tmp_path / "absent")
    assert info.value.path == str(tmp_path / "absent")


@pytest.mark.parametrize("content", [b"", b"\n", b"   \n"])
def test_empty_file_refused(tmp_path: Path, content: bytes) -> None:
    """An empty secret fails closed instead of falling through to another source."""
    with pytest.raises(CertiNextSecretFileError, match="empty"):
        read_secret_file(_secret(tmp_path, content))


def test_non_utf8_refused(tmp_path: Path) -> None:
    """Binary content is refused, and the message does not echo it."""
    with pytest.raises(CertiNextSecretFileError, match="not UTF-8") as info:
        read_secret_file(_secret(tmp_path, b"\xff\xfe\x00"))
    assert "\\xff" not in str(info.value)


def test_non_utf8_error_does_not_retain_content(tmp_path: Path) -> None:
    """The error keeps no reference to the raw bytes (external review R1, finding 1).

    A UnicodeDecodeError holds its whole input, so it must not be chained as
    ``__context__`` or ``__cause__``. The bytes must not survive in the
    traceback's frame locals either: error collectors capture those.
    """
    content = b"s3cret-\xff-tail"
    with pytest.raises(CertiNextSecretFileError) as info:
        read_secret_file(_secret(tmp_path, content))
    exc = info.value
    assert exc.__context__ is None
    assert exc.__cause__ is None
    tb = exc.__traceback__
    while tb is not None:
        # This test's own frame holds ``content``. Compare code objects, not
        # file paths: the path's spelling (drive-letter case) varies by shell.
        if tb.tb_frame.f_code is test_non_utf8_error_does_not_retain_content.__code__:
            tb = tb.tb_next
            continue
        for value in tb.tb_frame.f_locals.values():
            assert value is not content
            if isinstance(value, bytes):
                assert b"s3cret" not in value
        tb = tb.tb_next


def test_directory_refused(tmp_path: Path) -> None:
    """A directory is not a secret file (Windows reports it as permission denied)."""
    with pytest.raises(CertiNextSecretFileError, match="not a regular file|permission denied"):
        read_secret_file(tmp_path)


@posix_only
@pytest.mark.parametrize("mode", [0o404, 0o444, 0o602, 0o644, 0o666])
def test_world_accessible_refused(tmp_path: Path, mode: int) -> None:
    """Any world read or write bit is refused, and the mode is reported."""
    with pytest.raises(CertiNextSecretFileError, match=f"mode {mode:04o}"):
        read_secret_file(_secret(tmp_path, b"s3cret", mode))


@posix_only
@pytest.mark.parametrize("mode", [0o400, 0o440, 0o600, 0o640])
def test_owner_and_group_modes_allowed(tmp_path: Path, mode: int) -> None:
    """Owner- and group-only modes are accepted, so a service group can share the file."""
    assert read_secret_file(_secret(tmp_path, b"s3cret", mode)) == "s3cret"


@posix_only
def test_fifo_refused_without_blocking(tmp_path: Path) -> None:
    """A FIFO is refused instead of blocking the open waiting for a writer."""
    if sys.platform != "win32":  # mypy only narrows on an `if`; posix_only already skips
        fifo = tmp_path / "pipe"
        os.mkfifo(fifo, 0o600)
        with pytest.raises(CertiNextSecretFileError, match="not a regular file"):
            read_secret_file(fifo)


@posix_only
def test_unreadable_file(tmp_path: Path) -> None:
    """A file the process cannot read reports permission denied."""
    if sys.platform != "win32":  # mypy only narrows on an `if`; posix_only already skips
        if os.geteuid() == 0:
            pytest.skip("root reads mode-000 files")
        with pytest.raises(CertiNextSecretFileError, match="permission denied"):
            read_secret_file(_secret(tmp_path, b"s3cret", 0o000))


def test_session_reads_secret_file(tmp_path: Path) -> None:
    """``certinext.session(client_secret_file=...)`` uses the file's secret."""
    sess = certinext.session(client_id="acct", client_secret_file=_secret(tmp_path, b"s3cret\n"))
    assert sess._client._auth.client_secret == "s3cret"


def test_session_rejects_both_secret_arguments(tmp_path: Path) -> None:
    """Passing a secret and a secret file is ambiguous, so it is refused."""
    with pytest.raises(ValueError, match="not both"):
        certinext.session(client_id="acct", client_secret="x", client_secret_file=_secret(tmp_path, b"s3cret"))


def test_session_blank_secret_file_is_ignored() -> None:
    """A blank path counts as not given, matching the settings sources."""
    sess = certinext.session(client_id="acct", client_secret="x", client_secret_file="")
    assert sess._client._auth.client_secret == "x"
