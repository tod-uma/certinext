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

"""On-disk cache of certificate downloads for ``replacement-report --inspect``.

Deliberately narrow (see IDEA-006): it caches only what
:func:`certinext.replacement.build_report` downloads per certificate, keyed
by order number *and* serial number, so a reissue or rekey is always a miss.
Order status is never cached; the orders report stays live every run.

Entries hold the raw download payload, not the parsed result, so parser
fixes apply to cached data. They also hold who placed the order (name and
email), which is why the directory is per-user.

One JSON file per entry, written atomically (temp file + :func:`os.replace`)
because inspection runs on several threads. Every failure is non-fatal: an
unreadable entry is a miss, and a failed write is logged once and skipped.
"""

import contextlib
import datetime as dt
import hashlib
import json
import os
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import structlog

log = structlog.get_logger(__name__)

#: How long a cached download is trusted. The served chain can change (a CA
#: re-rooting is exactly the event this report exists for), so keep it short.
DEFAULT_MAX_AGE = dt.timedelta(days=7)

# Bump when the entry layout changes; other versions are ignored (misses).
_ENTRY_VERSION = 1

# Leftover temp files (a crash mid-write) older than this are pruned. Younger
# ones may belong to a concurrent run.
_STALE_TEMP_SECONDS = 3600

# Windows refuses os.replace onto a file another writer is replacing at that
# moment (WinError 5). Rare (one key per certificate per run), so retry briefly.
_REPLACE_ATTEMPTS = 5
_REPLACE_RETRY_SECONDS = 0.02


def _replace(src: str, dst: Path) -> None:
    """Atomically move ``src`` over ``dst``, retrying a transient Windows lock.

    Args:
        src: The temp file.
        dst: The entry file.

    Raises:
        OSError: If the move still fails after the retries.
    """
    for attempt in range(1, _REPLACE_ATTEMPTS + 1):
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            if attempt == _REPLACE_ATTEMPTS:
                raise
            time.sleep(_REPLACE_RETRY_SECONDS * attempt)


def _utcnow() -> dt.datetime:
    """Return the current time as a timezone-aware UTC datetime.

    Returns:
        ``datetime.now(timezone.utc)``.
    """
    return dt.datetime.now(dt.timezone.utc)


@dataclass(frozen=True)
class CachedInspection:
    """One cached certificate download.

    Attributes:
        download: The raw ``GET /ssl-certificates/{id}/certificate`` payload.
        ordered_by: ``{"name": ..., "email": ...}`` from the order detail.
        fetched_at: When it was downloaded (UTC).
    """

    download: dict[str, Any]
    ordered_by: dict[str, Any]
    fetched_at: dt.datetime


class InspectionCache:
    """A directory of cached certificate downloads.

    Safe to share between threads. Construct one per run and pass it to
    :func:`certinext.replacement.build_report`.

    Example::

        cache = InspectionCache(Path("~/.cache/certinext/x").expanduser())
        report = build_report(sess, criteria, inspect=True, cache=cache)
    """

    def __init__(
        self,
        directory: Path,
        *,
        max_age: dt.timedelta = DEFAULT_MAX_AGE,
        refresh: bool = False,
        clock: Callable[[], dt.datetime] = _utcnow,
    ) -> None:
        """
        Args:
            directory: Where entries live; created on first write.
            max_age: Entries older than this are misses and get pruned.
            refresh: Ignore existing entries (every lookup misses) but still
                write fresh ones.
            clock: Current-time function (a fake in tests).
        """
        self.directory = directory
        self.max_age = max_age
        self.refresh = refresh
        self._clock = clock
        self._lock = threading.Lock()
        self._writes = 0
        self._write_failed = False
        self._dir_ready = False

    @property
    def writes(self) -> int:
        """Entries written this run."""
        with self._lock:
            return self._writes

    def _path(self, order_number: str, serial: str) -> Path:
        """Return the entry file for one certificate.

        Hashed, so order numbers and serials never have to be valid (or
        non-reserved) file names.

        Args:
            order_number: CertiNext order number.
            serial: Certificate serial number.

        Returns:
            ``<directory>/<sha256>.json``.
        """
        digest = hashlib.sha256(f"{order_number}|{serial}".encode()).hexdigest()
        return self.directory / f"{digest}.json"

    def _fresh(self, fetched_at: dt.datetime) -> bool:
        """Return whether an entry fetched at ``fetched_at`` is still usable.

        Args:
            fetched_at: The entry's download time.

        Returns:
            True when it is no older than :attr:`max_age`.
        """
        return self._clock() - fetched_at <= self.max_age

    def get(self, order_number: str, serial: str) -> CachedInspection | None:
        """Return the cached download for one certificate, if usable.

        Args:
            order_number: CertiNext order number.
            serial: Certificate serial number.

        Returns:
            The entry, or ``None`` when refreshing, absent, expired,
            unreadable, from another layout version, or for a different
            certificate.
        """
        if self.refresh:
            return None
        path = self._path(order_number, serial)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if data.get("version") != _ENTRY_VERSION:
                return None
            if data.get("order_number") != order_number or data.get("serial") != serial:
                return None
            fetched_at = dt.datetime.fromisoformat(data["fetched_at"])
            download, ordered_by = data["download"], data["ordered_by"]
        except FileNotFoundError:
            return None
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
            log.debug("Ignoring unreadable cache entry", path=str(path), error=str(exc))
            return None
        if not (isinstance(download, dict) and isinstance(ordered_by, dict)):
            return None
        if fetched_at.tzinfo is None or not self._fresh(fetched_at):
            return None
        return CachedInspection(download=download, ordered_by=ordered_by, fetched_at=fetched_at)

    def _ensure_dir(self) -> None:
        """Create the cache directory, private to the user on POSIX.

        Raises:
            OSError: If it cannot be created.
        """
        if self._dir_ready:
            return
        self.directory.mkdir(parents=True, exist_ok=True)
        if sys.platform != "win32":
            # mkdir's mode is masked by umask and skips existing parents.
            self.directory.chmod(0o700)
        self._dir_ready = True

    def put(
        self, order_number: str, serial: str, download: dict[str, Any], ordered_by: dict[str, Any]
    ) -> None:
        """Store one certificate's download, replacing any older entry.

        Never raises: a failure is logged (once per run) and skipped, since
        losing a cache entry only costs a download next time.

        Args:
            order_number: CertiNext order number.
            serial: Certificate serial number.
            download: The raw download payload.
            ordered_by: ``{"name": ..., "email": ...}`` from the order detail.
        """
        entry = {
            "version": _ENTRY_VERSION,
            "fetched_at": self._clock().isoformat(),
            "order_number": order_number,
            "serial": serial,
            "download": download,
            "ordered_by": ordered_by,
        }
        path = self._path(order_number, serial)
        tmp: str | None = None
        try:
            with self._lock:
                self._ensure_dir()
            # NamedTemporaryFile creates the file 0600 on POSIX.
            with tempfile.NamedTemporaryFile(
                "w", encoding="utf-8", dir=self.directory, prefix=f".{path.stem}.",
                suffix=".tmp", delete=False,
            ) as fh:
                tmp = fh.name
                json.dump(entry, fh)
            _replace(tmp, path)
            tmp = None
        except (OSError, TypeError, ValueError) as exc:
            with self._lock:
                first, self._write_failed = not self._write_failed, True
            if first:
                log.warning(
                    "Cannot write inspection cache; continuing without saving",
                    path=str(self.directory), error=str(exc),
                )
            return
        finally:
            if tmp is not None:
                with contextlib.suppress(OSError):
                    os.unlink(tmp)
        with self._lock:
            self._writes += 1

    def prune(self) -> int:
        """Delete expired and unreadable entries plus stale temp files.

        Returns:
            How many files were deleted.
        """
        if not self.directory.is_dir():
            return 0
        removed = 0
        for path in self.directory.iterdir():
            if path.suffix == ".tmp":
                with contextlib.suppress(OSError):
                    if time.time() - path.stat().st_mtime > _STALE_TEMP_SECONDS:
                        path.unlink()
                        removed += 1
                continue
            if path.suffix != ".json":
                continue
            try:
                fetched_at = dt.datetime.fromisoformat(
                    json.loads(path.read_text(encoding="utf-8"))["fetched_at"]
                )
                keep = fetched_at.tzinfo is not None and self._fresh(fetched_at)
            except (OSError, ValueError, KeyError, TypeError):
                keep = False
            if not keep:
                with contextlib.suppress(OSError):
                    path.unlink()
                    removed += 1
        return removed
