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

"""Shared opt-in certificate download cache policy (ADR 0022)."""

import datetime as dt
import sys
from pathlib import Path
from typing import Any

import structlog
import typer

from certinext._config import cache_dir
from certinext._inspection_cache import DEFAULT_MAX_AGE, InspectionCache
from certinext.cli_support import prompt_stderr

log = structlog.get_logger()
_CACHE_SUBDIR = "replacement-inspect"
_MAX_AGE_DAYS = DEFAULT_MAX_AGE.days


def _resolve_cache(
    inspect: bool,
    cache: bool | None,
    refresh: bool,
    directory: Path | None,
    max_age_days: int | None = None,
    *,
    inspect_option: str = "--inspect",
) -> bool:
    """Decide whether this run uses the inspection cache.

    ``--refresh-cache``, ``--cache-dir`` and ``--cache-max-age`` imply
    ``--cache``. With none of the cache flags, ask on a terminal (Enter
    means no: reusing weeks-old downloads should be a choice) and stay off
    otherwise, so scheduled runs keep reading live.

    Args:
        inspect: Whether certificate downloads are enabled.
        inspect_option: Command-specific option required to use cached downloads.
        cache: ``--cache`` (True), ``--no-cache`` (False), or neither (None).
        refresh: Whether ``--refresh-cache`` was given.
        directory: The ``--cache-dir`` value, if any.
        max_age_days: The ``--cache-max-age`` value, if any.

    Returns:
        Whether to use the cache.

    Raises:
        typer.BadParameter: On ``--no-cache`` with a flag that implies ``--cache``
            when downloads are enabled.
    """
    implied = refresh or directory is not None or max_age_days is not None
    if not inspect:
        if cache is not None or implied:
            print(f"Cache options ignored: certificate downloads require {inspect_option}.", file=sys.stderr)
        return False
    if cache is False:
        if implied:
            raise typer.BadParameter(
                "--no-cache cannot be combined with --refresh-cache, --cache-dir or --cache-max-age",
                param_hint="--no-cache",
            )
        return False
    if cache or implied:
        return True
    if not sys.stdin.isatty():
        log.info("Inspection cache off (non-interactive); pass --cache to use it")
        return False
    try:
        answer = prompt_stderr(f"Use cached inspections up to {_MAX_AGE_DAYS} days old (faster, may be stale)? [y/N]: ")
    except EOFError:
        print(file=sys.stderr)
        return False
    return answer.strip().lower() in ("y", "yes")


def _build_cache(sess: Any, refresh: bool, directory: Path | None, max_age_days: int) -> InspectionCache:
    """Create the inspection cache for this run.

    Production and sandbox entries live in separate subdirectories, so one
    can never answer for the other.

    Args:
        sess: The session (for :attr:`CertiNextSession.sandbox`).
        refresh: Whether ``--refresh-cache`` was given.
        directory: The ``--cache-dir`` value, or None for the default.
        max_age_days: How old an entry may be and still be used; older
            entries are also pruned.

    Returns:
        The cache.
    """
    base = directory if directory is not None else cache_dir() / _CACHE_SUBDIR
    env = "sandbox" if getattr(sess, "sandbox", False) else "production"
    return InspectionCache(base.expanduser() / env, refresh=refresh, max_age=dt.timedelta(days=max_age_days))
