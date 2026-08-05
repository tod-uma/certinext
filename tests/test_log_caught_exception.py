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

"""Tests for :func:`certinext.cli_support.log_caught_exception` and its truncation.

This helper was promoted out of two byte-identical downstream copies (ADR 0013)
and gained an opt-in traceback on the visible line (ADR 0014). The tests here
pin the parts that make it safe to call from cron-fed scripts: the traceback is
off by default, truncation keeps the *innermost* frames, and the visible line
never carries a real newline that journald/rsyslog could split into fragments.
"""

import logging
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
import structlog

from certinext.cli_support import (
    TRACEBACK_FRAME_LIMIT,
    TRACEBACK_HINT,
    LogMode,
    format_truncated_traceback,
    log_caught_exception,
    setup_logging,
)


@pytest.fixture(autouse=True)
def _restore_logging() -> Iterator[None]:
    """Snapshot and restore global logging/structlog state around each test.

    ``setup_logging`` calls ``logging.basicConfig(force=True)``, which removes
    pytest's capture handler and would otherwise leak into unrelated tests.
    """
    root = logging.getLogger()
    saved_handlers = root.handlers[:]
    saved_level = root.level
    try:
        yield
    finally:
        root.handlers[:] = saved_handlers
        root.setLevel(saved_level)
        structlog.contextvars.clear_contextvars()
        structlog.reset_defaults()


def _raise_deeply(depth: int) -> None:
    """Recurse *depth* times then raise, to build a stack worth truncating.

    Args:
        depth: Remaining recursion depth.

    Raises:
        RecursionError: At the bottom of the recursion.
    """
    if depth:
        _raise_deeply(depth - 1)
        return
    raise RecursionError("maximum recursion depth exceeded")


def _caught(depth: int = 0) -> BaseException:
    """Return a raised-and-caught exception with a real traceback attached.

    Args:
        depth: Extra frames to build below the caller.

    Returns:
        The caught exception, with ``__traceback__`` populated.
    """
    try:
        _raise_deeply(depth)
    except RecursionError as exc:
        return exc
    raise AssertionError("unreachable")  # pragma: no cover


# --- format_truncated_traceback ------------------------------------------------

def test_truncation_keeps_the_innermost_frames_and_the_exception_line() -> None:
    """Truncation must keep the *end* of the stack, where the actual error is.

    ``traceback.format_exception``'s ``limit`` counts from the outermost frame
    when positive; the helper negates it so the innermost frames survive. Getting
    this backwards would keep the least informative half of a deep stack, which
    is also exactly what rsyslog's 8K tail truncation would do to us (ADR 0014).

    Asserted by comparing against the untruncated formatting rather than by
    counting ``File "`` lines: CPython collapses consecutive identical frames
    into ``[Previous line repeated N more times]``, so for a self-recursive
    stack the line count is not the frame count.
    """
    exc = _caught(depth=40)
    truncated = format_truncated_traceback(exc, limit=5)
    full = format_truncated_traceback(exc, limit=10_000)

    assert truncated.startswith("Traceback (most recent call last):")
    assert "RecursionError: maximum recursion depth exceeded" in truncated
    # The raise site is the innermost frame, so it must survive truncation.
    assert "_raise_deeply" in truncated
    assert len(truncated) < len(full), "truncation did not actually shorten the stack"
    # `exc.__traceback__` spans the catching frame down to the raise, so its
    # outermost frame is _caught — and that is what truncation drops first.
    assert "in _caught" in full
    assert "in _caught" not in truncated


def test_truncation_is_a_no_op_on_a_stack_shorter_than_the_limit() -> None:
    """A shallow traceback is returned whole rather than padded or trimmed."""
    exc = _caught()
    assert format_truncated_traceback(exc, limit=TRACEBACK_FRAME_LIMIT) == (
        format_truncated_traceback(exc, limit=10_000)
    )


def test_truncation_handles_an_exception_that_was_never_raised() -> None:
    """An exception with no __traceback__ formats to just its exception line."""
    formatted = format_truncated_traceback(ValueError("never raised"))

    assert "ValueError: never raised" in formatted
    assert "  File \"" not in formatted


# --- log_caught_exception -----------------------------------------------------

def test_default_omits_the_traceback_and_offers_the_hint() -> None:
    """Without include_traceback the visible line stays concise.

    This is the behaviour that keeps a per-domain loop from dumping one stack
    per iteration, so it is pinned as the default rather than left implicit.
    """
    with structlog.testing.capture_logs() as entries:
        log_caught_exception(structlog.get_logger(), "Failed to refresh domain", _caught())

    visible = entries[0]
    assert visible["log_level"] == "error"
    assert visible["error_type"] == "RecursionError"
    assert visible["hint"] == TRACEBACK_HINT
    assert "exception" not in visible


def test_include_traceback_attaches_the_stack_and_drops_the_hint() -> None:
    """With include_traceback the stack replaces the now-pointless re-run hint."""
    with structlog.testing.capture_logs() as entries:
        log_caught_exception(
            structlog.get_logger(), "Unexpected error", _caught(depth=3), include_traceback=True
        )

    visible = entries[0]
    assert "Traceback (most recent call last):" in visible["exception"]
    assert "RecursionError" in visible["exception"]
    assert "hint" not in visible


def test_include_traceback_truncates_to_the_frame_limit() -> None:
    """A deep stack on the visible line is trimmed, not passed through whole."""
    exc = _caught(depth=60)
    with structlog.testing.capture_logs() as entries:
        log_caught_exception(
            structlog.get_logger(), "Unexpected error", exc, include_traceback=True
        )

    attached = entries[0]["exception"]
    assert attached == format_truncated_traceback(exc, limit=TRACEBACK_FRAME_LIMIT)
    assert len(attached) < len(format_truncated_traceback(exc, limit=10_000))


def test_level_warning_downgrades_only_the_visible_line() -> None:
    """level="warning" applies to the concise line; the paired record stays debug."""
    with structlog.testing.capture_logs() as entries:
        log_caught_exception(
            structlog.get_logger(), "Failed to refresh domain", _caught(),
            level="warning", domain="example.edu",
        )

    assert [e["log_level"] for e in entries] == ["warning", "debug"]
    # Context reaches both records, so the debug traceback is attributable.
    assert all(e["domain"] == "example.edu" for e in entries)


def test_context_fields_reach_both_records() -> None:
    """Extra context is attached to the concise line and the debug traceback alike."""
    with structlog.testing.capture_logs() as entries:
        log_caught_exception(
            structlog.get_logger(), "Unexpected error", _caught(), attempt=2,
        )

    assert len(entries) == 2
    assert all(e["attempt"] == 2 for e in entries)


# --- end-to-end syslog safety -------------------------------------------------

def test_attached_traceback_stays_on_one_logfmt_line(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The visible line must never contain a real newline.

    journald and rsyslog split a message on newlines, so an unescaped traceback
    would be indexed as fragments — worse than having no traceback at all.
    LogfmtRenderer escapes them to a literal backslash-n; this pins that end to
    end rather than trusting the renderer's docs.
    """
    monkeypatch.setattr(sys.stderr, "isatty", lambda: False)
    setup_logging(0, log_mode=LogMode.VERBOSE)

    log_caught_exception(
        structlog.get_logger(), "Zabbix push failed", _caught(depth=5),
        include_traceback=True, env="prod",
    )

    err = capsys.readouterr().err.rstrip("\n")
    assert err.count("\n") == 0, "the traceback was not escaped onto a single line"
    assert 'exception="Traceback (most recent call last):\\n' in err
    assert "env=prod" in err
    assert "RecursionError" in err


def test_full_traceback_still_reaches_the_debug_sidecar_untruncated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Truncation applies to the visible line only; the file keeps everything.

    ADR 0014 trades journal volume for triage speed on the assumption that the
    sidecar remains the full-fidelity copy. If truncation leaked into the paired
    DEBUG record, that trade would silently stop holding.

    This also covers the ``exc_info=exc`` choice in the helper: with
    ``exc_info=True`` the traceback is resolved from ``sys.exc_info()``, which is
    empty here because the exception was caught in another function — the debug
    record would carry no traceback at all and this assertion would fail.
    """
    monkeypatch.setattr(sys.stderr, "isatty", lambda: False)
    debug_log_path = tmp_path / "debug.log"
    setup_logging(0, debug_log_path=debug_log_path)

    exc = _caught(depth=60)
    log_caught_exception(
        structlog.get_logger(), "Unexpected error", exc, include_traceback=True,
    )

    content = debug_log_path.read_text()
    # The outermost frame truncation drops (see the truncation test) is _caught.
    # Its presence in the file proves the sidecar kept the whole stack.
    assert "in _caught" not in format_truncated_traceback(exc, limit=TRACEBACK_FRAME_LIMIT)
    assert "in _caught" in content, "the sidecar's traceback was truncated too"
