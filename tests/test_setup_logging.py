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

"""Tests for :func:`certinext.cli_support.setup_logging` and its customization hooks.

The ``extra_priority_keys`` / ``console_quiet_keys`` / ``quiet_loggers``
parameters exist so downstream scripts (ums-certinext-scripts dcv-update) can
use the shared logging setup instead of forking it. These tests pin the hook
behavior and the backward-compatible defaults, plus the ``log_format`` switch
between the default logfmt non-interactive output and the opt-in JSON one.
"""

import logging
import sys
from collections.abc import Iterator

import pytest
import structlog

from certinext.cli_support import (
    LogFormat,
    _drop_keys_processor,
    _reorder_log_keys_processor,
    setup_logging,
)


@pytest.fixture(autouse=True)
def _restore_logging() -> Iterator[None]:
    """Snapshot and restore global logging/structlog state around each test.

    ``setup_logging`` calls ``logging.basicConfig(force=True)``, which removes
    existing root handlers (including pytest's capture handler) and would leak
    configuration into unrelated tests without this restore.
    """
    root = logging.getLogger()
    saved_handlers = root.handlers[:]
    saved_level = root.level
    saved_logger_levels = {
        name: logging.getLogger(name).level
        for name in ("httpx", "httpcore", "keyring", "jaraco", "win32ctypes", "filelock", "nm.wire")
    }
    try:
        yield
    finally:
        root.handlers[:] = saved_handlers
        root.setLevel(saved_level)
        for name, level in saved_logger_levels.items():
            logging.getLogger(name).setLevel(level)
        structlog.contextvars.clear_contextvars()
        structlog.reset_defaults()


def test_reorder_processor_places_extra_keys_after_builtins() -> None:
    """Extra priority keys are ordered right after the built-in fixed fields."""
    processor = _reorder_log_keys_processor(["correlation_id", "pid"])
    event = {
        "domain": "example.edu",
        "pid": 42,
        "event": "hello",
        "correlation_id": "abc",
        "level": "info",
        "timestamp": "t",
    }
    result = processor(None, "info", event)
    assert isinstance(result, dict)
    assert list(result.keys()) == ["timestamp", "level", "event", "correlation_id", "pid", "domain"]


def test_reorder_processor_default_matches_previous_behavior() -> None:
    """With no extra keys, ordering is the pre-hook behavior (timestamp/level/logger/event first)."""
    processor = _reorder_log_keys_processor(())
    event = {"b": 1, "event": "e", "logger": "x", "level": "info", "timestamp": "t", "a": 2}
    result = processor(None, "info", event)
    assert isinstance(result, dict)
    assert list(result.keys()) == ["timestamp", "level", "logger", "event", "b", "a"]


def test_drop_keys_processor_removes_only_named_keys() -> None:
    """The drop processor removes the named keys and tolerates absent ones."""
    processor = _drop_keys_processor(["correlation_id", "pid", "missing"])
    event = {"event": "hello", "correlation_id": "abc", "pid": 42, "domain": "example.edu"}
    result = processor(None, "info", event)
    assert result == {"event": "hello", "domain": "example.edu"}


def _render_foreign_record() -> str:
    """Emit a foreign stdlib record through the configured root handler formatter.

    Returns:
        The formatted log line as the handler would write it to stderr.
    """
    record = logging.LogRecord(
        name="somelib", level=logging.WARNING, pathname=__file__, lineno=1,
        msg="hello from somelib", args=(), exc_info=None,
    )
    handler = logging.getLogger().handlers[0]
    assert handler.formatter is not None
    return handler.formatter.format(record)


def test_console_quiet_keys_hidden_at_verbosity_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    """On a TTY at verbosity 0, console_quiet_keys are dropped from rendered output."""
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True)
    structlog.contextvars.bind_contextvars(correlation_id="abc-123", pid=99)

    setup_logging(0, console_quiet_keys=["correlation_id", "pid"])
    line = _render_foreign_record()
    assert "correlation_id" not in line
    assert "pid" not in line
    assert "hello from somelib" in line


def test_console_quiet_keys_shown_at_verbosity_one(monkeypatch: pytest.MonkeyPatch) -> None:
    """At -v and above the same keys are rendered, so operators can copy them."""
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True)
    structlog.contextvars.bind_contextvars(correlation_id="abc-123", pid=99)

    setup_logging(1, console_quiet_keys=["correlation_id", "pid"])
    line = _render_foreign_record()
    assert "correlation_id" in line
    assert "abc-123" in line


def test_logfmt_is_the_non_interactive_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Non-TTY output defaults to logfmt (key=value), not JSON.

    Splunk and other log aggregators auto-extract key=value pairs with no
    per-sourcetype configuration; JSON only gets that treatment if the whole
    event (including any syslog header) is valid JSON, which cron/syslog
    output never is.
    """
    monkeypatch.setattr(sys.stderr, "isatty", lambda: False)

    setup_logging(0)
    line = _render_foreign_record()
    assert "level=warning" in line
    assert 'event="hello from somelib"' in line
    assert not line.startswith("{")


def test_logfmt_output_carries_quiet_keys_in_priority_order(monkeypatch: pytest.MonkeyPatch) -> None:
    """Non-TTY (cron) output always carries the keys, ordered by extra_priority_keys."""
    monkeypatch.setattr(sys.stderr, "isatty", lambda: False)
    structlog.contextvars.bind_contextvars(correlation_id="abc-123", pid=99)

    setup_logging(
        0,
        extra_priority_keys=["correlation_id", "pid"],
        console_quiet_keys=["correlation_id", "pid"],
    )
    line = _render_foreign_record()
    assert "correlation_id=abc-123" in line
    assert line.index("correlation_id=") < line.index("pid=")
    assert line.index("event=") < line.index("correlation_id=")


def test_json_log_format_opts_back_into_json_output(monkeypatch: pytest.MonkeyPatch) -> None:
    """Explicit log_format=LogFormat.JSON restores the pre-1.1 JSON rendering."""
    monkeypatch.setattr(sys.stderr, "isatty", lambda: False)
    structlog.contextvars.bind_contextvars(correlation_id="abc-123", pid=99)

    setup_logging(
        0,
        log_format=LogFormat.JSON,
        extra_priority_keys=["correlation_id", "pid"],
        console_quiet_keys=["correlation_id", "pid"],
    )
    line = _render_foreign_record()
    assert '"correlation_id": "abc-123"' in line
    assert line.index('"correlation_id"') < line.index('"pid"')
    assert line.index('"event"') < line.index('"correlation_id"')


def test_interactive_output_ignores_log_format(monkeypatch: pytest.MonkeyPatch) -> None:
    """A TTY always renders human-readable console output, regardless of log_format."""
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True)

    setup_logging(0, log_format=LogFormat.JSON)
    line = _render_foreign_record()
    assert not line.startswith("{")
    assert "hello from somelib" in line


def test_quiet_loggers_capped_below_vvvv() -> None:
    """quiet_loggers are capped at WARNING below -vvvv, alongside the built-ins."""
    setup_logging(0, quiet_loggers=["filelock", "nm.wire"])
    assert logging.getLogger("filelock").level == logging.WARNING
    assert logging.getLogger("nm.wire").level == logging.WARNING
    assert logging.getLogger("httpx").level == logging.WARNING


def test_quiet_loggers_left_alone_at_vvvv() -> None:
    """At -vvvv third-party loggers are not capped, including quiet_loggers entries."""
    logging.getLogger("filelock").setLevel(logging.NOTSET)
    setup_logging(4, quiet_loggers=["filelock"])
    assert logging.getLogger("filelock").level == logging.NOTSET
