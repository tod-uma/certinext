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
off by default, truncation keeps *both ends* of the stack (ADR 0015), the output
carries no double quotes for Splunk's KV extractor to choke on, and the visible
line never carries a real newline that journald/rsyslog could split into
fragments.

The quote rule is enforced for the whole event dict by the `_sanitize_quotes`
processor rather than for the traceback alone (ADR 0016); the final section
covers it, including the boundaries it must not overstep - JSON output and the
debug-log sidecar both keep their quotes.
"""

import json
import logging
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
import structlog

from certinext.cli_support import (
    TRACEBACK_BYTE_LIMIT,
    TRACEBACK_HINT,
    LogFormat,
    LogMode,
    format_truncated_traceback,
    log_caught_exception,
    setup_logging,
)
from certinext.exceptions import CertiNextAPIError


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


def _ping(depth: int) -> None:
    """Recurse via :func:`_pong`, building a stack CPython cannot collapse.

    ``[Previous line repeated N more times]`` only collapses *consecutive
    identical* frames, so alternating between two functions defeats it and
    produces a traceback that grows linearly with depth. That is the shape the
    character cap has to handle (ADR 0014 measured ~50KB by depth 300).

    Args:
        depth: Remaining recursion depth.

    Raises:
        RecursionError: At the bottom of the recursion.
    """
    if depth:
        _pong(depth - 1)
        return
    raise RecursionError("maximum recursion depth exceeded")


def _pong(depth: int) -> None:
    """Recurse via :func:`_ping` — the other half of the alternating pair.

    Args:
        depth: Remaining recursion depth.

    Raises:
        RecursionError: Propagated from :func:`_ping`.
    """
    _ping(depth)


def _caught_alternating(depth: int) -> BaseException:
    """Return a caught exception whose traceback is too big for the byte budget.

    Args:
        depth: Recursion depth; each level adds two uncollapsible frames.

    Returns:
        The caught exception, with ``__traceback__`` populated.
    """
    try:
        _ping(depth)
    except RecursionError as exc:
        return exc
    raise AssertionError("unreachable")  # pragma: no cover


# --- format_truncated_traceback ------------------------------------------------

def test_a_deep_self_recursive_stack_survives_whole() -> None:
    """The regression test for ADR 0015: no frame limit, so both ends survive.

    This is the incident shape. A 965-frame ``__send_to_cluster`` redirect loop
    produced a traceback whose innermost frames were structlog's own log
    formatter — the code that happened to occupy frame ~1000, not the fault. The
    previous ``limit=-10`` spent the entire budget there and the journal line
    named nothing useful; the real traceback was 3971 characters and would have
    fitted whole.

    So: the call site *and* the raise site must both be present, untrimmed,
    because CPython's collapsing of repeated frames keeps such a stack small.
    """
    exc = _caught(depth=900)
    formatted = format_truncated_traceback(exc)

    assert len(formatted) <= TRACEBACK_BYTE_LIMIT
    assert "[... traceback truncated" not in formatted, "should have fitted whole"
    # CPython collapsed the repetition instead of emitting 900 frames.
    assert "[Previous line repeated" in formatted
    # Both ends: the outermost caller and the innermost raise site.
    assert "in _caught" in formatted
    assert "in _raise_deeply" in formatted
    assert formatted.rstrip().endswith("RecursionError: maximum recursion depth exceeded")


def test_output_carries_no_double_quotes() -> None:
    """Double quotes are replaced, so Splunk's KV extractor can read the field.

    Splunk's automatic ``key=value`` extraction does not understand ``\\"``
    inside a quoted value: one ``File "..."`` in the rendered ``exception="..."``
    field ends the field early and everything after it is mis-parsed as further
    key/value pairs, corrupting every field on the line. Frame lines are the
    guaranteed source of quotes, so their absence is the assertion.
    """
    formatted = format_truncated_traceback(_caught(depth=3))

    assert '"' not in formatted
    assert "  File '" in formatted, "frame lines should still be readable"


def test_an_explicit_negative_limit_still_keeps_the_innermost_frames() -> None:
    """The ``limit`` passthrough is retained for callers that want it.

    Only the *default* changed to None; a caller asking for innermost-only
    trimming still gets ``traceback.format_exception``'s negative-limit
    behaviour. Asserted against the unlimited formatting rather than by counting
    frame lines, since CPython collapses consecutive identical frames.
    """
    exc = _caught(depth=40)
    innermost = format_truncated_traceback(exc, limit=-5)
    full = format_truncated_traceback(exc)

    assert "in _raise_deeply" in innermost
    # `exc.__traceback__` spans the catching frame down to the raise, so its
    # outermost frame is _caught — dropped by an innermost-only limit, kept by
    # the new default.
    assert "in _caught" not in innermost
    assert "in _caught" in full


def _chained() -> BaseException:
    """Return a caught exception with a ``__cause__`` chain, as httpx produces.

    Returns:
        The outer exception, whose formatting includes both tracebacks.
    """
    try:
        try:
            _raise_deeply(20)
        except RecursionError as inner:
            raise ValueError("outer wrapper") from inner
    except ValueError as exc:
        return exc
    raise AssertionError("unreachable")  # pragma: no cover


def test_frame_limit_alone_does_not_bound_a_chained_traceback() -> None:
    """The frame limit is per chain link, so chaining multiplies it.

    This is why the character cap, not the frame limit, is the bound — and it is
    the common case rather than an edge one: every httpx failure arrives chained
    from httpcore. Pinned so the multiplication can't be quietly assumed away by
    a caller that passes ``limit`` expecting a total.
    """
    exc = _chained()
    # byte_limit disabled, so only the frame limit is in play.
    formatted = format_truncated_traceback(exc, limit=-5, byte_limit=10**6)

    assert "RecursionError" in formatted  # the cause
    assert "ValueError: outer wrapper" in formatted  # the effect
    # Two traceback headers: the limit was applied to each link separately, so
    # the frame budget is spent once per exception in the chain rather than once
    # overall. (Asserted via headers, not frame lines — CPython collapses
    # consecutive identical frames, so line counts understate frame counts.)
    assert formatted.count("Traceback (most recent call last):") == 2


def test_byte_limit_trims_the_middle_and_keeps_both_ends() -> None:
    """Over budget, the head and tail both survive and the middle is elided.

    The tail carries the exception line and innermost frames; the head names the
    call site. Keeping only the tail — the pre-ADR-0015 behaviour — is what left
    a deep-recursion journal line saying nothing about which code path failed.
    """
    exc = _chained()
    capped = format_truncated_traceback(exc, byte_limit=600)

    assert len(capped) <= 600
    # Head: the traceback still opens normally rather than mid-stack.
    assert capped.startswith("Traceback (most recent call last):")
    # Tail: the final exception line — the single most useful part — survives.
    assert capped.rstrip().endswith("ValueError: outer wrapper")
    # The elision sits between them, on its own line.
    assert "\n[... traceback truncated" in capped


def test_byte_limit_leaves_a_short_traceback_untouched() -> None:
    """A traceback already inside the budget is returned verbatim, unmarked."""
    capped = format_truncated_traceback(_caught(), byte_limit=10**6)

    assert "[... traceback truncated" not in capped
    assert capped.startswith("Traceback (most recent call last):")


def test_byte_limit_smaller_than_the_elision_marker_still_bounds_output() -> None:
    """A pathologically small budget still returns at most that many characters.

    The marker alone would exceed it, so the marker is dropped rather than the
    bound being silently violated.
    """
    capped = format_truncated_traceback(_chained(), byte_limit=20)

    assert len(capped) <= 20


def test_truncation_handles_an_exception_that_was_never_raised() -> None:
    """An exception with no __traceback__ formats to just its exception line."""
    formatted = format_truncated_traceback(ValueError("never raised"))

    assert "ValueError: never raised" in formatted
    assert "  File '" not in formatted


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


def test_include_traceback_caps_an_over_budget_stack() -> None:
    """A stack too big for the budget is capped on the visible line, not passed whole.

    Uses the alternating-frame recursion because that is the shape CPython
    *cannot* collapse — a directly self-recursive stack formats compactly enough
    to stay inside the budget (see the ADR 0015 regression test), so it would
    make this assertion vacuous.
    """
    exc = _caught_alternating(depth=200)
    with structlog.testing.capture_logs() as entries:
        log_caught_exception(
            structlog.get_logger(), "Unexpected error", exc, include_traceback=True
        )

    attached = entries[0]["exception"]
    assert attached == format_truncated_traceback(exc)
    assert len(attached) <= TRACEBACK_BYTE_LIMIT
    assert len(attached) < len(format_truncated_traceback(exc, byte_limit=10**6))
    assert "[... traceback truncated" in attached


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

    # Alternating frames, so the visible line genuinely is capped — a directly
    # self-recursive stack fits whole and would prove nothing here.
    exc = _caught_alternating(depth=200)
    log_caught_exception(
        structlog.get_logger(), "Unexpected error", exc, include_traceback=True,
    )

    # The file carries *both* records — the capped operational line and the
    # paired DEBUG one — so the capped traceback is legitimately present. Only
    # the last one, the DEBUG record's, claims to be full-fidelity.
    content = debug_log_path.read_text()
    assert "[... traceback truncated" in format_truncated_traceback(exc)
    sidecar = content[content.rindex("Traceback (most recent call last):"):]

    assert "[... traceback truncated" not in sidecar, "the sidecar was capped too"
    # The sidecar is also byte-exact: the visible line's quote substitution is a
    # transport concession for Splunk, not a change to the record of what failed.
    assert '  File "' in sidecar, "the sidecar's quotes were rewritten too"


# --- _sanitize_quotes (ADR 0016) -----------------------------------------------


def _assert_no_escaped_quote(rendered: str) -> None:
    """Assert no backslash-escaped quote survived into rendered logfmt output.

    ``LogfmtRenderer`` legitimately wraps any value containing whitespace in
    double quotes, so the mere presence of ``"`` on a line proves nothing. The
    corrupting construct is specifically ``\\"`` - an *inner* quote the renderer
    had to escape, which Splunk's ``kv_mode=auto`` extractor does not understand:
    it ends the value there and mis-parses the rest of the line as further
    key/value pairs.

    Args:
        rendered: A rendered log line.
    """
    assert '\\"' not in rendered, f"an escaped inner quote survived: {rendered!r}"


def test_quotes_in_the_error_field_are_sanitized(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A quote in ``str(exc)`` is rewritten, not just one in the traceback.

    This is the gap ADR 0016 closes. Before the processor, only
    :func:`format_truncated_traceback` sanitized its output, so an exception
    whose *message* carried a quote corrupted the line while the traceback
    beside it was safe.
    """
    monkeypatch.setattr(sys.stderr, "isatty", lambda: False)
    setup_logging(0)

    exc = ValueError('HTTP 502: <meta charset="utf-8"> bad gateway')
    log_caught_exception(structlog.get_logger(), "Request failed", exc)

    err = capsys.readouterr().err
    _assert_no_escaped_quote(err)
    assert "charset='utf-8'" in err, "the message text was lost, not just its quotes"


def test_quotes_in_caller_context_are_sanitized(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Arbitrary ``**context`` values are sanitized too.

    ``context`` is the open-ended exposure: every current and future call site
    can attach any value, so it cannot be audited the way a fixed field can.
    """
    monkeypatch.setattr(sys.stderr, "isatty", lambda: False)
    setup_logging(0)

    log_caught_exception(
        structlog.get_logger(),
        "Order lookup failed",
        ValueError("plain message"),
        detail='vendor said "no such order"',
    )

    err = capsys.readouterr().err
    _assert_no_escaped_quote(err)
    assert "'no such order'" in err


def test_quotes_in_the_event_name_are_sanitized(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The ``event`` message is a value like any other and is not exempt."""
    monkeypatch.setattr(sys.stderr, "isatty", lambda: False)
    setup_logging(0)

    structlog.get_logger().error('Could not parse "orderId" from the response')

    err = capsys.readouterr().err
    _assert_no_escaped_quote(err)
    assert "'orderId'" in err


def test_quotes_in_non_string_values_are_sanitized(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A dict value whose repr carries quotes is covered.

    ``fatal_api_error`` logs ``body=exc.body`` - a parsed JSON dict. Python's
    repr uses single quotes until a value contains one, at which point it
    switches to double quotes and the line would break.
    """
    monkeypatch.setattr(sys.stderr, "isatty", lambda: False)
    setup_logging(0)

    structlog.get_logger().error("Full response body", body={"detail": "it's rejected"})

    err = capsys.readouterr().err
    _assert_no_escaped_quote(err)
    assert "rejected" in err


def test_values_without_quotes_are_left_untouched(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sanitizing must not pre-stringify values that carry no quotes.

    ``LogfmtRenderer`` has its own ``bool`` handling - ``True`` renders as a bare
    key and ``False`` as ``false``. Coercing every non-string value to ``str``
    would leak Python's ``True``/``False`` into the log instead, so the processor
    rewrites a non-string value only when its rendered form actually contains a
    quote.
    """
    monkeypatch.setattr(sys.stderr, "isatty", lambda: False)
    setup_logging(0)

    structlog.get_logger().info("Order state", issued=True, revoked=False, count=3)

    err = capsys.readouterr().err
    assert "issued " in err or err.rstrip().endswith("issued"), "bare-key bool form was lost"
    assert "revoked=false" in err
    assert "issued=True" not in err
    assert "count=3" in err


def test_json_output_keeps_its_quotes(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    """JSON mode is deliberately not sanitized.

    JSON escaping is understood by every JSON parser, so rewriting quotes there
    would lose fidelity for no gain - the processor is registered on the logfmt
    chain only.
    """
    monkeypatch.setattr(sys.stderr, "isatty", lambda: False)
    setup_logging(0, log_format=LogFormat.JSON)

    structlog.get_logger().error("Parse failed", detail='vendor said "no"')

    err = capsys.readouterr().err
    assert json.loads(err)["detail"] == 'vendor said "no"'


def test_api_error_with_an_html_body_does_not_corrupt_the_line(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The realistic trigger: a proxy returning HTML instead of JSON.

    ``CertiNextAPIError.__str__`` falls through to embedding a non-dict body
    verbatim, and an HTML error page is wall-to-wall double quotes. Every
    subsequent field on the line - ``correlation_id`` included - used to be
    mis-parsed as key/value pairs, destroying exactly the fields needed to
    investigate the failure.
    """
    monkeypatch.setattr(sys.stderr, "isatty", lambda: False)
    setup_logging(0, extra_priority_keys=["correlation_id"])

    exc = CertiNextAPIError(502, '<html><meta charset="utf-8"></html>')
    log_caught_exception(
        structlog.get_logger(),
        "Zabbix push failed",
        exc,
        correlation_id="abc123",
    )

    err = capsys.readouterr().err
    _assert_no_escaped_quote(err)
    assert "correlation_id=abc123" in err, "the correlation id was swallowed by a broken field"
    assert "error_type=CertiNextAPIError" in err, "fields after the quoted value were lost"


def test_the_debug_sidecar_stays_byte_exact_when_the_line_is_sanitized(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The processor is scoped to the stderr chain, not the sidecar.

    ADR 0012 makes the sidecar the full-fidelity record and ADR 0016 keeps it
    that way: quote substitution is a transport concession for Splunk, not a
    change to the record of what failed. The two chains are separate
    ``ProcessorFormatter`` instances precisely so this holds.
    """
    monkeypatch.setattr(sys.stderr, "isatty", lambda: False)
    debug_log_path = tmp_path / "debug.log"
    setup_logging(0, debug_log_path=debug_log_path)

    exc = ValueError('vendor said "no such order"')
    log_caught_exception(structlog.get_logger(), "Order lookup failed", exc)

    assert '"no such order"' in debug_log_path.read_text(), "the sidecar was sanitized too"
