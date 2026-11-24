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

"""Tests for typed DCV attempt history and details (GitLab #42)."""

import json
from datetime import timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from certinext.models.dcv_attempts import SSLCOM_LATEST, DcvAttempt, DcvAttemptSummary
from certinext.models.domains import Domain

_CORPUS = Path(__file__).parent / "fixtures" / "corpus" / "prod"


def _body(name: str) -> Any:
    """Return the response body of a production corpus file.

    Args:
        name: Corpus file name.

    Returns:
        The captured ``response.body``.
    """
    with (_CORPUS / name).open(encoding="utf-8") as fh:
        return json.load(fh)["response"]["body"]


def _row(attempt_id: str) -> dict[str, Any]:
    """Return a minimal emSign-style history row.

    Args:
        attempt_id: The row's attempt id.

    Returns:
        A wire-shaped row dict.
    """
    return {"attemptId": attempt_id, "attemptedAt": "2026-10-26T19:12:49Z", "overallStatus": "VERIFIED"}


def _page(ids: list[str], total: int) -> dict[str, Any]:
    """Return a history wrapper page.

    Args:
        ids: Attempt ids on this page.
        total: The ``totalElements`` value.

    Returns:
        A wire-shaped wrapper dict.
    """
    return {"content": [_row(i) for i in ids], "page": 0, "size": len(ids), "totalElements": total}


class TestDcvAttemptsPager:
    """Domain.dcv_attempts() follows offset/limit paging to the end."""

    def test_single_page(self, domain: Domain, mock_client: MagicMock) -> None:
        """One page holding everything takes one request with offset 0, limit 50."""
        mock_client.get.return_value = _page(["3", "2", "1"], total=3)
        rows = domain.dcv_attempts()
        assert [r.attempt_id for r in rows] == ["3", "2", "1"]
        assert all(isinstance(r, DcvAttemptSummary) for r in rows)
        mock_client.get.assert_called_once_with(
            f"/api/certinext/v2/domains/{domain.id}/dcv/attempts", params={"offset": 0, "limit": 50}
        )

    def test_offset_advances_by_rows(self, domain: Domain, mock_client: MagicMock) -> None:
        """offset is a row offset: it advances by the rows received, not by one page."""
        mock_client.get.side_effect = [_page(["5", "4"], 5), _page(["3", "2"], 5), _page(["1"], 5)]
        rows = domain.dcv_attempts(page_size=2)
        assert [r.attempt_id for r in rows] == ["5", "4", "3", "2", "1"]
        offsets = [c.kwargs["params"]["offset"] for c in mock_client.get.call_args_list]
        assert offsets == [0, 2, 4]

    def test_empty_page_ends_the_walk(self, domain: Domain, mock_client: MagicMock) -> None:
        """An empty page stops paging even if totalElements claims more rows."""
        mock_client.get.side_effect = [_page(["2", "1"], 10), _page([], 10)]
        assert len(domain.dcv_attempts(page_size=2)) == 2
        assert mock_client.get.call_count == 2

    def test_under_reported_total_does_not_truncate(self, domain: Domain, mock_client: MagicMock) -> None:
        """A full page is never the end: rows past an under-reported totalElements are kept."""
        mock_client.get.side_effect = [_page(["4", "3"], 2), _page(["2", "1"], 2), _page([], 2)]
        rows = domain.dcv_attempts(page_size=2)
        assert [r.attempt_id for r in rows] == ["4", "3", "2", "1"]
        assert mock_client.get.call_count == 3

    def test_short_page_before_total_continues(self, domain: Domain, mock_client: MagicMock) -> None:
        """A short page short of totalElements (a lower server cap) does not end the walk."""
        mock_client.get.side_effect = [_page(["3", "2"], 3), _page(["1"], 3)]
        rows = domain.dcv_attempts(page_size=50)
        assert [r.attempt_id for r in rows] == ["3", "2", "1"]
        offsets = [c.kwargs["params"]["offset"] for c in mock_client.get.call_args_list]
        assert offsets == [0, 2]

    def test_full_last_page_costs_one_empty_request(self, domain: Domain, mock_client: MagicMock) -> None:
        """A history that is an exact multiple of page_size ends on the following empty page."""
        mock_client.get.side_effect = [_page(["2", "1"], 2), _page([], 2)]
        assert len(domain.dcv_attempts(page_size=2)) == 2
        assert mock_client.get.call_count == 2

    def test_bare_list_short_page_stops(self, domain: Domain, mock_client: MagicMock) -> None:
        """Without totalElements, a short page is the last one."""
        mock_client.get.return_value = [_row("1")]
        assert len(domain.dcv_attempts(page_size=2)) == 1
        assert mock_client.get.call_count == 1

    def test_offset_ignored_stops_without_repeats(self, domain: Domain, mock_client: MagicMock) -> None:
        """A bare-list server that ignores offset ends after the repeat, adding it once."""
        mock_client.get.return_value = [_row("2"), _row("1")]
        rows = domain.dcv_attempts(page_size=2)
        assert [r.attempt_id for r in rows] == ["2", "1"]
        assert mock_client.get.call_count == 2

    @pytest.mark.parametrize("size", [0, 51])
    def test_page_size_bounds(self, domain: Domain, mock_client: MagicMock, size: int) -> None:
        """page_size outside 1-50 is refused before any request."""
        with pytest.raises(ValueError, match="page_size"):
            domain.dcv_attempts(page_size=size)
        mock_client.get.assert_not_called()

    def test_sslcom_row(self, domain: Domain, mock_client: MagicMock) -> None:
        """An SSL.com history row parses with only attemptId and overallStatus."""
        mock_client.get.return_value = _body("domains-dcv-attempts-sslcom.json")
        (row,) = domain.dcv_attempts()
        assert row.attempt_id == SSLCOM_LATEST
        assert row.is_sslcom_latest
        assert row.attempted_at is None
        assert row.overall_status == "VERIFIED"

    @pytest.mark.parametrize("wire", ["2026-10-26T19:12:49Z", "2026-10-26T19:12:49", "2026-10-26 19:12:49"])
    def test_attempted_at_is_always_utc_aware(self, wire: str) -> None:
        """attemptedAt is UTC-aware with or without a Z, like attemptTimestamp (R2b finding 13)."""
        row = DcvAttemptSummary.model_validate({"attemptId": "1", "attemptedAt": wire})
        assert row.attempted_at is not None
        assert row.attempted_at.utcoffset() is not None
        assert row.attempted_at.astimezone(timezone.utc).hour == 19


class TestGetDcvAttempt:
    """Domain.get_dcv_attempt() returns a typed DcvAttempt."""

    def test_calls_attempt_path(self, domain: Domain, mock_client: MagicMock) -> None:
        """It GETs /domains/{id}/dcv/attempts/{attemptId}."""
        mock_client.get.return_value = {"status": "VERIFIED"}
        domain.get_dcv_attempt("729645")
        mock_client.get.assert_called_once_with(f"/api/certinext/v2/domains/{domain.id}/dcv/attempts/729645")

    @pytest.mark.parametrize("bad", ["1/../../x", "1/2", ".."])
    def test_attempt_id_must_be_one_path_segment(self, domain: Domain, mock_client: MagicMock, bad: str) -> None:
        """An id that would change the route is refused before any request (R2b finding 12)."""
        with pytest.raises(ValueError, match="path segment"):
            domain.get_dcv_attempt(bad)
        mock_client.get.assert_not_called()

    def test_emsign_attempt_id_filled_in_raw_untouched(self, domain: Domain, mock_client: MagicMock) -> None:
        """The wire lacks attemptId for emSign; the model fills it, as_dict() does not."""
        payload = _body("domains-dcv-attempts-detail.json")
        assert "attemptId" not in payload
        mock_client.get.return_value = payload
        attempt = domain.get_dcv_attempt("729645")
        assert attempt.attempt_id == "729645"
        assert attempt.as_dict() is payload
        assert "attemptId" not in attempt.as_dict()

    def test_sslcom_attempt(self, domain: Domain, mock_client: MagicMock) -> None:
        """An SSL.com attempt carries CA diagnostics and the sentinel id."""
        mock_client.get.return_value = _body("domains-dcv-attempts-sslcom-detail.json")
        attempt = domain.get_dcv_attempt(SSLCOM_LATEST)
        assert attempt.is_sslcom_latest
        assert attempt.diagnostics is not None
        assert attempt.diagnostics.ca_status == "VALIDATED"
        assert attempt.diagnostics.validated_by == "SSLCOM"
        assert attempt.diagnostics.covers_subdomains is True
        assert attempt.diagnostics.valid_till is not None
        assert attempt.diagnostics.valid_till.tzinfo is not None
        assert attempt.diagnostics.perspectives == []


class TestLatestDcvAttempt:
    """Domain.latest_dcv_attempt() goes history -> by-id and never uses /last."""

    def test_newest_row_then_by_id(self, domain: Domain, mock_client: MagicMock) -> None:
        """It reads one history row, then fetches that attempt by id."""
        mock_client.get.side_effect = [_page(["9"], 4), {"status": "VERIFIED", "diagnostics": {}}]
        attempt = domain.latest_dcv_attempt()
        assert isinstance(attempt, DcvAttempt)
        assert attempt.attempt_id == "9"
        paths = [c.args[0] for c in mock_client.get.call_args_list]
        assert paths == [
            f"/api/certinext/v2/domains/{domain.id}/dcv/attempts",
            f"/api/certinext/v2/domains/{domain.id}/dcv/attempts/9",
        ]
        assert mock_client.get.call_args_list[0].kwargs["params"] == {"offset": 0, "limit": 1}
        assert not any(p.endswith("/last") for p in paths)

    def test_no_attempts_returns_none(self, domain: Domain, mock_client: MagicMock) -> None:
        """A domain with an empty history has no latest attempt."""
        mock_client.get.return_value = _page([], 0)
        assert domain.latest_dcv_attempt() is None
        assert mock_client.get.call_count == 1


class TestDeprecatedRawMethods:
    """The raw 1.x methods still work but warn."""

    def test_last_dcv_attempt_warns(self, domain: Domain, mock_client: MagicMock) -> None:
        """last_dcv_attempt() emits a DeprecationWarning and still returns the raw dict."""
        mock_client.get.return_value = {"status": "VERIFIED"}
        with pytest.warns(DeprecationWarning, match="latest_dcv_attempt"):
            assert domain.last_dcv_attempt() == {"status": "VERIFIED"}

    def test_dcv_attempt_history_warns(self, domain: Domain, mock_client: MagicMock) -> None:
        """dcv_attempt_history() emits a DeprecationWarning and still returns the raw body."""
        mock_client.get.return_value = {"content": []}
        with pytest.warns(DeprecationWarning, match="dcv_attempts"):
            assert domain.dcv_attempt_history() == {"content": []}


class TestLeniency:
    """Malformed fields degrade to None/empty instead of raising (ADR 0005)."""

    def test_junk_diagnostics(self) -> None:
        """Wrong-typed nested values do not fail validation."""
        attempt = DcvAttempt.model_validate({"diagnostics": "oops"})
        assert attempt.diagnostics is None
        diag = DcvAttempt.model_validate(
            {
                "diagnostics": {
                    "perspectives": None,
                    "nextSteps": "x",
                    "consensus": [],
                    "schemaVersion": "abc",
                    "coversSubdomains": "0",
                    "tokenIsStale": None,
                    "attemptTimestamp": "not a date",
                }
            }
        ).diagnostics
        assert diag is not None
        assert diag.perspectives == []
        assert diag.next_steps == []
        assert diag.consensus is None
        assert diag.schema_version is None
        assert diag.covers_subdomains is False
        assert diag.token_is_stale is None
        assert diag.attempt_timestamp is None

    def test_non_dict_list_elements_dropped(self) -> None:
        """Non-dict elements of a dict-list field are dropped, not fatal; the wire keeps them."""
        payload = {
            "diagnostics": {
                "perspectives": ["bad", {"resolver": "a"}, None],
                "nextSteps": [{"key": "k"}, 7],
            }
        }
        attempt = DcvAttempt.model_validate(payload)
        diag = attempt.diagnostics
        assert diag is not None
        assert diag.perspectives == [{"resolver": "a"}]
        assert diag.next_steps == [{"key": "k"}]
        assert attempt.as_dict()["diagnostics"]["perspectives"] == ["bad", {"resolver": "a"}, None]

    def test_numeric_attempt_id_becomes_str(self) -> None:
        """An integer attemptId is coerced to str."""
        assert DcvAttemptSummary.model_validate({"attemptId": 729645}).attempt_id == "729645"


class TestCorpus:
    """Facts established from the production corpus."""

    def test_emsign_attempt_timestamp_is_utc(self) -> None:
        """The detail's offset-less attemptTimestamp equals the history row's Z time."""
        detail = DcvAttempt.model_validate(_body("domains-dcv-attempts-detail.json"))
        newest = DcvAttemptSummary.model_validate(_body("domains-dcv-attempts.json")["content"][0])
        assert detail.diagnostics is not None
        assert detail.diagnostics.attempt_timestamp is not None
        assert detail.diagnostics.attempt_timestamp.tzinfo == timezone.utc
        assert detail.diagnostics.attempt_timestamp == newest.attempted_at

    def test_emsign_detail_has_perspectives(self) -> None:
        """emSign diagnostics carry per-resolver perspectives and consensus."""
        diag = DcvAttempt.model_validate(_body("domains-dcv-attempts-detail.json")).diagnostics
        assert diag is not None
        assert diag.perspectives
        assert diag.consensus is not None
        assert diag.ca_status is None
