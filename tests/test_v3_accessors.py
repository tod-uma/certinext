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

"""Tests for the v3 CLM paging helper and read-only accessors."""

import json
from collections.abc import Mapping, Sequence
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from structlog.testing import capture_logs

from certinext._v3 import iter_v3_rows, unwrap_v3
from certinext.api_credentials import ApiCredentialAccessor
from certinext.audit import AuditAccessor
from certinext.client import CertiNextClient
from certinext.session import CertiNextSession
from certinext.users import UserAccessor
from certinext.v3_orders import V3OrderAccessor, V3OrderDetail

_CORPUS = Path(__file__).parent / "fixtures" / "corpus" / "prod"


def _body(filename: str) -> Any:
    """Return the response body of a prod corpus file.

    Args:
        filename: Corpus file name.

    Returns:
        The captured ``response.body``.
    """
    with (_CORPUS / filename).open(encoding="utf-8") as fh:
        return json.load(fh)["response"]["body"]


def _client(*bodies: Any) -> MagicMock:
    """Return a mock client whose ``get`` returns ``bodies`` in order.

    Args:
        *bodies: Response bodies, one per expected call.

    Returns:
        A ``MagicMock`` specced as :class:`CertiNextClient`.
    """
    client = MagicMock(spec=CertiNextClient)
    client.get.side_effect = list(bodies)
    return client


def _page(key: str, ids: range, total: Any) -> dict[str, Any]:
    """Build a v3 envelope with one row per id.

    Args:
        key: The envelope's list key.
        ids: Row ids.
        total: The ``totalResults`` value (int, string or ``None``).

    Returns:
        The envelope dict.
    """
    env: dict[str, Any] = {key: [{"id": str(i)} for i in ids], "pageNumber": 1, "pageSize": 2}
    if total is not None:
        env["totalResults"] = total
    return env


class TestUnwrap:
    """unwrap_v3 handles every envelope shape seen on the wire."""

    def test_string_total(self) -> None:
        """The orders envelope sends totalResults as a string."""
        rows, total = unwrap_v3({"orders": [{"a": 1}], "totalResults": "1694"}, "orders")
        assert rows == [{"a": 1}] and total == 1694

    def test_bare_list(self) -> None:
        """users/detailed is a bare array with no total."""
        assert unwrap_v3([{"a": 1}, "junk"], "users") == ([{"a": 1}], None)

    @pytest.mark.parametrize("body", [{}, {"orders": None}, None, "text", {"orders": [], "totalResults": "n/a"}])
    def test_degenerate(self, body: Any) -> None:
        """Missing keys and odd bodies yield no rows and no total."""
        assert unwrap_v3(body, "orders") == ([], None)

    @pytest.mark.parametrize("body", [{"items": [{"a": 1}]}, {"orders": None}, None, "text"])
    def test_unexpected_envelope_warns(self, body: Any) -> None:
        """A changed envelope is logged, not passed off silently as an empty list."""
        with capture_logs() as logs:
            assert unwrap_v3(body, "orders") == ([], None)
        assert [e["event"] for e in logs] == ["v3_envelope_unexpected"]

    def test_expected_envelope_is_quiet(self) -> None:
        """An empty but well-formed envelope logs nothing."""
        with capture_logs() as logs:
            unwrap_v3({"orders": [], "totalResults": "0"}, "orders")
        assert logs == []


def _events(logs: Sequence[Mapping[str, Any]]) -> list[tuple[str, str]]:
    """Return ``(event, log_level)`` pairs from captured structlog entries.

    Args:
        logs: Entries from :func:`structlog.testing.capture_logs`.

    Returns:
        One pair per entry.
    """
    return [(e["event"], e["log_level"]) for e in logs]


class TestIterRows:
    """iter_v3_rows treats totalResults as a hint and stops on empty, short or repeated pages."""

    def test_full_last_page_costs_one_extra_call(self) -> None:
        """A full page never ends the walk; an exact multiple needs one empty page to confirm."""
        client = _client(_page("x", range(0, 2), "4"), _page("x", range(2, 4), "4"), _page("x", range(0), "4"))
        with capture_logs() as logs:
            rows = list(iter_v3_rows(client, "/p", "x", page_size=2))
        assert [r["id"] for r in rows] == ["0", "1", "2", "3"]
        assert client.get.call_count == 3
        assert client.get.call_args_list[1].kwargs["params"] == {"pageNumber": 2, "pageSize": 2}
        assert logs == []

    def test_short_page_with_total_reached_stops(self) -> None:
        """A short page that reaches the total ends the walk without an extra call."""
        client = _client(_page("x", range(0, 2), 3), _page("x", range(2, 3), 3))
        assert len(list(iter_v3_rows(client, "/p", "x", page_size=2))) == 3
        assert client.get.call_count == 2

    def test_stops_on_short_page_without_total(self) -> None:
        """With no total, a short page ends the walk."""
        client = _client(_page("x", range(0, 2), None), _page("x", range(2, 3), None))
        assert len(list(iter_v3_rows(client, "/p", "x", page_size=2))) == 3

    def test_server_page_cap_keeps_walking(self) -> None:
        """Asked for 4 but capped at 2: short pages continue while the total says rows remain."""
        client = _client(_page("x", range(0, 2), 5), _page("x", range(2, 4), 5), _page("x", range(4, 5), 5))
        rows = list(iter_v3_rows(client, "/p", "x", page_size=4))
        assert [r["id"] for r in rows] == ["0", "1", "2", "3", "4"]
        assert client.get.call_count == 3

    @pytest.mark.parametrize("total", [0, "2", 3])
    def test_stale_low_total_does_not_truncate(self, total: Any) -> None:
        """A total below the real row count (including 0) cannot end a walk of full pages."""
        client = _client(_page("x", range(0, 2), total), _page("x", range(2, 4), total), _page("x", range(4, 5), total))
        assert len(list(iter_v3_rows(client, "/p", "x", page_size=2))) == 5

    def test_empty_first_page(self) -> None:
        """An empty first page yields nothing after one call."""
        client = _client(_page("x", range(0), 0))
        with capture_logs() as logs:
            assert list(iter_v3_rows(client, "/p", "x", page_size=2)) == []
        assert client.get.call_count == 1
        assert logs == []

    def test_repeated_page_stops(self) -> None:
        """A clamped (repeated) page with no total ends the walk with a warning, without duplicating rows."""
        same = _page("x", range(0, 2), None)
        client = _client(same, dict(same), dict(same))
        with capture_logs() as logs:
            assert len(list(iter_v3_rows(client, "/p", "x", page_size=2))) == 2
        assert client.get.call_count == 2
        assert _events(logs) == [("v3_page_repeated", "warning")]

    def test_repeat_after_total_is_a_clean_end(self) -> None:
        """Past the end, a server that repeats its last page is normal: debug, not warning."""
        last = _page("x", range(2, 4), 4)
        client = _client(_page("x", range(0, 2), 4), last, dict(last))
        with capture_logs() as logs:
            assert len(list(iter_v3_rows(client, "/p", "x", page_size=2))) == 4
        assert _events(logs) == [("v3_page_repeated", "debug")]

    def test_walk_short_of_total_warns(self) -> None:
        """Ending with fewer rows than the reported total logs v3_walk_incomplete."""
        client = _client(_page("x", range(0, 2), 9), _page("x", range(0), 9))
        with capture_logs() as logs:
            assert len(list(iter_v3_rows(client, "/p", "x", page_size=2))) == 2
        assert _events(logs) == [("v3_walk_incomplete", "warning")]

    def test_record_limit_and_filters(self) -> None:
        """size_param and filters reach the query string."""
        client = _client(_page("x", range(0, 1), 1))
        list(iter_v3_rows(client, "/p", "x", page_size=50, size_param="recordLimit", params={"f": "v"}))
        assert client.get.call_args.kwargs["params"] == {"f": "v", "pageNumber": 1, "recordLimit": 50}

    def test_bad_page_size(self) -> None:
        """A page size below 1 is rejected before any request."""
        client = _client()
        with pytest.raises(ValueError):
            list(iter_v3_rows(client, "/p", "x", page_size=0))
        client.get.assert_not_called()


class TestV3Orders:
    """V3OrderAccessor."""

    def test_get_list_parses_corpus(self) -> None:
        """The prod capture parses; order dates are UTC-aware (verified against v2).

        The capture is one 100-row page of 1694, so asking for 1000 is the
        server-cap case: the pager walks on and the empty second page ends it.
        """
        body = _body("v3-orders.json")
        client = _client(body, {"orders": [], "totalResults": body["totalResults"]})
        orders = V3OrderAccessor(client).get_list(page_size=1000)
        assert client.get.call_count == 2
        assert len(orders) == len(body["orders"])
        issued = next(o for o in orders if o.expires_on is not None)
        assert isinstance(issued.expires_on, datetime) and issued.expires_on.tzinfo == timezone.utc

    @pytest.mark.parametrize(("flag", "sent"), [(True, 1), (False, 0)])
    def test_exclude_ignored_is_numeric(self, flag: bool, sent: int) -> None:
        """excludeIgnored goes out as 0/1; true/false get 400 from the API."""
        client = _client({"orders": [], "totalResults": "0"})
        V3OrderAccessor(client).get_list(exclude_ignored=flag)
        assert client.get.call_args.kwargs["params"]["excludeIgnored"] == sent

    def test_exclude_ignored_omitted_by_default(self) -> None:
        """No filter is sent unless asked for."""
        client = _client({"orders": [], "totalResults": "0"})
        V3OrderAccessor(client).get_page()
        assert "excludeIgnored" not in client.get.call_args.kwargs["params"]

    def test_get_detail_by_order_id(self) -> None:
        """get() hits orders/{orderId} and flattens orderedBy."""
        body = _body("v3-orders-detail.json")
        client = _client(body)
        detail = V3OrderAccessor(client).get(body["orderId"])
        client.get.assert_called_once_with(f"/api/v3/certinext/orders/{body['orderId']}")
        assert isinstance(detail, V3OrderDetail)
        assert detail.ordered_by == body["orderedBy"]["user"]
        assert detail.certificate is not None and detail.certificate.serial_number
        assert detail.renewal_notifications_enabled is False


class TestAudit:
    """AuditAccessor."""

    def test_date_window(self) -> None:
        """since/until go out as ISO days in fromDate/toDate."""
        client = _client({"auditLogs": [], "totalResults": 0})
        AuditAccessor(client).get_list(since=date(2026, 11, 22), until=date(2026, 11, 23))
        params = client.get.call_args.kwargs["params"]
        assert params["fromDate"] == "2026-11-22" and params["toDate"] == "2026-11-23"

    def test_list_modules(self) -> None:
        """The module list is returned as strings."""
        body = _body("v3-audit-logs-modules.json")
        assert AuditAccessor(_client(body)).list_modules() == body

    def test_list_modules_non_list(self) -> None:
        """An unexpected body yields an empty list, not an error."""
        assert AuditAccessor(_client({"status": "success"})).list_modules() == []


class TestUsers:
    """UserAccessor."""

    def test_get_list_pages_by_record_limit(self) -> None:
        """users pages with recordLimit; pageSize is ignored there."""
        client = _client(_body("v3-users.json"))
        users = UserAccessor(client).get_list()
        assert users and "recordLimit" in client.get.call_args.kwargs["params"]
        assert "pageSize" not in client.get.call_args.kwargs["params"]

    def test_list_detailed_flags(self) -> None:
        """users/detailed is a bare array; "0"/"1" flags become bools."""
        details = UserAccessor(_client(_body("v3-users-detailed.json"))).list_detailed()
        assert details and all(isinstance(d.is_active, bool) for d in details)

    def test_roles_and_permissions(self) -> None:
        """Roles page by recordLimit; permissions are fetched by role id."""
        roles_body, perms_body = _body("v3-users-roles.json"), _body("v3-users-roles-permissions.json")
        client = _client(roles_body, perms_body)
        acc = UserAccessor(client)
        roles = acc.list_roles()
        assert "recordLimit" in client.get.call_args.kwargs["params"]
        role_id = roles[0].custom_role_id
        assert role_id is not None
        perms = acc.role_permissions(role_id)
        assert client.get.call_args.args[0] == f"/api/v3/certinext/users/roles/{role_id}/permissions"
        assert len(perms) == len(perms_body["permissions"])

    def test_group_members_joins_user_ids(self) -> None:
        """userIds is sent comma-separated."""
        client = _client(_body("v3-users-groups-members.json"))
        members = UserAccessor(client).group_members(user_ids=["id-a", "id-b"])
        assert client.get.call_args.kwargs["params"] == {"userIds": "id-a,id-b"}
        assert members

    @pytest.mark.parametrize("kwargs", [{}, {"user_ids": []}])
    def test_group_members_needs_an_argument(self, kwargs: dict[str, Any]) -> None:
        """Neither argument (or no ids) is refused locally instead of a 400."""
        client = _client()
        with pytest.raises(ValueError):
            UserAccessor(client).group_members(**kwargs)
        client.get.assert_not_called()

    def test_group_members_rejects_bare_string(self) -> None:
        """A bare str would iterate by character (userIds=i,d,-,a); it is refused."""
        client = _client()
        with pytest.raises(TypeError, match="not a str"):
            UserAccessor(client).group_members(user_ids="id-abc")
        client.get.assert_not_called()


_BAD_IDS = ["", ".", "..", "a/b", "../x", "a?b=1", "a#b", "a\\b"]


class TestPathSegmentGuard:
    """Caller ids cannot leave the route their path was built for (R2 finding 4)."""

    @pytest.mark.parametrize("bad", _BAD_IDS)
    def test_v3_order_get_rejects(self, bad: str) -> None:
        """v3 orders/{id} refuses a non-segment id before any request."""
        client = _client()
        with pytest.raises(ValueError):
            V3OrderAccessor(client).get(bad)
        client.get.assert_not_called()

    @pytest.mark.parametrize("bad", _BAD_IDS)
    def test_role_permissions_rejects(self, bad: str) -> None:
        """users/roles/{id}/permissions refuses a non-segment id before any request."""
        client = _client()
        with pytest.raises(ValueError):
            UserAccessor(client).role_permissions(bad)
        client.get.assert_not_called()


def test_api_credentials_get_list() -> None:
    """The credentials list parses from the prod capture."""
    body = _body("v3-apis.json")
    creds = ApiCredentialAccessor(_client(body)).get_list()
    assert len(creds) == len(body["credentials"])


def test_session_mounts_v3_accessors() -> None:
    """A session exposes every v3 accessor."""
    sess = CertiNextSession(client_id="x", client_secret="y")
    assert isinstance(sess.v3_orders, V3OrderAccessor)
    assert isinstance(sess.audit, AuditAccessor)
    assert isinstance(sess.users, UserAccessor)
    assert isinstance(sess.api_credentials, ApiCredentialAccessor)
