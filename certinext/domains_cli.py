#!/usr/bin/env python3
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

"""Manage CertiNext domains via the REST API."""

import argparse
import dataclasses
import json
from typing import Any

from tabulate import tabulate

import certinext
from certinext._cli import add_connection_args, apply_sandbox, build_session
from certinext.domains import Domain


def _show_domain(domain: Domain, use_json: bool) -> None:
    if use_json:
        print(json.dumps(domain.as_dict(), indent=2))
    else:
        print(domain)


def _show_domains(domains: list[Domain], use_json: bool) -> None:
    if use_json:
        print(json.dumps([d.as_dict() for d in domains], indent=2))
    else:
        if not domains:
            print("(no domains)")
            return
        print(tabulate([d.to_row() for d in domains], headers="keys", tablefmt="simple"))


def _show_data(data: dict[str, Any] | list[Any], use_json: bool) -> None:
    if use_json:
        print(json.dumps(data, indent=2))
        return
    if isinstance(data, list):
        if data and isinstance(data[0], dict):
            print(tabulate(data, headers="keys", tablefmt="simple"))
        else:
            for item in data:
                print(item)
    else:
        print(tabulate(list(data.items()), tablefmt="simple"))


# --- subcommand handlers ---

def cmd_list(args: argparse.Namespace, sess: certinext.CertiNextSession) -> None:
    kwargs: dict[str, Any] = {}
    if args.offset is not None:
        kwargs["offset"] = args.offset
    if args.limit is not None:
        kwargs["limit"] = args.limit
    _show_domains(sess.domain.get_list(**kwargs), args.json)


def cmd_get(args: argparse.Namespace, sess: certinext.CertiNextSession) -> None:
    _show_domain(sess.domain.get(args.id), args.json)


def cmd_create(args: argparse.Namespace, sess: certinext.CertiNextSession) -> None:
    fields: dict[str, str] = {}
    if args.extra:
        for pair in args.extra:
            key, _, value = pair.partition("=")
            fields[key] = value
    _show_domain(sess.domain.create(args.name, **fields), args.json)


def cmd_deactivate(args: argparse.Namespace, sess: certinext.CertiNextSession) -> None:
    if not args.yes:
        confirm = input(f"Deactivate domain '{args.id}'? [y/N] ").strip().lower()
        if confirm != "y":
            print("Aborted.")
            return
    _show_domain(sess.domain.get(args.id).deactivate(), args.json)


def cmd_get_dcv(args: argparse.Namespace, sess: certinext.CertiNextSession) -> None:
    _show_data(dataclasses.asdict(sess.domain.get(args.id).get_dcv()), args.json)


def cmd_verify_dcv(args: argparse.Namespace, sess: certinext.CertiNextSession) -> None:
    _show_data(sess.domain.get(args.id).verify(), args.json)


def cmd_change_dcv_method(args: argparse.Namespace, sess: certinext.CertiNextSession) -> None:
    _show_data(sess.domain.get(args.id).change_dcv_method(args.method), args.json)


def cmd_last_dcv_attempt(args: argparse.Namespace, sess: certinext.CertiNextSession) -> None:
    _show_data(sess.domain.get(args.id).last_dcv_attempt(), args.json)


def cmd_dcv_attempt_history(args: argparse.Namespace, sess: certinext.CertiNextSession) -> None:
    _show_data(sess.domain.get(args.id).dcv_attempt_history(), args.json)


# --- parser setup ---

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="certinext-domains",
        description="Manage CertiNext domains",
    )
    parser.add_argument(
        "--json", action="store_true", default=False,
        help="Output raw JSON instead of tabular format",
    )

    conn = parser.add_argument_group("connection")
    add_connection_args(conn, scope=True)

    sub = parser.add_subparsers(dest="command", required=True, metavar="<command>")

    list_p = sub.add_parser("list", help="List all domains")
    list_p.add_argument("--offset", type=int, help="Number of records to skip")
    list_p.add_argument("--limit", type=int, help="Maximum records to return")

    get_p = sub.add_parser("get", help="Get a single domain by name or ID")
    get_p.add_argument("id", metavar="NAME_OR_ID", help="Domain name (e.g. maine.edu) or domain ID")

    create_p = sub.add_parser("create", help="Create a new domain")
    create_p.add_argument("name", help="Domain name (e.g. example.com)")
    create_p.add_argument("extra", nargs="*", metavar="KEY=VALUE",
        help="Additional fields to include in the request body")

    deactivate_p = sub.add_parser("deactivate", help="Deactivate a domain")
    deactivate_p.add_argument("id", help="Domain ID")
    deactivate_p.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompt")

    get_dcv_p = sub.add_parser("get-dcv", help="Get DCV status for a domain")
    get_dcv_p.add_argument("id", help="Domain ID")

    verify_dcv_p = sub.add_parser("verify-dcv", help="Trigger DCV verification for a domain")
    verify_dcv_p.add_argument("id", help="Domain ID")

    change_dcv_p = sub.add_parser("change-dcv-method", help="Change the DCV method for a domain")
    change_dcv_p.add_argument("id", help="Domain ID")
    change_dcv_p.add_argument("method", help="DCV method: DNS-TXT or HTTP-URL")

    last_attempt_p = sub.add_parser("last-dcv-attempt", help="Get the last DCV attempt for a domain")
    last_attempt_p.add_argument("id", help="Domain ID")

    history_p = sub.add_parser("dcv-attempt-history", help="Get DCV attempt history for a domain")
    history_p.add_argument("id", help="Domain ID")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    apply_sandbox(args)
    sess = build_session(args)

    handlers = {
        "list": cmd_list,
        "get": cmd_get,
        "create": cmd_create,
        "deactivate": cmd_deactivate,
        "get-dcv": cmd_get_dcv,
        "verify-dcv": cmd_verify_dcv,
        "change-dcv-method": cmd_change_dcv_method,
        "last-dcv-attempt": cmd_last_dcv_attempt,
        "dcv-attempt-history": cmd_dcv_attempt_history,
    }
    handlers[args.command](args, sess)


if __name__ == "__main__":
    main()
