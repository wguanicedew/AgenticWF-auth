"""agenticwf — command-line access to the AgenticWF API.

    agenticwf login                     sign in via the browser (device flow)
    agenticwf token                     print a valid access token (for curl)
    agenticwf whoami                    show the identity the API sees
    agenticwf call GET /api/v1/me       call the API
    agenticwf call POST /api/v1/sessions/s1/messages --data '{"text": "hi"}'
    agenticwf logout                    revoke and forget cached tokens

    curl -H "Authorization: Bearer $(agenticwf token)" https://app.example.org/api/v1/me

Scripts and CI can skip `login` with a personal access token from the web UI (Admin > Tokens):

    export AGENTICWF_TOKEN=pat_...      # or AGENTICWF_TOKEN_FILE=~/.config/agenticwf/token
    agenticwf whoami

The service clients add their commands, with the same sign-in:

    agenticwf kb ...                    pip install agenticwf-kb-client
    agenticwf agent ...                 pip install agenticwf-agent-client
"""

from __future__ import annotations

import argparse
import json
import sys

from agenticwf_auth_cli.client import ApiError, AuthError, Client

# Entry points of this group add a subcommand: `register(subparsers)` adds a parser and sets its
# `run(args) -> int` default; `args.auth` holds the sign-in options given here (for service_access).
COMMANDS_GROUP = "agenticwf.commands"


def _command_plugins() -> list:
    from importlib.metadata import entry_points

    found = entry_points()
    found = found.select(group=COMMANDS_GROUP) if hasattr(found, "select") else found.get(COMMANDS_GROUP, [])
    return sorted(found, key=lambda ep: ep.name)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agenticwf", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--auth-url", help="Logto URL (AGENTICWF_AUTH_URL)")
    parser.add_argument("--api-url", help="application URL (AGENTICWF_API_URL)")
    parser.add_argument("--client-id", help="Logto application id (AGENTICWF_CLIENT_ID)")
    parser.add_argument("--resource", help="API resource indicator (AGENTICWF_RESOURCE)")
    parser.add_argument("--scopes", help="space separated scopes (AGENTICWF_SCOPES)")
    sub = parser.add_subparsers(dest="command", required=True)
    login = sub.add_parser("login")
    login.add_argument("--no-browser", action="store_true")
    sub.add_parser("logout")
    sub.add_parser("token")
    sub.add_parser("whoami")
    call = sub.add_parser("call")
    call.add_argument("method")
    call.add_argument("path")
    call.add_argument("--data", help="JSON request body")
    for plugin in _command_plugins():
        try:
            plugin.load()(sub)
        except Exception as exc:  # noqa: BLE001 - a broken client package must not break login
            print(f"agenticwf: `{plugin.name}` commands unavailable ({plugin.value}: {exc})", file=sys.stderr)
    args = parser.parse_args(argv)
    args.auth = {"auth_url": args.auth_url, "api_url": args.api_url, "client_id": args.client_id,
                 "resource": args.resource, "scopes": args.scopes}

    try:
        if getattr(args, "run", None):
            return args.run(args)
        client = Client.from_env(**args.auth)
        if args.command == "login":
            client.login(open_browser=not args.no_browser)
        elif args.command == "logout":
            client.logout()
        elif args.command == "token":
            print(client.access_token())
        elif args.command == "whoami":
            print(json.dumps(client.request("GET", "/api/v1/me"), indent=2))
        elif args.command == "call":
            body = json.loads(args.data) if args.data else None
            result = client.request(args.method, args.path, json_body=body)
            print(json.dumps(result, indent=2) if not isinstance(result, str) else result)
    except AuthError as exc:
        print(f"agenticwf: {exc}", file=sys.stderr)
        return 2
    except ApiError as exc:
        if isinstance(exc.body, dict) and exc.body.get("error") == "approval_pending":
            print("agenticwf: your account is awaiting approval by an administrator.\n"
                  "Once approved, run `agenticwf logout && agenticwf login` to pick up the new permissions.",
                  file=sys.stderr)
            return 3
        print(f"agenticwf: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
