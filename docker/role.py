#!/usr/local/bin/python3.14 -ISB
"""One closed role request from the trusted Docker supervisor."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from hobnail.client import Client, PsqlTransport, canonical_json, parse_json
from hobnail.effects import FileObserver, FilePublisher, dispatch_file, observe_file

specification = importlib.util.spec_from_file_location("hobnail_docker_owned_psql", ROOT / "docker/psql_owned.py")
owned = importlib.util.module_from_spec(specification)
specification.loader.exec_module(owned)
FRAME_LIMIT = 36_000_000


def read_frame(stream):
    raw = stream.read(FRAME_LIMIT + 1)
    if not isinstance(raw, bytes) or len(raw) > FRAME_LIMIT:
        raise ValueError("request frame exceeds its byte limit")
    frame = parse_json(raw.decode("utf-8"))
    if not isinstance(frame, dict) or set(frame) != {"config", "request"}:
        raise ValueError("an exact configuration/request frame is required")
    owned.validate_config(frame["config"])
    validate_request(frame["config"]["role"], frame["request"])
    return frame


def validate_request(role, request):
    if not isinstance(request, dict) or not isinstance(request.get("command"), str):
        raise ValueError("invalid role request")
    command = request["command"]
    if role == "admin":
        if command == "sql" and set(request) == {"command", "sql"}:
            if not isinstance(request["sql"], str) or not request["sql"] or "\x00" in request["sql"]:
                raise ValueError("invalid internal SQL")
            return
        if command == "install" and set(request) == {"command"}:
            return
        raise ValueError("unsupported administrator request")
    if command == "api" and set(request) == {"command", "operation", "payload"}:
        if (not isinstance(request["operation"], str) or not request["operation"]
                or "\x00" in request["operation"] or not isinstance(request["payload"], dict)):
            raise ValueError("invalid API request")
        return
    if command in {"file.dispatch", "file.observe"} and set(request) == {"command", "effect_id"}:
        required = "adapter" if command == "file.dispatch" else "observer"
        if role != required or type(request["effect_id"]) is not int or request["effect_id"] < 1:
            raise ValueError("consumer request differs from role authority")
        return
    raise ValueError("unsupported role request")


def install_kernel(connection):
    specification = importlib.util.spec_from_file_location("hobnail_docker_installer", ROOT / "scripts/install.py")
    installer = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(installer)
    # All values already satisfy the closed identifier/socket configuration.
    dsn = (f"host={connection.host} port={connection.port} dbname={connection.database} "
           f"user={connection.user} sslmode=disable connect_timeout={connection.connect_timeout}")
    return installer.install(dsn, psql=str(ROOT / "docker/psql_owned.py"))


def handle(config, request):
    connection = owned.validate_config(config)
    validate_request(config["role"], request)
    command = request["command"]
    if command == "install":
        return install_kernel(connection)
    transport = PsqlTransport(connection, psql=owned.PSQL)
    if command == "sql":
        return {"sql_output": transport.execute_sql(request["sql"], sensitive=True)}
    client = Client(transport)
    if command == "api":
        return client.call(request["operation"], request["payload"])
    if command == "file.dispatch":
        return dispatch_file(client, request["effect_id"], FilePublisher("/destination", observer_group=20001))
    return observe_file(client, request["effect_id"], FileObserver("/destination", adapter_owner_uid=10006))


def main(stream=None, output=None):
    stream = sys.stdin.buffer if stream is None else stream
    output = sys.stdout if output is None else output
    try:
        os.umask(0o077)
        tempfile.tempdir = str(owned.SCRATCH)
        frame = read_frame(stream)
        owned.write_config(frame["config"])
        response = handle(frame["config"], frame["request"])
        output.write(canonical_json(response) + "\n")
    except Exception as error:
        # Preserve typed authentication failure; never serialize exception text.
        output.write(json.dumps({"service_error": type(error).__name__}) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
