"""Reviewed role controller. Configuration comes only from its allowed file."""

from dataclasses import replace
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys

# Load only this explicitly granted package. Scanning its parent directory
# would require widening the profile over unrelated packages or source trees.
package = Path(sys.argv[2]).resolve()
specification = importlib.util.spec_from_file_location("hobnail", package / "__init__.py",
                                                     submodule_search_locations=[str(package)])
module = importlib.util.module_from_spec(specification)
sys.modules["hobnail"] = module
specification.loader.exec_module(module)
from hobnail.client import Client, Connection, PsqlTransport, TransportError, canonical_json, parse_json


def probe(config, transport, request):
    """Controlled qualification actions; no returned file or credential content."""
    result = {"session_user": transport.execute_sql("SELECT session_user").strip(), "files": []}
    for path in request.get("files", []):
        try:
            data = Path(path).read_bytes()
            result["files"].append({"readable": True, "sha256": hashlib.sha256(data).hexdigest()})
        except PermissionError:
            result["files"].append({"readable": False, "reason": "permission_denied"})
        except OSError:
            result["files"].append({"readable": False, "reason": "other_error"})
    if request.get("admin_connection"):
        denied = False
        try:
            attempted = PsqlTransport(replace(transport.connection, user="postgres", password=None), psql=transport.psql)
            attempted.execute_sql("SELECT session_user")
        except TransportError:
            denied = True
        result["administrator_without_password_denied"] = denied
        denied = False
        try:
            attempted = PsqlTransport(replace(transport.connection, user="postgres"), psql=transport.psql)
            attempted.execute_sql("SELECT session_user")
        except TransportError:
            denied = True
        result["administrator_with_role_password_denied"] = denied
    if "marker" in request:
        marker = Path(request["marker"])
        try:
            with marker.open("ab") as stream:
                stream.write(b"unauthorized-change")
                stream.flush()
                os.fsync(stream.fileno())
            result["marker_write_denied"] = False
        except PermissionError:
            result["marker_write_denied"] = True
        except OSError:
            result["marker_write_denied"] = None
    if "unix_listener" in request:
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(1)
            try:
                connection.connect(request["unix_listener"])
                connection.sendall(b"controlled-probe")
                result["other_socket_denied"] = False
            except PermissionError:
                result["other_socket_denied"] = True
            except OSError:
                result["other_socket_denied"] = None
    if "tcp_port" in request:
        with socket.socket() as connection:
            connection.settimeout(1)
            try:
                connection.connect(("127.0.0.1", request["tcp_port"]))
                connection.sendall(b"controlled-probe")
                result["tcp_denied"] = False
            except PermissionError:
                result["tcp_denied"] = True
            except OSError:
                result["tcp_denied"] = None
    return result


def main():
    try:
        descriptor = os.open(sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "r") as stream:
            config = parse_json(stream.read(16385))
        request = parse_json(sys.stdin.read(36_000_001))
        transport = PsqlTransport(Connection(**config["connection"]), psql=config["psql"])
        print(canonical_json(probe(config, transport, request)))
    except Exception as error:
        print(json.dumps({"probe_error": type(error).__name__}))

if __name__ == "__main__":
    main()
