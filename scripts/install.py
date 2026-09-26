#!/usr/bin/env python3
"""Install the additive Hobnail kernel using an existing PostgreSQL 18 psql.

The connection must be an administrative session. Runtime login creation and
binding remain explicit deployment steps. Passwords must stay out of the DSN
and command line; explicit local administrative authentication is supported.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
from urllib.parse import parse_qsl, unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]


class InstallError(RuntimeError):
    """The transactional install was refused or failed."""


def _literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _connection_options(dsn: str) -> dict[str, str]:
    """Parse only explicit safe connection fields, never libpq service aliases."""
    if not dsn or "\x00" in dsn:
        raise ValueError("use a nonempty explicit DSN without inline credentials")
    pairs: list[tuple[str, str]]
    if dsn.startswith(("postgres://", "postgresql://")):
        parsed = urlsplit(dsn)
        if parsed.password is not None or parsed.fragment:
            raise ValueError("inline credentials and URL fragments are forbidden")
        pairs = [("host", unquote(parsed.hostname or "")), ("port", str(parsed.port or 5432)),
                 ("dbname", unquote(parsed.path.removeprefix("/"))), ("user", unquote(parsed.username or ""))]
        pairs.extend(parse_qsl(parsed.query, keep_blank_values=True))
    else:
        words = shlex.split(dsn)
        if any("=" not in word for word in words):
            raise ValueError("DSN must explicitly specify host, port, dbname and user")
        pairs = [tuple(word.split("=", 1)) for word in words]
    allowed = {"host", "port", "dbname", "user", "sslmode", "connect_timeout"}
    options: dict[str, str] = {}
    for key, value in pairs:
        if key not in allowed or key in options or not value or "\x00" in value:
            raise ValueError("DSN contains an unsupported, duplicate or empty connection field")
        options[key] = value
    if not {"host", "port", "dbname", "user"} <= options.keys():
        raise ValueError("DSN must explicitly specify host, port, dbname and user")
    if not options["port"].isdigit() or not 1 <= int(options["port"]) <= 65535:
        raise ValueError("invalid database port")
    if options.get("sslmode", "disable") not in {"disable", "require"}:
        raise ValueError("installer supports explicit local sockets or TLS without ambient client certificates")
    options.setdefault("sslmode", "disable")
    options.setdefault("connect_timeout", "10")
    if not options["connect_timeout"].isdigit() or not 1 <= int(options["connect_timeout"]) <= 120:
        raise ValueError("invalid connection timeout")
    return options


def migration_files() -> list[Path]:
    files = sorted((ROOT / "migrations").glob("[0-9][0-9][0-9]_*.sql"))
    if not files or [int(path.name[:3]) for path in files] != list(range(1, len(files) + 1)):
        raise InstallError("migration numbers must start at one and be contiguous")
    return files


def install(dsn: str, psql: str = "psql") -> dict[str, object]:
    """Apply pending migrations atomically and reject changed applied files.

    No package installation, shared server startup, login passwords, runtime
    memberships or public repository operations are performed here.
    """
    options = _connection_options(dsn)
    executable = shutil.which(psql)
    if executable is None:
        raise InstallError("existing reviewed psql executable not found")
    files = migration_files()
    versions = [(int(path.name[:3]), hashlib.sha256(path.read_bytes()).hexdigest(), path.read_text()) for path in files]
    source = [r"\set ON_ERROR_STOP on", "BEGIN;", "SET LOCAL lock_timeout='10s';", "SET LOCAL statement_timeout='60s';",
              "SELECT pg_advisory_xact_lock(hashtextextended('hobnail.install',0));", r"""
DO $install$
DECLARE r record;
BEGIN
 IF current_setting('server_version_num')::integer / 10000 <> 18 THEN
  RAISE EXCEPTION 'Hobnail protocol 1 supports PostgreSQL 18 only';
 END IF;
 IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=session_user) THEN
  RAISE EXCEPTION 'Installation requires an administrative session_user';
 END IF;
 IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='hobnail_owner') THEN
  CREATE ROLE hobnail_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
 END IF;
 SELECT * INTO r FROM pg_roles WHERE rolname='hobnail_owner';
 IF r.rolcanlogin OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls
    OR EXISTS(SELECT FROM pg_auth_members WHERE member=r.oid OR roleid=r.oid) THEN
  RAISE EXCEPTION 'Existing hobnail_owner has unsafe flags or membership';
 END IF;
 IF EXISTS(SELECT FROM pg_namespace WHERE nspname='hobnail' AND nspowner<>r.oid) THEN
  RAISE EXCEPTION 'Existing hobnail schema has a different owner';
 END IF;
 IF EXISTS(SELECT FROM pg_namespace WHERE nspname='hobnail') AND to_regclass('hobnail.migrations') IS NULL THEN
  RAISE EXCEPTION 'Existing hobnail schema has no reviewed migration ledger';
 END IF;
 EXECUTE format('GRANT CREATE ON DATABASE %I TO hobnail_owner',current_database());
END $install$;
SELECT to_regclass('hobnail.migrations') IS NOT NULL AS has_ledger \gset
\if :has_ledger
""", "DO $verify$ BEGIN",
              f"IF EXISTS(SELECT FROM hobnail.migrations WHERE version>{len(versions)}) THEN RAISE EXCEPTION 'Database is newer than this installer'; END IF;"]
    for version, checksum, _ in versions:
        source.append(f"IF EXISTS(SELECT FROM hobnail.migrations WHERE version={version} AND sha256<>{_literal(checksum)}) THEN RAISE EXCEPTION 'Applied migration {version} checksum differs'; END IF;")
    source.extend(["END $verify$;", r"\endif", "SET LOCAL ROLE hobnail_owner;"])
    for version, checksum, sql in versions:
        if version == 1:
            source.extend([r"\if :has_ledger", r"\else", sql,
                           f"INSERT INTO hobnail.migrations(version,sha256) VALUES ({version},{_literal(checksum)});", r"\endif"])
        else:
            source.extend([f"SELECT EXISTS(SELECT FROM hobnail.migrations WHERE version={version}) AS migration_present \\gset",
                           r"\if :migration_present", r"\else", sql,
                           f"INSERT INTO hobnail.migrations(version,sha256) VALUES ({version},{_literal(checksum)});", r"\endif"])
    source.extend(["RESET ROLE;", r"""
DO $finish$
BEGIN
 IF EXISTS(SELECT FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='hobnail' AND c.relowner<>(SELECT oid FROM pg_roles WHERE rolname='hobnail_owner'))
    OR EXISTS(SELECT FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='hobnail' AND p.proowner<>(SELECT oid FROM pg_roles WHERE rolname='hobnail_owner')) THEN
  RAISE EXCEPTION 'Hobnail object ownership drift detected';
 END IF;
 IF NOT EXISTS(SELECT FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='hobnail' AND p.proname='api' AND p.prosecdef
      AND p.proconfig @> ARRAY['search_path=pg_catalog, hobnail, pg_temp','TimeZone=UTC'])
    OR EXISTS(SELECT FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='hobnail' AND (p.proname<>'api' AND p.prosecdef
      OR NOT coalesce(p.proconfig @> ARRAY['search_path=pg_catalog, hobnail, pg_temp'],false))) THEN
  RAISE EXCEPTION 'Hobnail function security drift detected';
 END IF;
 IF EXISTS(SELECT FROM unnest(ARRAY['audit','plugins','contracts','approvals','artifacts','snapshots','results','acceptances','reservations','idempotency','effect_reports','credential_profiles','credential_requests','credential_events','qualifications']) ledger(name)
   WHERE NOT EXISTS(SELECT FROM pg_trigger t WHERE t.tgrelid=to_regclass('hobnail.'||ledger.name)
    AND t.tgname=CASE WHEN ledger.name='audit' THEN 'audit_immutable' ELSE 'immutable' END
    AND t.tgenabled IN ('O','A') AND t.tgfoid='hobnail.immutable()'::regprocedure AND (t.tgtype::integer & 56)=56)) THEN
  RAISE EXCEPTION 'Hobnail ledger enforcement drift detected';
 END IF;
 EXECUTE format('REVOKE CREATE ON DATABASE %I FROM hobnail_owner',current_database());
END $finish$;
COMMIT;
SELECT jsonb_build_object('installed',true,'protocol',1,'migrations',(SELECT jsonb_agg(jsonb_build_object('version',version,'sha256',sha256) ORDER BY version) FROM hobnail.migrations));
"""])
    # Never consult ambient PGOPTIONS, service files, ~/.pgpass or ~/.postgresql.
    # This installer intentionally has no implicit credential source.
    with tempfile.TemporaryDirectory(prefix="hobnail-install-") as directory:
        options.update({"passfile": os.devnull, "application_name": "hobnail-installer",
                        "gssencmode": "disable", "sslcert": str(Path(directory) / "absent.crt"),
                        "sslkey": str(Path(directory) / "absent.key"),
                        "sslrootcert": str(Path(directory) / "absent-root.crt"),
                        "sslcrl": str(Path(directory) / "absent-crl.pem"), "sslcrldir": directory})
        environment = {"LC_ALL": "C", "PGPASSFILE": os.devnull, "PGSERVICEFILE": os.devnull,
                       "PGSYSCONFDIR": directory}
        conninfo = " ".join(key + "='" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"
                            for key, value in options.items())
        result = subprocess.run([str(Path(executable).absolute()), "-X", "-q", "-A", "-t", "-w", "--dbname", conninfo],
                                input="\n".join(source), text=True, capture_output=True, env=environment, timeout=120, check=False)
    if result.returncode:
        # Connection errors may contain identifying data. SQL errors are exposed
        # only as the failing source line number, never arbitrary server text.
        raise InstallError(f"transactional installation failed (psql exit {result.returncode}); no completion receipt")
    lines = [line for line in result.stdout.splitlines() if line.startswith('{"')]
    if len(lines) != 1:
        raise InstallError("installer did not return exactly one completion receipt")
    receipt = json.loads(lines[0])
    if receipt.get("installed") is not True or receipt.get("protocol") != 1:
        raise InstallError("invalid installation receipt")
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dsn", required=True, help="administrative connection without inline passwords")
    parser.add_argument("--psql", default="psql", help="existing reviewed psql executable")
    args = parser.parse_args()
    try:
        print(json.dumps(install(args.dsn, args.psql), sort_keys=True))
        return 0
    except (InstallError, ValueError, OSError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"hobnail install: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
