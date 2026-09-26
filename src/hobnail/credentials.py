"""Replaceable credential providers; secrets never enter Hobnail API payloads.

The native provider uses PostgreSQL's role/password implementation, not a secret
store. Its administrator transport must run outside worker and evaluator
processes. Role comments retain only nonsensitive recovery metadata. The OpenBao
adapter is protocol-tested but is not a qualified installed deployment.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import math
import re
import secrets
import ssl
import threading
from typing import Any, Mapping, Protocol
import urllib.error
import urllib.parse
import urllib.request

from .client import Client, PasswordAuthenticationFailed, PsqlTransport, TransportError, canonical_json, parse_json


_IDENTIFIER = re.compile(r"[A-Za-z0-9_.:/-]{1,128}\Z")
_LOGIN = re.compile(r"hn_[0-9a-f]{32}\Z")
_NATIVE_REF = re.compile(r"pg:(hn_[0-9a-f]{32}):([0-9a-f]{32})\Z")
_COMMENT_PREFIX = "hobnail-credential-v1:"
_ROLES = {"worker", "registrar", "verifier", "adapter", "observer", "approver", "credential_provider", "auditor"}


class CredentialError(RuntimeError):
    """A safe provider failure; no credential or remote response body is included."""


class Secret:
    """Explicit disclosure is required; formatting and repr are always redacted."""

    __slots__ = ("_value",)

    def __init__(self, value: str):
        if not isinstance(value, str) or not value or "\x00" in value:
            raise ValueError("secret must be nonempty text without NUL")
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "Secret(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"


def _identifier(value: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError("invalid credential identifier")
    return value


def _timestamp(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None:
            raise ValueError("timezone required")
        return result.astimezone(timezone.utc)
    except (TypeError, ValueError, AttributeError):
        raise CredentialError("provider returned an invalid timestamp") from None


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _sql(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


@dataclass(frozen=True)
class CredentialProfile:
    """Trusted owner configuration, never supplied by a workload request.

    ``role`` is a Hobnail authority label. The native backend grants only schema
    usage and API execution, not PostgreSQL role membership. OpenBao's
    ``backend_role`` is an exact owner-configured database role endpoint.
    """

    name: str
    principals: frozenset[str]
    role: str
    max_ttl_seconds: int = 300
    max_lifetime_seconds: int = 1800
    renewable: bool = False
    backend_role: str | None = None
    connection_limit: int = 4

    def __post_init__(self) -> None:
        _identifier(self.name)
        if not isinstance(self.principals, frozenset) or not self.principals:
            raise ValueError("principals must be a nonempty frozen set")
        for principal in self.principals:
            _identifier(principal)
        if self.role not in _ROLES:
            raise ValueError("unknown Hobnail role")
        for key in ("max_ttl_seconds", "max_lifetime_seconds"):
            if type(getattr(self, key)) is not int or not 1 <= getattr(self, key) <= 86400:
                raise ValueError("credential lifetime limits must be integers from 1 to 86400")
        if self.max_lifetime_seconds < self.max_ttl_seconds or type(self.renewable) is not bool:
            raise ValueError("invalid credential renewal configuration")
        if type(self.connection_limit) is not int or not 1 <= self.connection_limit <= 100:
            raise ValueError("connection limit must be from 1 to 100")
        if self.backend_role is not None and not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", self.backend_role):
            raise ValueError("OpenBao backend role must be one literal path segment")


@dataclass(frozen=True)
class CredentialRequest:
    request_id: int
    profile: str
    principal: str
    role: str
    ttl_seconds: int

    def __post_init__(self) -> None:
        if type(self.request_id) is not int or self.request_id <= 0:
            raise ValueError("request ID must be a positive integer")
        _identifier(self.profile)
        _identifier(self.principal)
        if self.role not in _ROLES or type(self.ttl_seconds) is not int or not 1 <= self.ttl_seconds <= 86400:
            raise ValueError("invalid credential role or TTL")


@dataclass(frozen=True)
class CredentialLease:
    request_id: int
    profile: str
    principal: str
    role: str
    lease_ref: str
    login: str
    created_at: str
    expires_at: str
    renewable: bool
    password: Secret | None = field(default=None, repr=False, compare=False)
    credential_id: int | None = None

    def issued_payload(self) -> dict[str, Any]:
        """The only fields sent to Hobnail; deliberately excludes the password."""
        return {"request_id": self.request_id, "lease_ref": self.lease_ref,
                "login": self.login, "expires_at": _utc(_timestamp(self.expires_at)), "renewable": self.renewable}


@dataclass(frozen=True)
class CredentialObservation:
    lease_ref: str
    result: str
    login_enabled: bool | None
    active_sessions: int | None
    observed_at: str
    detail: str


class CredentialProvider(Protocol):
    def issue(self, request: CredentialRequest) -> CredentialLease: ...
    def renew(self, lease_ref: str, ttl_seconds: int) -> CredentialLease: ...
    def revoke(self, lease_ref: str) -> CredentialObservation: ...
    def observe(self, lease_ref: str) -> CredentialObservation: ...


class _Profiles:
    def __init__(self, provider_id: str, profiles: Mapping[str, CredentialProfile]):
        self.provider_id = _identifier(provider_id)
        self.profiles = dict(profiles)
        if not self.profiles or any(k != v.name for k, v in self.profiles.items()):
            raise ValueError("profiles must be keyed by exact profile name")

    def _approve(self, request: CredentialRequest) -> CredentialProfile:
        profile = self.profiles.get(request.profile)
        if profile is None or request.principal not in profile.principals or request.role != profile.role:
            raise CredentialError("credential scope is not owner-approved")
        if request.ttl_seconds > profile.max_ttl_seconds:
            raise CredentialError("requested TTL exceeds the owner-approved profile")
        return profile


def _scram(password: str) -> str:
    """Produce PostgreSQL's SCRAM-SHA-256 verifier using the standard library."""
    salt = secrets.token_bytes(16)
    salted = hashlib.pbkdf2_hmac("sha256", password.encode("ascii"), salt, 4096)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    b64 = lambda value: base64.b64encode(value).decode("ascii")
    return f"SCRAM-SHA-256$4096:{b64(salt)}${b64(stored_key)}:{b64(server_key)}"


class PostgresCredentialProvider(_Profiles):
    """Fresh bounded PostgreSQL logins with actual active-session revocation.

    Only roles created by this provider and carrying its matching recovery
    marker are managed. No existing role is adopted, dropped, or given a new
    password. The role remains NOLOGIN after revocation to preserve identity.
    Database PUBLIC grants and pg_hba.conf remain deployment responsibilities.
    """

    capabilities = frozenset({"dynamic_credentials", "renewal", "active_session_termination", "confirmed_revocation"})

    def __init__(self, admin: PsqlTransport, *, provider_id: str, profiles: Mapping[str, CredentialProfile]):
        super().__init__(provider_id, profiles)
        self._admin = admin
        self._issued: dict[int, tuple[CredentialRequest, CredentialLease]] = {}
        self._lock = threading.RLock()

    def _json(self, sql: str, *, sensitive: bool = False) -> Any:
        try:
            return parse_json(self._admin.execute_sql("SET TIME ZONE 'UTC';\n" + sql, sensitive=sensitive).strip())
        except (TransportError, ValueError, TypeError):
            raise CredentialError("PostgreSQL credential operation failed; reconcile before retrying") from None

    def inventory(self) -> list[CredentialLease]:
        """Recover nonsensitive metadata after restart; never recover passwords."""
        rows = self._json("SELECT coalesce(json_agg(json_build_object('login',r.rolname,'oid',r.oid,"
                          "'expires_at',r.rolvaliduntil,'comment',d.description)), '[]'::json) "
                          "FROM pg_catalog.pg_roles r JOIN pg_catalog.pg_shdescription d "
                          "ON d.objoid=r.oid AND d.classoid='pg_authid'::regclass "
                          "WHERE r.rolname ~ '^hn_[0-9a-f]{32}$' AND d.description LIKE "
                          + _sql(_COMMENT_PREFIX + "%") + ";")
        result = []
        for row in rows:
            try:
                meta = parse_json(row["comment"][len(_COMMENT_PREFIX):])
                if meta["provider"] != self.provider_id:
                    continue
                request = CredentialRequest(meta["request_id"], meta["profile"], meta["principal"], meta["role"], meta["ttl_seconds"])
                profile = self._approve(request)
                if meta["oid"] != row["oid"] or not _NATIVE_REF.fullmatch(meta["lease_ref"]):
                    raise ValueError("role identity changed")
                if _NATIVE_REF.fullmatch(meta["lease_ref"]).group(1) != row["login"]:
                    raise ValueError("role name changed")
                _timestamp(meta["created_at"])
                _timestamp(row["expires_at"])
                result.append(CredentialLease(request.request_id, request.profile, request.principal,
                                             request.role, meta["lease_ref"], row["login"], meta["created_at"],
                                             row["expires_at"], profile.renewable))
            except (KeyError, TypeError, ValueError, CredentialError):
                raise CredentialError("owned credential recovery metadata is invalid") from None
        return result

    def _owned(self, lease_ref: str) -> CredentialLease:
        if not isinstance(lease_ref, str) or not _NATIVE_REF.fullmatch(lease_ref):
            raise CredentialError("not an owned PostgreSQL credential reference")
        matches = [item for item in self.inventory() if item.lease_ref == lease_ref]
        if len(matches) != 1:
            raise CredentialError("owned credential is missing or its identity changed")
        return matches[0]

    def issue(self, request: CredentialRequest) -> CredentialLease:
        profile = self._approve(request)
        with self._lock:
            if request.request_id in self._issued:
                previous, lease = self._issued[request.request_id]
                if previous != request:
                    raise CredentialError("credential request ID was reused with different scope")
                if self.observe(lease.lease_ref).result != "active":
                    raise CredentialError("previously issued credential is no longer active")
                return lease
            if any(item.request_id == request.request_id for item in self.inventory()):
                raise CredentialError("request already issued; material unavailable after restart; reconcile existing lease")
            login = "hn_" + secrets.token_hex(16)
            lease_ref = f"pg:{login}:{secrets.token_hex(16)}"
            password = Secret(secrets.token_urlsafe(36))
            # COPY sends the verifier as protocol data, not SQL statement text.
            # PostgreSQL logs can remain enabled; no plaintext password is sent.
            verifier = _scram(password.reveal())
            metadata = {"provider": self.provider_id, "request_id": request.request_id,
                        "profile": request.profile, "principal": request.principal,
                        "role": request.role, "ttl_seconds": request.ttl_seconds, "lease_ref": lease_ref}
            sql = f"""BEGIN;
CREATE TEMP TABLE hobnail_credential_material (verifier text, created_at timestamptz DEFAULT clock_timestamp()) ON COMMIT DROP;
COPY pg_temp.hobnail_credential_material (verifier) FROM STDIN;
{verifier}
\\.
DO $provider$
DECLARE material record; role_oid oid; meta jsonb; expires timestamptz;
BEGIN
  SELECT * INTO STRICT material FROM pg_temp.hobnail_credential_material;
  expires := material.created_at + make_interval(secs => {request.ttl_seconds});
  EXECUTE format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT CONNECTION LIMIT %s PASSWORD %L VALID UNTIL %L',
    {_sql(login)}, {profile.connection_limit}, material.verifier, expires);
  SELECT oid INTO STRICT role_oid FROM pg_catalog.pg_roles WHERE rolname={_sql(login)};
  meta := {_sql(canonical_json(metadata))}::jsonb || jsonb_build_object('oid',role_oid,'created_at',material.created_at);
  EXECUTE format('COMMENT ON ROLE %I IS %L', {_sql(login)}, {_sql(_COMMENT_PREFIX)} || meta::text);
  EXECUTE format('GRANT USAGE ON SCHEMA hobnail TO %I', {_sql(login)});
  EXECUTE format('GRANT EXECUTE ON FUNCTION hobnail.api(text,jsonb) TO %I', {_sql(login)});
END $provider$;
SELECT json_build_object('created_at',created_at,'expires_at',created_at + make_interval(secs => {request.ttl_seconds}))
FROM pg_temp.hobnail_credential_material;
COMMIT;
"""
            data = self._json(sql, sensitive=True)
            lease = CredentialLease(request.request_id, request.profile, request.principal, request.role,
                                    lease_ref, login, data["created_at"], data["expires_at"], profile.renewable, password)
            self._issued[request.request_id] = (request, lease)
            return lease

    def renew(self, lease_ref: str, ttl_seconds: int) -> CredentialLease:
        with self._lock:
            lease = self._owned(lease_ref)
            profile = self.profiles[lease.profile]
            if not profile.renewable or type(ttl_seconds) is not int or not 1 <= ttl_seconds <= profile.max_ttl_seconds:
                raise CredentialError("renewal is unsupported or exceeds the approved TTL")
            deadline = _utc(_timestamp(lease.created_at) + timedelta(seconds=profile.max_lifetime_seconds))
            sql = "BEGIN; DO $renew$ DECLARE expiry timestamptz; BEGIN "
            sql += "SELECT clock_timestamp()+make_interval(secs=>" + str(ttl_seconds) + ") INTO expiry; "
            sql += "IF expiry > " + _sql(deadline) + "::timestamptz OR NOT EXISTS (SELECT FROM pg_roles WHERE rolname=" + _sql(lease.login)
            sql += " AND rolcanlogin AND rolvaliduntil > clock_timestamp() AND rolvaliduntil < expiry) THEN RAISE EXCEPTION 'renewal refused'; END IF; "
            sql += "EXECUTE format('ALTER ROLE %I VALID UNTIL %L', " + _sql(lease.login) + ", expiry); END $renew$; "
            sql += "SELECT json_build_object('expires_at',rolvaliduntil) FROM pg_roles WHERE rolname=" + _sql(lease.login) + "; COMMIT;"
            data = self._json(sql)
            renewed = replace(lease, expires_at=data["expires_at"])
            if lease.request_id in self._issued:
                request, old = self._issued[lease.request_id]
                renewed = replace(renewed, password=old.password)
                self._issued[lease.request_id] = (request, renewed)
            return renewed

    def observe(self, lease_ref: str) -> CredentialObservation:
        lease = self._owned(lease_ref)
        data = self._json("SELECT json_build_object('login_enabled',r.rolcanlogin,'unexpired',r.rolvaliduntil>clock_timestamp(),"
                          "'active_sessions',(SELECT count(*) FROM pg_stat_activity a WHERE a.usesysid=r.oid),"
                          "'observed_at',clock_timestamp()) FROM pg_roles r WHERE r.rolname=" + _sql(lease.login) + ";")
        result = "confirmed" if not data["login_enabled"] and data["active_sessions"] == 0 else (
            "active" if data["login_enabled"] and data["unexpired"] else "pending")
        return CredentialObservation(lease_ref, result, data["login_enabled"], data["active_sessions"], data["observed_at"],
                                     "PostgreSQL catalog and live session observation; expiry alone does not terminate sessions")

    def revoke(self, lease_ref: str) -> CredentialObservation:
        with self._lock:
            lease = self._owned(lease_ref)
            # Commit NOLOGIN first: no new authenticated session can race the
            # termination query. Termination with a timeout waits for exit.
            self._json("DO $revoke$ BEGIN EXECUTE format('ALTER ROLE %I NOLOGIN', " + _sql(lease.login)
                       + "); END $revoke$; SELECT json_build_object('disabled',true);")
            self._json("SELECT json_build_object('terminated',coalesce(bool_and(pg_terminate_backend(pid,5000)),true)) "
                       "FROM pg_stat_activity WHERE usename=" + _sql(lease.login) + " AND pid<>pg_backend_pid();")
            return self.observe(lease_ref)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        raise CredentialError("credential endpoint redirect refused")


# These functions are intentionally outside the kernel schema. Only an explicit
# trusted administrator installs them; hobnail_owner gains no role-administration
# privileges. No OpenBao SQL template substitutes a password or verifier.
_EXTERNAL_HOOKS = {
    "create_role(profile_name text,login_name text,expiration timestamptz)": """
DECLARE e hobnail.external_profiles; a hobnail.external_attempts; q hobnail.credential_requests;
 created timestamptz; expires timestamptz; new_oid oid;
BEGIN
 SELECT * INTO e FROM hobnail.external_profiles WHERE profile=profile_name AND issuer_login=session_user;
 IF NOT FOUND THEN RAISE EXCEPTION 'external issuer scope refused'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('hobnail.external.profile:'||profile_name,0));
 SELECT * INTO a FROM hobnail.external_attempts WHERE profile=profile_name AND state='prepared' FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'no prepared external issuance'; END IF;
 SELECT * INTO STRICT q FROM hobnail.credential_requests WHERE id=a.request_id;
 created:=clock_timestamp();
 IF login_name IS NULL OR expiration IS NULL OR login_name !~ '^hbx_[a-z0-9]{32}$' OR q.at+interval '5 minutes'<=created
    OR EXISTS(SELECT FROM pg_roles WHERE rolname=login_name)
    OR EXISTS(SELECT FROM hobnail.external_creations WHERE login=login_name::name)
    OR NOT isfinite(expiration) OR expiration<=created THEN RAISE EXCEPTION 'fresh creation refused'; END IF;
 expires:=least(expiration,created+make_interval(secs=>e.issuance_ttl_seconds));
 EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 4 VALID UNTIL %L',login_name,expires);
 SELECT oid INTO STRICT new_oid FROM pg_roles WHERE rolname=login_name;
 INSERT INTO hobnail.external_creations(request_id,login,role_oid,created_at,initial_expires_at,issuer_login,creation_txid)
 VALUES(q.id,login_name::name,new_oid,created,expires,session_user,pg_current_xact_id());
 UPDATE hobnail.external_attempts SET state='created' WHERE request_id=q.id;
 EXECUTE format('GRANT USAGE ON SCHEMA hobnail,hobnail_external TO %I',login_name);
 EXECUTE format('GRANT EXECUTE ON FUNCTION hobnail.api(text,jsonb),hobnail_external.authenticate(bigint) TO %I',login_name);
 PERFORM hobnail.append_audit('credential.external.created',jsonb_build_object('request_id',q.id,'login',login_name),
  jsonb_build_object('ok',true,'role_oid',new_oid,'expires_at',expires,'login_enabled',false),NULL);
 RETURN hobnail.external_data(q.id);
END
""",
    "renew_role(profile_name text,login_name text,expiration timestamptz)": """
DECLARE e hobnail.external_profiles; c hobnail.external_creations; q hobnail.credential_requests;
 l hobnail.credential_leases; p hobnail.credential_profiles; expires timestamptz; current_expiry timestamptz;
BEGIN
 SELECT * INTO e FROM hobnail.external_profiles WHERE profile=profile_name AND issuer_login=session_user;
 IF NOT FOUND THEN RAISE EXCEPTION 'external issuer scope refused'; END IF;
 SELECT x.* INTO c FROM hobnail.external_creations x JOIN hobnail.external_attempts a ON a.request_id=x.request_id
 WHERE x.login=login_name::name AND a.profile=profile_name AND a.state='bound';
 IF NOT FOUND THEN RAISE EXCEPTION 'unknown bound external creation'; END IF;
 SELECT * INTO l FROM hobnail.credential_leases WHERE request_id=c.request_id FOR UPDATE;
 SELECT * INTO STRICT q FROM hobnail.credential_requests WHERE id=c.request_id;
 SELECT * INTO STRICT p FROM hobnail.credential_profiles WHERE profile=profile_name;
 IF l.state<>'active' OR l.expires_at<=clock_timestamp() OR NOT l.renewable OR NOT p.renewable
  OR l.renewal_requested_at IS NULL OR l.renewal_requested_at+interval '5 minutes'<=clock_timestamp()
  OR NOT hobnail.external_role_safe(c.login,c.role_oid,true) OR expiration IS NULL OR NOT isfinite(expiration) THEN
  RAISE EXCEPTION 'external renewal refused'; END IF;
 SELECT rolvaliduntil INTO current_expiry FROM pg_roles WHERE oid=c.role_oid;
 IF current_expiry<>l.expires_at THEN RAISE EXCEPTION 'external expiry changed'; END IF;
 expires:=least(expiration,clock_timestamp()+make_interval(secs=>l.renewal_ttl),
                c.created_at+make_interval(secs=>p.max_lifetime_seconds));
 IF expires<=current_expiry THEN RAISE EXCEPTION 'external renewal does not extend'; END IF;
 EXECUTE format('ALTER ROLE %I VALID UNTIL %L',c.login,expires);
 PERFORM hobnail.append_audit('credential.external.renewed',jsonb_build_object('request_id',q.id),
  jsonb_build_object('ok',true,'expires_at',expires),NULL);
 RETURN hobnail.external_data(q.id);
END
""",
    "revoke_role(profile_name text,login_name text)": """
DECLARE c hobnail.external_creations;
BEGIN
 IF NOT EXISTS(SELECT FROM hobnail.external_profiles WHERE profile=profile_name AND issuer_login=session_user) THEN
  RAISE EXCEPTION 'external issuer scope refused'; END IF;
 SELECT x.* INTO c FROM hobnail.external_creations x JOIN hobnail.external_attempts a ON a.request_id=x.request_id
 WHERE x.login=login_name::name AND a.profile=profile_name;
 IF NOT FOUND THEN RAISE EXCEPTION 'unknown external creation'; END IF;
 IF EXISTS(SELECT FROM pg_roles WHERE rolname=c.login AND oid<>c.role_oid) THEN RAISE EXCEPTION 'external role identity changed'; END IF;
 IF EXISTS(SELECT FROM pg_roles WHERE oid=c.role_oid) THEN EXECUTE format('ALTER ROLE %I NOLOGIN',c.login); END IF;
 PERFORM hobnail.append_audit('credential.external.revoke_requested',jsonb_build_object('request_id',c.request_id),
  jsonb_build_object('ok',true,'confirmation','requires committed login disable and independent session observation'),NULL);
 RETURN hobnail.external_data(c.request_id);
END
""",
    "authenticate(request_id_value bigint)": """
DECLARE a hobnail.external_attempts; c hobnail.external_creations;
BEGIN
 SELECT * INTO a FROM hobnail.external_attempts WHERE request_id=request_id_value FOR UPDATE;
 SELECT * INTO c FROM hobnail.external_creations WHERE request_id=request_id_value;
 IF a.state IS DISTINCT FROM 'created' OR c.login IS DISTINCT FROM session_user
    OR a.lease_ref IS NULL OR a.activated_at IS NULL
    OR NOT hobnail.external_role_safe(c.login,c.role_oid,true)
    OR NOT EXISTS(SELECT FROM pg_roles WHERE oid=c.role_oid AND rolvaliduntil>clock_timestamp()) THEN
  RAISE EXCEPTION 'external authentication refused'; END IF;
 UPDATE hobnail.external_attempts SET authenticated_at=clock_timestamp() WHERE request_id=a.request_id;
 PERFORM hobnail.append_audit('credential.external.authenticated',jsonb_build_object('request_id',a.request_id),
  jsonb_build_object('ok',true,'login',session_user,'role_oid',c.role_oid),NULL);
 RETURN hobnail.external_data(a.request_id);
END
""",
}


def configure_openbao_postgres(admin: PsqlTransport, *, profile: str, issuer_login: str,
                               backend_role: str, issuance_ttl_seconds: int, mount: str = "database") -> dict[str, str]:
    """Explicit owner setup. Return exact nonsecret OpenBao role statements.

    The supplied existing issuer login receives only hook execution, never
    CREATEROLE. Its credentials and the OpenBao configuration are supplied by the
    operator separately. This routine does not inspect or configure a vault.
    """
    _identifier(profile)
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", issuer_login):
        raise ValueError("issuer login must be a simple PostgreSQL identifier")
    if any(not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value) for value in (backend_role, mount)):
        raise ValueError("backend role and mount must be exact literal path segments")
    if type(issuance_ttl_seconds) is not int or not 1 <= issuance_ttl_seconds <= 86400:
        raise ValueError("issuance TTL must be from 1 to 86400")
    ddl = []
    for signature, body in _EXTERNAL_HOOKS.items():
        ddl.append(f"CREATE FUNCTION hobnail_external.{signature} RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER "
                   "SET search_path=pg_catalog,hobnail,pg_temp SET timezone='UTC' AS $hook$" + body + "$hook$;")
    prefix = f"{mount}/creds/{backend_role}/"
    if len(prefix) + 36 > 128:
        raise ValueError("backend lease reference would exceed the protocol identifier limit")
    # Existing reviewed hooks may receive a new exact profile/caller grant.
    # Never replace their code, adopt unknown functions, or alter an old profile.
    existing = parse_json(admin.execute_sql("SELECT json_build_object('exists',to_regnamespace('hobnail_external') IS NOT NULL);").strip())
    if existing["exists"]:
        PostgresExternalBridge(admin, Client(admin)).verify_hooks()
        ddl = []
    schema_sql = "" if existing["exists"] else "CREATE SCHEMA hobnail_external; REVOKE ALL ON SCHEMA hobnail_external FROM PUBLIC;"
    sql = f"""BEGIN;
DO $check$ BEGIN
 IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=session_user) THEN RAISE EXCEPTION 'explicit administrator required'; END IF;
 IF NOT EXISTS(SELECT FROM hobnail.credential_profiles WHERE profile={_sql(profile)} AND max_ttl_seconds>={issuance_ttl_seconds}) THEN RAISE EXCEPTION 'unapproved profile'; END IF;
 IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname={_sql(issuer_login)}
   AND hobnail.external_role_safe(rolname,oid,true))
   OR EXISTS(SELECT FROM hobnail.principals WHERE login={_sql(issuer_login)}::name) THEN RAISE EXCEPTION 'unsafe issuer identity'; END IF;
END $check$;
{schema_sql}
""" + "\n".join(ddl) + ("\nREVOKE ALL ON ALL FUNCTIONS IN SCHEMA hobnail_external FROM PUBLIC;\n" if not existing["exists"] else "") + f"""
GRANT USAGE ON SCHEMA hobnail_external TO "{issuer_login}";
GRANT EXECUTE ON FUNCTION hobnail_external.create_role(text,text,timestamptz),
 hobnail_external.renew_role(text,text,timestamptz),hobnail_external.revoke_role(text,text) TO "{issuer_login}";
INSERT INTO hobnail.external_profiles(profile,issuer_login,lease_prefix,issuance_ttl_seconds)
 VALUES({_sql(profile)},{_sql(issuer_login)}::name,{_sql(prefix)},{issuance_ttl_seconds});
COMMIT;
"""
    try:
        admin.execute_sql(sql)
    except TransportError:
        raise CredentialError("external hook setup failed; reconcile installation state") from None
    return {
        "username_template": "hbx_{{ random 32 | lowercase }}",
        "creation_statements": f"SELECT hobnail_external.create_role({_sql(profile)}, '{{{{name}}}}', '{{{{expiration}}}}'::timestamptz)",
        "renew_statements": f"SELECT hobnail_external.renew_role({_sql(profile)}, '{{{{name}}}}', '{{{{expiration}}}}'::timestamptz)",
        "revocation_statements": f"SELECT hobnail_external.revoke_role({_sql(profile)}, '{{{{name}}}}')",
        "rollback_statements": f"SELECT hobnail_external.revoke_role({_sql(profile)}, '{{{{name}}}}')",
        "default_ttl": str(issuance_ttl_seconds),
    }


class PostgresExternalBridge:
    """Trusted downstream controller for a prepared external issuance.

    The admin connection is explicit and confined to the provider service.
    Witness checks precede every change. No existing unwitnessed role is adopted.
    """

    def __init__(self, admin: PsqlTransport, client: Client):
        self.admin, self.client = admin, client

    def data(self, request_id: int) -> dict[str, Any]:
        return self.client.require("credential.external.get", {"request_id": request_id})["data"]

    def prepare(self, request_id: int) -> None:
        self.verify_hooks()
        data = self.client.require("credential.external.prepare", {"request_id": request_id})["data"]
        if data["existing"]:
            raise CredentialError("external attempt already exists; reconcile before another HTTP issuance")

    def verify_hooks(self) -> None:
        rows = parse_json(self.admin.execute_sql("""SELECT coalesce(json_agg(json_build_object(
 'name',p.proname,'source',p.prosrc,'owner',pg_get_userbyid(p.proowner),'definer',p.prosecdef,'config',p.proconfig,
 'callers',(SELECT json_agg(coalesce(pg_get_userbyid(a.grantee),'PUBLIC'))
   FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.privilege_type='EXECUTE'))),'[]'::json)
 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='hobnail_external';""").strip())
        identities = parse_json(self.admin.execute_sql("""SELECT json_build_object(
 'schema_owner',(SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='hobnail_external'),
 'schema_grants',(SELECT json_agg(json_build_array(coalesce(pg_get_userbyid(a.grantee),'PUBLIC'),a.privilege_type))
  FROM pg_namespace n, LATERAL aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner))) a WHERE n.nspname='hobnail_external'),
 'issuers',(SELECT coalesce(json_agg(issuer_login),'[]') FROM hobnail.external_profiles),
 'issuers_safe',(SELECT coalesce(bool_and(hobnail.external_role_safe(e.issuer_login,r.oid,true)),true)
  FROM hobnail.external_profiles e LEFT JOIN pg_roles r ON r.rolname=e.issuer_login),
 'created',(SELECT coalesce(json_agg(login),'[]') FROM hobnail.external_creations));""").strip())
        expected = {signature.split('(')[0]:body for signature,body in _EXTERNAL_HOOKS.items()}
        schema_readers={self.admin.connection.user,*identities['issuers'],*identities['created']}
        if (identities['schema_owner']!=self.admin.connection.user
                or any(caller not in schema_readers or (privilege=='CREATE' and caller!=self.admin.connection.user)
                       for caller,privilege in identities['schema_grants'] or [])
                or not identities['issuers_safe'] or len(rows)!=len(expected) or {row['name'] for row in rows}!=set(expected)):
            raise CredentialError("external hook inventory differs from reviewed functions")
        for row in rows:
            allowed={self.admin.connection.user,*(identities['created'] if row['name']=='authenticate' else identities['issuers'])}
            if (row['source']!=expected[row['name']] or row['owner']!=self.admin.connection.user or not row['definer']
                    or set(row['config'] or [])!={'search_path=pg_catalog, hobnail, pg_temp','TimeZone=UTC'}
                    or not set(row['callers'] or []).issubset(allowed)):
                raise CredentialError("external hook source, ownership or execution grant drift")

    def activate(self, lease: CredentialLease) -> CredentialLease:
        data = self.client.require("credential.external.received", {
            "request_id": lease.request_id, "login": lease.login, "lease_ref": lease.lease_ref})["data"]
        if data["state"] != "created" or not data["role_matches"] or data["login_enabled"] or lease.password is None:
            raise CredentialError("external fresh inactive creation was not observed")
        verifier = _scram(lease.password.reveal())
        sql = f"""BEGIN;
SET LOCAL TIME ZONE 'UTC';
CREATE TEMP TABLE hobnail_external_material (verifier text) ON COMMIT DROP;
COPY pg_temp.hobnail_external_material FROM STDIN;
{verifier}
\\.
DO $activate$ DECLARE c hobnail.external_creations; a hobnail.external_attempts; secret_verifier text;
BEGIN
 SELECT * INTO a FROM hobnail.external_attempts WHERE request_id={lease.request_id} FOR UPDATE;
 SELECT * INTO c FROM hobnail.external_creations WHERE request_id={lease.request_id};
 IF a.state IS DISTINCT FROM 'created' OR a.activated_at IS NOT NULL
    OR a.lease_ref IS DISTINCT FROM {_sql(lease.lease_ref)} OR c.login IS DISTINCT FROM {_sql(lease.login)}::name
    OR NOT hobnail.external_role_safe(c.login,c.role_oid,false)
    OR NOT EXISTS(SELECT FROM pg_roles WHERE oid=c.role_oid AND rolvaliduntil=c.initial_expires_at AND rolvaliduntil>clock_timestamp()) THEN
  RAISE EXCEPTION 'external activation refused'; END IF;
 SELECT verifier INTO STRICT secret_verifier FROM pg_temp.hobnail_external_material;
 EXECUTE format('ALTER ROLE %I LOGIN PASSWORD %L',c.login,secret_verifier);
 UPDATE hobnail.external_attempts SET activated_at=clock_timestamp() WHERE request_id=a.request_id;
 PERFORM hobnail.append_audit('credential.external.activated',jsonb_build_object('request_id',a.request_id),jsonb_build_object('ok',true),NULL);
END $activate$;
COMMIT;
"""
        try:
            self.admin.execute_sql(sql, sensitive=True)
            connection = replace(self.admin.connection, user=lease.login, password=lease.password.reveal())
            wrong = PsqlTransport(replace(connection, password=secrets.token_urlsafe(48)), psql=self.admin.psql)
            try:
                wrong.execute_sql("SELECT session_user;")
            except PasswordAuthenticationFailed:
                pass
            else:
                raise CredentialError("downstream authentication accepts an incorrect password")
            proof = PsqlTransport(connection, psql=self.admin.psql)
            actual = parse_json(proof.execute_sql(f"SELECT hobnail_external.authenticate({lease.request_id});").strip())
        except TransportError:
            raise CredentialError("external credential activation/authentication failed") from None
        return replace(lease, created_at=actual["created_at"], expires_at=actual["expires_at"])

    def revoke_local(self, request_id: int) -> dict[str, Any]:
        data = self.data(request_id)
        if data["login"] is None:
            return data
        # Repeat the witnessed OID check inside the mutating transaction; commit
        # NOLOGIN before a separate connection terminates remaining sessions.
        sql = f"""DO $disable$ DECLARE c hobnail.external_creations;
BEGIN
 SELECT * INTO STRICT c FROM hobnail.external_creations WHERE request_id={request_id};
 IF EXISTS(SELECT FROM pg_roles WHERE rolname=c.login AND oid<>c.role_oid) THEN RAISE EXCEPTION 'external identity changed'; END IF;
 IF EXISTS(SELECT FROM pg_roles WHERE oid=c.role_oid) THEN EXECUTE format('ALTER ROLE %I NOLOGIN',c.login); END IF;
END $disable$;
"""
        try:
            self.admin.execute_sql(sql)
            self.admin.execute_sql("SELECT pg_terminate_backend(pid,5000) FROM pg_stat_activity WHERE usesysid="
                                   + str(data["role_oid"]) + " AND pid<>pg_backend_pid();")
        except TransportError:
            raise CredentialError("external downstream revocation unconfirmed") from None
        return self.data(request_id)

    def close(self, request_id: int, provider_cleanup: str) -> None:
        self.client.require("credential.external.close", {"request_id": request_id, "provider_cleanup": provider_cleanup})


class OpenBaoCredentialProvider(_Profiles):
    """OpenBao database engine adapter; live server qualification is outstanding.

    A successful revoke HTTP response is only pending. An independent downstream
    observer must establish login denial and active-session termination. The
    token stays in this controller and is never sent through an HTTP redirect,
    inherited proxy, URL, process argument, API payload, or exception body.
    """

    capabilities = frozenset({"dynamic_credentials", "renewal"})

    def __init__(self, *, address: str, token: Secret, provider_id: str,
                 profiles: Mapping[str, CredentialProfile], ca_file: str | None = None,
                 mount: str = "database", timeout: float = 5, allow_insecure_loopback: bool = False,
                 bridge: PostgresExternalBridge | None = None):
        super().__init__(provider_id, profiles)
        url = urllib.parse.urlsplit(address)
        if (url.username or url.password or url.query or url.fragment or url.path not in ("", "/")
                or not url.hostname or url.scheme not in {"https", "http"}):
            raise ValueError("OpenBao address must be one origin without credentials, path, query, or fragment")
        if url.scheme != "https" and not (allow_insecure_loopback and url.hostname in {"127.0.0.1", "::1"}):
            raise ValueError("OpenBao requires certificate-verified HTTPS")
        if not isinstance(token, Secret) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", mount):
            raise ValueError("explicit secret token and a literal mount name are required")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be positive and finite")
        self.address = address.rstrip("/")
        self._token = token
        self.mount = mount
        self.timeout = timeout
        self.bridge = bridge
        self._confirmed_revocations: set[str] = set()
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect(),
                                                  urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=ca_file)))
        self._leases: dict[str, CredentialLease] = {}
        self._lock = threading.RLock()

    def _request(self, method: str, path: str, payload: Mapping[str, Any] | None = None) -> dict[str, Any]:
        body = None if payload is None else canonical_json(dict(payload)).encode("utf-8")
        request = urllib.request.Request(self.address + "/v1/" + path, data=body, method=method,
                                         headers={"X-Vault-Token": self._token.reveal(), "Content-Type": "application/json"})
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                if path == "sys/leases/revoke" and response.status == 202:
                    raise CredentialError("external revocation was queued; confirmation is pending")
                data = response.read(1024 * 1024 + 1)
                if len(data) > 1024 * 1024:
                    raise CredentialError("OpenBao response exceeds the limit")
                result = {} if not data else parse_json(data.decode("utf-8"))
                if not isinstance(result, dict) or result.get("errors"):
                    raise CredentialError("OpenBao returned an invalid response")
                return result
        except urllib.error.HTTPError as error:
            error.close()
            raise CredentialError("OpenBao request failed; outcome may require reconciliation") from None
        except (urllib.error.URLError, TimeoutError, ValueError, UnicodeError, OSError):
            raise CredentialError("OpenBao request failed; outcome may require reconciliation") from None

    def issue(self, request: CredentialRequest) -> CredentialLease:
        if self.bridge is None:
            return self._issue_http(request)
        self._approve(request)
        with self._lock:
            self.bridge.prepare(request.request_id)
            try:
                lease = self._issue_http(request)
                lease = self.bridge.activate(lease)
                self._leases[lease.lease_ref] = lease
                return lease
            except Exception:
                self.cleanup_attempt(request.request_id)
                raise

    def _issue_http(self, request: CredentialRequest) -> CredentialLease:
        profile = self._approve(request)
        if profile.backend_role is None:
            raise CredentialError("profile lacks an owner-approved OpenBao database role")
        with self._lock:
            if any(item.request_id == request.request_id for item in self._leases.values()):
                raise CredentialError("OpenBao request already issued; no automatic redispatch")
            started = datetime.now(timezone.utc)
            result = self._request("GET", self.mount + "/creds/" + profile.backend_role)
            lease_ref = result.get("lease_id")
            expected_prefix = self.mount + "/creds/" + profile.backend_role + "/"
            scoped_reference = (isinstance(lease_ref, str) and bool(_IDENTIFIER.fullmatch(lease_ref))
                                and lease_ref.startswith(expected_prefix) and len(lease_ref) > len(expected_prefix))
            try:
                duration = result["lease_duration"]
                login, password = result["data"]["username"], result["data"]["password"]
                if not isinstance(password, str) or not password or not password.isascii() or len(password)>1024:
                    raise ValueError("unsupported password encoding or size")
                if not scoped_reference:
                    raise ValueError("invalid lease reference")
                _identifier(lease_ref)
                if type(duration) is not int or not 1 <= duration <= request.ttl_seconds:
                    raise ValueError("backend TTL exceeds requested authority")
                if not isinstance(login, str) or not login or len(login) > 63 or "\x00" in login:
                    raise ValueError("invalid database login")
                if type(result["renewable"]) is not bool:
                    raise ValueError("invalid renewable value")
                lease = CredentialLease(request.request_id, request.profile, request.principal, request.role,
                                        lease_ref, login, _utc(started), _utc(started + timedelta(seconds=duration)),
                                        profile.renewable and result["renewable"], Secret(password))
            except (KeyError, TypeError, ValueError):
                if scoped_reference:
                    self._request("PUT", "sys/leases/revoke", {"lease_id": lease_ref, "sync": True})
                raise CredentialError("OpenBao issuance violated the approved profile; reconciliation required") from None
            self._leases[lease_ref] = lease
            return lease

    def _owned(self, lease_ref: str) -> CredentialLease:
        if not isinstance(lease_ref, str) or lease_ref not in self._leases:
            raise CredentialError("unknown OpenBao lease; recover from authenticated kernel metadata first")
        return self._leases[lease_ref]

    def recover(self, lease: CredentialLease) -> None:
        """Use only safe metadata obtained by the broker from credential.get."""
        self._approve(CredentialRequest(lease.request_id, lease.profile, lease.principal, lease.role, 1))
        _identifier(lease.lease_ref)
        if not lease.lease_ref.startswith(self.mount + "/creds/" + str(self.profiles[lease.profile].backend_role) + "/"):
            raise CredentialError("OpenBao recovery reference differs from the approved backend role")
        _timestamp(lease.created_at)
        _timestamp(lease.expires_at)
        self._leases[lease.lease_ref] = replace(lease, password=None)

    def renew(self, lease_ref: str, ttl_seconds: int) -> CredentialLease:
        with self._lock:
            lease = self._owned(lease_ref)
            profile = self.profiles[lease.profile]
            now = datetime.now(timezone.utc)
            if (not lease.renewable or type(ttl_seconds) is not int or not 1 <= ttl_seconds <= profile.max_ttl_seconds
                    or now >= _timestamp(lease.expires_at)
                    or now + timedelta(seconds=ttl_seconds) > _timestamp(lease.created_at) + timedelta(seconds=profile.max_lifetime_seconds)):
                raise CredentialError("OpenBao renewal exceeds approved lifetime")
            # OpenBao decodes JSON numbers as json.Number while its HCL ACL
            # literals are Go ints; exact numeric allowlists do not match.
            # Duration strings are part of the actual endpoint grammar. Keep
            # the public/kernel TTL domain integer-valued and send exact units.
            result = self._request("PUT", "sys/leases/renew", {"lease_id": lease_ref, "increment": f"{ttl_seconds}s"})
            duration = result.get("lease_duration")
            if type(duration) is not int or not 1 <= duration <= ttl_seconds or result.get("lease_id") != lease_ref:
                self._request("PUT", "sys/leases/revoke", {"lease_id": lease_ref, "sync": True})
                raise CredentialError("OpenBao renewal exceeded authority; revocation requested")
            renewed = replace(lease, expires_at=_utc(now + timedelta(seconds=duration)))
            if self.bridge is not None:
                actual = self.bridge.data(lease.request_id)
                if (actual["role_matches"] is not True or actual["login_enabled"] is not True
                        or _timestamp(actual["expires_at"]) <= _timestamp(lease.expires_at)):
                    raise CredentialError("external renewal did not change the witnessed role expiry")
                renewed = replace(lease, expires_at=actual["expires_at"])
            self._leases[lease_ref] = renewed
            return renewed

    def observe(self, lease_ref: str) -> CredentialObservation:
        lease = self._owned(lease_ref)
        if self.bridge is not None:
            data = self.bridge.data(lease.request_id)
            confirmed = lease_ref in self._confirmed_revocations or data["provider_cleanup"] == "confirmed"
            return self._observation(data, lease_ref, "confirmed" if confirmed else "pending")
        return CredentialObservation(lease_ref, "pending", None, None, _utc(datetime.now(timezone.utc)),
                                     "OpenBao API state does not establish downstream login denial or active-session termination")

    def _observation(self, data: dict[str, Any], lease_ref: str, provider_cleanup: str) -> CredentialObservation:
        if data["role_matches"] is False:
            raise CredentialError("external role OID changed; no adoption or confirmation permitted")
        disabled = data["login_enabled"] is not True and data["active_sessions"] == 0
        result = "confirmed" if disabled and provider_cleanup == "confirmed" else (
            "active" if data["login_enabled"] is True and _timestamp(data["expires_at"]) > datetime.now(timezone.utc) else "pending")
        return CredentialObservation(lease_ref, result, data["login_enabled"], data["active_sessions"], data["observed_at"],
                                     "Witnessed PostgreSQL role/session observation; external lease cleanup " + provider_cleanup)

    def cleanup_attempt(self, request_id: int) -> CredentialObservation:
        """Recover even a lost HTTP response, without generating another lease."""
        if self.bridge is None:
            raise CredentialError("external recovery needs a configured PostgreSQL bridge")
        data = self.bridge.revoke_local(request_id)
        reference = data["lease_ref"]
        if reference is None:
            matches = [lease.lease_ref for lease in self._leases.values() if lease.request_id == request_id]
            reference = matches[0] if len(matches) == 1 else None
        cleanup = "unavailable"
        if reference is not None:
            try:
                self._request("PUT", "sys/leases/revoke", {"lease_id": reference, "sync": True})
                self._confirmed_revocations.add(reference)
                cleanup = "confirmed"
            except CredentialError:
                cleanup = "pending"
        if data["credential_id"] is None and (data["login"] is not None or cleanup == "confirmed"):
            self.bridge.close(request_id, cleanup)
        return self._observation(data, reference or "unreturned-external-lease", cleanup)

    def revoke(self, lease_ref: str) -> CredentialObservation:
        with self._lock:
            lease = self._owned(lease_ref)
            if self.bridge is not None:
                data = self.bridge.revoke_local(lease.request_id)
                if data["state"] == "closed" and data["provider_cleanup"] == "confirmed":
                    return self._observation(data, lease_ref, "confirmed")
                cleanup = "confirmed"
                try:
                    self._request("PUT", "sys/leases/revoke", {"lease_id": lease_ref, "sync": True})
                    self._confirmed_revocations.add(lease_ref)
                except CredentialError:
                    cleanup = "pending"
                return self._observation(data, lease_ref, cleanup)
            self._request("PUT", "sys/leases/revoke", {"lease_id": lease_ref, "sync": True})
            return self.observe(lease_ref)


class CredentialBroker:
    """Resolve authority through the kernel before invoking privileged providers."""

    def __init__(self, client: Client, provider: CredentialProvider):
        self.client, self.provider = client, provider

    def _cleanup_issued(self, lease: CredentialLease) -> CredentialObservation:
        """Reconcile effective revocation with committed metadata after lost replies."""
        try:
            request = self.client.require("credential.request.get", {"request_id": lease.request_id})["data"]
            credential_id = request.get("credential_id")
            state = None
            if credential_id is not None:
                state = self.client.require("credential.get", {"credential_id": credential_id})["data"]["state"]
                if state != "revoked":
                    self.client.require("credential.revoke_requested", {"credential_id": credential_id})
        except Exception:
            # Kernel unavailability cannot prevent reducing downstream authority.
            # Do not call this metadata reconciled until a later read succeeds.
            try:
                self.provider.revoke(lease.lease_ref)
            except CredentialError:
                raise CredentialError("credential cleanup and kernel reconciliation are unconfirmed") from None
            raise CredentialError("downstream cleanup attempted; kernel reconciliation remains pending") from None
        observation = self.provider.revoke(lease.lease_ref)
        if credential_id is not None and state != "revoked":
            try:
                self.client.require("credential.revoked", {
                    "credential_id": credential_id, "result": observation.result,
                    "receipt": {"reason": "uncertain_operation_cleanup", "observed_at": observation.observed_at,
                                "login_enabled": observation.login_enabled, "active_sessions": observation.active_sessions}})
            except Exception:
                raise CredentialError("downstream cleanup observed; kernel reconciliation remains pending") from None
        if isinstance(self.provider, OpenBaoCredentialProvider) and self.provider.bridge is not None and observation.result == "confirmed":
            self.provider.bridge.close(lease.request_id, "confirmed")
        return observation

    def reconcile_request(self, request_id: int) -> CredentialObservation:
        """Recover an uncertain native issuance without issuing fresh authority.

        Safe persisted provider metadata supplies the existing lease reference;
        no lost password is recovered and no new credential is generated.
        """
        request = self.client.require("credential.request.get", {"request_id": request_id})["data"]
        if isinstance(self.provider, OpenBaoCredentialProvider) and self.provider.bridge is not None:
            if request.get("credential_id") is None:
                return self.provider.cleanup_attempt(request_id)
            self._get(request["credential_id"])
            data = self.provider.bridge.data(request_id)
            return self._cleanup_issued(self.provider._owned(data["lease_ref"]))
        if not isinstance(self.provider, PostgresCredentialProvider):
            raise CredentialError("this provider needs an explicit persisted lease reference for recovery")
        leases = [lease for lease in self.provider.inventory() if lease.request_id == request_id
                  and lease.principal == request["principal"] and lease.profile == request["profile"]]
        if len(leases) != 1:
            raise CredentialError("issuance recovery requires exactly one existing provider lease")
        return self._cleanup_issued(leases[0])

    def issue_request(self, request_id: int) -> CredentialLease:
        if isinstance(self.provider, OpenBaoCredentialProvider) and self.provider.bridge is None:
            raise CredentialError("OpenBao broker issuance requires a configured creation/authentication bridge")
        data = self.client.require("credential.request.get", {"request_id": request_id})["data"]
        if data.get("issued"):
            raise CredentialError("credential request is already issued; reconcile its existing lease")
        request = CredentialRequest(data["request_id"], data["profile"], data["principal"], data["role"], data["requested_ttl"])
        lease = self.provider.issue(request)
        try:
            registered = self.client.require("credential.issued", lease.issued_payload())
        except Exception:
            # Material has not been delivered yet. Fail closed even if the
            # registration committed but its response was lost.
            self._cleanup_issued(lease)
            raise
        return replace(lease, credential_id=registered["data"]["credential_id"])

    def _get(self, credential_id: int) -> dict[str, Any]:
        data = self.client.require("credential.get", {"credential_id": credential_id})["data"]
        if isinstance(self.provider, OpenBaoCredentialProvider):
            self.provider.recover(CredentialLease(data["request_id"], data["profile"], data["principal"],
                                                 data["role"], data["lease_ref"], data["login"], data["issued_at"],
                                                 data["expires_at"], data["renewable"], credential_id=credential_id))
        return data

    def renew_requested(self, credential_id: int) -> CredentialLease:
        """Fulfil the exact kernel-recorded renewal, never a caller-chosen TTL."""
        data = self._get(credential_id)
        if data["state"] != "active" or not data.get("renewal_requested_at") or not data.get("renewal_ttl"):
            raise CredentialError("there is no active authorized renewal request")
        try:
            lease = self.provider.renew(data["lease_ref"], data["renewal_ttl"])
        except Exception:
            if isinstance(self.provider, OpenBaoCredentialProvider) and self.provider.bridge is not None:
                self._cleanup_issued(self.provider._owned(data["lease_ref"]))
            raise
        try:
            self.client.require("credential.renewed", {"credential_id": credential_id, "expires_at": lease.expires_at})
        except Exception:
            self._cleanup_issued(lease)
            raise
        return replace(lease, credential_id=credential_id)

    def revoke_requested(self, credential_id: int) -> CredentialObservation:
        """Act after authorized principal, approver or provider revocation request."""
        data = self._get(credential_id)
        if data["state"] not in {"revocation_pending", "revoked"} or not data.get("revocation_requested_at"):
            raise CredentialError("there is no authorized revocation request")
        if data["state"] == "revoked":
            observation = self.provider.observe(data["lease_ref"])
            if observation.result != "confirmed":
                raise CredentialError("downstream state contradicts the recorded revocation")
            return observation
        try:
            observation = self.provider.revoke(data["lease_ref"])
        except CredentialError:
            self.client.require("credential.revoked", {"credential_id": credential_id, "result": "failed",
                                                        "receipt": {"detail": "provider revocation failed; reconciliation required"}})
            raise
        self.client.require("credential.revoked", {"credential_id": credential_id, "result": observation.result,
                                                    "receipt": {"observed_at": observation.observed_at,
                                                                "login_enabled": observation.login_enabled,
                                                                "active_sessions": observation.active_sessions,
                                                                "detail": observation.detail}})
        if isinstance(self.provider, OpenBaoCredentialProvider) and self.provider.bridge is not None and observation.result == "confirmed":
            self.provider.bridge.close(data["request_id"], "confirmed")
        return observation
