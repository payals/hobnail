-- External issuer creation is an observed fact, not a native role comment.
-- Privileged hooks are installed separately by an explicitly supplied admin.
CREATE TABLE hobnail.external_profiles (
 profile text PRIMARY KEY REFERENCES hobnail.credential_profiles,
 issuer_login name NOT NULL UNIQUE,
 lease_prefix text NOT NULL,
 issuance_ttl_seconds integer NOT NULL CHECK(issuance_ttl_seconds BETWEEN 1 AND 86400),
 at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE hobnail.external_attempts (
 request_id bigint PRIMARY KEY REFERENCES hobnail.credential_requests,
 profile text NOT NULL REFERENCES hobnail.external_profiles,
 state text NOT NULL CHECK(state IN ('prepared','created','bound','closed')),
 prepared_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 lease_ref text UNIQUE,
 provider_cleanup text NOT NULL DEFAULT 'unavailable' CHECK(provider_cleanup IN ('confirmed','pending','unavailable')),
 authenticated_at timestamptz,
 activated_at timestamptz
);
CREATE UNIQUE INDEX external_single_pending ON hobnail.external_attempts(profile)
 WHERE state IN ('prepared','created');
CREATE TABLE hobnail.external_creations (
 request_id bigint PRIMARY KEY REFERENCES hobnail.external_attempts,
 login name NOT NULL UNIQUE,
 role_oid oid NOT NULL UNIQUE,
 created_at timestamptz NOT NULL,
 initial_expires_at timestamptz NOT NULL,
 issuer_login name NOT NULL,
 creation_txid xid8 NOT NULL
);
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON hobnail.external_profiles
 FOR EACH STATEMENT EXECUTE FUNCTION hobnail.immutable();
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON hobnail.external_creations
 FOR EACH STATEMENT EXECUTE FUNCTION hobnail.immutable();

CREATE FUNCTION hobnail.external_role_safe(login_name name, expected_oid oid, enabled boolean)
RETURNS boolean LANGUAGE sql SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT FROM pg_roles r WHERE r.rolname=login_name AND r.oid=expected_oid
  AND r.rolcanlogin=enabled AND NOT (r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls)
  AND NOT EXISTS(SELECT FROM pg_auth_members WHERE member=r.oid)
  AND NOT EXISTS(SELECT FROM pg_database WHERE datdba=r.oid)
  AND NOT EXISTS(SELECT FROM pg_namespace WHERE nspowner=r.oid)
  AND NOT EXISTS(SELECT FROM pg_class WHERE relowner=r.oid)
  AND NOT EXISTS(SELECT FROM pg_proc WHERE proowner=r.oid)
  AND NOT has_database_privilege(login_name,current_database(),'CREATE')
  AND NOT EXISTS(SELECT FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname IN ('hobnail','hobnail_external') AND CASE
      WHEN c.relkind IN ('r','p','v','m','f') THEN has_table_privilege(login_name,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
      WHEN c.relkind='S' THEN has_sequence_privilege(login_name,c.oid,'USAGE,SELECT,UPDATE') ELSE false END));
$$;

CREATE FUNCTION hobnail.external_data(request_id_value bigint) RETURNS jsonb
LANGUAGE sql SET search_path=pg_catalog,hobnail SET timezone='UTC' AS $$
 SELECT jsonb_build_object('request_id',a.request_id,'profile',a.profile,'state',a.state,
  'principal',q.principal,'role',q.role,'requested_ttl',q.requested_ttl,
  'lease_ref',a.lease_ref,'provider_cleanup',a.provider_cleanup,'login',c.login,'role_oid',c.role_oid,'created_at',c.created_at,
  'expires_at',r.rolvaliduntil,'role_matches',r.oid=c.role_oid,'login_enabled',r.rolcanlogin,
  'authenticated_at',a.authenticated_at,'activated_at',a.activated_at,
  'active_sessions',(SELECT count(*) FROM pg_stat_activity s WHERE s.usesysid=c.role_oid),
  'observed_at',clock_timestamp(),'credential_id',(SELECT id FROM credential_leases WHERE request_id=a.request_id))
 FROM external_attempts a JOIN credential_requests q ON q.id=a.request_id
 LEFT JOIN external_creations c ON c.request_id=a.request_id
 LEFT JOIN pg_roles r ON r.rolname=c.login WHERE a.request_id=request_id_value;
$$;

ALTER FUNCTION hobnail.credential_api(text,jsonb,hobnail.principals) RENAME TO credential_api_native;
CREATE FUNCTION hobnail.credential_api(op text,payload jsonb,p hobnail.principals) RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog,hobnail SET timezone='UTC' AS $$
DECLARE q credential_requests; prof credential_profiles; ext external_profiles;
 a external_attempts; c external_creations; current_requester principals;
 lease credential_leases; row_id bigint; expiry timestamptz;
BEGIN
 IF op NOT LIKE 'credential.external.%' AND NOT (
  op='credential.issued' AND EXISTS(SELECT FROM credential_requests r JOIN external_profiles e ON e.profile=r.profile
                                   WHERE r.id::text=payload->>'request_id')) THEN
  RETURN hobnail.credential_api_native(op,payload,p);
 END IF;
 IF op NOT IN ('credential.external.prepare','credential.external.get','credential.external.received',
               'credential.external.close','credential.issued') THEN PERFORM hobnail.refuse('UNKNOWN_OPERATION'); END IF;
 IF op='credential.external.received' THEN
  PERFORM hobnail.only_keys(payload,ARRAY['request_id','login','lease_ref'],ARRAY['request_id','login','lease_ref']);
 ELSIF op='credential.external.close' THEN
  PERFORM hobnail.only_keys(payload,ARRAY['request_id','provider_cleanup'],ARRAY['request_id','provider_cleanup']);
  IF payload->>'provider_cleanup' NOT IN ('confirmed','pending','unavailable') THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
 ELSIF op='credential.issued' THEN
  PERFORM hobnail.only_keys(payload,ARRAY['request_id','login','lease_ref','expires_at','renewable'],
    ARRAY['request_id','login','lease_ref','expires_at','renewable']);
 ELSE PERFORM hobnail.only_keys(payload,ARRAY['request_id'],ARRAY['request_id']); END IF;
 row_id:=hobnail.integer_value(payload->'request_id',1,9223372036854775807);
 SELECT * INTO q FROM credential_requests WHERE id=row_id;
 IF NOT FOUND THEN PERFORM hobnail.refuse('NOT_FOUND'); END IF;
 SELECT * INTO prof FROM credential_profiles WHERE profile=q.profile;
 PERFORM hobnail.credential_provider_scope(p,prof);
 SELECT * INTO ext FROM external_profiles WHERE profile=q.profile;
 IF NOT FOUND THEN PERFORM hobnail.refuse('UNSUPPORTED_CAPABILITY'); END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('hobnail.external.profile:'||q.profile,0));
 SELECT * INTO a FROM external_attempts WHERE request_id=q.id FOR UPDATE;
 IF op='credential.external.prepare' THEN
  IF FOUND THEN RETURN hobnail.external_data(q.id)||jsonb_build_object('existing',true); END IF;
  IF q.requested_ttl<ext.issuance_ttl_seconds THEN PERFORM hobnail.refuse('CREDENTIAL_SCOPE'); END IF;
  IF q.at+interval '5 minutes'<=clock_timestamp()
     OR EXISTS(SELECT FROM credential_leases WHERE request_id=q.id)
     OR EXISTS(SELECT FROM external_attempts WHERE profile=q.profile AND state IN ('prepared','created')) THEN
   PERFORM hobnail.refuse('RECONCILIATION_REQUIRED');
  END IF;
  INSERT INTO external_attempts(request_id,profile,state) VALUES(q.id,q.profile,'prepared');
  RETURN hobnail.external_data(q.id)||jsonb_build_object('existing',false);
 END IF;
 IF a.request_id IS NULL THEN PERFORM hobnail.refuse('NOT_FOUND'); END IF;
 IF op='credential.external.get' THEN RETURN hobnail.external_data(q.id); END IF;
 SELECT * INTO c FROM external_creations WHERE request_id=q.id;
 IF op='credential.external.close' THEN
  -- Without a creation witness an old HTTP call may still reach the issuer.
  -- Keep its profile slot fenced until an authoritative cleanup is observed.
  IF c.request_id IS NULL AND a.state='prepared' AND payload->>'provider_cleanup'<>'confirmed' THEN
   PERFORM hobnail.refuse('REVOCATION_PENDING');
  END IF;
  IF c.request_id IS NOT NULL AND (
     EXISTS(SELECT FROM pg_roles WHERE rolname=c.login AND (oid<>c.role_oid OR rolcanlogin))
     OR EXISTS(SELECT FROM pg_stat_activity WHERE usesysid=c.role_oid)) THEN
   PERFORM hobnail.refuse('REVOCATION_PENDING');
  END IF;
  IF EXISTS(SELECT FROM credential_leases WHERE request_id=q.id AND state<>'revoked') THEN
   PERFORM hobnail.refuse('REVOCATION_PENDING');
  END IF;
  UPDATE external_attempts SET state='closed',provider_cleanup=payload->>'provider_cleanup' WHERE request_id=q.id;
  RETURN hobnail.external_data(q.id);
 END IF;
 IF a.state<>'created' OR c.request_id IS NULL
    OR payload->>'login' IS DISTINCT FROM c.login::text
    OR NOT hobnail.identifier(payload->>'lease_ref')
    OR left(payload->>'lease_ref',length(ext.lease_prefix))<>ext.lease_prefix
    OR length(payload->>'lease_ref')<=length(ext.lease_prefix) THEN
  PERFORM hobnail.refuse('CREDENTIAL_SCOPE');
 END IF;
 IF op='credential.external.received' THEN
  IF a.lease_ref IS NOT NULL AND a.lease_ref<>payload->>'lease_ref' THEN PERFORM hobnail.refuse('CREDENTIAL_SCOPE'); END IF;
  UPDATE external_attempts SET lease_ref=payload->>'lease_ref' WHERE request_id=q.id;
  RETURN hobnail.external_data(q.id);
 END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('hobnail.credential.request:'||q.id::text,0));
 IF EXISTS(SELECT FROM credential_leases WHERE request_id=q.id) THEN PERFORM hobnail.refuse('ALREADY_RECORDED'); END IF;
 SELECT * INTO current_requester FROM principals WHERE login=q.requester_login AND enabled FOR SHARE;
 IF NOT FOUND OR current_requester.principal_id<>q.principal OR current_requester.role<>q.role
   OR current_requester.contracts<>q.contracts OR current_requester.sources<>q.sources OR current_requester.profiles<>q.profiles
   OR current_requester.role<>prof.role OR NOT current_requester.principal_id=ANY(prof.principals)
   OR NOT prof.profile=ANY(current_requester.profiles)
   OR (current_requester.valid_until IS NOT NULL AND current_requester.valid_until<=clock_timestamp()) THEN
  PERFORM hobnail.refuse('CREDENTIAL_SCOPE');
 END IF;
 expiry:=hobnail.credential_timestamp(payload->'expires_at');
 IF a.authenticated_at IS NULL OR a.authenticated_at+interval '60 seconds'<=clock_timestamp()
   OR a.lease_ref IS DISTINCT FROM payload->>'lease_ref'
   OR NOT hobnail.external_role_safe(c.login,c.role_oid,true)
   OR NOT EXISTS(SELECT FROM pg_roles WHERE oid=c.role_oid AND rolvaliduntil=expiry)
   OR expiry<=clock_timestamp() OR expiry>c.created_at+make_interval(secs=>q.requested_ttl)
   OR EXISTS(SELECT FROM principals WHERE login=c.login)
   OR jsonb_typeof(payload->'renewable') IS DISTINCT FROM 'boolean'
   OR ((payload->>'renewable')::boolean AND NOT prof.renewable) THEN
  PERFORM hobnail.refuse('CREDENTIAL_SCOPE');
 END IF;
 INSERT INTO credential_leases(request_id,lease_ref,login,issued_at,expires_at,renewable)
 VALUES(q.id,a.lease_ref,c.login,c.created_at,expiry,(payload->>'renewable')::boolean) RETURNING * INTO lease;
 INSERT INTO principals(login,principal_id,role,contracts,sources,profiles,enabled,valid_until)
 VALUES(c.login,q.principal,q.role,q.contracts,q.sources,q.profiles,true,expiry);
 UPDATE external_attempts SET state='bound' WHERE request_id=q.id;
 INSERT INTO credential_events(credential_id,operation,principal,detail)
 VALUES(lease.id,op,p.principal_id,jsonb_build_object('provenance','external_creation_and_authenticated_binding',
   'role_oid',c.role_oid,'issuer_login',c.issuer_login,'expires_at',expiry));
 RETURN hobnail.credential_safe_data(lease,q);
END $$;
REVOKE ALL ON ALL TABLES IN SCHEMA hobnail FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA hobnail FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA hobnail FROM PUBLIC;
GRANT EXECUTE ON FUNCTION hobnail.api(text,jsonb) TO PUBLIC;
