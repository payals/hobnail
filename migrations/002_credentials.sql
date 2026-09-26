-- Credential metadata and qualification evidence. Secrets never enter this API.
-- Run transactionally as hobnail_owner after 001_hobnail.sql.
CREATE TABLE hobnail.credential_profiles (
  profile text PRIMARY KEY,
  provider text NOT NULL,
  principals text[] NOT NULL,
  role text NOT NULL,
  max_ttl_seconds integer NOT NULL CHECK (max_ttl_seconds > 0),
  max_lifetime_seconds integer NOT NULL CHECK (max_lifetime_seconds >= max_ttl_seconds),
  renewable boolean NOT NULL,
  capabilities text[] NOT NULL,
  configured_by text NOT NULL,
  at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE hobnail.credential_requests (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  profile text NOT NULL REFERENCES hobnail.credential_profiles,
  principal text NOT NULL,
  requester_login name NOT NULL,
  role text NOT NULL,
  contracts text[] NOT NULL,
  sources text[] NOT NULL,
  profiles text[] NOT NULL,
  requested_ttl integer NOT NULL CHECK (requested_ttl > 0),
  at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE hobnail.credential_leases (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  request_id bigint NOT NULL UNIQUE REFERENCES hobnail.credential_requests,
  lease_ref text NOT NULL UNIQUE,
  login name UNIQUE,
  issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  renewable boolean NOT NULL,
  state text NOT NULL DEFAULT 'active'
    CHECK (state IN ('active','revocation_pending','revocation_failed','revoked')),
  renewal_ttl integer,
  renewal_requested_at timestamptz,
  revocation_requested_at timestamptz
);
CREATE TABLE hobnail.credential_events (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  credential_id bigint NOT NULL REFERENCES hobnail.credential_leases,
  operation text NOT NULL,
  principal text NOT NULL,
  detail jsonb NOT NULL,
  at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE hobnail.qualifications (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  configuration_digest text NOT NULL,
  checks jsonb NOT NULL,
  recorded_by text NOT NULL,
  expires_at timestamptz NOT NULL,
  at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX qualifications_configuration ON hobnail.qualifications(configuration_digest,id);
DO $$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['credential_profiles','credential_requests','credential_events','qualifications'] LOOP
    EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON hobnail.%I FOR EACH STATEMENT EXECUTE FUNCTION hobnail.immutable()',t);
  END LOOP;
END $$;

CREATE FUNCTION hobnail.credential_timestamp(value jsonb) RETURNS timestamptz
LANGUAGE plpgsql SET search_path=pg_catalog,hobnail AS $$
DECLARE v text; result timestamptz;
BEGIN
  IF jsonb_typeof(value) IS DISTINCT FROM 'string' THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
  v := value #>> '{}';
  IF v !~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|\+00:00)$' THEN
    PERFORM hobnail.refuse('INVALID_REQUEST');
  END IF;
  BEGIN result := v::timestamptz;
  EXCEPTION WHEN invalid_datetime_format OR datetime_field_overflow THEN
    PERFORM hobnail.refuse('INVALID_REQUEST');
  END;
  IF NOT isfinite(result) THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
  RETURN result;
END $$;

CREATE FUNCTION hobnail.credential_provider_scope(
  p hobnail.principals, profile hobnail.credential_profiles
) RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,hobnail AS $$
BEGIN
  PERFORM hobnail.require_capability(p,'credential_provider');
  IF p.principal_id<>profile.provider OR NOT profile.profile=ANY(p.profiles) THEN
    PERFORM hobnail.refuse('CREDENTIAL_SCOPE');
  END IF;
END $$;

CREATE FUNCTION hobnail.credential_safe_data(
  lease hobnail.credential_leases, request hobnail.credential_requests
) RETURNS jsonb LANGUAGE sql SET search_path=pg_catalog AS $$
  SELECT jsonb_build_object(
    'credential_id',lease.id,'request_id',request.id,'principal',request.principal,
    'profile',request.profile,'role',request.role,'lease_ref',lease.lease_ref,'login',lease.login,
    'issued_at',lease.issued_at,'expires_at',lease.expires_at,'renewable',lease.renewable,
    'state',CASE WHEN lease.state='active' AND lease.expires_at<=clock_timestamp()
                 THEN 'expired' ELSE lease.state END,
    'renewal_ttl',lease.renewal_ttl,
    'renewal_requested_at',lease.renewal_requested_at,
    'revocation_requested_at',lease.revocation_requested_at)
$$;

CREATE FUNCTION hobnail.credential_api(op text, payload jsonb, p hobnail.principals)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog,hobnail SET timezone='UTC' AS $$
DECLARE
  prof hobnail.credential_profiles;
  req hobnail.credential_requests;
  lease hobnail.credential_leases;
  requester hobnail.principals;
  ttl bigint;
  lifetime bigint;
  row_id bigint;
  expiry timestamptz;
  now_at timestamptz;
  login_name text;
  value_text text;
  allowed_principals text[];
  capability_list text[];
  pg_identity record;
  role_comment text;
  role_metadata jsonb;
  created_at timestamptz;
BEGIN
  IF op='credential.profile' THEN
    -- The core API must use the same owner gate before bypassing authentication.
    -- This second check keeps the extension safe if dispatch is changed later.
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname=session_user AND rolsuper) THEN
      PERFORM hobnail.refuse('FORBIDDEN');
    END IF;
    PERFORM hobnail.only_keys(payload,
      ARRAY['profile','provider','principals','role','max_ttl_seconds','max_lifetime_seconds','renewable','capabilities'],
      ARRAY['profile','provider','principals','role','max_ttl_seconds','max_lifetime_seconds','renewable','capabilities']);
    IF NOT hobnail.identifier(payload->>'profile') OR NOT hobnail.identifier(payload->>'provider')
       OR jsonb_typeof(payload->'renewable') IS DISTINCT FROM 'boolean' THEN
      PERFORM hobnail.refuse('INVALID_REQUEST');
    END IF;
    allowed_principals := hobnail.string_array(payload->'principals');
    capability_list := hobnail.string_array(payload->'capabilities');
    ttl := hobnail.integer_value(payload->'max_ttl_seconds',1,86400);
    lifetime := hobnail.integer_value(payload->'max_lifetime_seconds',ttl,86400);
    IF cardinality(allowed_principals)=0
       OR payload->>'role' NOT IN ('worker','registrar','verifier','adapter','observer','approver','auditor','credential_provider')
       OR NOT capability_list <@ ARRAY['dynamic_postgres','renewal','revocation','active_session_termination']::text[]
       OR NOT 'dynamic_postgres'=ANY(capability_list)
       OR ((payload->>'renewable')::boolean AND NOT 'renewal'=ANY(capability_list)) THEN
      PERFORM hobnail.refuse('UNSUPPORTED_CAPABILITY');
    END IF;
    IF NOT EXISTS (SELECT FROM hobnail.principals x WHERE x.principal_id=payload->>'provider'
          AND x.role='credential_provider' AND x.enabled AND payload->>'profile'=ANY(x.profiles))
       OR EXISTS (SELECT FROM unnest(allowed_principals) allowed WHERE NOT EXISTS
          (SELECT FROM hobnail.principals x WHERE x.principal_id=allowed AND x.enabled
             AND x.role=payload->>'role' AND payload->>'profile'=ANY(x.profiles))) THEN
      PERFORM hobnail.refuse('CREDENTIAL_SCOPE');
    END IF;
    IF EXISTS (SELECT FROM hobnail.credential_profiles x WHERE x.profile=payload->>'profile') THEN
      PERFORM hobnail.refuse('VERSION_CONFLICT');
    END IF;
    INSERT INTO hobnail.credential_profiles
      (profile,provider,principals,role,max_ttl_seconds,max_lifetime_seconds,renewable,capabilities,configured_by)
    VALUES (payload->>'profile',payload->>'provider',allowed_principals,payload->>'role',
      ttl,lifetime,(payload->>'renewable')::boolean,capability_list,session_user)
    RETURNING * INTO prof;
    RETURN jsonb_build_object('profile',prof.profile,'state','configured','provider',prof.provider,
      'role',prof.role,'max_ttl_seconds',prof.max_ttl_seconds,'max_lifetime_seconds',prof.max_lifetime_seconds);
  END IF;

  IF op='credential.request' THEN
    PERFORM hobnail.only_keys(payload,ARRAY['profile','ttl_seconds','idempotency_key'],ARRAY['profile','ttl_seconds','idempotency_key']);
    IF NOT hobnail.identifier(payload->>'profile') OR NOT hobnail.identifier(payload->>'idempotency_key') THEN
      PERFORM hobnail.refuse('INVALID_REQUEST');
    END IF;
    SELECT * INTO prof FROM hobnail.credential_profiles WHERE profile=payload->>'profile';
    IF NOT FOUND THEN PERFORM hobnail.refuse('NOT_FOUND'); END IF;
    IF NOT prof.profile=ANY(p.profiles) OR NOT p.principal_id=ANY(prof.principals)
       OR p.role<>prof.role THEN PERFORM hobnail.refuse('CREDENTIAL_SCOPE'); END IF;
    ttl := hobnail.integer_value(payload->'ttl_seconds',1,86400);
    IF ttl>prof.max_ttl_seconds THEN PERFORM hobnail.refuse('CREDENTIAL_SCOPE'); END IF;
    INSERT INTO hobnail.credential_requests(profile,principal,requester_login,role,contracts,sources,profiles,requested_ttl)
    VALUES (prof.profile,p.principal_id,p.login,p.role,p.contracts,p.sources,p.profiles,ttl) RETURNING * INTO req;
    RETURN jsonb_build_object('request_id',req.id,'principal',req.principal,'profile',req.profile,
      'requested_ttl',req.requested_ttl,'role',req.role,'state','requested');
  END IF;

  IF op IN ('credential.request.get','credential.issued') THEN
    IF op='credential.request.get' THEN
      PERFORM hobnail.only_keys(payload,ARRAY['request_id'],ARRAY['request_id']);
    ELSE
      PERFORM hobnail.only_keys(payload,ARRAY['request_id','lease_ref','login','expires_at','renewable'],
        ARRAY['request_id','lease_ref','login','expires_at','renewable']);
    END IF;
    row_id := hobnail.integer_value(payload->'request_id',1,9223372036854775807);
    SELECT * INTO req FROM hobnail.credential_requests WHERE id=row_id;
    IF NOT FOUND THEN PERFORM hobnail.refuse('NOT_FOUND'); END IF;
    SELECT * INTO prof FROM hobnail.credential_profiles WHERE profile=req.profile;
    PERFORM hobnail.credential_provider_scope(p,prof);
    IF op='credential.request.get' THEN
      RETURN jsonb_build_object('request_id',req.id,'principal',req.principal,'profile',req.profile,
        'requested_ttl',req.requested_ttl,'role',req.role,'contracts',req.contracts,'sources',req.sources,
        'requested_at',req.at,'issued',EXISTS(SELECT FROM hobnail.credential_leases WHERE request_id=req.id),
        'credential_id',(SELECT id FROM hobnail.credential_leases WHERE request_id=req.id));
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('hobnail.credential.request:'||req.id::text,0));
    IF EXISTS (SELECT FROM hobnail.credential_leases WHERE request_id=req.id) THEN
      PERFORM hobnail.refuse('ALREADY_RECORDED');
    END IF;
    SELECT * INTO requester FROM hobnail.principals WHERE login=req.requester_login AND enabled FOR SHARE;
    IF NOT FOUND OR requester.principal_id<>req.principal OR requester.role<>req.role
       OR requester.contracts<>req.contracts OR requester.sources<>req.sources OR requester.profiles<>req.profiles
       OR requester.role<>prof.role OR NOT requester.principal_id=ANY(prof.principals)
       OR NOT prof.profile=ANY(requester.profiles)
       OR (requester.valid_until IS NOT NULL AND requester.valid_until<=clock_timestamp()) THEN
      PERFORM hobnail.refuse('CREDENTIAL_SCOPE');
    END IF;
    login_name := payload->>'login';
    IF jsonb_typeof(payload->'login') IS DISTINCT FROM 'string'
       OR login_name !~ '^[a-z][a-z0-9_]{0,62}$'
       OR NOT hobnail.identifier(payload->>'lease_ref')
       OR jsonb_typeof(payload->'renewable') IS DISTINCT FROM 'boolean' THEN
      PERFORM hobnail.refuse('INVALID_REQUEST');
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('hobnail.credential.login:'||login_name,0));
    IF EXISTS (SELECT FROM hobnail.principals WHERE login=login_name::name)
       OR EXISTS (SELECT FROM hobnail.credential_leases WHERE login=login_name::name OR lease_ref=payload->>'lease_ref') THEN
      PERFORM hobnail.refuse('CREDENTIAL_SCOPE');
    END IF;
    SELECT * INTO pg_identity FROM pg_roles WHERE rolname=login_name;
    IF NOT FOUND OR NOT pg_identity.rolcanlogin OR pg_identity.rolsuper OR pg_identity.rolcreaterole
       OR pg_identity.rolcreatedb OR pg_identity.rolreplication OR pg_identity.rolbypassrls
       OR EXISTS (SELECT FROM pg_auth_members WHERE member=pg_identity.oid)
       OR EXISTS (SELECT FROM pg_database WHERE datdba=pg_identity.oid)
       OR EXISTS (SELECT FROM pg_namespace WHERE nspowner=pg_identity.oid)
       OR EXISTS (SELECT FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname='hobnail' AND
            (c.relowner=pg_identity.oid OR CASE
              WHEN c.relkind IN ('r','p','v','m','f') THEN
                has_table_privilege(login_name,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
              WHEN c.relkind='S' THEN has_sequence_privilege(login_name,c.oid,'USAGE,SELECT,UPDATE')
              ELSE false END))
       OR EXISTS (SELECT FROM pg_proc f JOIN pg_namespace n ON n.oid=f.pronamespace
          WHERE n.nspname='hobnail' AND f.proowner=pg_identity.oid)
       OR has_database_privilege(login_name,current_database(),'CREATE') THEN
      PERFORM hobnail.refuse('CREDENTIAL_SCOPE');
    END IF;
    now_at := clock_timestamp();
    expiry := hobnail.credential_timestamp(payload->'expires_at');
    role_comment := shobj_description(pg_identity.oid,'pg_authid');
    IF role_comment IS NULL OR octet_length(role_comment)>16384
       OR left(role_comment,22)<>'hobnail-credential-v1:' THEN
      PERFORM hobnail.refuse('CREDENTIAL_SCOPE');
    END IF;
    BEGIN role_metadata := substring(role_comment FROM 23)::jsonb;
    EXCEPTION WHEN invalid_text_representation THEN PERFORM hobnail.refuse('CREDENTIAL_SCOPE'); END;
    IF jsonb_typeof(role_metadata) IS DISTINCT FROM 'object'
       OR role_metadata->>'provider' IS DISTINCT FROM prof.provider
       OR role_metadata->>'request_id' IS DISTINCT FROM req.id::text
       OR role_metadata->>'profile' IS DISTINCT FROM req.profile
       OR role_metadata->>'principal' IS DISTINCT FROM req.principal
       OR role_metadata->>'role' IS DISTINCT FROM req.role
       OR role_metadata->>'ttl_seconds' IS DISTINCT FROM req.requested_ttl::text
       OR role_metadata->>'lease_ref' IS DISTINCT FROM payload->>'lease_ref'
       OR role_metadata->>'oid' IS DISTINCT FROM pg_identity.oid::text THEN
      PERFORM hobnail.refuse('CREDENTIAL_SCOPE');
    END IF;
    created_at := hobnail.credential_timestamp(role_metadata->'created_at');
    IF req.at + interval '5 minutes' <= now_at
       OR created_at<req.at OR created_at>now_at
       OR expiry<=now_at OR expiry>now_at+make_interval(secs=>req.requested_ttl)
       OR pg_identity.rolvaliduntil IS DISTINCT FROM expiry
       OR ((payload->>'renewable')::boolean AND NOT prof.renewable) THEN
      PERFORM hobnail.refuse('CREDENTIAL_SCOPE');
    END IF;
    INSERT INTO hobnail.credential_leases(request_id,lease_ref,login,issued_at,expires_at,renewable)
    VALUES(req.id,payload->>'lease_ref',login_name::name,created_at,expiry,(payload->>'renewable')::boolean) RETURNING * INTO lease;
    INSERT INTO hobnail.principals(login,principal_id,role,contracts,sources,profiles,enabled,valid_until)
    VALUES(login_name::name,req.principal,req.role,req.contracts,req.sources,req.profiles,true,expiry);
    INSERT INTO hobnail.credential_events(credential_id,operation,principal,detail)
    VALUES(lease.id,op,p.principal_id,jsonb_build_object('expires_at',expiry,'login',login_name));
    RETURN hobnail.credential_safe_data(lease,req);
  END IF;

  IF op NOT IN ('credential.renew_requested','credential.renewed','credential.revoke_requested','credential.revoked','credential.get') THEN
    PERFORM hobnail.refuse('UNKNOWN_OPERATION');
  END IF;
  IF op='credential.renew_requested' THEN
    PERFORM hobnail.only_keys(payload,ARRAY['credential_id','ttl_seconds'],ARRAY['credential_id','ttl_seconds']);
  ELSIF op='credential.renewed' THEN
    PERFORM hobnail.only_keys(payload,ARRAY['credential_id','expires_at'],ARRAY['credential_id','expires_at']);
  ELSIF op='credential.revoked' THEN
    PERFORM hobnail.only_keys(payload,ARRAY['credential_id','result','receipt'],ARRAY['credential_id','result','receipt']);
  ELSE
    PERFORM hobnail.only_keys(payload,ARRAY['credential_id'],ARRAY['credential_id']);
  END IF;
  row_id := hobnail.integer_value(payload->'credential_id',1,9223372036854775807);
  SELECT * INTO lease FROM hobnail.credential_leases WHERE id=row_id FOR UPDATE;
  IF NOT FOUND THEN PERFORM hobnail.refuse('NOT_FOUND'); END IF;
  SELECT * INTO req FROM hobnail.credential_requests WHERE id=lease.request_id;
  SELECT * INTO prof FROM hobnail.credential_profiles WHERE profile=req.profile;
  IF op IN ('credential.renewed','credential.revoked') THEN
    PERFORM hobnail.credential_provider_scope(p,prof);
  ELSIF op='credential.get' THEN
    IF p.principal_id<>req.principal AND p.role<>'auditor'
       AND NOT (p.role='credential_provider' AND p.principal_id=prof.provider AND prof.profile=ANY(p.profiles)) THEN
      PERFORM hobnail.refuse('CREDENTIAL_SCOPE');
    END IF;
    RETURN hobnail.credential_safe_data(lease,req);
  ELSIF p.principal_id<>req.principal THEN
    IF op='credential.revoke_requested' AND p.role='credential_provider' THEN
      -- The issuing provider may reduce its own issued authority during crash
      -- cleanup. This never grants issuance, renewal or another profile's access.
      PERFORM hobnail.credential_provider_scope(p,prof);
    ELSIF op<>'credential.revoke_requested' OR p.role<>'approver' OR NOT prof.profile=ANY(p.profiles) THEN
      PERFORM hobnail.refuse('CREDENTIAL_SCOPE');
    END IF;
  END IF;
  now_at := clock_timestamp();
  IF op IN ('credential.renew_requested','credential.renewed') THEN
    IF lease.state<>'active' THEN PERFORM hobnail.refuse('REVOCATION_PENDING'); END IF;
    IF lease.expires_at<=now_at THEN PERFORM hobnail.refuse('CREDENTIAL_EXPIRED'); END IF;
    IF NOT lease.renewable OR NOT prof.renewable THEN PERFORM hobnail.refuse('UNSUPPORTED_CAPABILITY'); END IF;
  END IF;
  IF op='credential.renew_requested' THEN
    ttl := hobnail.integer_value(payload->'ttl_seconds',1,86400);
    IF ttl>prof.max_ttl_seconds OR now_at+make_interval(secs=>ttl)>lease.issued_at+make_interval(secs=>prof.max_lifetime_seconds) THEN
      PERFORM hobnail.refuse('CREDENTIAL_SCOPE');
    END IF;
    IF lease.renewal_requested_at IS NOT NULL THEN PERFORM hobnail.refuse('ALREADY_RECORDED'); END IF;
    UPDATE hobnail.credential_leases SET renewal_ttl=ttl,renewal_requested_at=now_at WHERE id=lease.id RETURNING * INTO lease;
    INSERT INTO hobnail.credential_events(credential_id,operation,principal,detail)
    VALUES(lease.id,op,p.principal_id,jsonb_build_object('ttl_seconds',ttl));
  ELSIF op='credential.renewed' THEN
    IF lease.renewal_requested_at IS NULL THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
    expiry := hobnail.credential_timestamp(payload->'expires_at');
    IF expiry<=now_at OR expiry<=lease.expires_at
       OR lease.renewal_requested_at+interval '5 minutes'<=now_at
       OR expiry>now_at+make_interval(secs=>lease.renewal_ttl)
       OR expiry>lease.issued_at+make_interval(secs=>prof.max_lifetime_seconds) THEN
      PERFORM hobnail.refuse('CREDENTIAL_SCOPE');
    END IF;
    IF NOT EXISTS (SELECT FROM hobnail.principals WHERE login=lease.login AND enabled
         AND principal_id=req.principal AND role=req.role AND valid_until=lease.expires_at) THEN
      PERFORM hobnail.refuse('CREDENTIAL_SCOPE');
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname=lease.login AND rolcanlogin AND rolvaliduntil=expiry) THEN
      PERFORM hobnail.refuse('CREDENTIAL_SCOPE');
    END IF;
    UPDATE hobnail.credential_leases SET expires_at=expiry,renewal_ttl=NULL,renewal_requested_at=NULL
    WHERE id=lease.id RETURNING * INTO lease;
    UPDATE hobnail.principals SET valid_until=expiry WHERE login=lease.login;
    INSERT INTO hobnail.credential_events(credential_id,operation,principal,detail)
    VALUES(lease.id,op,p.principal_id,jsonb_build_object('expires_at',expiry));
  ELSIF op='credential.revoke_requested' THEN
    IF lease.state='revoked' THEN RETURN hobnail.credential_safe_data(lease,req); END IF;
    UPDATE hobnail.credential_leases
    SET state='revocation_pending',revocation_requested_at=coalesce(revocation_requested_at,now_at),
        renewal_ttl=NULL,renewal_requested_at=NULL
    WHERE id=lease.id RETURNING * INTO lease;
    -- Framework permission ends now; downstream revocation remains explicitly pending.
    UPDATE hobnail.principals SET enabled=false WHERE login=lease.login;
    INSERT INTO hobnail.credential_events(credential_id,operation,principal,detail)
    VALUES(lease.id,op,p.principal_id,jsonb_build_object('framework_access','disabled','downstream','pending'));
  ELSIF op='credential.revoked' THEN
    value_text := payload->>'result';
    IF value_text NOT IN ('confirmed','pending','failed') THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
    PERFORM hobnail.metadata(payload->'receipt');
    IF lease.state='revoked' THEN PERFORM hobnail.refuse('ALREADY_RECORDED'); END IF;
    IF lease.revocation_requested_at IS NULL THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
    IF value_text='confirmed' AND NOT 'revocation'=ANY(prof.capabilities) THEN PERFORM hobnail.refuse('UNSUPPORTED_CAPABILITY'); END IF;
    IF value_text='confirmed' AND
       (EXISTS (SELECT FROM pg_roles WHERE rolname=lease.login AND rolcanlogin)
        OR EXISTS (SELECT FROM pg_stat_activity WHERE usename=lease.login)) THEN
      PERFORM hobnail.refuse('REVOCATION_PENDING');
    END IF;
    UPDATE hobnail.credential_leases SET state=CASE value_text WHEN 'confirmed' THEN 'revoked'
      WHEN 'pending' THEN 'revocation_pending' ELSE 'revocation_failed' END WHERE id=lease.id RETURNING * INTO lease;
    UPDATE hobnail.principals SET enabled=false WHERE login=lease.login;
    INSERT INTO hobnail.credential_events(credential_id,operation,principal,detail)
    VALUES(lease.id,op,p.principal_id,jsonb_build_object('result',value_text,'receipt',payload->'receipt'));
  END IF;
  RETURN hobnail.credential_safe_data(lease,req);
END $$;

CREATE FUNCTION hobnail.qualification_api(op text, payload jsonb, p hobnail.principals)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog,hobnail SET timezone='UTC' AS $$
DECLARE check_entry jsonb; expiry timestamptz; record_id bigint; records jsonb;
BEGIN
  IF op='qualification.record' THEN
    PERFORM hobnail.require_capability(p,'approver');
    PERFORM hobnail.only_keys(payload,ARRAY['configuration_digest','checks','expires_at'],ARRAY['configuration_digest','checks','expires_at']);
    IF NOT hobnail.is_digest(payload->>'configuration_digest')
       OR jsonb_typeof(payload->'checks') IS DISTINCT FROM 'array'
       OR jsonb_array_length(payload->'checks') NOT BETWEEN 1 AND 64
       OR octet_length((payload->'checks')::text)>1048576 THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
    expiry := hobnail.credential_timestamp(payload->'expires_at');
    IF expiry<=clock_timestamp() OR expiry>clock_timestamp()+interval '7 days' THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
    FOR check_entry IN SELECT value FROM jsonb_array_elements(payload->'checks') LOOP
      PERFORM hobnail.only_keys(check_entry,ARRAY['id','result','evidence'],ARRAY['id','result','evidence']);
      IF NOT hobnail.identifier(check_entry->>'id') OR check_entry->>'result' NOT IN ('pass','fail','error','unsupported') THEN
        PERFORM hobnail.refuse('INVALID_REQUEST');
      END IF;
      PERFORM hobnail.metadata(check_entry->'evidence');
    END LOOP;
    IF (SELECT count(DISTINCT value->>'id') FROM jsonb_array_elements(payload->'checks')) <> jsonb_array_length(payload->'checks') THEN
      PERFORM hobnail.refuse('INVALID_REQUEST');
    END IF;
    INSERT INTO hobnail.qualifications(configuration_digest,checks,recorded_by,expires_at)
    VALUES(payload->>'configuration_digest',payload->'checks',p.principal_id,expiry) RETURNING id INTO record_id;
    RETURN jsonb_build_object('qualification_id',record_id,'state','recorded','grants_authority',false);
  ELSIF op='qualification.get' THEN
    PERFORM hobnail.only_keys(payload,ARRAY['configuration_digest'],ARRAY['configuration_digest']);
    IF NOT hobnail.is_digest(payload->>'configuration_digest') THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
    SELECT coalesce(jsonb_agg(to_jsonb(q)||jsonb_build_object('expired',q.expires_at<=clock_timestamp()) ORDER BY q.id),'[]'::jsonb)
      INTO records FROM (SELECT * FROM hobnail.qualifications WHERE configuration_digest=payload->>'configuration_digest' ORDER BY id DESC LIMIT 100) q;
    RETURN jsonb_build_object('records',records,'grants_authority',false,
      'meaning','Stored observations; actual deployment qualification requires the complete applicable probe suite.');
  END IF;
  PERFORM hobnail.refuse('UNKNOWN_OPERATION');
  RETURN NULL;
END $$;

REVOKE ALL ON ALL TABLES IN SCHEMA hobnail FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA hobnail FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA hobnail FROM PUBLIC;
GRANT EXECUTE ON FUNCTION hobnail.api(text,jsonb) TO PUBLIC;
