-- Hobnail 0.2 kernel. Applied transactionally by scripts/install.py as hobnail_owner.
-- PostgreSQL 18 only. Runtime authority is session_user, never a JSON identity.
CREATE SCHEMA hobnail AUTHORIZATION hobnail_owner;
REVOKE ALL ON SCHEMA hobnail FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA hobnail REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
CREATE TABLE hobnail.migrations (
  version integer PRIMARY KEY, sha256 text NOT NULL, installed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE hobnail.principals (
  login name PRIMARY KEY,
  principal_id text NOT NULL CHECK (length(principal_id) BETWEEN 1 AND 128),
  role text NOT NULL CHECK (role IN ('registrar','approver','worker','verifier','adapter','observer','auditor','credential_provider')),
  contracts text[] NOT NULL DEFAULT '{}',
  sources text[] NOT NULL DEFAULT '{}',
  profiles text[] NOT NULL DEFAULT '{}',
  valid_until timestamptz,
  enabled boolean NOT NULL DEFAULT true
);
CREATE TABLE hobnail.audit_head (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  seq bigint NOT NULL DEFAULT 0,
  hash text NOT NULL DEFAULT repeat('0',64)
);
INSERT INTO hobnail.audit_head DEFAULT VALUES;
CREATE TABLE hobnail.audit (
  seq bigint PRIMARY KEY,
  event jsonb NOT NULL,
  previous_hash text NOT NULL,
  hash text NOT NULL
);
CREATE FUNCTION hobnail.immutable() RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, hobnail AS $$
BEGIN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='immutable_record'; END $$;
CREATE TRIGGER audit_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON hobnail.audit
FOR EACH STATEMENT EXECUTE FUNCTION hobnail.immutable();
CREATE FUNCTION hobnail.digest(value jsonb) RETURNS text LANGUAGE sql IMMUTABLE STRICT
SET search_path = pg_catalog AS $$ SELECT encode(sha256(convert_to(value::text,'UTF8')),'hex') $$;
CREATE FUNCTION hobnail.refuse(code text) RETURNS void LANGUAGE plpgsql
SET search_path = pg_catalog AS $$ BEGIN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE=code; END $$;
CREATE FUNCTION hobnail.only_keys(value jsonb, allowed text[], required text[] DEFAULT '{}'::text[]) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, hobnail AS $$
BEGIN
  IF jsonb_typeof(value) IS DISTINCT FROM 'object' OR EXISTS (SELECT FROM jsonb_object_keys(value) k WHERE NOT k=ANY(allowed))
     OR EXISTS (SELECT FROM unnest(required) k WHERE NOT value ? k OR value->k='null'::jsonb) THEN
    PERFORM hobnail.refuse('INVALID_REQUEST');
  END IF;
END $$;
CREATE FUNCTION hobnail.redact(value jsonb) RETURNS jsonb LANGUAGE plpgsql
SET search_path=pg_catalog,hobnail AS $$
DECLARE result jsonb; k text; v jsonb;
BEGIN
 IF jsonb_typeof(value)='object' THEN
  result:='{}';
  FOR k,v IN SELECT * FROM jsonb_each(value) LOOP
   IF k IN ('content_hex','token','password','secret','authorization','access_token','refresh_token','api_key') THEN
    result:=result||jsonb_build_object(k,jsonb_build_object('redacted_sha256',hobnail.digest(v)));
   ELSE result:=result||jsonb_build_object(k,hobnail.redact(v)); END IF;
  END LOOP;
  RETURN result;
 ELSIF jsonb_typeof(value)='array' THEN
  SELECT coalesce(jsonb_agg(hobnail.redact(e)),'[]') INTO result FROM jsonb_array_elements(value) e;
  RETURN result;
 ELSE RETURN value; END IF;
END $$;
CREATE FUNCTION hobnail.append_audit(op text, request jsonb, result jsonb, principal text) RETURNS bigint
LANGUAGE plpgsql SET search_path = pg_catalog, hobnail SET timezone = 'UTC' AS $$
DECLARE h hobnail.audit_head; e jsonb; next_hash text;
BEGIN
  -- The physical singleton row serializes both the sequence and head. At a stale
  -- repeatable-read snapshot PostgreSQL raises serialization_failure; no fork is committed.
  SELECT * INTO h FROM hobnail.audit_head WHERE singleton FOR UPDATE;
  e := jsonb_build_object('sequence',h.seq+1,'at',clock_timestamp(),'login',session_user,
        'principal',principal,'operation',left(op,80),'request_sha256',hobnail.digest(request),
        'ok',result->'ok','code',result->'code','request',hobnail.redact(request),
        'response',CASE WHEN op='audit.export' THEN result-'data' ELSE hobnail.redact(result) END,
        'response_sha256',hobnail.digest(result));
  next_hash := encode(sha256(decode(h.hash,'hex') || convert_to(e::text,'UTF8')),'hex');
  INSERT INTO hobnail.audit VALUES (h.seq+1,e,h.hash,next_hash);
  UPDATE hobnail.audit_head SET seq=h.seq+1,hash=next_hash WHERE singleton;
  RETURN h.seq+1;
END $$;
CREATE FUNCTION hobnail.authenticate() RETURNS hobnail.principals LANGUAGE plpgsql
SET search_path = pg_catalog, hobnail AS $$
DECLARE p hobnail.principals; r record;
BEGIN
  SELECT * INTO p FROM hobnail.principals WHERE login=session_user AND enabled AND (valid_until IS NULL OR valid_until>clock_timestamp());
  IF NOT FOUND THEN PERFORM hobnail.refuse('UNAUTHENTICATED'); END IF;
  SELECT * INTO r FROM pg_roles WHERE rolname=session_user;
  IF NOT r.rolcanlogin OR (r.rolvaliduntil IS NOT NULL AND r.rolvaliduntil<=clock_timestamp()) OR r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls
     OR EXISTS (SELECT FROM pg_auth_members WHERE member=r.oid)
     OR r.oid=(SELECT datdba FROM pg_database WHERE datname=current_database())
     OR EXISTS (SELECT FROM pg_namespace WHERE nspowner=r.oid AND nspname NOT LIKE 'pg_temp_%' AND nspname NOT LIKE 'pg_toast_temp_%')
     OR has_database_privilege(session_user,current_database(),'CREATE')
     OR EXISTS (SELECT FROM pg_class t JOIN pg_namespace ns ON ns.oid=t.relnamespace WHERE ns.nspname='hobnail' AND t.relkind IN ('r','p','v','m','f') AND has_table_privilege(session_user,t.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))
     OR EXISTS (SELECT FROM pg_class t JOIN pg_namespace ns ON ns.oid=t.relnamespace WHERE ns.nspname='hobnail' AND CASE WHEN t.relkind='S' THEN has_sequence_privilege(session_user,t.oid,'USAGE,SELECT,UPDATE') ELSE false END)
  THEN PERFORM hobnail.refuse('FORBIDDEN'); END IF;
  RETURN p;
END $$;
CREATE FUNCTION hobnail.require_capability(p hobnail.principals, cap text) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog,hobnail AS $$
BEGIN IF p.role<>cap THEN PERFORM hobnail.refuse('FORBIDDEN'); END IF; END $$;
CREATE FUNCTION hobnail.identifier(value text) RETURNS boolean LANGUAGE sql IMMUTABLE
SET search_path=pg_catalog AS $$ SELECT coalesce(value ~ '^[A-Za-z0-9_.:/-]{1,128}$',false) $$;
CREATE FUNCTION hobnail.is_digest(value text) RETURNS boolean LANGUAGE sql IMMUTABLE
SET search_path=pg_catalog AS $$ SELECT coalesce(value ~ '^[0-9a-f]{64}$',false) $$;
CREATE FUNCTION hobnail.integer_value(value jsonb, minimum bigint, maximum bigint) RETURNS bigint
LANGUAGE plpgsql SET search_path=pg_catalog,hobnail AS $$
DECLARE n numeric;
BEGIN
  IF jsonb_typeof(value) IS DISTINCT FROM 'number' THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
  n := (value::text)::numeric;
  IF n<>trunc(n) OR n<minimum OR n>maximum THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
  RETURN n::bigint;
END $$;
CREATE FUNCTION hobnail.string_array(value jsonb, maximum integer DEFAULT 128) RETURNS text[]
LANGUAGE plpgsql SET search_path=pg_catalog,hobnail AS $$
DECLARE result text[]; n integer;
BEGIN
  IF jsonb_typeof(value) IS DISTINCT FROM 'array' OR jsonb_array_length(value)>maximum
     OR EXISTS (SELECT FROM jsonb_array_elements(value) e WHERE jsonb_typeof(e)<>'string' OR NOT hobnail.identifier(e#>>'{}'))
  THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
  SELECT coalesce(array_agg(e#>>'{}'),'{}'),count(DISTINCT e) INTO result,n FROM jsonb_array_elements(value) e;
  IF n<>cardinality(result) THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
  RETURN result;
END $$;
CREATE FUNCTION hobnail.metadata(value jsonb) RETURNS void LANGUAGE plpgsql
SET search_path=pg_catalog,hobnail AS $$ BEGIN
 IF jsonb_typeof(value) IS DISTINCT FROM 'object' OR octet_length(value::text)>16384 THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
END $$;
CREATE TABLE hobnail.plugins (
  digest text PRIMARY KEY, plugin_id text NOT NULL, version integer NOT NULL, kind text NOT NULL,
  manifest jsonb NOT NULL, registered_by text NOT NULL, registered_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(plugin_id,version)
);
CREATE TABLE hobnail.contracts (
  contract_id text NOT NULL, version integer NOT NULL, document jsonb NOT NULL, digest text NOT NULL,
  proposed_by text NOT NULL, proposed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(contract_id,version)
);
CREATE TABLE hobnail.contract_heads (
  contract_id text PRIMARY KEY, active_version integer,
  FOREIGN KEY(contract_id,active_version) REFERENCES hobnail.contracts(contract_id,version)
);
CREATE TABLE hobnail.approvals (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, contract_id text NOT NULL, version integer NOT NULL,
  approved_by text NOT NULL, at timestamptz NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY(contract_id,version) REFERENCES hobnail.contracts(contract_id,version)
);
CREATE TABLE hobnail.artifacts (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, content bytea NOT NULL CHECK(octet_length(content)<=1048576),
  digest text NOT NULL, media_type text NOT NULL, submitted_by text NOT NULL, at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE hobnail.snapshots (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, contract_id text NOT NULL, source text NOT NULL, version integer NOT NULL,
  content bytea NOT NULL CHECK(octet_length(content)<=1048576), digest text NOT NULL, media_type text NOT NULL,
  registered_by text NOT NULL, at timestamptz NOT NULL DEFAULT clock_timestamp(), UNIQUE(contract_id,source,version)
);
CREATE TABLE hobnail.source_heads (
  contract_id text NOT NULL, source text NOT NULL, snapshot_id bigint NOT NULL REFERENCES hobnail.snapshots,
  PRIMARY KEY(contract_id,source)
);
CREATE TABLE hobnail.candidates (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, contract_id text NOT NULL, version integer NOT NULL,
  artifact_id bigint NOT NULL REFERENCES hobnail.artifacts, inputs jsonb NOT NULL, binding jsonb NOT NULL,
  binding_digest text NOT NULL, submitted_by text NOT NULL, at timestamptz NOT NULL DEFAULT clock_timestamp(),
  generation integer NOT NULL DEFAULT 0, lease_token uuid, lease_until timestamptz, verifier text,
  FOREIGN KEY(contract_id,version) REFERENCES hobnail.contracts(contract_id,version)
);
CREATE TABLE hobnail.results (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, candidate_id bigint NOT NULL REFERENCES hobnail.candidates,
  generation integer NOT NULL, check_id text NOT NULL, plugin_digest text NOT NULL, binding_digest text NOT NULL,
  verifier text NOT NULL, result text NOT NULL CHECK(result IN ('pass','fail','error','inconclusive')),
  detail jsonb NOT NULL, at timestamptz NOT NULL DEFAULT clock_timestamp(), UNIQUE(candidate_id,generation,check_id)
);
CREATE TABLE hobnail.acceptances (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, candidate_id bigint NOT NULL REFERENCES hobnail.candidates,
  generation integer NOT NULL, binding_digest text NOT NULL, accepted_by text NOT NULL, at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE hobnail.budget_counters (
  contract_id text NOT NULL, budget text NOT NULL, used bigint NOT NULL DEFAULT 0 CHECK(used>=0), PRIMARY KEY(contract_id,budget)
);
CREATE TABLE hobnail.reservations (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, contract_id text NOT NULL, budget text NOT NULL, units bigint NOT NULL,
  principal text NOT NULL, at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE hobnail.idempotency (
  principal text NOT NULL, operation text NOT NULL, key text NOT NULL, request_digest text NOT NULL,
  response jsonb NOT NULL, PRIMARY KEY(principal,operation,key)
);
CREATE TABLE hobnail.effects (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, candidate_id bigint NOT NULL REFERENCES hobnail.candidates,
  action jsonb NOT NULL, requested_by text NOT NULL, at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL, state text NOT NULL DEFAULT 'reserved',
  generation integer NOT NULL DEFAULT 0, lease_token uuid, lease_until timestamptz, adapter text,
  dispatched_at timestamptz, cancel_requested_at timestamptz
);
CREATE TABLE hobnail.effect_reports (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, effect_id bigint NOT NULL REFERENCES hobnail.effects,
  principal text NOT NULL, kind text NOT NULL, outcome text NOT NULL, artifact_digest text, receipt jsonb NOT NULL,
  at timestamptz NOT NULL DEFAULT clock_timestamp()
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['plugins','contracts','approvals','artifacts','snapshots','results','acceptances','reservations','idempotency','effect_reports'] LOOP
  EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON hobnail.%I FOR EACH STATEMENT EXECUTE FUNCTION hobnail.immutable()',t);
 END LOOP;
END $$;
CREATE FUNCTION hobnail.validate_git_arguments(args jsonb) RETURNS void LANGUAGE plpgsql
SET search_path=pg_catalog,hobnail AS $$
DECLARE path text; other_path text; paths text[]:='{}'; item jsonb; branch text; message text;
 aliases jsonb:='{}'; prefix text; part text;
BEGIN
 PERFORM hobnail.only_keys(args,ARRAY['branch','base_commit','paths','message'],ARRAY['branch','base_commit','paths','message']);
 branch:=args->>'branch'; message:=args->>'message';
 IF jsonb_typeof(args->'branch')<>'string' OR branch !~ '^[A-Za-z0-9][A-Za-z0-9_./-]{0,127}$'
   OR branch ~ '(\.\.|//|(^|/)\.|\.lock(/|$)|[./]$)' OR jsonb_typeof(args->'base_commit')<>'string'
   OR args->>'base_commit' !~ '^([0-9a-f]{40}|[0-9a-f]{64})$' OR jsonb_typeof(args->'message')<>'string'
   OR octet_length(message)>2048 OR message !~ '[^[:space:]]' OR position(chr(13) IN message)>0 OR right(message,1)=chr(10)
   OR jsonb_typeof(args->'paths')<>'array' OR jsonb_array_length(args->'paths') NOT BETWEEN 1 AND 64 THEN
  PERFORM hobnail.refuse('INVALID_REQUEST');
 END IF;
 FOR item IN SELECT * FROM jsonb_array_elements(args->'paths') LOOP
  path:=item#>>'{}';
  IF jsonb_typeof(item)<>'string' OR octet_length(path)>1024 OR path !~ '^[A-Za-z0-9_./-]+$'
    OR path ~ '(^/|/$|//|(^|/)\.\.?(/|$))'
    OR lower(path) ~ '(^|/)(\.git|\.gitignore|\.gitattributes|\.gitmodules|\.gitconfig|\.githooks|\.husky|\.pre-commit-config\.yaml)(/|$)'
    OR path=ANY(paths) THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
  FOREACH other_path IN ARRAY paths LOOP
   IF left(path,length(other_path)+1)=other_path||'/' OR left(other_path,length(path)+1)=path||'/' THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
  END LOOP;
  prefix:='';
  FOREACH part IN ARRAY string_to_array(path,'/') LOOP
   prefix:=CASE WHEN prefix='' THEN part ELSE prefix||'/'||part END;
   IF aliases ? lower(prefix) AND aliases->>lower(prefix)<>prefix THEN
    PERFORM hobnail.refuse('INVALID_REQUEST');
   END IF;
   aliases:=aliases||jsonb_build_object(lower(prefix),prefix);
  END LOOP;
  paths:=array_append(paths,path);
 END LOOP;
END $$;
CREATE FUNCTION hobnail.validate_document(d jsonb) RETURNS void LANGUAGE plpgsql
SET search_path=pg_catalog,hobnail AS $$
DECLARE x jsonb; y jsonb; k text; a text[]; names text[]; checks text[]; actions text[]; n bigint;
BEGIN
 PERFORM hobnail.only_keys(d,ARRAY['schema_version','description','access','subject','sources','checks','actions','budgets','expires_at'],ARRAY['schema_version','access','subject','sources','checks','actions','budgets','expires_at']);
 IF d->'schema_version'<>'1'::jsonb OR octet_length(d::text)>131072 OR
    (d ? 'description' AND (jsonb_typeof(d->'description')<>'string' OR octet_length(d->>'description')>2048)) THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
 PERFORM hobnail.only_keys(d->'access',ARRAY['workers','verifiers','observers','adapters'],ARRAY['workers','verifiers','observers','adapters']);
 FOREACH k IN ARRAY ARRAY['workers','verifiers','observers'] LOOP
  a:=hobnail.string_array(d->'access'->k);
  IF cardinality(a)=0 THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
 END LOOP;
 IF jsonb_typeof(d->'access'->'adapters')<>'object' THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
 FOR k,x IN SELECT * FROM jsonb_each(d->'access'->'adapters') LOOP
  IF NOT hobnail.identifier(k) THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
  a:=hobnail.string_array(x);
  IF cardinality(a)=0 THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
 END LOOP;
 PERFORM hobnail.only_keys(d->'subject',ARRAY['media_type','max_bytes'],ARRAY['media_type','max_bytes']);
 IF jsonb_typeof(d->'subject'->'media_type')<>'string' OR length(d->'subject'->>'media_type') NOT BETWEEN 1 AND 128 THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
 n:=hobnail.integer_value(d->'subject'->'max_bytes',1,1048576);
 IF jsonb_typeof(d->'sources')<>'array' OR jsonb_array_length(d->'sources') NOT BETWEEN 1 AND 16 THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
 names:='{}';
 FOR x IN SELECT * FROM jsonb_array_elements(d->'sources') LOOP
  PERFORM hobnail.only_keys(x,ARRAY['name','registrars','require_current'],ARRAY['name','registrars','require_current']);
  IF jsonb_typeof(x->'name')<>'string' OR NOT hobnail.identifier(x->>'name') OR (x->>'name')=ANY(names) OR jsonb_typeof(x->'require_current')<>'boolean' THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
  a:=hobnail.string_array(x->'registrars');
  IF cardinality(a)=0 THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
  names:=array_append(names,x->>'name');
 END LOOP;
 IF jsonb_typeof(d->'checks')<>'array' OR jsonb_array_length(d->'checks') NOT BETWEEN 1 AND 64 THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
 checks:='{}';
 FOR x IN SELECT * FROM jsonb_array_elements(d->'checks') LOOP
  PERFORM hobnail.only_keys(x,ARRAY['id','plugin','plugin_digest','parameters','max_age_seconds'],ARRAY['id','plugin','plugin_digest','parameters','max_age_seconds']);
  IF jsonb_typeof(x->'id')<>'string' OR jsonb_typeof(x->'plugin')<>'string' OR jsonb_typeof(x->'plugin_digest')<>'string' OR NOT hobnail.identifier(x->>'id') OR (x->>'id')=ANY(checks) OR NOT hobnail.is_digest(x->>'plugin_digest') THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
  checks:=array_append(checks,x->>'id');
  n:=hobnail.integer_value(x->'max_age_seconds',1,86400);
  IF x->>'plugin'='bytes.sha256' THEN
   PERFORM hobnail.only_keys(x->'parameters',ARRAY['expected'],ARRAY['expected']);
   IF NOT hobnail.is_digest(x->'parameters'->>'expected') THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
  ELSIF x->>'plugin'='json.required_fields' THEN
   PERFORM hobnail.only_keys(x->'parameters',ARRAY['pointers'],ARRAY['pointers']);
   IF jsonb_typeof(x->'parameters'->'pointers')<>'array' OR jsonb_array_length(x->'parameters'->'pointers') NOT BETWEEN 1 AND 128 THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
   FOR y IN SELECT * FROM jsonb_array_elements(x->'parameters'->'pointers') LOOP
    IF jsonb_typeof(y)<>'string' OR octet_length(y#>>'{}')>2048 OR ((y#>>'{}')<>'' AND left(y#>>'{}',1)<>'/') OR (y#>>'{}') ~ '~([^01]|$)' THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
   END LOOP;
   IF (SELECT count(*)<>count(DISTINCT value) FROM jsonb_array_elements(x->'parameters'->'pointers')) THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
  ELSIF x->>'plugin'='json.equals' THEN
   PERFORM hobnail.only_keys(x->'parameters',ARRAY['source','pairs'],ARRAY['source','pairs']);
   IF NOT (x->'parameters'->>'source')=ANY(names) OR jsonb_typeof(x->'parameters'->'pairs')<>'array' OR jsonb_array_length(x->'parameters'->'pairs') NOT BETWEEN 1 AND 128 THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
   FOR y IN SELECT * FROM jsonb_array_elements(x->'parameters'->'pairs') LOOP
    PERFORM hobnail.only_keys(y,ARRAY['artifact','input'],ARRAY['artifact','input']);
    FOREACH k IN ARRAY ARRAY['artifact','input'] LOOP
     IF jsonb_typeof(y->k)<>'string' OR octet_length(y->>k)>2048 OR ((y->>k)<>'' AND left(y->>k,1)<>'/') OR (y->>k) ~ '~([^01]|$)' THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
    END LOOP;
   END LOOP;
   IF (SELECT count(*)<>count(DISTINCT value) FROM jsonb_array_elements(x->'parameters'->'pairs')) THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
  ELSIF x->>'plugin' ~ '^custom:[A-Za-z0-9_.:/-]+$' AND hobnail.identifier(x->>'plugin') THEN
   PERFORM hobnail.metadata(x->'parameters');
  ELSE PERFORM hobnail.refuse('UNSUPPORTED_CAPABILITY'); END IF;
 END LOOP;
 IF jsonb_typeof(d->'actions')<>'array' OR jsonb_array_length(d->'actions')>16 THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
 actions:='{}';
 FOR x IN SELECT * FROM jsonb_array_elements(d->'actions') LOOP
  PERFORM hobnail.only_keys(x,ARRAY['name','plugin','plugin_digest','target','arguments','max_age_seconds'],ARRAY['name','plugin','plugin_digest','target','arguments','max_age_seconds']);
  IF jsonb_typeof(x->'name')<>'string' OR jsonb_typeof(x->'plugin')<>'string' OR jsonb_typeof(x->'plugin_digest')<>'string' OR NOT hobnail.identifier(x->>'name') OR (x->>'name')=ANY(actions) OR NOT hobnail.is_digest(x->>'plugin_digest') OR jsonb_typeof(x->'target')<>'string' OR octet_length(x->>'target') NOT BETWEEN 1 AND 1024
   OR NOT (d->'access'->'adapters' ? (x->>'name')) THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
  IF x->>'plugin' NOT IN ('file.publish','research.promote','git.commit') THEN PERFORM hobnail.refuse('UNSUPPORTED_CAPABILITY'); END IF;
  IF x->>'target' ~ '(^/|/$|//|(^|/)\.\.?(/|$)|[[:cntrl:]]|\\)' THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
  PERFORM hobnail.metadata(x->'arguments');
  IF x->>'plugin'='git.commit' THEN
   IF NOT hobnail.identifier(x->>'target') THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
   PERFORM hobnail.validate_git_arguments(x->'arguments');
  ELSIF x->'arguments'<>'{}'::jsonb THEN PERFORM hobnail.refuse('UNSUPPORTED_CAPABILITY'); END IF;
  IF x->>'plugin'='research.promote' AND x->>'target' !~ '(^|/)[0-9a-f]{64}\.json$' THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
  n:=hobnail.integer_value(x->'max_age_seconds',1,86400);
  actions:=array_append(actions,x->>'name');
 END LOOP;
 IF EXISTS (SELECT FROM jsonb_object_keys(d->'access'->'adapters') names(name) WHERE NOT names.name=ANY(actions)) THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
 IF jsonb_typeof(d->'budgets')<>'object' OR NOT d->'budgets' ?& ARRAY['verification','effects'] THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
 FOR k,x IN SELECT * FROM jsonb_each(d->'budgets') LOOP
  IF NOT hobnail.identifier(k) THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
  n:=hobnail.integer_value(x,0,1000000000);
 END LOOP;
 IF jsonb_typeof(d->'expires_at')<>'string' OR d->>'expires_at' !~ '^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,6})?Z$' THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
 PERFORM (d->>'expires_at')::timestamptz;
END $$;
CREATE FUNCTION hobnail.scope(p hobnail.principals, contract_id text, d jsonb DEFAULT NULL, action text DEFAULT NULL) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog,hobnail AS $$
DECLARE allowlist jsonb;
BEGIN
 IF NOT contract_id=ANY(p.contracts) THEN PERFORM hobnail.refuse('SCOPE_MISMATCH'); END IF;
 IF d IS NULL OR p.role IN ('approver','auditor','registrar','credential_provider') THEN RETURN; END IF;
 allowlist:=CASE p.role WHEN 'worker' THEN d->'access'->'workers' WHEN 'verifier' THEN d->'access'->'verifiers'
  WHEN 'observer' THEN d->'access'->'observers' WHEN 'adapter' THEN d->'access'->'adapters'->action ELSE NULL END;
 IF allowlist IS NULL OR NOT allowlist ? p.principal_id THEN PERFORM hobnail.refuse('SCOPE_MISMATCH'); END IF;
END $$;
CREATE FUNCTION hobnail.active_contract(cid text) RETURNS hobnail.contracts LANGUAGE plpgsql
SET search_path=pg_catalog,hobnail AS $$
DECLARE h hobnail.contract_heads; c hobnail.contracts;
BEGIN
 SELECT * INTO h FROM hobnail.contract_heads WHERE contract_id=cid FOR UPDATE;
 IF NOT FOUND OR h.active_version IS NULL THEN PERFORM hobnail.refuse('POLICY_INACTIVE'); END IF;
 SELECT * INTO c FROM hobnail.contracts WHERE contract_id=cid AND version=h.active_version;
 IF (c.document->>'expires_at')::timestamptz<=clock_timestamp() THEN PERFORM hobnail.refuse('POLICY_EXPIRED'); END IF;
 RETURN c;
END $$;
CREATE FUNCTION hobnail.consume(cid text, budget_name text, units bigint, who text, d jsonb) RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog,hobnail AS $$
DECLARE cap bigint; total bigint; rid bigint;
BEGIN
 IF NOT d->'budgets' ? budget_name THEN PERFORM hobnail.refuse('SCOPE_MISMATCH'); END IF;
 cap:=(d->'budgets'->>budget_name)::bigint;
 INSERT INTO hobnail.budget_counters(contract_id,budget) VALUES(cid,budget_name) ON CONFLICT DO NOTHING;
 SELECT used INTO total FROM hobnail.budget_counters WHERE contract_id=cid AND budget=budget_name FOR UPDATE;
 IF units<=0 OR total+units>cap THEN PERFORM hobnail.refuse('BUDGET_EXHAUSTED'); END IF;
 UPDATE hobnail.budget_counters SET used=used+units WHERE contract_id=cid AND budget=budget_name;
 INSERT INTO hobnail.reservations(contract_id,budget,units,principal) VALUES(cid,budget_name,units,who) RETURNING id INTO rid;
 RETURN jsonb_build_object('reservation_id',rid,'used',total+units,'remaining',cap-total-units);
END $$;
CREATE FUNCTION hobnail.eligible(cand hobnail.candidates, need_results boolean DEFAULT true) RETURNS hobnail.contracts
LANGUAGE plpgsql SET search_path=pg_catalog,hobnail AS $$
DECLARE c hobnail.contracts; s jsonb; r hobnail.results; snap hobnail.snapshots; check_doc jsonb;
BEGIN
 c:=hobnail.active_contract(cand.contract_id);
 IF c.version<>cand.version THEN PERFORM hobnail.refuse('POLICY_INACTIVE'); END IF;
 FOR s IN SELECT * FROM jsonb_array_elements(c.document->'sources') LOOP
  SELECT * INTO snap FROM hobnail.snapshots WHERE id=(cand.inputs->>(s->>'name'))::bigint;
  IF NOT FOUND OR snap.contract_id<>cand.contract_id OR snap.source<>s->>'name' THEN PERFORM hobnail.refuse('INPUT_MISMATCH'); END IF;
  IF snap.registered_by=cand.submitted_by THEN PERFORM hobnail.refuse('SELF_JUDGING'); END IF;
  IF NOT s->'registrars' ? snap.registered_by OR NOT EXISTS(SELECT FROM hobnail.principals WHERE principal_id=snap.registered_by AND role='registrar' AND enabled AND cand.contract_id=ANY(contracts) AND snap.source=ANY(sources)) THEN PERFORM hobnail.refuse('FORBIDDEN'); END IF;
  IF (s->>'require_current')::boolean AND NOT EXISTS (SELECT FROM hobnail.source_heads WHERE contract_id=cand.contract_id AND source=s->>'name' AND snapshot_id=snap.id) THEN PERFORM hobnail.refuse('INPUT_STALE'); END IF;
 END LOOP;
 IF need_results THEN
  FOR check_doc IN SELECT * FROM jsonb_array_elements(c.document->'checks') LOOP
   SELECT * INTO r FROM hobnail.results WHERE candidate_id=cand.id AND generation=cand.generation AND check_id=check_doc->>'id';
   IF NOT FOUND THEN PERFORM hobnail.refuse('MISSING_CHECKS'); END IF;
   IF r.result<>'pass' THEN PERFORM hobnail.refuse('CHECK_FAILED'); END IF;
   IF r.binding_digest<>cand.binding_digest OR r.plugin_digest<>check_doc->>'plugin_digest' THEN PERFORM hobnail.refuse('BINDING_MISMATCH'); END IF;
   IF r.verifier=cand.submitted_by THEN PERFORM hobnail.refuse('SELF_JUDGING'); END IF;
   IF NOT c.document->'access'->'verifiers' ? r.verifier OR NOT EXISTS (SELECT FROM hobnail.principals WHERE principal_id=r.verifier AND role='verifier' AND enabled AND cand.contract_id=ANY(contracts)) THEN PERFORM hobnail.refuse('FORBIDDEN'); END IF;
   IF r.at+make_interval(secs=>(check_doc->>'max_age_seconds')::integer)<=clock_timestamp() THEN PERFORM hobnail.refuse('EVIDENCE_STALE'); END IF;
  END LOOP;
 END IF;
 RETURN c;
END $$;
CREATE FUNCTION hobnail.artifact_data(artifact_id bigint) RETURNS jsonb LANGUAGE sql STABLE
SET search_path=pg_catalog,hobnail AS $$
 SELECT jsonb_build_object('artifact_id',id,'content_hex',encode(content,'hex'),'digest',digest,'media_type',media_type,'size',octet_length(content)) FROM hobnail.artifacts WHERE id=artifact_id
$$;
CREATE FUNCTION hobnail.input_data(input_map jsonb) RETURNS jsonb LANGUAGE sql STABLE
SET search_path=pg_catalog,hobnail AS $$
 SELECT coalesce(jsonb_object_agg(k,jsonb_build_object('snapshot_id',s.id,'digest',s.digest,'content_hex',encode(s.content,'hex'),'media_type',s.media_type,'version',s.version)),'{}')
 FROM jsonb_each_text(input_map) i(k,v) JOIN hobnail.snapshots s ON s.id=v::bigint
$$;
CREATE FUNCTION hobnail.dispatch(op text, payload jsonb, p hobnail.principals) RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog,hobnail SET timezone='UTC' AS $$
DECLARE cid text; ver integer; c hobnail.contracts; cand hobnail.candidates; eff hobnail.effects;
 art hobnail.artifacts; snap hobnail.snapshots; plug hobnail.plugins; r record;
 d jsonb; x jsonb; y jsonb; v jsonb; binding jsonb; source_doc jsonb; action_doc jsonb;
 raw bytea; dig text; ids jsonb; rid bigint; i bigint; cur bigint; n bigint; seconds integer; b text;
 caps text[]; role_name text; scope_names text[]; h hobnail.audit_head; actual_hash text; last_hash text; good boolean; seq bigint;
BEGIN
 IF op='principal.bind' THEN
  PERFORM hobnail.only_keys(payload,ARRAY['login','principal','role','contracts','sources','profiles'],ARRAY['login','principal','role','contracts','sources','profiles']);
  IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=session_user) THEN PERFORM hobnail.refuse('FORBIDDEN'); END IF;
  IF NOT hobnail.identifier(payload->>'login') OR NOT hobnail.identifier(payload->>'principal') OR payload->>'role' NOT IN ('worker','registrar','verifier','adapter','observer','approver','credential_provider','auditor') THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
  SELECT * INTO r FROM pg_roles WHERE rolname=payload->>'login';
  IF NOT FOUND OR NOT r.rolcanlogin OR r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls
    OR EXISTS (SELECT FROM pg_auth_members WHERE member=r.oid) OR r.oid=(SELECT datdba FROM pg_database WHERE datname=current_database())
    OR EXISTS (SELECT FROM pg_namespace WHERE nspowner=r.oid) OR has_database_privilege(r.oid,current_database(),'CREATE')
    OR EXISTS (SELECT FROM pg_class t JOIN pg_namespace ns ON ns.oid=t.relnamespace WHERE ns.nspname='hobnail' AND t.relkind IN ('r','p','v','m','f') AND has_table_privilege(r.oid,t.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))
    OR EXISTS (SELECT FROM pg_class t JOIN pg_namespace ns ON ns.oid=t.relnamespace WHERE ns.nspname='hobnail' AND CASE WHEN t.relkind='S' THEN has_sequence_privilege(r.oid,t.oid,'USAGE,SELECT,UPDATE') ELSE false END) THEN PERFORM hobnail.refuse('FORBIDDEN'); END IF;
  INSERT INTO hobnail.principals(login,principal_id,role,contracts,sources,profiles)
   VALUES(payload->>'login',payload->>'principal',payload->>'role',hobnail.string_array(payload->'contracts'),hobnail.string_array(payload->'sources'),hobnail.string_array(payload->'profiles'));
  RETURN jsonb_build_object('principal',payload->>'principal','login',payload->>'login');
 ELSIF op='plugin.register' THEN
  PERFORM hobnail.require_capability(p,'approver');
  PERFORM hobnail.only_keys(payload,ARRAY['plugin_id','version','kind','manifest'],ARRAY['plugin_id','version','kind','manifest']);
  ver:=hobnail.integer_value(payload->'version',1,2147483647);
  IF NOT hobnail.identifier(payload->>'plugin_id') OR payload->>'kind' NOT IN ('validator','effect') THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
  d:=payload->'manifest'; PERFORM hobnail.metadata(d);
  PERFORM hobnail.only_keys(d,ARRAY['implementation','input_media_types','parameters','capabilities','result_semantics','execution_backend'],ARRAY['implementation','input_media_types','parameters','capabilities','result_semantics','execution_backend']);
  IF NOT hobnail.is_digest(d->>'implementation') OR jsonb_typeof(d->'input_media_types')<>'array' OR jsonb_typeof(d->'capabilities')<>'array' OR jsonb_typeof(d->'parameters')<>'object' OR jsonb_typeof(d->'execution_backend')<>'string' OR jsonb_typeof(d->'result_semantics') NOT IN ('object','string') THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
  caps:=hobnail.string_array(d->'input_media_types'); caps:=hobnail.string_array(d->'capabilities');
  IF (payload->>'kind'='validator' AND ((payload->>'plugin_id' NOT IN ('bytes.sha256','json.required_fields','json.equals') AND payload->>'plugin_id' !~ '^custom:[A-Za-z0-9_.:/-]+$') OR d->>'execution_backend'<>'isolated-json' OR NOT caps <@ ARRAY['read_artifact','read_inputs']::text[])) OR (payload->>'kind'='effect' AND (NOT ((payload->>'plugin_id'='file.publish' AND d->>'execution_backend'='local-file') OR (payload->>'plugin_id'='research.promote' AND d->>'execution_backend'='research-registry') OR (payload->>'plugin_id'='git.commit' AND d->>'execution_backend'='local-git')))) THEN PERFORM hobnail.refuse('UNSUPPORTED_CAPABILITY'); END IF;
  dig:=hobnail.digest(jsonb_build_object('plugin_id',payload->'plugin_id','version',ver,'kind',payload->'kind','manifest',d));
  INSERT INTO hobnail.plugins VALUES(dig,payload->>'plugin_id',ver,payload->>'kind',d,p.principal_id,clock_timestamp());
  RETURN jsonb_build_object('plugin_digest',dig);
 ELSIF op='contract.propose' THEN
  IF p.role NOT IN ('worker','registrar','approver') THEN PERFORM hobnail.refuse('FORBIDDEN'); END IF;
  PERFORM hobnail.only_keys(payload,ARRAY['contract_id','version','document'],ARRAY['contract_id','version','document']);
  cid:=payload->>'contract_id'; ver:=hobnail.integer_value(payload->'version',1,2147483647);
  IF NOT hobnail.identifier(cid) THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
  PERFORM hobnail.scope(p,cid); PERFORM hobnail.validate_document(payload->'document');
  dig:=hobnail.digest(payload->'document');
  INSERT INTO hobnail.contract_heads(contract_id) VALUES(cid) ON CONFLICT DO NOTHING;
  PERFORM 1 FROM hobnail.contract_heads WHERE contract_id=cid FOR UPDATE;
  INSERT INTO hobnail.contracts(contract_id,version,document,digest,proposed_by) VALUES(cid,ver,payload->'document',dig,p.principal_id);
  RETURN jsonb_build_object('contract_id',cid,'version',ver,'policy_digest',dig);
 ELSIF op='contract.activate' THEN
  PERFORM hobnail.require_capability(p,'approver');
  PERFORM hobnail.only_keys(payload,ARRAY['contract_id','version','expected_active_version'],ARRAY['contract_id','version']);
  IF NOT payload ? 'expected_active_version' THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
  cid:=payload->>'contract_id'; ver:=hobnail.integer_value(payload->'version',1,2147483647); PERFORM hobnail.scope(p,cid);
  SELECT active_version INTO cur FROM hobnail.contract_heads WHERE contract_id=cid FOR UPDATE;
  IF NOT FOUND THEN PERFORM hobnail.refuse('NOT_FOUND'); END IF;
  IF payload->'expected_active_version' <> 'null'::jsonb THEN i:=hobnail.integer_value(payload->'expected_active_version',1,2147483647); ELSE i:=NULL; END IF;
  IF cur IS DISTINCT FROM i THEN PERFORM hobnail.refuse('VERSION_CONFLICT'); END IF;
  SELECT * INTO c FROM hobnail.contracts WHERE contract_id=cid AND version=ver;
  IF NOT FOUND THEN PERFORM hobnail.refuse('NOT_FOUND'); END IF;
  IF c.proposed_by=p.principal_id THEN PERFORM hobnail.refuse('SELF_JUDGING'); END IF;
  d:=c.document; PERFORM hobnail.validate_document(d);
  IF (d->>'expires_at')::timestamptz<=clock_timestamp() THEN PERFORM hobnail.refuse('POLICY_EXPIRED'); END IF;
  FOR x IN SELECT value FROM jsonb_array_elements(d->'checks') UNION ALL SELECT value FROM jsonb_array_elements(d->'actions') LOOP
   SELECT * INTO plug FROM hobnail.plugins WHERE digest=x->>'plugin_digest' AND plugin_id=x->>'plugin';
   IF NOT FOUND THEN PERFORM hobnail.refuse('PLUGIN_MISMATCH'); END IF;
   IF NOT plug.manifest->'input_media_types' ? (d->'subject'->>'media_type') THEN PERFORM hobnail.refuse('UNSUPPORTED_CAPABILITY'); END IF;
   IF (x ? 'id' AND plug.kind<>'validator') OR (x ? 'name' AND plug.kind<>'effect') THEN PERFORM hobnail.refuse('PLUGIN_MISMATCH'); END IF;
  END LOOP;
  FOREACH b IN ARRAY ARRAY['workers','verifiers','observers'] LOOP
   role_name:=CASE b WHEN 'workers' THEN 'worker' WHEN 'verifiers' THEN 'verifier' ELSE 'observer' END;
   FOR x IN SELECT * FROM jsonb_array_elements(d->'access'->b) LOOP
    IF NOT EXISTS (SELECT FROM hobnail.principals WHERE principal_id=x#>>'{}' AND role=role_name AND enabled AND cid=ANY(contracts)) THEN PERFORM hobnail.refuse('SCOPE_MISMATCH'); END IF;
   END LOOP;
  END LOOP;
  FOR x IN SELECT * FROM jsonb_array_elements(d->'sources') LOOP
   FOR y IN SELECT * FROM jsonb_array_elements(x->'registrars') LOOP
    IF NOT EXISTS (SELECT FROM hobnail.principals WHERE principal_id=y#>>'{}' AND role='registrar' AND enabled AND cid=ANY(contracts) AND (x->>'name')=ANY(sources)) THEN PERFORM hobnail.refuse('SCOPE_MISMATCH'); END IF;
   END LOOP;
  END LOOP;
  FOR x IN SELECT value FROM jsonb_each(d->'access'->'adapters') LOOP
   FOR y IN SELECT * FROM jsonb_array_elements(x) LOOP
    IF NOT EXISTS (SELECT FROM hobnail.principals WHERE principal_id=y#>>'{}' AND role='adapter' AND enabled AND cid=ANY(contracts)) THEN PERFORM hobnail.refuse('SCOPE_MISMATCH'); END IF;
   END LOOP;
  END LOOP;
  UPDATE hobnail.contract_heads SET active_version=ver WHERE contract_id=cid;
  INSERT INTO hobnail.approvals(contract_id,version,approved_by) VALUES(cid,ver,p.principal_id);
  RETURN jsonb_build_object('contract_id',cid,'version',ver,'policy_digest',c.digest);
 ELSIF op IN ('contract.get','coverage.inspect') THEN
  PERFORM hobnail.only_keys(payload,ARRAY['contract_id','version'],ARRAY['contract_id']); cid:=payload->>'contract_id'; PERFORM hobnail.scope(p,cid);
  IF payload ? 'version' THEN ver:=hobnail.integer_value(payload->'version',1,2147483647); ELSE SELECT active_version INTO ver FROM hobnail.contract_heads WHERE contract_id=cid; END IF;
  SELECT * INTO c FROM hobnail.contracts WHERE contract_id=cid AND version=ver;
  IF NOT FOUND THEN PERFORM hobnail.refuse('NOT_FOUND'); END IF;
  IF op='coverage.inspect' THEN
   SELECT jsonb_agg(requirement) INTO v FROM (
    SELECT jsonb_build_object('id','check:'||(x->>'id'),'status',CASE WHEN x->>'plugin' LIKE 'custom:%' THEN 'external' ELSE 'implemented' END,'mechanism',x->>'plugin','qualification_requirement','independent isolated runner with approved implementation digest') requirement FROM jsonb_array_elements(c.document->'checks') x
    UNION ALL SELECT jsonb_build_object('id','source:'||(x->>'name'),'status','implemented','mechanism','independent immutable source registration and current-snapshot binding','qualification_requirement','trusted source registrar and authentic source acquisition') FROM jsonb_array_elements(c.document->'sources') x
    UNION ALL SELECT jsonb_build_object('id','action:'||(x->>'name'),'status','implemented','mechanism',x->>'plugin','qualification_requirement','exclusive protected consumer, exact target confinement, independent observation') FROM jsonb_array_elements(c.document->'actions') x
    UNION ALL SELECT jsonb_build_object('id','budget:'||j.name,'status','implemented','mechanism','lineage counter and immutable reservations','qualification_requirement','all relevant work must reserve before execution') FROM jsonb_object_keys(c.document->'budgets') j(name)
    UNION ALL SELECT jsonb_build_object('id','authority','status','implemented','mechanism','authenticated stable principal, scoped registry and policy allowlists','qualification_requirement','actual identity and permission probes; administrators remain trusted')
    UNION ALL SELECT jsonb_build_object('id','binding','status','implemented','mechanism','database hashes exact bytes and complete source-policy-check bindings','qualification_requirement','protected evaluator consumes the exact registered bytes')
   ) covered;
   RETURN jsonb_build_object('requirements',v,'qualification','not_established_by_registration');
  END IF;
  RETURN jsonb_build_object('contract_id',cid,'version',ver,'document',c.document,'policy_digest',c.digest,'proposed_by',c.proposed_by,'active',EXISTS(SELECT FROM hobnail.contract_heads WHERE contract_id=cid AND active_version=ver),'approvals',(SELECT coalesce(jsonb_agg(to_jsonb(a)),'[]') FROM hobnail.approvals a WHERE contract_id=cid AND version=ver));
 ELSIF op='artifact.put' THEN
  PERFORM hobnail.require_capability(p,'worker'); PERFORM hobnail.only_keys(payload,ARRAY['content_hex','media_type'],ARRAY['content_hex','media_type']);
  IF jsonb_typeof(payload->'content_hex')<>'string' OR payload->>'content_hex' !~ '^([0-9a-f]{2})*$' OR length(payload->>'content_hex')>2097152 OR jsonb_typeof(payload->'media_type')<>'string' OR length(payload->>'media_type') NOT BETWEEN 1 AND 128 THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
  raw:=decode(payload->>'content_hex','hex'); dig:=encode(sha256(raw),'hex');
  INSERT INTO hobnail.artifacts(content,digest,media_type,submitted_by) VALUES(raw,dig,payload->>'media_type',p.principal_id) RETURNING id INTO rid;
  RETURN jsonb_build_object('artifact_id',rid,'digest',dig,'size',octet_length(raw));
 ELSIF op='input.put' THEN
  PERFORM hobnail.require_capability(p,'registrar'); PERFORM hobnail.only_keys(payload,ARRAY['contract_id','source','version','content_hex','media_type','expected_current'],ARRAY['contract_id','source','version','content_hex','media_type']);
  IF NOT payload ? 'expected_current' THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
  cid:=payload->>'contract_id'; c:=hobnail.active_contract(cid); PERFORM hobnail.scope(p,cid);
  SELECT value INTO source_doc FROM jsonb_array_elements(c.document->'sources') WHERE value->>'name'=payload->>'source';
  IF source_doc IS NULL OR NOT (payload->>'source')=ANY(p.sources) OR NOT source_doc->'registrars' ? p.principal_id THEN PERFORM hobnail.refuse('SCOPE_MISMATCH'); END IF;
  ver:=hobnail.integer_value(payload->'version',1,2147483647);
  IF jsonb_typeof(payload->'content_hex')<>'string' OR payload->>'content_hex' !~ '^([0-9a-f]{2})*$' OR length(payload->>'content_hex')>2097152 OR jsonb_typeof(payload->'media_type')<>'string' OR length(payload->>'media_type') NOT BETWEEN 1 AND 128 THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
  SELECT snapshot_id INTO cur FROM hobnail.source_heads WHERE contract_id=cid AND source=payload->>'source';
  IF payload->'expected_current'<>'null'::jsonb THEN i:=hobnail.integer_value(payload->'expected_current',1,9223372036854775807); ELSE i:=NULL; END IF;
  IF cur IS DISTINCT FROM i THEN PERFORM hobnail.refuse('VERSION_CONFLICT'); END IF;
  raw:=decode(payload->>'content_hex','hex'); dig:=encode(sha256(raw),'hex');
  INSERT INTO hobnail.snapshots(contract_id,source,version,content,digest,media_type,registered_by) VALUES(cid,payload->>'source',ver,raw,dig,payload->>'media_type',p.principal_id) RETURNING id INTO rid;
  INSERT INTO hobnail.source_heads VALUES(cid,payload->>'source',rid) ON CONFLICT(contract_id,source) DO UPDATE SET snapshot_id=excluded.snapshot_id;
  RETURN jsonb_build_object('snapshot_id',rid,'digest',dig);
 ELSIF op='candidate.submit' THEN
  PERFORM hobnail.require_capability(p,'worker'); PERFORM hobnail.only_keys(payload,ARRAY['contract_id','artifact_id','inputs','idempotency_key'],ARRAY['contract_id','artifact_id','inputs','idempotency_key']);
  cid:=payload->>'contract_id'; c:=hobnail.active_contract(cid); PERFORM hobnail.scope(p,cid,c.document);
  i:=hobnail.integer_value(payload->'artifact_id',1,9223372036854775807); SELECT * INTO art FROM hobnail.artifacts WHERE id=i;
  IF NOT FOUND THEN PERFORM hobnail.refuse('NOT_FOUND'); END IF;
  IF art.submitted_by<>p.principal_id THEN PERFORM hobnail.refuse('FORBIDDEN'); END IF;
  IF art.media_type<>c.document->'subject'->>'media_type' OR octet_length(art.content)>(c.document->'subject'->>'max_bytes')::integer THEN PERFORM hobnail.refuse('ARTIFACT_MISMATCH'); END IF;
  IF jsonb_typeof(payload->'inputs')<>'object' OR (SELECT count(*) FROM jsonb_object_keys(payload->'inputs'))<>jsonb_array_length(c.document->'sources') THEN PERFORM hobnail.refuse('INPUT_MISMATCH'); END IF;
  ids:='{}';
  FOR source_doc IN SELECT * FROM jsonb_array_elements(c.document->'sources') LOOP
   i:=hobnail.integer_value(payload->'inputs'->(source_doc->>'name'),1,9223372036854775807); SELECT * INTO snap FROM hobnail.snapshots WHERE id=i;
   IF NOT FOUND OR snap.contract_id<>cid OR snap.source<>source_doc->>'name' THEN PERFORM hobnail.refuse('INPUT_MISMATCH'); END IF;
   IF snap.registered_by=p.principal_id THEN PERFORM hobnail.refuse('SELF_JUDGING'); END IF;
   IF NOT source_doc->'registrars' ? snap.registered_by OR NOT EXISTS(SELECT FROM hobnail.principals WHERE principal_id=snap.registered_by AND role='registrar' AND enabled AND cid=ANY(contracts) AND snap.source=ANY(sources)) THEN PERFORM hobnail.refuse('FORBIDDEN'); END IF;
   IF (source_doc->>'require_current')::boolean AND NOT EXISTS(SELECT FROM hobnail.source_heads WHERE contract_id=cid AND source=snap.source AND snapshot_id=snap.id) THEN PERFORM hobnail.refuse('INPUT_STALE'); END IF;
   ids:=ids||jsonb_build_object(snap.source,jsonb_build_object('snapshot_id',snap.id,'digest',snap.digest));
  END LOOP;
  binding:=jsonb_build_object('protocol',1,'principal',p.principal_id,'contract_id',cid,'version',c.version,'policy_digest',c.digest,'artifact_digest',art.digest,'inputs',ids); dig:=hobnail.digest(binding);
  INSERT INTO hobnail.candidates(contract_id,version,artifact_id,inputs,binding,binding_digest,submitted_by) VALUES(cid,c.version,art.id,payload->'inputs',binding,dig,p.principal_id) RETURNING id INTO rid;
  RETURN jsonb_build_object('candidate_id',rid,'binding_digest',dig);
 ELSIF op IN ('candidate.get','candidate.accept','verification.claim','verification.record') THEN
  IF op IN ('candidate.get','candidate.accept') THEN PERFORM hobnail.only_keys(payload,ARRAY['candidate_id'],ARRAY['candidate_id']);
  ELSIF op='verification.claim' THEN PERFORM hobnail.only_keys(payload,ARRAY['candidate_id','lease_seconds'],ARRAY['candidate_id','lease_seconds']);
  ELSE PERFORM hobnail.only_keys(payload,ARRAY['candidate_id','token','generation','binding_digest','check_id','plugin_digest','result','detail'],ARRAY['candidate_id','token','generation','binding_digest','check_id','plugin_digest','result','detail']); END IF;
  i:=hobnail.integer_value(payload->'candidate_id',1,9223372036854775807); SELECT * INTO cand FROM hobnail.candidates WHERE id=i;
  IF NOT FOUND THEN PERFORM hobnail.refuse('NOT_FOUND'); END IF;
  PERFORM 1 FROM hobnail.contract_heads WHERE contract_id=cand.contract_id FOR UPDATE;
  SELECT * INTO cand FROM hobnail.candidates WHERE id=i FOR UPDATE;
  SELECT * INTO c FROM hobnail.contracts WHERE contract_id=cand.contract_id AND version=cand.version;
  PERFORM hobnail.scope(p,cand.contract_id,c.document);
  IF op='candidate.get' THEN
   BEGIN PERFORM hobnail.eligible(cand); b:='eligible'; EXCEPTION WHEN SQLSTATE 'P0001' THEN b:=SQLERRM; END;
   RETURN jsonb_build_object('candidate_id',cand.id,'binding',cand.binding,'binding_digest',cand.binding_digest,'generation',cand.generation,'decision',b,'eligible',b='eligible','artifact',hobnail.artifact_data(cand.artifact_id),'inputs',hobnail.input_data(cand.inputs),'contract',c.document,'results',(SELECT coalesce(jsonb_agg(to_jsonb(rr) ORDER BY id),'[]') FROM hobnail.results rr WHERE candidate_id=cand.id),'acceptances',(SELECT coalesce(jsonb_agg(to_jsonb(a)),'[]') FROM hobnail.acceptances a WHERE candidate_id=cand.id));
  ELSIF op='candidate.accept' THEN
   IF p.role NOT IN ('worker','verifier') OR (p.role='worker' AND p.principal_id<>cand.submitted_by) THEN PERFORM hobnail.refuse('FORBIDDEN'); END IF;
   c:=hobnail.eligible(cand);
   INSERT INTO hobnail.acceptances(candidate_id,generation,binding_digest,accepted_by) VALUES(cand.id,cand.generation,cand.binding_digest,p.principal_id) RETURNING id INTO rid;
   RETURN jsonb_build_object('candidate_id',cand.id,'acceptance_id',rid,'binding_digest',cand.binding_digest,'accepted',true);
  END IF;
  PERFORM hobnail.require_capability(p,'verifier'); IF p.principal_id=cand.submitted_by THEN PERFORM hobnail.refuse('SELF_JUDGING'); END IF;
  c:=hobnail.eligible(cand,false);
  IF op='verification.claim' THEN
   seconds:=hobnail.integer_value(payload->'lease_seconds',1,300);
   IF cand.lease_until>clock_timestamp() THEN PERFORM hobnail.refuse('LEASE_MISMATCH'); END IF;
   SELECT count(*) INTO n FROM hobnail.results WHERE candidate_id=cand.id AND generation=cand.generation;
   IF n=jsonb_array_length(c.document->'checks') THEN PERFORM hobnail.refuse('ALREADY_RECORDED'); END IF;
   v:=hobnail.consume(cand.contract_id,'verification',1,p.principal_id,c.document);
   UPDATE hobnail.candidates SET generation=generation+1,lease_token=gen_random_uuid(),lease_until=clock_timestamp()+make_interval(secs=>seconds),verifier=p.principal_id WHERE id=cand.id RETURNING * INTO cand;
   RETURN jsonb_build_object('candidate_id',cand.id,'token',cand.lease_token,'generation',cand.generation,'lease_until',cand.lease_until,'binding_digest',cand.binding_digest,'artifact',hobnail.artifact_data(cand.artifact_id),'inputs',hobnail.input_data(cand.inputs),'contract',c.document,'checks',(SELECT jsonb_agg(j.value||jsonb_build_object('manifest',pl.manifest)) FROM jsonb_array_elements(c.document->'checks') j JOIN hobnail.plugins pl ON pl.digest=j.value->>'plugin_digest'),'reservation',v);
  END IF;
  n:=hobnail.integer_value(payload->'generation',1,2147483647);
  IF cand.verifier<>p.principal_id OR cand.lease_token IS DISTINCT FROM (payload->>'token')::uuid OR cand.generation<>n THEN PERFORM hobnail.refuse('LEASE_MISMATCH'); END IF;
  IF cand.lease_until<=clock_timestamp() THEN PERFORM hobnail.refuse('LEASE_EXPIRED'); END IF;
  IF payload->>'binding_digest'<>cand.binding_digest THEN PERFORM hobnail.refuse('BINDING_MISMATCH'); END IF;
  SELECT value INTO x FROM jsonb_array_elements(c.document->'checks') WHERE value->>'id'=payload->>'check_id';
  IF x IS NULL THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
  IF payload->>'plugin_digest'<>x->>'plugin_digest' THEN PERFORM hobnail.refuse('PLUGIN_MISMATCH'); END IF;
  IF payload->>'result' NOT IN ('pass','fail','error','inconclusive') THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
  PERFORM hobnail.metadata(payload->'detail');
  IF EXISTS(SELECT FROM hobnail.results WHERE candidate_id=cand.id AND generation=cand.generation AND check_id=payload->>'check_id') THEN PERFORM hobnail.refuse('ALREADY_RECORDED'); END IF;
  INSERT INTO hobnail.results(candidate_id,generation,check_id,plugin_digest,binding_digest,verifier,result,detail) VALUES(cand.id,cand.generation,payload->>'check_id',payload->>'plugin_digest',cand.binding_digest,p.principal_id,payload->>'result',payload->'detail') RETURNING id INTO rid;
  RETURN jsonb_build_object('result_id',rid,'candidate_id',cand.id,'result',payload->>'result');
 ELSIF op IN ('budget.get','budget.consume') THEN
  IF op='budget.get' THEN PERFORM hobnail.only_keys(payload,ARRAY['contract_id'],ARRAY['contract_id']);
  ELSE PERFORM hobnail.only_keys(payload,ARRAY['contract_id','budget','units','idempotency_key'],ARRAY['contract_id','budget','units','idempotency_key']); END IF;
  cid:=payload->>'contract_id'; c:=hobnail.active_contract(cid); PERFORM hobnail.scope(p,cid,c.document);
  IF op='budget.get' THEN
   SELECT jsonb_object_agg(k,jsonb_build_object('cap',value,'used',coalesce(bc.used,0),'remaining',greatest(value::text::bigint-coalesce(bc.used,0),0))) INTO v FROM jsonb_each(c.document->'budgets') j(k,value) LEFT JOIN hobnail.budget_counters bc ON bc.contract_id=cid AND bc.budget=k;
   RETURN jsonb_build_object('contract_id',cid,'budgets',v);
  END IF;
  PERFORM hobnail.require_capability(p,'worker');
  IF payload->>'budget' IN ('verification','effects') THEN PERFORM hobnail.refuse('FORBIDDEN'); END IF;
  n:=hobnail.integer_value(payload->'units',1,1000000000);
  RETURN hobnail.consume(cid,payload->>'budget',n,p.principal_id,c.document);
 ELSIF op='effect.request' THEN
  PERFORM hobnail.require_capability(p,'worker'); PERFORM hobnail.only_keys(payload,ARRAY['candidate_id','action','args','idempotency_key'],ARRAY['candidate_id','action','args','idempotency_key']);
  i:=hobnail.integer_value(payload->'candidate_id',1,9223372036854775807); SELECT * INTO cand FROM hobnail.candidates WHERE id=i;
  IF NOT FOUND THEN PERFORM hobnail.refuse('NOT_FOUND'); END IF;
  c:=hobnail.eligible(cand); PERFORM hobnail.scope(p,cand.contract_id,c.document);
  IF cand.submitted_by<>p.principal_id THEN PERFORM hobnail.refuse('FORBIDDEN'); END IF;
  IF NOT EXISTS(SELECT FROM hobnail.acceptances WHERE candidate_id=cand.id AND generation=cand.generation) THEN PERFORM hobnail.refuse('MISSING_CHECKS'); END IF;
  SELECT value INTO action_doc FROM jsonb_array_elements(c.document->'actions') WHERE value->>'name'=payload->>'action';
  IF action_doc IS NULL OR action_doc->'arguments' IS DISTINCT FROM payload->'args' THEN PERFORM hobnail.refuse('ACTION_MISMATCH'); END IF;
  v:=hobnail.consume(cand.contract_id,'effects',1,p.principal_id,c.document);
  INSERT INTO hobnail.effects(candidate_id,action,requested_by,expires_at) VALUES(cand.id,action_doc,p.principal_id,least((c.document->>'expires_at')::timestamptz,clock_timestamp()+make_interval(secs=>(action_doc->>'max_age_seconds')::integer))) RETURNING id INTO rid;
  RETURN jsonb_build_object('effect_id',rid,'state','reserved','reservation',v);
 ELSIF op IN ('effect.get','effect.claim','effect.dispatch','effect.report','effect.observe','effect.cancel') THEN
  IF op IN ('effect.get','effect.cancel') THEN PERFORM hobnail.only_keys(payload,ARRAY['effect_id'],ARRAY['effect_id']);
  ELSIF op='effect.claim' THEN PERFORM hobnail.only_keys(payload,ARRAY['effect_id','lease_seconds'],ARRAY['effect_id','lease_seconds']);
  ELSIF op='effect.dispatch' THEN PERFORM hobnail.only_keys(payload,ARRAY['effect_id','token','generation'],ARRAY['effect_id','token','generation']);
  ELSIF op='effect.report' THEN PERFORM hobnail.only_keys(payload,ARRAY['effect_id','token','generation','outcome','receipt'],ARRAY['effect_id','token','generation','outcome','receipt']);
  ELSE PERFORM hobnail.only_keys(payload,ARRAY['effect_id','outcome','artifact_digest','receipt'],ARRAY['effect_id','outcome','receipt']); END IF;
  i:=hobnail.integer_value(payload->'effect_id',1,9223372036854775807); SELECT * INTO eff FROM hobnail.effects WHERE id=i;
  IF NOT FOUND THEN PERFORM hobnail.refuse('NOT_FOUND'); END IF;
  SELECT * INTO cand FROM hobnail.candidates WHERE id=eff.candidate_id;
  PERFORM 1 FROM hobnail.contract_heads WHERE contract_id=cand.contract_id FOR UPDATE;
  SELECT * INTO eff FROM hobnail.effects WHERE id=i FOR UPDATE;
  SELECT * INTO c FROM hobnail.contracts WHERE contract_id=cand.contract_id AND version=cand.version;
  PERFORM hobnail.scope(p,cand.contract_id,c.document,eff.action->>'name');
  IF op='effect.get' THEN
   RETURN jsonb_build_object('effect_id',eff.id,'candidate_id',eff.candidate_id,'state',eff.state,'action',eff.action,'artifact',hobnail.artifact_data(cand.artifact_id),'binding_digest',cand.binding_digest,'requested_by',eff.requested_by,'adapter',eff.adapter,'expires_at',eff.expires_at,'dispatched_at',eff.dispatched_at,'cancel_requested_at',eff.cancel_requested_at,'reports',(SELECT coalesce(jsonb_agg(to_jsonb(er) ORDER BY id),'[]') FROM hobnail.effect_reports er WHERE effect_id=eff.id));
  ELSIF op='effect.cancel' THEN
   IF p.role<>'approver' AND (p.role<>'worker' OR p.principal_id<>eff.requested_by) THEN PERFORM hobnail.refuse('FORBIDDEN'); END IF;
   UPDATE hobnail.effects SET cancel_requested_at=coalesce(cancel_requested_at,clock_timestamp()),state=CASE WHEN dispatched_at IS NULL THEN 'cancelled' ELSE state END WHERE id=eff.id RETURNING * INTO eff;
   INSERT INTO hobnail.effect_reports(effect_id,principal,kind,outcome,receipt) VALUES(eff.id,p.principal_id,'cancellation',CASE WHEN eff.dispatched_at IS NULL THEN 'cancelled' ELSE 'requested' END,'{}');
   RETURN jsonb_build_object('effect_id',eff.id,'state',eff.state,'cancel_requested_at',eff.cancel_requested_at);
  ELSIF op='effect.observe' THEN
   PERFORM hobnail.require_capability(p,'observer');
   IF p.principal_id=eff.requested_by OR p.principal_id=eff.adapter THEN PERFORM hobnail.refuse('SELF_JUDGING'); END IF;
   IF payload->>'outcome' NOT IN ('complete','absent','mismatch','unknown') THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
   PERFORM hobnail.metadata(payload->'receipt');
   dig:=payload->>'artifact_digest';
   IF dig IS NOT NULL AND NOT hobnail.is_digest(dig) THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
   IF payload->>'outcome'='complete' AND dig IS NULL THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
   SELECT * INTO art FROM hobnail.artifacts WHERE id=cand.artifact_id;
   b:=CASE WHEN payload->>'outcome'='complete' AND dig=art.digest AND eff.dispatched_at IS NOT NULL THEN 'complete'
           WHEN payload->>'outcome'='mismatch' OR (payload->>'outcome'='complete' AND (dig<>art.digest OR eff.dispatched_at IS NULL)) THEN 'control_failure'
           ELSE 'reconcile' END;
   -- Contradictory observations remain in the ledger; a later success cannot erase a failure.
   IF eff.state='control_failure' THEN b:='control_failure'; END IF;
   INSERT INTO hobnail.effect_reports(effect_id,principal,kind,outcome,artifact_digest,receipt) VALUES(eff.id,p.principal_id,'observation',payload->>'outcome',dig,payload->'receipt');
   UPDATE hobnail.effects SET state=b WHERE id=eff.id;
   RETURN jsonb_build_object('effect_id',eff.id,'state',b,'control_failure',b='control_failure');
  END IF;
  PERFORM hobnail.require_capability(p,'adapter');
  IF p.principal_id=eff.requested_by THEN PERFORM hobnail.refuse('SELF_JUDGING'); END IF;
  IF op='effect.claim' THEN
   seconds:=hobnail.integer_value(payload->'lease_seconds',1,300);
   IF eff.cancel_requested_at IS NOT NULL THEN PERFORM hobnail.refuse('CANCELLED'); END IF;
   IF eff.state<>'reserved' OR eff.dispatched_at IS NOT NULL THEN PERFORM hobnail.refuse('RECONCILIATION_REQUIRED'); END IF;
   c:=hobnail.eligible(cand);
   IF eff.expires_at<=clock_timestamp() THEN PERFORM hobnail.refuse('EVIDENCE_STALE'); END IF;
   IF eff.lease_until>clock_timestamp() THEN PERFORM hobnail.refuse('LEASE_MISMATCH'); END IF;
   UPDATE hobnail.effects SET generation=generation+1,lease_token=gen_random_uuid(),lease_until=clock_timestamp()+make_interval(secs=>seconds),adapter=p.principal_id WHERE id=eff.id RETURNING * INTO eff;
   SELECT manifest INTO d FROM hobnail.plugins WHERE digest=eff.action->>'plugin_digest';
   RETURN jsonb_build_object('effect_id',eff.id,'candidate_id',cand.id,'token',eff.lease_token,'generation',eff.generation,'lease_until',eff.lease_until,'binding_digest',cand.binding_digest,'artifact',hobnail.artifact_data(cand.artifact_id),'action',eff.action||jsonb_build_object('manifest',d),'target',eff.action->'target','args',eff.action->'arguments');
  END IF;
  n:=hobnail.integer_value(payload->'generation',1,2147483647);
  IF eff.adapter IS DISTINCT FROM p.principal_id OR eff.lease_token IS DISTINCT FROM (payload->>'token')::uuid OR eff.generation<>n THEN PERFORM hobnail.refuse('LEASE_MISMATCH'); END IF;
  IF eff.lease_until<=clock_timestamp() THEN PERFORM hobnail.refuse('LEASE_EXPIRED'); END IF;
  IF op='effect.dispatch' THEN
   IF eff.cancel_requested_at IS NOT NULL THEN PERFORM hobnail.refuse('CANCELLED'); END IF;
   IF eff.dispatched_at IS NOT NULL OR eff.state<>'reserved' THEN PERFORM hobnail.refuse('RECONCILIATION_REQUIRED'); END IF;
   c:=hobnail.eligible(cand);
   IF eff.expires_at<=clock_timestamp() THEN PERFORM hobnail.refuse('EVIDENCE_STALE'); END IF;
   UPDATE hobnail.effects SET dispatched_at=clock_timestamp(),state='dispatched' WHERE id=eff.id;
   INSERT INTO hobnail.effect_reports(effect_id,principal,kind,outcome,receipt) VALUES(eff.id,p.principal_id,'dispatch','authorized',jsonb_build_object('binding_digest',cand.binding_digest,'generation',eff.generation));
   RETURN jsonb_build_object('effect_id',eff.id,'state','dispatched','authorized',true);
  END IF;
  IF eff.dispatched_at IS NULL THEN PERFORM hobnail.refuse('RECONCILIATION_REQUIRED'); END IF;
  IF payload->>'outcome' NOT IN ('attempted','uncertain','failed') THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
  PERFORM hobnail.metadata(payload->'receipt');
  IF EXISTS(SELECT FROM hobnail.effect_reports WHERE effect_id=eff.id AND kind='report') THEN PERFORM hobnail.refuse('ALREADY_RECORDED'); END IF;
  INSERT INTO hobnail.effect_reports(effect_id,principal,kind,outcome,receipt) VALUES(eff.id,p.principal_id,'report',payload->>'outcome',payload->'receipt');
  UPDATE hobnail.effects SET state=CASE WHEN state IN ('complete','control_failure','reconcile') THEN state ELSE payload->>'outcome' END WHERE id=eff.id RETURNING * INTO eff;
  RETURN jsonb_build_object('effect_id',eff.id,'state',eff.state);
 ELSIF op='audit.export' THEN
  PERFORM hobnail.require_capability(p,'auditor'); PERFORM hobnail.only_keys(payload,ARRAY['after','limit'],ARRAY['after','limit']);
  i:=hobnail.integer_value(payload->'after',0,9223372036854775807); n:=hobnail.integer_value(payload->'limit',1,1000);
  SELECT * INTO h FROM hobnail.audit_head WHERE singleton FOR UPDATE;
  good:=true; last_hash:=repeat('0',64); seq:=0;
  FOR r IN SELECT a.* FROM hobnail.audit a ORDER BY a.seq LOOP
   actual_hash:=encode(sha256(decode(r.previous_hash,'hex')||convert_to(r.event::text,'UTF8')),'hex');
   good:=good AND r.seq=seq+1 AND (r.event->>'sequence')::bigint=r.seq AND r.previous_hash=last_hash AND r.hash=actual_hash;
   seq:=r.seq; last_hash:=r.hash;
  END LOOP;
  good:=good AND seq=h.seq AND last_hash=h.hash;
  SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY a.seq),'[]') INTO v FROM (SELECT au.*,au.event::text AS event_canonical FROM hobnail.audit au WHERE au.seq>i ORDER BY au.seq LIMIT n) a;
  SELECT jsonb_build_object('immutable_triggers_valid',bool_and(EXISTS(
    SELECT FROM pg_trigger t WHERE t.tgrelid=to_regclass('hobnail.'||names.name)
      AND t.tgname=CASE WHEN names.name='audit' THEN 'audit_immutable' ELSE 'immutable' END
      AND t.tgenabled IN ('O','A') AND t.tgfoid='hobnail.immutable()'::regprocedure
      AND (t.tgtype::integer & 56)=56)),
    'runtime_privileges_valid',NOT EXISTS(
     SELECT FROM hobnail.principals pr JOIN pg_roles ro ON ro.rolname=pr.login
     WHERE pr.enabled AND (ro.rolsuper OR ro.rolcreaterole OR ro.rolcreatedb OR ro.rolreplication OR ro.rolbypassrls
       OR EXISTS(SELECT FROM pg_auth_members am WHERE am.member=ro.oid)
       OR EXISTS(SELECT FROM pg_class tc JOIN pg_namespace ns ON ns.oid=tc.relnamespace
        WHERE ns.nspname='hobnail' AND tc.relkind IN ('r','p','v','m','f')
         AND has_table_privilege(ro.oid,tc.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))))) INTO d
   FROM unnest(ARRAY['audit','plugins','contracts','approvals','artifacts','snapshots','results','acceptances','reservations','idempotency','effect_reports','credential_profiles','credential_requests','credential_events','qualifications']) names(name);
  RETURN jsonb_build_object('events',v,'head',jsonb_build_object('sequence',h.seq,'hash',h.hash),'chain_valid',good,'enforcement',d,'administrator_rewrite_detection',false);
 ELSIF op LIKE 'credential.%' THEN
  RETURN hobnail.credential_api(op,payload,p);
 ELSIF op LIKE 'qualification.%' THEN
  RETURN hobnail.qualification_api(op,payload,p);
 ELSE PERFORM hobnail.refuse('UNKNOWN_OPERATION');
 END IF;
END $$;
CREATE FUNCTION hobnail.api(op text, payload jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,hobnail SET timezone='UTC' AS $$
DECLARE p hobnail.principals; result jsonb; data jsonb; idem_key text; request_hash text; old hobnail.idempotency;
 event_id bigint; denial text; status text; field_name text;
BEGIN
 BEGIN
  IF op IS NULL OR length(op)>80 OR payload IS NULL OR jsonb_typeof(payload)<>'object' OR octet_length(payload::text)>2300000 THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
  FOREACH field_name IN ARRAY ARRAY['login','principal','role','contract_id','source','budget','action','token','binding_digest','check_id','plugin_id','plugin_digest','kind','result','outcome','content_hex','media_type','idempotency_key','profile','provider','lease_ref','configuration_digest'] LOOP
   IF payload ? field_name AND jsonb_typeof(payload->field_name)<>'string' THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
  END LOOP;
  IF op IN ('principal.bind','credential.profile') THEN
   IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=session_user) THEN PERFORM hobnail.refuse('FORBIDDEN'); END IF;
  ELSE p:=hobnail.authenticate(); END IF;
  IF op IN ('candidate.submit','effect.request','budget.consume','credential.request') THEN
   idem_key:=payload->>'idempotency_key'; IF NOT hobnail.identifier(idem_key) THEN PERFORM hobnail.refuse('INVALID_REQUEST'); END IF;
   -- Serialize a stable identity's key before looking at the response. Hash collisions only serialize unrelated callers.
   PERFORM pg_advisory_xact_lock(hashtextextended(p.principal_id||'/'||op||'/'||idem_key,0));
   request_hash:=hobnail.digest(payload);
   SELECT * INTO old FROM hobnail.idempotency WHERE principal=p.principal_id AND operation=op AND hobnail.idempotency.key=idem_key;
   IF FOUND THEN
    IF old.request_digest<>request_hash THEN PERFORM hobnail.refuse('IDEMPOTENCY_CONFLICT'); END IF;
    result:=old.response;
   END IF;
  END IF;
  IF result IS NULL THEN
   data:=hobnail.dispatch(op,payload,p);
   status:=CASE op WHEN 'candidate.submit' THEN 'submitted' WHEN 'candidate.accept' THEN 'accepted' WHEN 'contract.activate' THEN 'active' WHEN 'verification.record' THEN 'recorded' ELSE coalesce(data->>'state','ok') END;
   result:=jsonb_build_object('ok',true,'status',status,'data',data);
   IF idem_key IS NOT NULL THEN INSERT INTO hobnail.idempotency VALUES(p.principal_id,op,idem_key,request_hash,result); END IF;
  END IF;
 EXCEPTION
  WHEN SQLSTATE 'P0001' THEN result:=jsonb_build_object('ok',false,'status','denied','code',SQLERRM,'detail','{}'::jsonb);
  WHEN unique_violation THEN result:=jsonb_build_object('ok',false,'status','denied','code','ALREADY_RECORDED','detail','{}'::jsonb);
  WHEN invalid_text_representation OR numeric_value_out_of_range OR invalid_datetime_format OR datetime_field_overflow OR invalid_parameter_value THEN
   result:=jsonb_build_object('ok',false,'status','denied','code','INVALID_REQUEST','detail','{}'::jsonb);
 END;
 event_id:=hobnail.append_audit(coalesce(op,'<null>'),coalesce(payload,'null'::jsonb),result,p.principal_id);
 RETURN result||jsonb_build_object('event_id',event_id);
END $$;
REVOKE ALL ON ALL TABLES IN SCHEMA hobnail FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA hobnail FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA hobnail FROM PUBLIC;
GRANT USAGE ON SCHEMA hobnail TO PUBLIC;
GRANT EXECUTE ON FUNCTION hobnail.api(text,jsonb) TO PUBLIC;
