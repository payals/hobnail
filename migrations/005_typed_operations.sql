-- Additive protocol-1 discovery and typed convenience functions. The generic
-- API remains the authority, audit and compatibility boundary.
ALTER FUNCTION hobnail.dispatch(text,jsonb,hobnail.principals) RENAME TO dispatch_protocol_1;

CREATE FUNCTION hobnail.dispatch(op text, payload jsonb, p hobnail.principals) RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER
SET search_path=pg_catalog,hobnail,pg_temp SET timezone='UTC' AS $$
BEGIN
 IF op='session.get' THEN
  PERFORM hobnail.only_keys(payload,ARRAY[]::text[]);
  RETURN jsonb_build_object('principal_id',p.principal_id,'role',p.role,
                           'contracts',p.contracts,'valid_until',p.valid_until);
 END IF;
 RETURN hobnail.dispatch_protocol_1(op,payload,p);
END $$;
REVOKE EXECUTE ON FUNCTION hobnail.dispatch(text,jsonb,hobnail.principals),
 hobnail.dispatch_protocol_1(text,jsonb,hobnail.principals) FROM PUBLIC;

-- These are deliberately not STRICT: required SQL NULL arguments enter the
-- common API as JSON null and receive its recorded refusal. SQL type-conversion
-- errors happen before function entry and cannot promise an audit record.
CREATE FUNCTION hobnail.session_get() RETURNS jsonb
LANGUAGE sql SECURITY INVOKER CALLED ON NULL INPUT
SET search_path=pg_catalog,hobnail,pg_temp SET timezone='UTC' AS $$
 SELECT hobnail.api('session.get','{}'::jsonb)
$$;

CREATE FUNCTION hobnail.contract_propose(contract_id text, version integer, document jsonb) RETURNS jsonb
LANGUAGE sql SECURITY INVOKER CALLED ON NULL INPUT
SET search_path=pg_catalog,hobnail,pg_temp SET timezone='UTC' AS $$
 SELECT hobnail.api('contract.propose',jsonb_build_object('contract_id',contract_id,'version',version,'document',document))
$$;

CREATE FUNCTION hobnail.artifact_put(content bytea, media_type text) RETURNS jsonb
LANGUAGE sql SECURITY INVOKER CALLED ON NULL INPUT
SET search_path=pg_catalog,hobnail,pg_temp SET timezone='UTC' AS $$
 SELECT hobnail.api('artifact.put',jsonb_build_object('content_hex',encode(content,'hex'),'media_type',media_type))
$$;

CREATE FUNCTION hobnail.candidate_submit(contract_id text, artifact_id bigint, inputs jsonb, idempotency_key text) RETURNS jsonb
LANGUAGE sql SECURITY INVOKER CALLED ON NULL INPUT
SET search_path=pg_catalog,hobnail,pg_temp SET timezone='UTC' AS $$
 SELECT hobnail.api('candidate.submit',jsonb_build_object('contract_id',contract_id,'artifact_id',artifact_id,'inputs',inputs,'idempotency_key',idempotency_key))
$$;

CREATE FUNCTION hobnail.candidate_get(candidate_id bigint) RETURNS jsonb
LANGUAGE sql SECURITY INVOKER CALLED ON NULL INPUT
SET search_path=pg_catalog,hobnail,pg_temp SET timezone='UTC' AS $$
 SELECT hobnail.api('candidate.get',jsonb_build_object('candidate_id',candidate_id))
$$;

CREATE FUNCTION hobnail.verification_claim(candidate_id bigint, lease_seconds integer DEFAULT 60) RETURNS jsonb
LANGUAGE sql SECURITY INVOKER CALLED ON NULL INPUT
SET search_path=pg_catalog,hobnail,pg_temp SET timezone='UTC' AS $$
 SELECT hobnail.api('verification.claim',jsonb_build_object('candidate_id',candidate_id,'lease_seconds',lease_seconds))
$$;

CREATE FUNCTION hobnail.verification_record(candidate_id bigint, token uuid, generation integer,
 binding_digest text, check_id text, plugin_digest text, result text, detail jsonb) RETURNS jsonb
LANGUAGE sql SECURITY INVOKER CALLED ON NULL INPUT
SET search_path=pg_catalog,hobnail,pg_temp SET timezone='UTC' AS $$
 SELECT hobnail.api('verification.record',jsonb_build_object('candidate_id',candidate_id,'token',token::text,
  'generation',generation,'binding_digest',binding_digest,'check_id',check_id,'plugin_digest',plugin_digest,
  'result',result,'detail',detail))
$$;

CREATE FUNCTION hobnail.candidate_accept(candidate_id bigint) RETURNS jsonb
LANGUAGE sql SECURITY INVOKER CALLED ON NULL INPUT
SET search_path=pg_catalog,hobnail,pg_temp SET timezone='UTC' AS $$
 SELECT hobnail.api('candidate.accept',jsonb_build_object('candidate_id',candidate_id))
$$;

CREATE FUNCTION hobnail.budget_get(contract_id text) RETURNS jsonb
LANGUAGE sql SECURITY INVOKER CALLED ON NULL INPUT
SET search_path=pg_catalog,hobnail,pg_temp SET timezone='UTC' AS $$
 SELECT hobnail.api('budget.get',jsonb_build_object('contract_id',contract_id))
$$;

CREATE FUNCTION hobnail.budget_consume(contract_id text, budget text, units bigint, idempotency_key text) RETURNS jsonb
LANGUAGE sql SECURITY INVOKER CALLED ON NULL INPUT
SET search_path=pg_catalog,hobnail,pg_temp SET timezone='UTC' AS $$
 SELECT hobnail.api('budget.consume',jsonb_build_object('contract_id',contract_id,'budget',budget,'units',units,'idempotency_key',idempotency_key))
$$;

CREATE FUNCTION hobnail.effect_request(candidate_id bigint, action text, args jsonb, idempotency_key text) RETURNS jsonb
LANGUAGE sql SECURITY INVOKER CALLED ON NULL INPUT
SET search_path=pg_catalog,hobnail,pg_temp SET timezone='UTC' AS $$
 SELECT hobnail.api('effect.request',jsonb_build_object('candidate_id',candidate_id,'action',action,'args',args,'idempotency_key',idempotency_key))
$$;

CREATE FUNCTION hobnail.effect_get(effect_id bigint) RETURNS jsonb
LANGUAGE sql SECURITY INVOKER CALLED ON NULL INPUT
SET search_path=pg_catalog,hobnail,pg_temp SET timezone='UTC' AS $$
 SELECT hobnail.api('effect.get',jsonb_build_object('effect_id',effect_id))
$$;

CREATE FUNCTION hobnail.effect_cancel(effect_id bigint) RETURNS jsonb
LANGUAGE sql SECURITY INVOKER CALLED ON NULL INPUT
SET search_path=pg_catalog,hobnail,pg_temp SET timezone='UTC' AS $$
 SELECT hobnail.api('effect.cancel',jsonb_build_object('effect_id',effect_id))
$$;

GRANT EXECUTE ON FUNCTION hobnail.session_get(),
 hobnail.contract_propose(text,integer,jsonb), hobnail.artifact_put(bytea,text),
 hobnail.candidate_submit(text,bigint,jsonb,text), hobnail.candidate_get(bigint),
 hobnail.verification_claim(bigint,integer),
 hobnail.verification_record(bigint,uuid,integer,text,text,text,text,jsonb),
 hobnail.candidate_accept(bigint), hobnail.budget_get(text),
 hobnail.budget_consume(text,text,bigint,text),
 hobnail.effect_request(bigint,text,jsonb,text), hobnail.effect_get(bigint),
 hobnail.effect_cancel(bigint) TO PUBLIC;
