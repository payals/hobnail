-- A structural backstop for acceptance receipts. This proves the immutable
-- evidence set, not current eligibility or historical credential authorization.
-- Existing receipt rows and applied migration bytes are never rewritten.
CREATE TABLE hobnail.acceptance_proofs (
 candidate_id bigint NOT NULL REFERENCES hobnail.candidates,
 generation integer NOT NULL CONSTRAINT acceptance_proof_generation CHECK(generation>0),
 binding_digest text NOT NULL CONSTRAINT acceptance_proof_binding CHECK(hobnail.is_digest(binding_digest)),
 proof jsonb NOT NULL CONSTRAINT acceptance_proof_object CHECK(jsonb_typeof(proof)='object'),
 proof_digest text NOT NULL CONSTRAINT acceptance_proof_digest
  CHECK(hobnail.is_digest(proof_digest) AND proof_digest=hobnail.digest(proof)),
 PRIMARY KEY(candidate_id,generation,binding_digest),
 CONSTRAINT acceptance_proof_identity CHECK(
  (proof->>'candidate_id')::bigint IS NOT DISTINCT FROM candidate_id
  AND (proof->>'generation')::integer IS NOT DISTINCT FROM generation
  AND proof->>'binding_digest' IS NOT DISTINCT FROM binding_digest)
);
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON hobnail.acceptance_proofs
FOR EACH STATEMENT EXECUTE FUNCTION hobnail.immutable();

CREATE FUNCTION hobnail.acceptance_proof_document(p_candidate_id bigint, p_generation integer, p_binding_digest text)
RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER
SET search_path=pg_catalog,hobnail,pg_temp SET timezone='UTC' AS $$
DECLARE cand hobnail.candidates; policy hobnail.contracts; artifact hobnail.artifacts;
 snapshot hobnail.snapshots; verdict hobnail.results; plugin hobnail.plugins;
 source_doc jsonb; check_doc jsonb; input_bindings jsonb:='{}'; expected_binding jsonb;
 evidence jsonb; check_count integer; result_count integer; verifier_count integer;
BEGIN
 IF p_generation IS NULL OR p_generation<=0 OR NOT hobnail.is_digest(p_binding_digest) THEN
  PERFORM hobnail.refuse('INVALID_ACCEPTANCE_PROOF');
 END IF;
 SELECT * INTO cand FROM hobnail.candidates c WHERE c.id=p_candidate_id FOR SHARE;
 IF NOT FOUND OR cand.binding_digest IS DISTINCT FROM p_binding_digest THEN
  PERFORM hobnail.refuse('INVALID_ACCEPTANCE_PROOF');
 END IF;
 SELECT * INTO policy FROM hobnail.contracts c WHERE c.contract_id=cand.contract_id AND c.version=cand.version;
 IF NOT FOUND OR policy.digest IS DISTINCT FROM hobnail.digest(policy.document)
    OR jsonb_typeof(policy.document->'checks') IS DISTINCT FROM 'array'
    OR jsonb_typeof(policy.document->'sources') IS DISTINCT FROM 'array'
    OR jsonb_typeof(cand.inputs) IS DISTINCT FROM 'object' THEN
  PERFORM hobnail.refuse('INVALID_ACCEPTANCE_PROOF');
 END IF;
 check_count:=jsonb_array_length(policy.document->'checks');
 IF check_count NOT BETWEEN 1 AND 64
    OR (SELECT count(DISTINCT j->>'id') FROM jsonb_array_elements(policy.document->'checks') j)<>check_count
    OR jsonb_array_length(policy.document->'sources') NOT BETWEEN 1 AND 16
    OR (SELECT count(*) FROM jsonb_object_keys(cand.inputs))<>jsonb_array_length(policy.document->'sources') THEN
  PERFORM hobnail.refuse('INVALID_ACCEPTANCE_PROOF');
 END IF;
 SELECT * INTO artifact FROM hobnail.artifacts a WHERE a.id=cand.artifact_id;
 IF NOT FOUND OR artifact.submitted_by IS DISTINCT FROM cand.submitted_by
    OR artifact.digest IS DISTINCT FROM encode(sha256(artifact.content),'hex') THEN
  PERFORM hobnail.refuse('INVALID_ACCEPTANCE_PROOF');
 END IF;
 FOR source_doc IN SELECT * FROM jsonb_array_elements(policy.document->'sources') LOOP
  IF jsonb_typeof(source_doc->'name') IS DISTINCT FROM 'string'
     OR jsonb_typeof(cand.inputs->(source_doc->>'name')) IS DISTINCT FROM 'number' THEN
   PERFORM hobnail.refuse('INVALID_ACCEPTANCE_PROOF');
  END IF;
  SELECT * INTO snapshot FROM hobnail.snapshots s WHERE s.id=(cand.inputs->>(source_doc->>'name'))::bigint;
  IF NOT FOUND OR snapshot.contract_id IS DISTINCT FROM cand.contract_id
     OR snapshot.source IS DISTINCT FROM source_doc->>'name'
     OR snapshot.registered_by IS NOT DISTINCT FROM cand.submitted_by
     OR NOT coalesce(source_doc->'registrars' ? snapshot.registered_by,false)
     OR snapshot.digest IS DISTINCT FROM encode(sha256(snapshot.content),'hex')
     OR input_bindings ? snapshot.source THEN
   PERFORM hobnail.refuse('INVALID_ACCEPTANCE_PROOF');
  END IF;
  input_bindings:=input_bindings||jsonb_build_object(snapshot.source,
   jsonb_build_object('snapshot_id',snapshot.id,'digest',snapshot.digest));
 END LOOP;
 expected_binding:=jsonb_build_object('protocol',1,'principal',cand.submitted_by,
  'contract_id',cand.contract_id,'version',policy.version,'policy_digest',policy.digest,
  'artifact_digest',artifact.digest,'inputs',input_bindings);
 IF cand.binding IS DISTINCT FROM expected_binding OR p_binding_digest IS DISTINCT FROM hobnail.digest(expected_binding) THEN
  PERFORM hobnail.refuse('INVALID_ACCEPTANCE_PROOF');
 END IF;
 SELECT count(*),count(DISTINCT r.verifier) INTO result_count,verifier_count
 FROM hobnail.results r WHERE r.candidate_id=cand.id AND r.generation=p_generation;
 IF result_count<>check_count OR verifier_count<>1 THEN
  PERFORM hobnail.refuse('INVALID_ACCEPTANCE_PROOF');
 END IF;
 FOR check_doc IN SELECT * FROM jsonb_array_elements(policy.document->'checks') LOOP
  SELECT * INTO verdict FROM hobnail.results r
   WHERE r.candidate_id=cand.id AND r.generation=p_generation AND r.check_id=check_doc->>'id';
  IF NOT FOUND OR verdict.result IS DISTINCT FROM 'pass'
     OR verdict.binding_digest IS DISTINCT FROM p_binding_digest
     OR verdict.plugin_digest IS DISTINCT FROM check_doc->>'plugin_digest'
     OR verdict.verifier IS NOT DISTINCT FROM cand.submitted_by
     OR NOT coalesce(policy.document->'access'->'verifiers' ? verdict.verifier,false) THEN
   PERFORM hobnail.refuse('INVALID_ACCEPTANCE_PROOF');
  END IF;
  SELECT * INTO plugin FROM hobnail.plugins p WHERE p.digest=verdict.plugin_digest;
  IF NOT FOUND OR plugin.kind IS DISTINCT FROM 'validator' OR plugin.plugin_id IS DISTINCT FROM check_doc->>'plugin' THEN
   PERFORM hobnail.refuse('INVALID_ACCEPTANCE_PROOF');
  END IF;
 END LOOP;
 SELECT jsonb_agg(jsonb_build_object('result_id',r.id,'check_id',r.check_id,
  'plugin_digest',r.plugin_digest,'result',r.result,'verifier',r.verifier,'observed_at',r.at)
  ORDER BY r.check_id COLLATE "C") INTO evidence
 FROM hobnail.results r WHERE r.candidate_id=cand.id AND r.generation=p_generation;
 RETURN jsonb_build_object('proof_version',1,'candidate_id',cand.id,'generation',p_generation,
  'binding_digest',p_binding_digest,'binding',expected_binding,'checks',evidence);
END $$;

-- Backfill is insert-only and uses each receipt's recorded generation. It never
-- consults contract/source heads, current identities, leases or the clock.
DO $backfill$
DECLARE receipt record; document jsonb;
BEGIN
 FOR receipt IN SELECT DISTINCT candidate_id,generation,binding_digest FROM hobnail.acceptances LOOP
  document:=hobnail.acceptance_proof_document(receipt.candidate_id,receipt.generation,receipt.binding_digest);
  INSERT INTO hobnail.acceptance_proofs(candidate_id,generation,binding_digest,proof,proof_digest)
   VALUES(receipt.candidate_id,receipt.generation,receipt.binding_digest,document,hobnail.digest(document));
 END LOOP;
END $backfill$;

CREATE FUNCTION hobnail.require_acceptance_proof() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER
SET search_path=pg_catalog,hobnail,pg_temp SET timezone='UTC' AS $$
DECLARE document jsonb; existing hobnail.acceptance_proofs;
BEGIN
 document:=hobnail.acceptance_proof_document(NEW.candidate_id,NEW.generation,NEW.binding_digest);
 INSERT INTO hobnail.acceptance_proofs(candidate_id,generation,binding_digest,proof,proof_digest)
  VALUES(NEW.candidate_id,NEW.generation,NEW.binding_digest,document,hobnail.digest(document))
  ON CONFLICT(candidate_id,generation,binding_digest) DO NOTHING;
 SELECT * INTO existing FROM hobnail.acceptance_proofs p WHERE p.candidate_id=NEW.candidate_id
  AND p.generation=NEW.generation AND p.binding_digest=NEW.binding_digest;
 IF NOT FOUND OR existing.proof IS DISTINCT FROM document OR existing.proof_digest IS DISTINCT FROM hobnail.digest(document) THEN
  PERFORM hobnail.refuse('INVALID_ACCEPTANCE_PROOF');
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER acceptance_requires_proof BEFORE INSERT ON hobnail.acceptances
FOR EACH ROW EXECUTE FUNCTION hobnail.require_acceptance_proof();
ALTER TABLE hobnail.acceptances ADD CONSTRAINT acceptances_proof
 FOREIGN KEY(candidate_id,generation,binding_digest)
 REFERENCES hobnail.acceptance_proofs(candidate_id,generation,binding_digest);

REVOKE ALL ON TABLE hobnail.acceptance_proofs FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION hobnail.acceptance_proof_document(bigint,integer,text),
 hobnail.require_acceptance_proof() FROM PUBLIC;
