-- The worker's side. Everything the actor writes lands here, through typed functions only.
CREATE SCHEMA work;

-- A token generator: time-ordered uuidv7 on PostgreSQL 18+, random uuid before that.
DO $$
BEGIN
  IF current_setting('server_version_num')::int >= 180000 THEN
    EXECUTE 'CREATE FUNCTION work.new_token() RETURNS uuid LANGUAGE sql VOLATILE AS $f$ SELECT uuidv7() $f$';
  ELSE
    EXECUTE 'CREATE FUNCTION work.new_token() RETURNS uuid LANGUAGE sql VOLATILE AS $f$ SELECT gen_random_uuid() $f$';
  END IF;
END $$;

-- Ledgers are append-only. Only the owner could turn that off, and the chain in eval records if it does.
CREATE FUNCTION work.forbid_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'ledger is append-only: % on % refused', TG_OP, TG_TABLE_NAME;
END $$;

-- 1. Steps and the state machine as data. An undeclared edge is an error, not a code path.
CREATE TABLE work.transitions (
  from_state text NOT NULL,
  to_state   text NOT NULL,
  PRIMARY KEY (from_state, to_state)
);
INSERT INTO work.transitions VALUES
  ('queued',   'running'),
  ('running',  'verified'),
  ('running',  'failed'),
  ('failed',   'queued'),
  ('verified', 'done');

CREATE TABLE work.steps (
  id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  name       text        NOT NULL,
  status     text        NOT NULL DEFAULT 'queued',
  created_by text        NOT NULL DEFAULT session_user,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE FUNCTION work.guard_transition() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM work.transitions WHERE from_state = OLD.status AND to_state = NEW.status) THEN
    RAISE EXCEPTION 'illegal transition % -> % on step %', OLD.status, NEW.status, NEW.id;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER steps_guard BEFORE UPDATE OF status ON work.steps
  FOR EACH ROW EXECUTE FUNCTION work.guard_transition();

-- 2. What the worker claims. The engine stamps who really connected, and from where.
CREATE TABLE work.attempts (
  id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  step_id    bigint      NOT NULL REFERENCES work.steps,
  actor      text        NOT NULL,                     -- session_user at the time, stamped by the door
  claim      text        NOT NULL,                     -- what the worker says happened
  detail     jsonb,
  from_addr  inet,
  at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON work.attempts (step_id, id);
CREATE TRIGGER attempts_immutable BEFORE UPDATE OR DELETE ON work.attempts
  FOR EACH ROW EXECUTE FUNCTION work.forbid_mutation();

-- 3. Gates leave a row either way. Absence of a row is never a pass.
CREATE TABLE work.gate_log (
  id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  step_id    bigint      NOT NULL REFERENCES work.steps,
  gate       text        NOT NULL,
  passed     boolean     NOT NULL,
  detail     jsonb,
  written_by text        NOT NULL,
  at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON work.gate_log (step_id, id);
CREATE TRIGGER gate_log_immutable BEFORE UPDATE OR DELETE ON work.gate_log
  FOR EACH ROW EXECUTE FUNCTION work.forbid_mutation();

CREATE FUNCTION work.all_gates_passed(p_step bigint) RETURNS boolean
  LANGUAGE sql STABLE SET search_path = pg_catalog, work AS $$
  -- zero rows must read as false, never as "not false"
  SELECT count(*) FILTER (WHERE passed) = count(*) AND count(*) > 0
  FROM work.gate_log WHERE step_id = p_step
$$;

-- 4. Jobs: one worker per job, and a crashed worker's job does not vanish.
CREATE TABLE work.jobs (
  id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  step_id     bigint      NOT NULL REFERENCES work.steps,
  lease_token uuid,
  lease_until timestamptz,
  attempts    int         NOT NULL DEFAULT 0,
  done_at     timestamptz
);
CREATE INDEX ON work.jobs (id) WHERE done_at IS NULL;

-- The typed doors. SECURITY DEFINER with a pinned search_path; they stamp session_user, which
-- survives SET ROLE and is the identity pg_hba bound the connection to.
CREATE FUNCTION work.new_step(p_name text) RETURNS bigint
  LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, work AS $$
  INSERT INTO work.steps (name) VALUES (p_name) RETURNING id
$$;

CREATE FUNCTION work.enqueue(p_step bigint) RETURNS bigint
  LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, work AS $$
  INSERT INTO work.jobs (step_id) VALUES (p_step) RETURNING id
$$;

CREATE FUNCTION work.claim_job(p_lease interval DEFAULT interval '5 minutes')
  RETURNS TABLE (job_id bigint, step_id bigint, lease_token uuid, lease_until timestamptz)
  LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, work AS $$
  WITH next AS (
    SELECT id FROM work.jobs
    WHERE done_at IS NULL AND (lease_until IS NULL OR lease_until < now())
    ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1
  )
  UPDATE work.jobs j
     SET lease_token = work.new_token(), lease_until = now() + p_lease, attempts = attempts + 1
    FROM next WHERE j.id = next.id
  RETURNING j.id, j.step_id, j.lease_token, j.lease_until
$$;

CREATE FUNCTION work.finish_job(p_job bigint, p_token uuid) RETURNS boolean
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, work AS $$
DECLARE n int;
BEGIN
  -- every later verb must present the current token
  UPDATE work.jobs SET done_at = now()
   WHERE id = p_job AND lease_token = p_token AND done_at IS NULL AND lease_until >= now();
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n = 0 THEN
    RAISE EXCEPTION 'job % not finished: token mismatch, lease expired, or already done', p_job;
  END IF;
  RETURN true;
END $$;

CREATE FUNCTION work.file_attempt(p_step bigint, p_claim text, p_detail jsonb DEFAULT NULL) RETURNS bigint
  LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, work AS $$
  INSERT INTO work.attempts (step_id, actor, claim, detail, from_addr)
  VALUES (p_step, session_user, p_claim, p_detail, inet_client_addr())
  RETURNING id
$$;

CREATE FUNCTION work.record_gate(p_step bigint, p_gate text, p_passed boolean, p_detail jsonb DEFAULT NULL) RETURNS bigint
  LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, work AS $$
  INSERT INTO work.gate_log (step_id, gate, passed, detail, written_by)
  VALUES (p_step, p_gate, p_passed, p_detail, session_user)
  RETURNING id
$$;

CREATE FUNCTION work.transition(p_step bigint, p_to text) RETURNS text
  LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, work AS $$
  UPDATE work.steps SET status = p_to WHERE id = p_step RETURNING status
$$;
