-- The grader's side. Whoever did the work cannot write here, read here, or become someone who can.
CREATE SCHEMA eval;

CREATE TABLE eval.verdicts (
  id         bigint      PRIMARY KEY,               -- assigned by the seal, inside a lock, so id order is chain order
  step_id    bigint      NOT NULL REFERENCES work.steps,
  attempt_id bigint      NOT NULL REFERENCES work.attempts,
  actor      text        NOT NULL,                  -- copied from the attempt by the seal
  judge      text        NOT NULL,                  -- session_user at the time, stamped by the seal
  passed     boolean     NOT NULL,
  note       text,
  from_addr  inet,
  at         timestamptz NOT NULL DEFAULT now(),
  prev_hash  bytea,
  hash       bytea       NOT NULL,
  CONSTRAINT no_self_judging CHECK (judge IS DISTINCT FROM actor)
);
CREATE SEQUENCE eval.verdicts_id_seq OWNED BY eval.verdicts.id;
CREATE INDEX ON eval.verdicts (step_id, id);

-- Every verdict seals the one before it.
CREATE FUNCTION eval.seal_verdict() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE prev bytea;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext('eval.verdicts'));            -- one sealer at a time
  NEW.id        := nextval('eval.verdicts_id_seq');                     -- id assigned inside the lock
  NEW.actor     := (SELECT actor FROM work.attempts WHERE id = NEW.attempt_id);
  NEW.judge     := session_user;                                        -- not what the client wrote
  NEW.from_addr := inet_client_addr();
  SELECT hash INTO prev FROM eval.verdicts ORDER BY id DESC LIMIT 1;    -- READ COMMITTED: the last committed seal
  NEW.prev_hash := prev;
  NEW.hash := sha256(coalesce(prev, '\x'::bytea) ||
              convert_to(format('%s|%s|%s|%s|%s|%s|%s', NEW.id, NEW.step_id, NEW.attempt_id, NEW.actor, NEW.judge, NEW.passed,
                                to_char(NEW.at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')), 'UTF8'));
  RETURN NEW;
END $$;
CREATE TRIGGER verdicts_seal      BEFORE INSERT           ON eval.verdicts FOR EACH ROW EXECUTE FUNCTION eval.seal_verdict();
CREATE TRIGGER verdicts_immutable BEFORE UPDATE OR DELETE ON eval.verdicts FOR EACH ROW EXECUTE FUNCTION work.forbid_mutation();

-- Walk the chain. rows_intact fails if any row was edited after sealing; links_intact fails if a row was removed.
CREATE VIEW eval.chain_check AS
SELECT count(*) AS verdicts,
       coalesce(bool_and(hash = sha256(coalesce(prev_hash, '\x'::bytea) ||
                convert_to(format('%s|%s|%s|%s|%s|%s|%s', id, step_id, attempt_id, actor, judge, passed,
                                  to_char(at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')), 'UTF8'))), true) AS rows_intact,
       coalesce(bool_and(prev_hash IS NOT DISTINCT FROM lag_hash), true) AS links_intact
FROM (SELECT v.*, lag(hash) OVER (ORDER BY id) AS lag_hash FROM eval.verdicts v) s;

-- The grader's one door.
CREATE FUNCTION eval.record_verdict(p_attempt bigint, p_passed boolean, p_note text DEFAULT NULL) RETURNS bigint
  LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, eval, work AS $$
  INSERT INTO eval.verdicts (step_id, attempt_id, passed, note)
  SELECT a.step_id, a.id, p_passed, p_note FROM work.attempts a WHERE a.id = p_attempt
  RETURNING id
$$;
