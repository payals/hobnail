-- Grants. The rule of the pack: no runtime role can write a table. Writes go through the typed doors.
REVOKE ALL ON SCHEMA work, eval FROM PUBLIC;
REVOKE ALL ON ALL TABLES    IN SCHEMA work, eval FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA work, eval FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA work, eval FROM PUBLIC;

-- The actor: may read the work, may write only through the doors, cannot see eval at all.
GRANT USAGE ON SCHEMA work TO actor_role;
GRANT SELECT ON work.steps, work.transitions, work.attempts, work.gate_log, work.jobs TO actor_role;
GRANT EXECUTE ON FUNCTION
  work.new_step(text),
  work.enqueue(bigint),
  work.claim_job(interval),
  work.finish_job(bigint, uuid),
  work.file_attempt(bigint, text, jsonb),
  work.record_gate(bigint, text, boolean, jsonb),
  work.transition(bigint, text),
  work.all_gates_passed(bigint)
TO actor_role;

-- The grader: may read the work and the verdicts, may add a verdict, may move a step. Nothing else.
GRANT USAGE ON SCHEMA work, eval TO grader_role;
GRANT SELECT ON work.steps, work.transitions, work.attempts, work.gate_log, work.jobs TO grader_role;
GRANT SELECT ON eval.verdicts, eval.chain_check TO grader_role;
GRANT EXECUTE ON FUNCTION
  eval.record_verdict(bigint, boolean, text),
  work.transition(bigint, text),
  work.all_gates_passed(bigint)
TO grader_role;

-- Whatever is created later in these schemas starts closed.
ALTER DEFAULT PRIVILEGES FOR ROLE admit_owner IN SCHEMA work, eval REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE admit_owner IN SCHEMA work, eval REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
