-- Admit test scenario. Every ERROR below is the engine refusing; tests/expected.txt lists them in order.
-- Runs as three real connections: the installer (owner hat), actor_role, grader_role.
-- Variables are supplied by tests/run.sh: :owner_uri :actor_uri :grader_uri
\set ON_ERROR_STOP off
\set VERBOSITY default
\pset footer off

\echo '== 1. the state machine is a table'
SELECT work.new_step('answer the question') AS step;                 -- step 1
SELECT work.transition(1, 'done');                                    -- queued -> done is not an edge
SELECT work.transition(1, 'running');

\echo '== 2. one worker per job; a token, not a belief'
SELECT work.enqueue(1);                                               -- job 1
SELECT work.enqueue(1);                                               -- job 2
SELECT 'assert: two claims, two different jobs' AS check,
       (SELECT count(DISTINCT job_id) FROM (SELECT job_id FROM work.claim_job()
                                             UNION ALL SELECT job_id FROM work.claim_job()) c) = 2 AS ok;
SELECT 'assert: a third claim gets nothing' AS check, (SELECT count(*) FROM work.claim_job()) = 0 AS ok;
SELECT work.finish_job(1, '00000000-0000-0000-0000-000000000000');    -- wrong token
SELECT 'assert: the right token finishes the job' AS check,
       work.finish_job(1, (SELECT lease_token FROM work.jobs WHERE id = 1)) AS ok;

\echo '== 3. absence of evidence is not a pass'
SELECT 'assert: no gate rows reads as false, not NULL' AS check, work.all_gates_passed(1) IS FALSE AS ok;
SELECT work.record_gate(1, 'format', true);
SELECT work.record_gate(1, 'grounding', false);
SELECT 'assert: one failed gate reads as false' AS check, work.all_gates_passed(1) IS FALSE AS ok;
UPDATE work.gate_log SET passed = true WHERE gate = 'grounding';      -- refused
DELETE FROM work.gate_log WHERE gate = 'grounding';                   -- refused

\echo '== 4. the worker connects as itself and files its claim'
\connect :actor_uri
SELECT session_user, current_user;
SELECT work.file_attempt(1, 'fix applied, tests green') AS attempt;   -- attempt 1
SELECT work.record_gate(1, 'tests', true);
INSERT INTO work.gate_log (step_id, gate, passed, written_by) VALUES (1, 'tests', true, 'me');  -- no table write
SELECT * FROM eval.verdicts;                                          -- cannot even look
SELECT eval.record_verdict(1, true);                                  -- cannot grade
SET ROLE grader_role;                                                 -- cannot become the grader
SELECT work.transition(1, 'verified');                                -- no verdict yet: refused at COMMIT

\echo '== 5. the grader connects as itself and says whether it worked'
\connect :grader_uri
SELECT session_user, current_user;
SELECT work.file_attempt(1, 'I did it myself');                       -- the grader is not a worker
SELECT eval.record_verdict(1, true, 'tests re-run from a clean checkout') AS verdict;   -- verdict 1
SELECT id, step_id, attempt_id, actor, judge, passed FROM eval.verdicts;
UPDATE eval.verdicts SET passed = false WHERE id = 1;                 -- refused
DELETE FROM eval.verdicts WHERE id = 1;                               -- refused
SELECT work.transition(1, 'verified');                                -- now admitted
SELECT 'assert: step 1 is verified' AS check, (SELECT status FROM work.steps WHERE id = 1) = 'verified' AS ok;

\echo '== 6. nobody grades their own work, not even the owner'
\connect :owner_uri
SELECT work.new_step('owner does one') AS step;                       -- step 2
SELECT work.transition(2, 'running');
SELECT work.file_attempt(2, 'owner did this one') AS attempt;         -- attempt 2, actor = the owner
SELECT eval.record_verdict(2, true);                                  -- judge = actor: refused

\echo '== 7. the ledger cannot be rewritten, and a bypass leaves a mark'
\connect :grader_uri
SELECT eval.record_verdict(2, false, 'not reproducible') AS verdict;  -- a failing verdict, sealed on the one before
SELECT 'assert: chain intact' AS check, rows_intact AND links_intact AS ok FROM eval.chain_check;
\connect :owner_uri
UPDATE eval.verdicts SET passed = true WHERE passed = false;          -- even the owner is refused by the trigger
ALTER TABLE eval.verdicts DISABLE TRIGGER verdicts_immutable;         -- but only the owner can switch it off
UPDATE eval.verdicts SET passed = true WHERE passed = false;          -- turn the fail into a pass
SELECT 'assert: chain broken after the bypass' AS check, NOT rows_intact AS ok FROM eval.chain_check;

\echo '== 8. the catalog says whether the rules still bind'
SELECT tgrelid::regclass AS "table", tgname, tgenabled FROM pg_trigger
 WHERE tgrelid IN ('work.steps'::regclass, 'work.gate_log'::regclass, 'work.attempts'::regclass, 'eval.verdicts'::regclass)
   AND NOT tgisinternal ORDER BY 1, 2;                                 -- D = disabled: a rule that no longer binds
ALTER TABLE eval.verdicts ENABLE TRIGGER verdicts_immutable;
