-- Three roles. The owner holds every object and nobody logs in as it.
-- The two runtime roles hold no write privilege on any table; they get EXECUTE on typed functions.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'admit_owner') THEN
    CREATE ROLE admit_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'actor_role') THEN
    CREATE ROLE actor_role LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;   -- the worker / the agent
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'grader_role') THEN
    CREATE ROLE grader_role LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;  -- the verifier
  END IF;
  -- The owner may create schemas in this database, and the installer wears the owner hat for the rest of the install.
  EXECUTE format('GRANT CREATE ON DATABASE %I TO admit_owner', current_database());
  EXECUTE format('GRANT admit_owner TO %I', current_user);
END $$;

COMMENT ON ROLE admit_owner IS 'Owns the admit schemas. Nobody logs in as this role. The owner can disable triggers; the hash chain records if it does.';
COMMENT ON ROLE actor_role  IS 'Does the work. May file attempts, record gate results, claim jobs, move steps. Cannot see eval.';
COMMENT ON ROLE grader_role IS 'Says whether it worked. May read the work and record verdicts. Cannot rewrite one.';

SET ROLE admit_owner;
