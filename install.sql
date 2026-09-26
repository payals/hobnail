-- Admit: install everything in one session so SET ROLE carries across files.
-- Usage:  psql -X -v ON_ERROR_STOP=1 -d <your database> -f install.sql
-- Run this as a superuser or as a role that can CREATE ROLE and CREATE SCHEMA.
-- Nobody should log in as the owner role it creates; see README "Who owns what".
\set ON_ERROR_STOP on
\ir schema/001_roles.sql
\ir schema/002_work.sql
\ir schema/003_eval.sql
\ir schema/004_admission.sql
\ir schema/005_grants.sql
RESET ROLE;
\echo 'admit: installed. Runtime roles: actor_role, grader_role. Owner: admit_owner (NOLOGIN).'
