-- Preserve applied migration checksums while making temporary relation lookup
-- explicit. pg_temp is searched first for relations when omitted, even when
-- pg_catalog is the first listed schema. Every nested function must retain the
-- safe order; changing only the SECURITY DEFINER entrypoint is insufficient.
DO $catalog_order$
DECLARE routine record;
BEGIN
  FOR routine IN
    SELECT n.nspname,p.proname,pg_catalog.pg_get_function_identity_arguments(p.oid) AS arguments
    FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='hobnail'
  LOOP
    EXECUTE pg_catalog.format('ALTER FUNCTION %I.%I(%s) SET search_path TO pg_catalog,hobnail,pg_temp',
      routine.nspname,routine.proname,routine.arguments);
  END LOOP;
END $catalog_order$;
