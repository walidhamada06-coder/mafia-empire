-- Agro Green Farm ERP - P0 security hardening patch
-- Target: Supabase project vhbhbzcywtmtwtpqvnhw
-- Apply ONLY to a verified staging database first. Do not run against production
-- until a backup is confirmed and the frontend dependency checks pass.
-- This patch is intentionally fail-closed for the dangerous restore RPC.

BEGIN;

-- 1) Stop anonymous access to operational views and ensure invoker RLS is used.
REVOKE ALL PRIVILEGES ON TABLE
  public.v_inventory_status,
  public.v_animal_performance,
  public.v_barn_headcount,
  public.v_dashboard_summary
FROM PUBLIC, anon;

ALTER VIEW public.v_inventory_status SET (security_invoker = true);
ALTER VIEW public.v_animal_performance SET (security_invoker = true);
ALTER VIEW public.v_barn_headcount SET (security_invoker = true);
ALTER VIEW public.v_dashboard_summary SET (security_invoker = true);

-- 2) Fail closed: the existing restore routine performs broad TRUNCATE operations.
-- Remove execution from every application/API role. Keep the function definition
-- untouched until a farm-scoped restore implementation has been built and tested.
REVOKE ALL PRIVILEGES ON FUNCTION public.restore_farm_backup(jsonb)
FROM PUBLIC, anon, authenticated, service_role;

-- 3) A disabled profile must not continue receiving a farm scope through RLS.
CREATE OR REPLACE FUNCTION public.current_farm_id()
RETURNS uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path TO 'public', 'pg_temp'
AS $function$
  SELECT up.farm_id
  FROM public.user_profiles AS up
  WHERE up.id = (SELECT auth.uid())
    AND up.active IS TRUE
  LIMIT 1;
$function$;

COMMIT;

-- Verification queries (run after applying on staging):
-- SELECT relname, reloptions,
--        has_table_privilege('anon', oid, 'SELECT') AS anon_select
-- FROM pg_class
-- WHERE oid IN (
--   'public.v_inventory_status'::regclass,
--   'public.v_animal_performance'::regclass,
--   'public.v_barn_headcount'::regclass,
--   'public.v_dashboard_summary'::regclass
-- );
--
-- SELECT has_function_privilege('anon',
--   'public.restore_farm_backup(jsonb)', 'EXECUTE') AS anon_can_restore,
--        has_function_privilege('authenticated',
--   'public.restore_farm_backup(jsonb)', 'EXECUTE') AS user_can_restore,
--        has_function_privilege('service_role',
--   'public.restore_farm_backup(jsonb)', 'EXECUTE') AS service_can_restore;
--
-- SELECT public.current_farm_id(); -- must be NULL for inactive profiles.
