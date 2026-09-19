-- Phase 2: tenant isolation helper functions.
-- All are SECURITY DEFINER with an explicit, empty search_path (every
-- referenced object below is fully schema-qualified) so they cannot be
-- hijacked by a search_path manipulation, and all derive the acting user
-- from auth.uid() internally — none accepts a caller-supplied user id as
-- proof of identity.

create or replace function public.is_restaurant_member(target_restaurant_id uuid)
returns boolean
language sql
security definer
stable
set search_path = ''
as $$
  select exists (
    select 1
    from public.restaurant_members m
    where m.restaurant_id = target_restaurant_id
      and m.user_id = auth.uid()
      and m.status = 'active'
  );
$$;

revoke all on function public.is_restaurant_member(uuid) from public;
grant execute on function public.is_restaurant_member(uuid) to authenticated;

create or replace function public.has_branch_access(target_branch_id uuid)
returns boolean
language sql
security definer
stable
set search_path = ''
as $$
  select exists (
    select 1
    from public.branches b
    join public.restaurant_members m on m.restaurant_id = b.restaurant_id
    where b.id = target_branch_id
      and m.user_id = auth.uid()
      and m.status = 'active'
      and (
        m.role in ('owner', 'admin')
        or exists (
          select 1
          from public.member_branch_access a
          where a.member_id = m.id
            and a.branch_id = target_branch_id
        )
      )
  );
$$;

revoke all on function public.has_branch_access(uuid) from public;
grant execute on function public.has_branch_access(uuid) to authenticated;

-- Preferred signature per the approved spec: no user_id parameter. The
-- acting user is always derived from auth.uid() internally, so a caller can
-- never supply another user's id as proof of authorization. Super Admin
-- impersonation does not call this function as the impersonated user — it
-- is a separate, server-side, service-role-backed path (migration 12).
create or replace function public.has_capability(target_branch_id uuid, target_capability text)
returns boolean
language sql
security definer
stable
set search_path = ''
as $$
  select exists (
    select 1
    from public.branches b
    join public.restaurant_members m on m.restaurant_id = b.restaurant_id
    join public.role_capabilities rc on rc.role = m.role and rc.capability = target_capability
    where b.id = target_branch_id
      and m.user_id = auth.uid()
      and m.status = 'active'
      and (
        m.role in ('owner', 'admin')
        or exists (
          select 1
          from public.member_branch_access a
          where a.member_id = m.id
            and a.branch_id = target_branch_id
        )
      )
  );
$$;

revoke all on function public.has_capability(uuid, text) from public;
grant execute on function public.has_capability(uuid, text) to authenticated;

-- Restaurant-wide capability check, for resources that have no branch_id
-- of their own (restaurants, restaurant_members, member_branch_access,
-- custom allergens). This deliberately ignores member_branch_access
-- scoping and checks the seeded role_capabilities matrix directly — which
-- is safe because every capability this helper is used for in migration 04
-- (restaurant.manage, team.manage) is held only by owner/admin in the seed
-- data, so the result is equivalent to "is an owner/admin member of this
-- restaurant". It is intentionally NOT used for branch.manage (branch
-- creation), because branch_manager also holds branch.manage but is
-- "restricted to assigned branches" — a not-yet-created branch has no
-- membership row to restrict against, so branch creation is gated by an
-- explicit owner/admin check instead (see migration 04).
create or replace function public.has_restaurant_capability(target_restaurant_id uuid, target_capability text)
returns boolean
language sql
security definer
stable
set search_path = ''
as $$
  select exists (
    select 1
    from public.restaurant_members m
    join public.role_capabilities rc on rc.role = m.role and rc.capability = target_capability
    where m.restaurant_id = target_restaurant_id
      and m.user_id = auth.uid()
      and m.status = 'active'
  );
$$;

revoke all on function public.has_restaurant_capability(uuid, text) from public;
grant execute on function public.has_restaurant_capability(uuid, text) to authenticated;

-- ---------------------------------------------------------------------
-- SECURITY DEFINER / EXECUTE GRANT AUDIT — final grants, documented.
--
-- Every function below relies on auth.uid()/RLS internally, but internal
-- authorization checks are deliberately not treated as sufficient on their
-- own: EXECUTE is additionally revoked from PUBLIC (Postgres's default)
-- and re-granted only to the roles that genuinely need to call each one.
--
--   is_restaurant_member(uuid)                    -> authenticated only
--   has_branch_access(uuid)                        -> authenticated only
--   has_capability(uuid, text)                      -> authenticated only
--   has_restaurant_capability(uuid, text)           -> authenticated only
--     None of these four is called from any anon-facing RLS policy (the
--     public read policies compare restaurants/branches.status directly),
--     so anon never receives EXECUTE. There is no overload of any of
--     these that accepts a user_id parameter.
--
--   publish_availability_change(uuid, text)         -> authenticated only
--     (migration 06) — anon has no EXECUTE at all, so an anonymous caller
--     is rejected at the grant level before the function's own
--     has_capability('product.availability') check is ever reached.
--     authenticated may call it only because the function itself derives
--     auth.uid() internally and checks the capability per-call; the grant
--     alone does not authorize any particular mutation.
--
--   storage_path_uuid(text, int)                    -> authenticated only
--     (migration 13) — pure path parsing, no table access, but still
--     restricted to the only policies that reference it (both
--     authenticated-only).
--
--   analytics_event_chain_valid(uuid, uuid, uuid, uuid) -> anon AND authenticated
--     (migration 11) — the one deliberate exception to "anon gets nothing":
--     it backs the analytics_events INSERT WITH CHECK, the only anon-facing
--     write path in the schema, and returns only a boolean, never row data.
--
--   create_menu_for_branch()                        -> no role at all
--   reject_menu_version_mutation()                   -> no role at all
--   reject_audit_log_mutation()                       -> no role at all
--     (migrations 05/06/10) — all three are `returns trigger`, which
--     Postgres will only ever invoke through the trigger mechanism itself
--     (a direct call is refused regardless of grants), so no role needs,
--     or receives, EXECUTE on them.
--
-- See tests/db/20_rls_tests.sql for the tests proving anon (and, for
-- publish_availability_change, an authenticated role that does hold the
-- capability but calls it as a different, unrelated tenant) cannot
-- execute these functions.
-- ---------------------------------------------------------------------
