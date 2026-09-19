-- Phase 2: audit_logs. Append-only; history-preserving on delete.

create table public.audit_logs (
  id uuid primary key default gen_random_uuid(),
  actor_user_id uuid references public.profiles (id) on delete set null,
  restaurant_id uuid references public.restaurants (id) on delete set null,
  branch_id uuid references public.branches (id) on delete set null,
  action text not null,
  entity_type text not null,
  entity_id uuid,
  before jsonb,
  after jsonb,
  metadata jsonb,
  created_at timestamptz not null default now()
);

create index audit_logs_restaurant_id_idx on public.audit_logs (restaurant_id, created_at);
create index audit_logs_branch_id_idx on public.audit_logs (branch_id, created_at);

alter table public.audit_logs enable row level security;
alter table public.audit_logs force row level security;

-- Authenticated restaurant users may read only according to audit.view
-- capability (owner/admin exclusive per the seeded matrix). Normal
-- authenticated users have no INSERT/UPDATE/DELETE policy at all — trusted
-- server-side code writes audit logs in a later phase via the service
-- role, which bypasses RLS.

create policy audit_logs_select_admins on public.audit_logs
  for select to authenticated
  using (
    restaurant_id is not null
    and public.has_restaurant_capability(restaurant_id, 'audit.view')
  );

-- Defense in depth, matching menu_versions: audit_logs is append-only, so
-- UPDATE/DELETE are hard-blocked for every role, not just denied by the
-- absence of an RLS policy.
--
-- Same narrow exception as menu_versions: actor_user_id, restaurant_id and
-- branch_id are all ON DELETE SET NULL (preserve the log row when the
-- actor/restaurant/branch is later deleted), and Postgres implements that
-- as an UPDATE — so the trigger must allow exactly "one or more of those
-- three columns moving from a value to NULL, nothing else changed" and
-- reject every other UPDATE (any change to action/entity_type/entity_id/
-- before/after/metadata/created_at).
create or replace function public.reject_audit_log_mutation()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  -- Each nullable FK column is allowed to be unchanged (including
  -- already-null, so a second, independent cascade on a different column
  -- of the same row — e.g. branch_id nulled after restaurant_id was
  -- already nulled by an earlier cascade — is not itself blocked) or to
  -- move to NULL. IS NOT DISTINCT FROM (rather than =) is required
  -- because ordinary NULL = NULL evaluates to NULL, not TRUE, which would
  -- make this whole condition — and therefore every legitimate cascade —
  -- silently fail closed.
  if tg_op = 'UPDATE'
    and new.id = old.id
    and new.action = old.action
    and new.entity_type = old.entity_type
    and new.entity_id is not distinct from old.entity_id
    and new.before is not distinct from old.before
    and new.after is not distinct from old.after
    and new.metadata is not distinct from old.metadata
    and new.created_at = old.created_at
    and (new.actor_user_id is not distinct from old.actor_user_id or new.actor_user_id is null)
    and (new.restaurant_id is not distinct from old.restaurant_id or new.restaurant_id is null)
    and (new.branch_id is not distinct from old.branch_id or new.branch_id is null)
  then
    return new;
  end if;

  raise exception 'audit_logs is append-only: % is not permitted on this table', tg_op;
end;
$$;

-- SECURITY DEFINER function EXECUTE audit: not SECURITY DEFINER (same
-- reasoning as reject_menu_version_mutation) — `returns trigger` makes it
-- uncallable outside the trigger mechanism either way, but PUBLIC's
-- default EXECUTE is revoked anyway, as defense-in-depth.
revoke all on function public.reject_audit_log_mutation() from public;

create trigger audit_logs_block_update
  before update on public.audit_logs
  for each row execute function public.reject_audit_log_mutation();

create trigger audit_logs_block_delete
  before delete on public.audit_logs
  for each row execute function public.reject_audit_log_mutation();
