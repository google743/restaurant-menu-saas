-- Phase 2: super_admins and impersonation_sessions.
-- super_admins is deliberately outside tenant membership: no super_admin
-- role on restaurant_members, no OR is_super_admin condition anywhere in
-- tenant RLS (verified across every policy in this migration set — none
-- references this table).

create table public.super_admins (
  user_id uuid primary key references public.profiles (id) on delete cascade,
  created_at timestamptz not null default now(),
  created_by uuid references public.profiles (id) on delete set null
);

-- impersonation_sessions retains history deliberately: neither reference
-- CASCADEs. restaurant_id and super_admin_id are both nullable with
-- ON DELETE SET NULL so impersonation/security history survives a
-- restaurant being deleted, or (in principle) a Super Admin account being
-- removed. Actual impersonation authorization logic (the signed, httpOnly,
-- short-TTL cookie; capability satisfaction; audit attribution to the real
-- Super Admin) is NOT implemented in Phase 2 — this is schema only.
create table public.impersonation_sessions (
  id uuid primary key default gen_random_uuid(),
  super_admin_id uuid references public.super_admins (user_id) on delete set null,
  restaurant_id uuid references public.restaurants (id) on delete set null,
  started_at timestamptz not null default now(),
  ended_at timestamptz,
  reason text,
  created_at timestamptz not null default now()
);

create index impersonation_sessions_super_admin_id_idx on public.impersonation_sessions (super_admin_id);
create index impersonation_sessions_restaurant_id_idx on public.impersonation_sessions (restaurant_id);

-- Client access must be denied outright for both tables: RLS is enabled
-- and forced, and NO policy is added for any role, including
-- authenticated. Server-only code, using the service role (which bypasses
-- RLS), reads and writes these in a later phase.

alter table public.super_admins enable row level security;
alter table public.super_admins force row level security;

alter table public.impersonation_sessions enable row level security;
alter table public.impersonation_sessions force row level security;

-- Restaurant creation is Super Admin only, and does NOT go through a
-- SECURITY DEFINER database function: ordinary authenticated users have no
-- INSERT policy on restaurants (migration 04), and no such function is
-- defined anywhere in this migration set. The approved sequence — verify
-- the authenticated Super Admin session, assertSuperAdmin() in server-only
-- code, use the service-role client, create the restaurant, deliberately
-- create the initial owner membership, write an audit log entry — is
-- application code for a later phase; the service role key is never
-- exposed to the browser.
