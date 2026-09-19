-- Phase 2: RLS for identity/tenancy tables.
-- Default-deny: every table below has RLS enabled and forced, and no
-- policy is added unless explicitly described here. No policy anywhere in
-- this file references service_role or contains a Super Admin bypass.

alter table public.profiles enable row level security;
alter table public.profiles force row level security;

alter table public.restaurants enable row level security;
alter table public.restaurants force row level security;

alter table public.branches enable row level security;
alter table public.branches force row level security;

alter table public.restaurant_members enable row level security;
alter table public.restaurant_members force row level security;

alter table public.member_branch_access enable row level security;
alter table public.member_branch_access force row level security;

alter table public.role_capabilities enable row level security;
alter table public.role_capabilities force row level security;

-- profiles ------------------------------------------------------------

create policy profiles_select_own on public.profiles
  for select to authenticated
  using (id = auth.uid());

create policy profiles_select_fellow_members on public.profiles
  for select to authenticated
  using (
    exists (
      select 1
      from public.restaurant_members mine
      join public.restaurant_members theirs on theirs.restaurant_id = mine.restaurant_id
      where mine.user_id = auth.uid()
        and mine.status = 'active'
        and theirs.user_id = profiles.id
        and theirs.status = 'active'
    )
  );

create policy profiles_insert_own on public.profiles
  for insert to authenticated
  with check (id = auth.uid());

create policy profiles_update_own on public.profiles
  for update to authenticated
  using (id = auth.uid())
  with check (id = auth.uid());

-- restaurants -----------------------------------------------------------
-- No INSERT policy for authenticated at all: restaurant creation is
-- Super Admin only, via server-side service-role code (later phase).

create policy restaurants_select_members on public.restaurants
  for select to authenticated
  using (public.is_restaurant_member(id));

create policy restaurants_select_public on public.restaurants
  for select to anon
  using (status = 'active');

create policy restaurants_update_managers on public.restaurants
  for update to authenticated
  using (public.has_restaurant_capability(id, 'restaurant.manage'))
  with check (public.has_restaurant_capability(id, 'restaurant.manage'));

-- branches ----------------------------------------------------------------

create policy branches_select_members on public.branches
  for select to authenticated
  using (public.has_branch_access(id));

create policy branches_select_public on public.branches
  for select to anon
  using (
    status = 'active'
    and exists (
      select 1 from public.restaurants r
      where r.id = branches.restaurant_id and r.status = 'active'
    )
  );

-- Branch creation is deliberately restricted to restaurant-wide roles
-- (owner/admin). branch_manager holds branch.manage too, but that grant is
-- "restricted to assigned branches" per the capability matrix, and a
-- not-yet-created branch cannot be an assigned branch.
create policy branches_insert_admins on public.branches
  for insert to authenticated
  with check (
    exists (
      select 1 from public.restaurant_members m
      where m.restaurant_id = branches.restaurant_id
        and m.user_id = auth.uid()
        and m.status = 'active'
        and m.role in ('owner', 'admin')
    )
  );

create policy branches_update_managers on public.branches
  for update to authenticated
  using (public.has_capability(id, 'branch.manage'))
  with check (public.has_capability(id, 'branch.manage'));

-- No UPDATE-of-arbitrary-column or DELETE policy is granted beyond this;
-- branch/restaurant deletion is not exposed to any authenticated role in
-- Phase 2 (fail closed by default).

-- restaurant_members --------------------------------------------------

create policy restaurant_members_select_fellow on public.restaurant_members
  for select to authenticated
  using (public.is_restaurant_member(restaurant_id));

create policy restaurant_members_insert_admins on public.restaurant_members
  for insert to authenticated
  with check (public.has_restaurant_capability(restaurant_id, 'team.manage'));

create policy restaurant_members_update_admins on public.restaurant_members
  for update to authenticated
  using (public.has_restaurant_capability(restaurant_id, 'team.manage'))
  with check (public.has_restaurant_capability(restaurant_id, 'team.manage'));

create policy restaurant_members_delete_admins on public.restaurant_members
  for delete to authenticated
  using (public.has_restaurant_capability(restaurant_id, 'team.manage'));

-- member_branch_access --------------------------------------------------

create policy member_branch_access_select_fellow on public.member_branch_access
  for select to authenticated
  using (
    exists (
      select 1 from public.restaurant_members m
      where m.id = member_branch_access.member_id
        and public.is_restaurant_member(m.restaurant_id)
    )
  );

create policy member_branch_access_write_admins on public.member_branch_access
  for all to authenticated
  using (
    exists (
      select 1 from public.restaurant_members m
      where m.id = member_branch_access.member_id
        and public.has_restaurant_capability(m.restaurant_id, 'team.manage')
    )
  )
  with check (
    exists (
      select 1 from public.restaurant_members m
      where m.id = member_branch_access.member_id
        and public.has_restaurant_capability(m.restaurant_id, 'team.manage')
    )
  );

-- role_capabilities ------------------------------------------------------
-- Read-only reference data for everyone; no write policy for authenticated
-- at all — capability matrix changes happen only through reviewed
-- migrations (Decision 5).

create policy role_capabilities_select_all on public.role_capabilities
  for select to authenticated, anon
  using (true);
