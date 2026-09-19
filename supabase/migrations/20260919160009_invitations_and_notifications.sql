-- Phase 2: invitations, invitation_branch_access, notifications.

create table public.invitations (
  id uuid primary key default gen_random_uuid(),
  restaurant_id uuid not null references public.restaurants (id) on delete cascade,
  email text not null,
  role public.restaurant_role not null,
  token text not null unique default encode(gen_random_bytes(24), 'hex'),
  status text not null default 'pending' check (status in ('pending', 'accepted', 'revoked', 'expired')),
  invited_by uuid references public.profiles (id) on delete set null,
  expires_at timestamptz not null default (now() + interval '7 days'),
  created_at timestamptz not null default now(),
  accepted_by uuid references public.profiles (id) on delete set null
);

create index invitations_restaurant_id_idx on public.invitations (restaurant_id);
create unique index invitations_token_idx on public.invitations (token);

-- Normalized join table, mirroring member_branch_access. An invitation may
-- target one or several branches; no branch_ids array. When invitation
-- acceptance logic is implemented in a later phase, these rows map
-- directly to member_branch_access rows.
create table public.invitation_branch_access (
  invitation_id uuid not null references public.invitations (id) on delete cascade,
  branch_id uuid not null references public.branches (id) on delete cascade,
  primary key (invitation_id, branch_id)
);

create index invitation_branch_access_branch_id_idx on public.invitation_branch_access (branch_id);

create table public.notifications (
  id uuid primary key default gen_random_uuid(),
  restaurant_id uuid not null references public.restaurants (id) on delete cascade,
  user_id uuid references public.profiles (id) on delete cascade,
  type text not null,
  payload jsonb,
  is_read boolean not null default false,
  created_at timestamptz not null default now()
);

create index notifications_restaurant_id_idx on public.notifications (restaurant_id);
create index notifications_user_id_idx on public.notifications (user_id);

alter table public.invitations enable row level security;
alter table public.invitations force row level security;

alter table public.invitation_branch_access enable row level security;
alter table public.invitation_branch_access force row level security;

alter table public.notifications enable row level security;
alter table public.notifications force row level security;

-- invitations -----------------------------------------------------------
-- team.manage is owner/admin exclusive per the seeded capability matrix, so
-- has_restaurant_capability(..., 'team.manage') is equivalent to
-- "is an owner/admin member of this restaurant" here. No anonymous access:
-- token-based invitation acceptance is server-side logic for a later phase.

create policy invitations_select_admins on public.invitations
  for select to authenticated
  using (public.has_restaurant_capability(restaurant_id, 'team.manage'));

create policy invitations_write_admins on public.invitations
  for all to authenticated
  using (public.has_restaurant_capability(restaurant_id, 'team.manage'))
  with check (public.has_restaurant_capability(restaurant_id, 'team.manage'));

-- invitation_branch_access -------------------------------------------

create policy invitation_branch_access_select_admins on public.invitation_branch_access
  for select to authenticated
  using (
    exists (
      select 1 from public.invitations i
      where i.id = invitation_branch_access.invitation_id
        and public.has_restaurant_capability(i.restaurant_id, 'team.manage')
    )
  );

create policy invitation_branch_access_write_admins on public.invitation_branch_access
  for all to authenticated
  using (
    exists (
      select 1 from public.invitations i
      where i.id = invitation_branch_access.invitation_id
        and public.has_restaurant_capability(i.restaurant_id, 'team.manage')
    )
  )
  with check (
    exists (
      select 1 from public.invitations i
      where i.id = invitation_branch_access.invitation_id
        and public.has_restaurant_capability(i.restaurant_id, 'team.manage')
    )
  );

-- notifications -----------------------------------------------------------
-- No authenticated INSERT policy: notifications are written by trusted
-- server-side code in a later phase (no automated email/push
-- infrastructure exists yet). A user may read and mark-read only their own
-- notifications.

create policy notifications_select_own on public.notifications
  for select to authenticated
  using (user_id = auth.uid());

create policy notifications_update_own_is_read on public.notifications
  for update to authenticated
  using (user_id = auth.uid())
  with check (user_id = auth.uid());
