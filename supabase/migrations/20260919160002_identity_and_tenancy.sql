-- Phase 2: identity and tenancy tables.
-- profiles, restaurants, restaurant_members, branches, member_branch_access,
-- role_capabilities (seeded).

create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  full_name text,
  avatar_url text,
  locale text not null default 'ar',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.restaurants (
  id uuid primary key default gen_random_uuid(),
  name_ar text not null,
  name_en text not null,
  slug text not null unique,
  logo_url text,
  brand_color text,
  country text,
  currency text,
  ar_enabled boolean not null default true,
  en_enabled boolean not null default true,
  primary_language text not null default 'ar' check (primary_language in ('ar', 'en')),
  status text not null default 'active' check (status in ('active', 'inactive', 'suspended')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- Ordinary authenticated users must NOT be able to insert restaurants.
-- Restaurant creation is Super Admin only, through server-side service-role
-- code, added in a later phase. No RLS INSERT policy is ever added for
-- `authenticated` on this table (see migration 04).

create table public.branches (
  id uuid primary key default gen_random_uuid(),
  restaurant_id uuid not null references public.restaurants (id) on delete cascade,
  name_ar text not null,
  name_en text not null,
  address text,
  phone text,
  whatsapp text,
  google_maps_url text,
  instagram_url text,
  opening_hours jsonb,
  cover_image_url text,
  status text not null default 'active' check (status in ('active', 'inactive')),
  slug text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (restaurant_id, slug)
);

create index branches_restaurant_id_idx on public.branches (restaurant_id);

-- branches.menu_status is deliberately NOT created. Publication status is
-- derived only from menus.published_version_id (migration 06) — a second
-- publication flag here would be a second source of truth that could drift.

create table public.restaurant_members (
  id uuid primary key default gen_random_uuid(),
  restaurant_id uuid not null references public.restaurants (id) on delete cascade,
  user_id uuid not null references public.profiles (id) on delete cascade,
  role public.restaurant_role not null,
  status text not null default 'active' check (status in ('active', 'invited', 'suspended', 'removed')),
  created_at timestamptz not null default now(),
  unique (restaurant_id, user_id)
);

create index restaurant_members_restaurant_id_idx on public.restaurant_members (restaurant_id);
create index restaurant_members_user_id_idx on public.restaurant_members (user_id);

create table public.member_branch_access (
  id uuid primary key default gen_random_uuid(),
  member_id uuid not null references public.restaurant_members (id) on delete cascade,
  branch_id uuid not null references public.branches (id) on delete cascade,
  created_at timestamptz not null default now(),
  unique (member_id, branch_id)
);

create index member_branch_access_member_id_idx on public.member_branch_access (member_id);
create index member_branch_access_branch_id_idx on public.member_branch_access (branch_id);

-- role_capabilities: global seeded reference table. RLS is enabled in
-- migration 04 with NO insert/update/delete policy for `authenticated` at
-- all — in V1, capability matrix changes happen only through reviewed
-- database migrations, never through application-level writes.
create table public.role_capabilities (
  role public.restaurant_role not null,
  capability text not null,
  primary key (role, capability)
);

insert into public.role_capabilities (role, capability) values
  -- owner: full capability set
  ('owner', 'restaurant.manage'),
  ('owner', 'branch.manage'),
  ('owner', 'menu.edit'),
  ('owner', 'menu.publish'),
  ('owner', 'product.edit'),
  ('owner', 'product.availability'),
  ('owner', 'team.manage'),
  ('owner', 'analytics.view'),
  ('owner', 'audit.view'),
  -- admin: same capability set as owner for V1
  ('admin', 'restaurant.manage'),
  ('admin', 'branch.manage'),
  ('admin', 'menu.edit'),
  ('admin', 'menu.publish'),
  ('admin', 'product.edit'),
  ('admin', 'product.availability'),
  ('admin', 'team.manage'),
  ('admin', 'analytics.view'),
  ('admin', 'audit.view'),
  -- branch_manager: restricted to assigned branches (enforced by has_capability)
  ('branch_manager', 'branch.manage'),
  ('branch_manager', 'menu.edit'),
  ('branch_manager', 'menu.publish'),
  ('branch_manager', 'product.edit'),
  ('branch_manager', 'product.availability'),
  ('branch_manager', 'analytics.view'),
  -- editor: restricted to assigned branches
  ('editor', 'menu.edit'),
  ('editor', 'product.edit'),
  ('editor', 'product.availability'),
  -- availability_staff: product.availability only, restricted to assigned branches
  ('availability_staff', 'product.availability'),
  -- viewer: analytics.view only, restricted to assigned branches
  ('viewer', 'analytics.view');
