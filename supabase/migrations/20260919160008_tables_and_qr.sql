-- Phase 2: restaurant_tables and qr_codes.
-- qr_codes is metadata only — it is never the source of truth for a public
-- URL. The URL is always derived at request time from the restaurant slug,
-- branch slug, and table public_token.

create table public.restaurant_tables (
  id uuid primary key default gen_random_uuid(),
  branch_id uuid not null references public.branches (id) on delete cascade,
  label text not null,
  -- Unique, random, non-sequential, safe to embed in a public QR URL. 32
  -- hex characters from pgcrypto's CSPRNG — never a sequential/derivable
  -- identifier.
  public_token text not null unique default encode(gen_random_bytes(16), 'hex'),
  status text not null default 'active' check (status in ('active', 'inactive')),
  created_at timestamptz not null default now()
);

create index restaurant_tables_branch_id_idx on public.restaurant_tables (branch_id);

create table public.qr_codes (
  id uuid primary key default gen_random_uuid(),
  scope text not null check (scope in ('restaurant', 'branch', 'table')),
  restaurant_id uuid not null references public.restaurants (id) on delete cascade,
  branch_id uuid references public.branches (id) on delete cascade,
  table_id uuid references public.restaurant_tables (id) on delete cascade,
  last_generated_at timestamptz,
  logo_overlay_enabled boolean not null default false,
  created_at timestamptz not null default now(),
  constraint qr_codes_scope_consistency check (
    (scope = 'restaurant' and branch_id is null and table_id is null)
    or (scope = 'branch' and branch_id is not null and table_id is null)
    or (scope = 'table' and branch_id is not null and table_id is not null)
  )
);

create index qr_codes_restaurant_id_idx on public.qr_codes (restaurant_id);
create index qr_codes_branch_id_idx on public.qr_codes (branch_id);
create index qr_codes_table_id_idx on public.qr_codes (table_id);

alter table public.restaurant_tables enable row level security;
alter table public.restaurant_tables force row level security;

alter table public.qr_codes enable row level security;
alter table public.qr_codes force row level security;

-- restaurant_tables ---------------------------------------------------
-- Anonymous visitors must be able to resolve a scanned public_token to its
-- branch/table (that is the entire point of the token being safe to embed
-- in a public URL), so active tables are anonymous-readable.

create policy restaurant_tables_select_members on public.restaurant_tables
  for select to authenticated
  using (public.has_branch_access(branch_id));

create policy restaurant_tables_select_public on public.restaurant_tables
  for select to anon
  using (status = 'active');

create policy restaurant_tables_write_managers on public.restaurant_tables
  for all to authenticated
  using (public.has_capability(branch_id, 'branch.manage'))
  with check (public.has_capability(branch_id, 'branch.manage'));

-- qr_codes ------------------------------------------------------------
-- Metadata only, staff-facing — not exposed to anonymous visitors.

create policy qr_codes_select_members on public.qr_codes
  for select to authenticated
  using (
    case
      when branch_id is not null then public.has_branch_access(branch_id)
      else public.is_restaurant_member(restaurant_id)
    end
  );

create policy qr_codes_write_managers on public.qr_codes
  for all to authenticated
  using (
    case
      when branch_id is not null then public.has_capability(branch_id, 'branch.manage')
      else public.has_restaurant_capability(restaurant_id, 'branch.manage')
    end
  )
  with check (
    case
      when branch_id is not null then public.has_capability(branch_id, 'branch.manage')
      else public.has_restaurant_capability(restaurant_id, 'branch.manage')
    end
  );
