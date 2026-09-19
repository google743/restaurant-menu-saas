-- Phase 2: menu_versions, the publish pointer, and the availability
-- micro-publish helper.
--
-- Circular FK note: menus.published_version_id needs to reference
-- menu_versions(id), and menu_versions.menu_id needs to reference
-- menus(id). menus is created first (migration 05) with
-- published_version_id as a bare uuid column (no FK yet). Here,
-- menu_versions is created referencing menus(id), and only then is the
-- published_version_id -> menu_versions(id) foreign key added to menus via
-- ALTER TABLE. This is the deliberate, and only, way to express a mutual
-- reference in DDL without a circular-dependency error, and it lets us
-- choose ON DELETE SET NULL for the menus side explicitly rather than
-- inheriting a default.

create table public.menu_versions (
  id uuid primary key default gen_random_uuid(),
  -- Nullable + ON DELETE SET NULL: a published snapshot survives even if
  -- its branch/menu is later hard-deleted — orphaned but preserved for
  -- history, exactly like audit_logs.
  menu_id uuid references public.menus (id) on delete set null,
  published_at timestamptz not null default now(),
  published_by uuid references public.profiles (id) on delete set null,
  snapshot jsonb not null,
  created_at timestamptz not null default now()
);

create index menu_versions_menu_id_idx on public.menu_versions (menu_id);

alter table public.menus
  add constraint menus_published_version_id_fkey
  foreign key (published_version_id) references public.menu_versions (id)
  on delete set null;

-- Append-only enforcement: reject UPDATE and DELETE outright, including for
-- privileged database paths (the trigger does not special-case any role —
-- no one, including the service role or SECURITY DEFINER functions, ever
-- changes the content of a menu_versions row after it is inserted).
--
-- One narrow, deliberate exception on UPDATE: menu_id references menus and
-- published_by references profiles, both ON DELETE SET NULL, so that a
-- published snapshot survives its branch/menu or its publisher being
-- deleted (history-preserving, like audit_logs). Postgres implements
-- ON DELETE SET NULL as an UPDATE, so a trigger that blocked every UPDATE
-- unconditionally would also block that legitimate cascade and make the
-- SET NULL foreign keys impossible to honor. The function below allows an
-- UPDATE only when it does exactly that — one or both of menu_id /
-- published_by moving from a value to NULL, with every other column
-- (including snapshot) byte-for-byte unchanged — and rejects anything else,
-- including any change to snapshot, published_at, or created_at.
create or replace function public.reject_menu_version_mutation()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  -- IS NOT DISTINCT FROM (not =) so an already-null column doesn't turn
  -- the whole condition NULL (and therefore falsy) when a second,
  -- independent cascade touches the other nullable column on the same
  -- row — see the identical note in reject_audit_log_mutation().
  if tg_op = 'UPDATE'
    and new.id = old.id
    and new.published_at = old.published_at
    and new.snapshot = old.snapshot
    and new.created_at = old.created_at
    and (new.menu_id is not distinct from old.menu_id or new.menu_id is null)
    and (new.published_by is not distinct from old.published_by or new.published_by is null)
  then
    return new;
  end if;

  raise exception 'menu_versions is append-only: % is not permitted on this table', tg_op;
end;
$$;

-- SECURITY DEFINER function EXECUTE audit: not SECURITY DEFINER (it needs
-- no elevated privilege — it only inspects OLD/NEW and raises), but
-- `returns trigger` means it can only ever be invoked by the trigger
-- mechanism regardless of grants, same as create_menu_for_branch above.
-- PUBLIC's default EXECUTE is revoked anyway, as defense-in-depth.
revoke all on function public.reject_menu_version_mutation() from public;

create trigger menu_versions_block_update
  before update on public.menu_versions
  for each row execute function public.reject_menu_version_mutation();

create trigger menu_versions_block_delete
  before delete on public.menu_versions
  for each row execute function public.reject_menu_version_mutation();

-- Snapshot shape convention (schema-relevant subset only — the full
-- publish flow that builds this snapshot from draft tables is application
-- logic for a later phase, per the specification):
--
--   {
--     "categories": [
--       {
--         "id": "<category uuid>",
--         ...category fields...,
--         "products": [
--           { "id": "<product uuid>", "availability": "available", ...product fields... }
--         ]
--       }
--     ]
--   }
--
-- publish_availability_change() below relies only on this categories[] ->
-- products[] -> availability path; it does not touch any other field.

-- AVAILABILITY MICRO PUBLISH ------------------------------------------
--
-- Lets a product.availability holder (availability_staff, or any other
-- role that also holds it) flip a product between 'available' and
-- 'sold_out' with the change visible to the public immediately, WITHOUT
-- requiring menu.publish and WITHOUT rebuilding the snapshot from live
-- draft tables (which would leak any other unpublished edit — price,
-- description, a new product — into the public menu).
--
-- SECURITY DEFINER is what lets a narrower capability (product.availability)
-- perform this public-visible write; ordinary RLS on `products` (migration
-- 07) does NOT grant availability_staff any UPDATE at all, so this
-- function is their only path to changing availability.
create or replace function public.publish_availability_change(
  target_product_id uuid,
  new_availability text
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_branch_id uuid;
  v_menu_id uuid;
  v_published_version_id uuid;
  v_snapshot jsonb;
  v_new_snapshot jsonb;
  v_cat_idx int;
  v_prod_idx int;
  v_new_version_id uuid;
begin
  -- availability_staff (and everyone else using this narrow path) may only
  -- ever set available/sold_out. 'hidden' is reachable only through the
  -- normal product.edit UPDATE path.
  if new_availability not in ('available', 'sold_out') then
    raise exception 'publish_availability_change: new_availability must be ''available'' or ''sold_out'', got %', new_availability;
  end if;

  -- Derive the product's branch internally through the FK chain:
  -- product -> category -> menu -> branch. The caller never supplies
  -- restaurant_id or branch_id.
  select m.branch_id, m.id
    into v_branch_id, v_menu_id
  from public.products p
  join public.categories c on c.id = p.category_id
  join public.menus m on m.id = c.menu_id
  where p.id = target_product_id;

  if v_branch_id is null then
    raise exception 'publish_availability_change: product % not found', target_product_id;
  end if;

  -- auth.uid() is derived internally; capability is checked against the
  -- derived branch, never a caller-supplied one.
  if not public.has_capability(v_branch_id, 'product.availability') then
    raise exception 'publish_availability_change: missing product.availability capability on branch %', v_branch_id;
  end if;

  update public.products
     set availability = new_availability::public.product_availability,
         updated_at = now()
   where id = target_product_id;

  select published_version_id into v_published_version_id
  from public.menus
  where id = v_menu_id;

  -- No published version yet: the change is draft-only. Stop here — do
  -- not create a menu_version.
  if v_published_version_id is null then
    return;
  end if;

  select snapshot into v_snapshot
  from public.menu_versions
  where id = v_published_version_id;

  -- Locate the product inside the current published snapshot.
  select (cat.ord - 1), (prod.ord - 1)
    into v_cat_idx, v_prod_idx
  from jsonb_array_elements(coalesce(v_snapshot -> 'categories', '[]'::jsonb)) with ordinality as cat (value, ord)
  cross join lateral jsonb_array_elements(coalesce(cat.value -> 'products', '[]'::jsonb)) with ordinality as prod (value, ord)
  where prod.value ->> 'id' = target_product_id::text
  limit 1;

  -- The product does not exist in the current published snapshot: do not
  -- create a new menu_version, do not expose the unpublished product.
  -- Leave only the draft availability change already applied above.
  if v_cat_idx is null then
    return;
  end if;

  -- Copy the CURRENT PUBLISHED SNAPSHOT and change only this one product's
  -- availability field. Never rebuilt from draft tables — no unpublished
  -- price/description/image/variant/addon change can leak in.
  v_new_snapshot := jsonb_set(
    v_snapshot,
    array['categories', v_cat_idx::text, 'products', v_prod_idx::text, 'availability'],
    to_jsonb(new_availability),
    false
  );

  insert into public.menu_versions (menu_id, published_by, snapshot)
  values (v_menu_id, auth.uid(), v_new_snapshot)
  returning id into v_new_version_id;

  update public.menus
     set published_version_id = v_new_version_id,
         draft_updated_at = now()
   where id = v_menu_id;
end;
$$;

revoke all on function public.publish_availability_change(uuid, text) from public;
grant execute on function public.publish_availability_change(uuid, text) to authenticated;
