-- Phase 2: RLS for the menu domain — draft tables (authenticated,
-- capability-gated) and the anonymous public read model (published
-- snapshot only, resolved solely through menus.published_version_id).

alter table public.menus enable row level security;
alter table public.menus force row level security;

alter table public.categories enable row level security;
alter table public.categories force row level security;

alter table public.products enable row level security;
alter table public.products force row level security;

alter table public.product_variants enable row level security;
alter table public.product_variants force row level security;

alter table public.product_addons enable row level security;
alter table public.product_addons force row level security;

alter table public.allergens enable row level security;
alter table public.allergens force row level security;

alter table public.product_allergens enable row level security;
alter table public.product_allergens force row level security;

alter table public.badges enable row level security;
alter table public.badges force row level security;

alter table public.product_badges enable row level security;
alter table public.product_badges force row level security;

alter table public.menu_versions enable row level security;
alter table public.menu_versions force row level security;

-- menus -------------------------------------------------------------------
-- No authenticated INSERT/UPDATE policy is granted at all in Phase 2: menu
-- rows are created only by the branches_create_menu trigger (migration
-- 05), and published_version_id must only ever be set by a SECURITY
-- DEFINER publish function (publish_availability_change here; a future
-- full-publish function later) — never by a direct client UPDATE, which
-- would bypass all publish validation. draft_updated_at maintenance for
-- ordinary draft edits is deferred to the full draft-editing Server
-- Actions in a later phase.

create policy menus_select_members on public.menus
  for select to authenticated
  using (public.has_branch_access(branch_id));

create policy menus_select_public on public.menus
  for select to anon
  using (
    exists (
      select 1
      from public.branches b
      join public.restaurants r on r.id = b.restaurant_id
      where b.id = menus.branch_id
        and b.status = 'active'
        and r.status = 'active'
    )
  );

-- categories ----------------------------------------------------------

create policy categories_select_members on public.categories
  for select to authenticated
  using (
    exists (
      select 1 from public.menus m
      where m.id = categories.menu_id and public.has_branch_access(m.branch_id)
    )
  );

create policy categories_write_editors on public.categories
  for all to authenticated
  using (
    exists (
      select 1 from public.menus m
      where m.id = categories.menu_id and public.has_capability(m.branch_id, 'menu.edit')
    )
  )
  with check (
    exists (
      select 1 from public.menus m
      where m.id = categories.menu_id and public.has_capability(m.branch_id, 'menu.edit')
    )
  );

-- products --------------------------------------------------------------
-- Deliberately no UPDATE grant for product.availability alone: RLS here
-- only ever grants writes to product.edit holders (owner, admin,
-- branch_manager, editor). availability_staff holds product.availability
-- but NOT product.edit, so they get no row here at all — their only path
-- to changing availability is publish_availability_change() (migration
-- 06), which performs its own UPDATE as the function owner, bypassing
-- this policy entirely. This is what makes availability_staff
-- "technically unable through RLS... to edit prices, names, descriptions,
-- images, variants, addons, categories" while still able to publish an
-- availability change.

create policy products_select_members on public.products
  for select to authenticated
  using (
    exists (
      select 1
      from public.categories c
      join public.menus m on m.id = c.menu_id
      where c.id = products.category_id and public.has_branch_access(m.branch_id)
    )
  );

create policy products_write_editors on public.products
  for all to authenticated
  using (
    exists (
      select 1
      from public.categories c
      join public.menus m on m.id = c.menu_id
      where c.id = products.category_id and public.has_capability(m.branch_id, 'product.edit')
    )
  )
  with check (
    exists (
      select 1
      from public.categories c
      join public.menus m on m.id = c.menu_id
      where c.id = products.category_id and public.has_capability(m.branch_id, 'product.edit')
    )
  );

-- product_variants --------------------------------------------------------

create policy product_variants_select_members on public.product_variants
  for select to authenticated
  using (
    exists (
      select 1
      from public.products p
      join public.categories c on c.id = p.category_id
      join public.menus m on m.id = c.menu_id
      where p.id = product_variants.product_id and public.has_branch_access(m.branch_id)
    )
  );

create policy product_variants_write_editors on public.product_variants
  for all to authenticated
  using (
    exists (
      select 1
      from public.products p
      join public.categories c on c.id = p.category_id
      join public.menus m on m.id = c.menu_id
      where p.id = product_variants.product_id and public.has_capability(m.branch_id, 'product.edit')
    )
  )
  with check (
    exists (
      select 1
      from public.products p
      join public.categories c on c.id = p.category_id
      join public.menus m on m.id = c.menu_id
      where p.id = product_variants.product_id and public.has_capability(m.branch_id, 'product.edit')
    )
  );

-- product_addons ----------------------------------------------------------

create policy product_addons_select_members on public.product_addons
  for select to authenticated
  using (
    exists (
      select 1
      from public.products p
      join public.categories c on c.id = p.category_id
      join public.menus m on m.id = c.menu_id
      where p.id = product_addons.product_id and public.has_branch_access(m.branch_id)
    )
  );

create policy product_addons_write_editors on public.product_addons
  for all to authenticated
  using (
    exists (
      select 1
      from public.products p
      join public.categories c on c.id = p.category_id
      join public.menus m on m.id = c.menu_id
      where p.id = product_addons.product_id and public.has_capability(m.branch_id, 'product.edit')
    )
  )
  with check (
    exists (
      select 1
      from public.products p
      join public.categories c on c.id = p.category_id
      join public.menus m on m.id = c.menu_id
      where p.id = product_addons.product_id and public.has_capability(m.branch_id, 'product.edit')
    )
  );

-- allergens -----------------------------------------------------------
-- Predefined (restaurant_id is null) rows are readable by any authenticated
-- user; custom rows only by members of the owning restaurant. Writes to
-- custom allergens use the restaurant-wide capability check (menu.edit is
-- held by branch_manager/editor too, and allergens are restaurant-level,
-- not branch-level, so there is no "not-yet-assigned-branch" ambiguity
-- here the way there is for branch creation).

create policy allergens_select on public.allergens
  for select to authenticated
  using (restaurant_id is null or public.is_restaurant_member(restaurant_id));

create policy allergens_write_editors on public.allergens
  for all to authenticated
  using (restaurant_id is not null and public.has_restaurant_capability(restaurant_id, 'menu.edit'))
  with check (restaurant_id is not null and public.has_restaurant_capability(restaurant_id, 'menu.edit'));

-- product_allergens -----------------------------------------------------

create policy product_allergens_select_members on public.product_allergens
  for select to authenticated
  using (
    exists (
      select 1
      from public.products p
      join public.categories c on c.id = p.category_id
      join public.menus m on m.id = c.menu_id
      where p.id = product_allergens.product_id and public.has_branch_access(m.branch_id)
    )
  );

create policy product_allergens_write_editors on public.product_allergens
  for all to authenticated
  using (
    exists (
      select 1
      from public.products p
      join public.categories c on c.id = p.category_id
      join public.menus m on m.id = c.menu_id
      where p.id = product_allergens.product_id and public.has_capability(m.branch_id, 'product.edit')
    )
  )
  with check (
    exists (
      select 1
      from public.products p
      join public.categories c on c.id = p.category_id
      join public.menus m on m.id = c.menu_id
      where p.id = product_allergens.product_id and public.has_capability(m.branch_id, 'product.edit')
    )
  );

-- badges ------------------------------------------------------------------
-- Global platform reference table, same write posture as role_capabilities:
-- readable by everyone, writable only through migrations.

create policy badges_select_all on public.badges
  for select to authenticated, anon
  using (true);

-- product_badges ----------------------------------------------------------

create policy product_badges_select_members on public.product_badges
  for select to authenticated
  using (
    exists (
      select 1
      from public.products p
      join public.categories c on c.id = p.category_id
      join public.menus m on m.id = c.menu_id
      where p.id = product_badges.product_id and public.has_branch_access(m.branch_id)
    )
  );

create policy product_badges_write_editors on public.product_badges
  for all to authenticated
  using (
    exists (
      select 1
      from public.products p
      join public.categories c on c.id = p.category_id
      join public.menus m on m.id = c.menu_id
      where p.id = product_badges.product_id and public.has_capability(m.branch_id, 'product.edit')
    )
  )
  with check (
    exists (
      select 1
      from public.products p
      join public.categories c on c.id = p.category_id
      join public.menus m on m.id = c.menu_id
      where p.id = product_badges.product_id and public.has_capability(m.branch_id, 'product.edit')
    )
  );

-- menu_versions -----------------------------------------------------------
-- No INSERT/UPDATE/DELETE policy for authenticated or anon at all: every
-- write happens through a SECURITY DEFINER publish function, which bypasses
-- RLS as its owning role. UPDATE/DELETE are additionally hard-blocked by
-- the triggers in migration 06 regardless of role.

create policy menu_versions_select_members on public.menu_versions
  for select to authenticated
  using (
    exists (
      select 1 from public.menus m
      where m.id = menu_versions.menu_id and public.has_branch_access(m.branch_id)
    )
  );

-- Anonymous visitors may read one and only one menu_versions row per menu:
-- the version currently referenced by menus.published_version_id. History
-- is never anonymous-readable, and draft tables are never touched by this
-- policy at all.
create policy menu_versions_select_published_only on public.menu_versions
  for select to anon
  using (
    exists (
      select 1
      from public.menus m
      join public.branches b on b.id = m.branch_id
      join public.restaurants r on r.id = b.restaurant_id
      where m.published_version_id = menu_versions.id
        and b.status = 'active'
        and r.status = 'active'
    )
  );
