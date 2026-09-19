-- Phase 2: menu domain tables (the draft, always-mutable relational model).
-- menus, categories, products, product_variants, product_addons,
-- allergens, product_allergens, badges, product_badges.
-- menu_versions and the publish pointer are added in migration 06 to avoid
-- a circular foreign key at creation time (see that file's header comment).

create table public.menus (
  id uuid primary key default gen_random_uuid(),
  branch_id uuid not null unique references public.branches (id) on delete cascade,
  -- published_version_id gets its foreign key to menu_versions added in
  -- migration 06, once that table exists.
  published_version_id uuid,
  draft_updated_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index menus_published_version_id_idx on public.menus (published_version_id);

-- Each branch has exactly one menu. Rather than relying on application
-- code to remember to create it, a trigger creates the menu row the moment
-- a branch is created, which is the only way to guarantee the invariant
-- holds for every branch. SECURITY DEFINER so it isn't blocked by
-- branches_insert_admins / a missing menus INSERT policy for the same
-- transaction's role.
create or replace function public.create_menu_for_branch()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.menus (branch_id) values (new.id);
  return new;
end;
$$;

-- SECURITY DEFINER function EXECUTE audit: this function's return type is
-- `trigger`, which Postgres refuses to invoke any other way ("trigger
-- functions can only be called as triggers") — the trigger mechanism
-- itself fires it regardless of the inserting role's function privileges,
-- so no grant is ever required for the branches_create_menu trigger to
-- work. Revoking PUBLIC's default EXECUTE is still done here, as
-- defense-in-depth: it removes any direct-call surface entirely rather
-- than relying on the trigger-only return type alone, and no role is
-- granted EXECUTE, because none should ever call it directly.
revoke all on function public.create_menu_for_branch() from public;

create trigger branches_create_menu
  after insert on public.branches
  for each row execute function public.create_menu_for_branch();

create table public.categories (
  id uuid primary key default gen_random_uuid(),
  menu_id uuid not null references public.menus (id) on delete cascade,
  name_ar text not null,
  name_en text not null,
  image_url text,
  display_order integer not null default 0,
  is_visible boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index categories_menu_id_display_order_idx on public.categories (menu_id, display_order);

create table public.products (
  id uuid primary key default gen_random_uuid(),
  category_id uuid not null references public.categories (id) on delete cascade,
  name_ar text not null,
  name_en text not null,
  description_ar text,
  description_en text,
  image_url text,
  -- base_price stays nullable. There is no cross-table CHECK requiring
  -- base_price or a product_variants row to exist — price completeness is
  -- validated in application logic during full publish, in a later phase.
  base_price numeric(12, 2),
  original_price numeric(12, 2),
  discounted_price numeric(12, 2),
  discount_percent numeric(5, 2) generated always as (
    case
      when original_price is not null and original_price > 0 and discounted_price is not null
        then round(((original_price - discounted_price) / original_price) * 100, 2)
      else null
    end
  ) stored,
  offer_start_at timestamptz,
  offer_end_at timestamptz,
  calories integer,
  prep_time_minutes integer,
  is_vegetarian boolean not null default false,
  spicy_level integer not null default 0 check (spicy_level between 0 and 3),
  display_order integer not null default 0,
  -- availability_staff may only move this between 'available' and
  -- 'sold_out', and only through publish_availability_change() (migration
  -- 06) — never through a direct UPDATE, which RLS never grants them
  -- (migration 07). 'hidden' is reachable only via the normal product.edit
  -- UPDATE path held by owner/admin/branch_manager/editor.
  availability public.product_availability not null default 'available',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index products_category_id_display_order_idx on public.products (category_id, display_order);

create table public.product_variants (
  id uuid primary key default gen_random_uuid(),
  product_id uuid not null references public.products (id) on delete cascade,
  name_ar text not null,
  name_en text not null,
  price numeric(12, 2),
  display_order integer not null default 0,
  created_at timestamptz not null default now()
);

create index product_variants_product_id_idx on public.product_variants (product_id);

-- Informational only in V1 — no ordering/cart semantics attach to addons.
create table public.product_addons (
  id uuid primary key default gen_random_uuid(),
  product_id uuid not null references public.products (id) on delete cascade,
  name_ar text not null,
  name_en text not null,
  price numeric(12, 2),
  display_order integer not null default 0,
  created_at timestamptz not null default now()
);

create index product_addons_product_id_idx on public.product_addons (product_id);

-- restaurant_id null = platform predefined allergen; restaurant_id set =
-- restaurant custom allergen.
create table public.allergens (
  id uuid primary key default gen_random_uuid(),
  restaurant_id uuid references public.restaurants (id) on delete cascade,
  name_ar text not null,
  name_en text not null,
  created_at timestamptz not null default now()
);

create index allergens_restaurant_id_idx on public.allergens (restaurant_id);

insert into public.allergens (restaurant_id, name_ar, name_en) values
  (null, 'الغلوتين', 'Gluten'),
  (null, 'الحليب', 'Milk'),
  (null, 'البيض', 'Eggs'),
  (null, 'المكسرات', 'Nuts'),
  (null, 'الصويا', 'Soy'),
  (null, 'الأسماك', 'Fish'),
  (null, 'السمسم', 'Sesame');

create table public.product_allergens (
  product_id uuid not null references public.products (id) on delete cascade,
  allergen_id uuid not null references public.allergens (id) on delete cascade,
  primary key (product_id, allergen_id)
);

create index product_allergens_allergen_id_idx on public.product_allergens (allergen_id);

-- Global platform reference table — not restaurant-scoped.
create table public.badges (
  id uuid primary key default gen_random_uuid(),
  key public.badge_key not null unique,
  name_ar text not null,
  name_en text not null
);

insert into public.badges (key, name_ar, name_en) values
  ('best_seller', 'الأكثر مبيعاً', 'Best Seller'),
  ('new', 'جديد', 'New'),
  ('chef_choice', 'اختيار الشيف', 'Chef''s Choice'),
  ('spicy', 'حار', 'Spicy'),
  ('offer', 'عرض', 'Offer');

create table public.product_badges (
  product_id uuid not null references public.products (id) on delete cascade,
  badge_id uuid not null references public.badges (id) on delete cascade,
  primary key (product_id, badge_id)
);

create index product_badges_badge_id_idx on public.product_badges (badge_id);

-- Removed from the earlier (rejected) draft: branch_product_availability,
-- branch_variant_availability, product_addon_groups. Availability lives
-- directly on products; addons are flat, informational-only rows.
