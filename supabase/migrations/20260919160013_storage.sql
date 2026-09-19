-- Phase 2: storage buckets and policies.
--
-- Three buckets, split first by content type and then, for product images,
-- by draft/published state — because a signed/expiring URL cannot safely
-- be referenced from an ISR-cached public page (the cache can keep serving
-- a URL after it has expired).
--
--   restaurant-assets    public  — logos, covers, branch covers. Restaurant/
--                                  branch profile fields have no draft/
--                                  published distinction, so this bucket
--                                  needs no further split.
--   product-images-draft   private — product photos being edited;
--                                    capability-gated, never anonymous-
--                                    readable.
--   product-images-public   public  — product photos referenced by a
--                                     published menu snapshot; stable,
--                                     non-expiring URLs, safe to embed in
--                                     ISR-cached HTML.
--
-- Path convention: products/{restaurantId}/{productId}/{variant}.webp and
-- branches/{branchId}/cover.webp — path-prefixed by tenant id so policies
-- (and future cleanup jobs) can scope by restaurant/branch without a
-- database join.
--
-- Promotion of a draft image into product-images-public happens at
-- menu.publish time, inside the same transaction that builds the new
-- menu_versions snapshot (application logic for a later phase, per the
-- specification) — it is not exposed as a direct client storage write
-- here, so product-images-public has no authenticated/anon write policy.
-- publish_availability_change() (migration 06) never touches images.

insert into storage.buckets (id, name, public) values
  ('restaurant-assets', 'restaurant-assets', true),
  ('product-images-draft', 'product-images-draft', false),
  ('product-images-public', 'product-images-public', true)
on conflict (id) do nothing;

-- Helper: first path segment as a uuid, or null if it doesn't parse. Used
-- to validate tenant ownership from the object path rather than trusting
-- the path string alone.
create or replace function public.storage_path_uuid(object_name text, segment_index int)
returns uuid
language sql
immutable
set search_path = ''
as $$
  select nullif((storage.foldername(object_name))[segment_index], '')::uuid;
$$;

-- SECURITY DEFINER function EXECUTE audit: not SECURITY DEFINER (it does
-- no table access at all — pure path parsing), but tightened to the
-- minimum required grant anyway. Only the authenticated-only write
-- policies below call it (restaurant_assets_write_managers,
-- product_images_draft_rw_editors) — no anon-facing policy references it,
-- so anon does not need, and does not get, EXECUTE here.
revoke all on function public.storage_path_uuid(text, int) from public;
grant execute on function public.storage_path_uuid(text, int) to authenticated;

-- restaurant-assets ---------------------------------------------------
-- Public bucket: anyone may read. Writes require restaurant.manage or
-- branch.manage on the restaurant/branch named in the path
-- (restaurants/{restaurantId}/... or branches/{branchId}/...).

create policy restaurant_assets_select_public on storage.objects
  for select to anon, authenticated
  using (bucket_id = 'restaurant-assets');

create policy restaurant_assets_write_managers on storage.objects
  for all to authenticated
  using (
    bucket_id = 'restaurant-assets'
    and (
      (
        (storage.foldername(name))[1] = 'restaurants'
        and public.has_restaurant_capability(public.storage_path_uuid(name, 2), 'restaurant.manage')
      )
      or (
        (storage.foldername(name))[1] = 'branches'
        and public.has_capability(public.storage_path_uuid(name, 2), 'branch.manage')
      )
    )
  )
  with check (
    bucket_id = 'restaurant-assets'
    and (
      (
        (storage.foldername(name))[1] = 'restaurants'
        and public.has_restaurant_capability(public.storage_path_uuid(name, 2), 'restaurant.manage')
      )
      or (
        (storage.foldername(name))[1] = 'branches'
        and public.has_capability(public.storage_path_uuid(name, 2), 'branch.manage')
      )
    )
  );

-- product-images-draft ------------------------------------------------
-- Private: capability-gated read and write, never anonymous-readable. Path
-- is products/{restaurantId}/{productId}/{variant}.webp — ownership is
-- checked against the restaurant segment with the restaurant-wide
-- capability helper (the path does not encode a branch).

create policy product_images_draft_rw_editors on storage.objects
  for all to authenticated
  using (
    bucket_id = 'product-images-draft'
    and (storage.foldername(name))[1] = 'products'
    and public.has_restaurant_capability(public.storage_path_uuid(name, 2), 'product.edit')
  )
  with check (
    bucket_id = 'product-images-draft'
    and (storage.foldername(name))[1] = 'products'
    and public.has_restaurant_capability(public.storage_path_uuid(name, 2), 'product.edit')
  );

-- product-images-public -----------------------------------------------
-- Public bucket, anonymous-readable, stable non-expiring URLs. No
-- authenticated/anon write policy: population happens only via the
-- trusted, server-side publish-time promotion step described above.

create policy product_images_public_select_public on storage.objects
  for select to anon, authenticated
  using (bucket_id = 'product-images-public');
