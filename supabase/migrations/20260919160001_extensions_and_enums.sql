-- Phase 2: extensions and shared enum types.
-- Rewritten from zero against the approved Phase 0 architecture and the
-- final Phase 2 implementation specification. See the "Phase 2 Architecture
-- Reconciliation" living document for the full design history.

create extension if not exists pgcrypto;

-- Restaurant membership role. Exactly the six roles approved in Phase 0 —
-- do not simplify or rename.
create type public.restaurant_role as enum (
  'owner',
  'admin',
  'branch_manager',
  'editor',
  'availability_staff',
  'viewer'
);

-- Product availability. availability_staff may only ever move a product
-- between 'available' and 'sold_out' (enforced in the micro-publish
-- function, migration 06); 'hidden' is reachable only through the normal
-- product.edit path.
create type public.product_availability as enum (
  'available',
  'sold_out',
  'hidden'
);

-- Global platform badge keys (badges table is a global reference list, not
-- restaurant-scoped).
create type public.badge_key as enum (
  'best_seller',
  'new',
  'chef_choice',
  'spicy',
  'offer'
);

-- Fixed analytics event vocabulary from the specification.
create type public.analytics_event_type as enum (
  'menu_view',
  'branch_view',
  'category_view',
  'product_view',
  'qr_scan',
  'search',
  'whatsapp_click',
  'phone_click',
  'instagram_click',
  'google_maps_click',
  'language_change',
  'filter_usage'
);
