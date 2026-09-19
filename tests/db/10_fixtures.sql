-- Phase 2 test fixtures. Runs as the postgres superuser (bypasses RLS) so
-- the data is deterministic regardless of policy correctness — the RLS
-- test suite (20_rls_tests.sql) is what actually exercises the policies.

-- ---------------------------------------------------------------------
-- Users
-- ---------------------------------------------------------------------
insert into auth.users (id, email) values
  ('a0000000-0000-0000-0000-000000000001', 'owner_a@example.com'),
  ('a0000000-0000-0000-0000-000000000002', 'admin_a@example.com'),
  ('a0000000-0000-0000-0000-000000000003', 'branchmgr_a1@example.com'),
  ('a0000000-0000-0000-0000-000000000004', 'editor_a1@example.com'),
  ('a0000000-0000-0000-0000-000000000005', 'availability_a1@example.com'),
  ('a0000000-0000-0000-0000-000000000006', 'viewer_a1@example.com'),
  ('a0000000-0000-0000-0000-000000000007', 'branchmgr_a_multi@example.com'),
  ('a0000000-0000-0000-0000-000000000008', 'branchmgr_a_noaccess@example.com'),
  ('b0000000-0000-0000-0000-000000000001', 'owner_b@example.com'),
  ('50000000-0000-0000-0000-000000000001', 'superadmin@example.com'),
  ('90000000-0000-0000-0000-000000000001', 'outsider@example.com');

insert into public.profiles (id, full_name, locale) values
  ('a0000000-0000-0000-0000-000000000001', 'Owner A', 'ar'),
  ('a0000000-0000-0000-0000-000000000002', 'Admin A', 'ar'),
  ('a0000000-0000-0000-0000-000000000003', 'Branch Manager A1', 'ar'),
  ('a0000000-0000-0000-0000-000000000004', 'Editor A1', 'ar'),
  ('a0000000-0000-0000-0000-000000000005', 'Availability Staff A1', 'ar'),
  ('a0000000-0000-0000-0000-000000000006', 'Viewer A1', 'ar'),
  ('a0000000-0000-0000-0000-000000000007', 'Branch Manager A Multi', 'ar'),
  ('a0000000-0000-0000-0000-000000000008', 'Branch Manager A No Access', 'ar'),
  ('b0000000-0000-0000-0000-000000000001', 'Owner B', 'ar'),
  ('50000000-0000-0000-0000-000000000001', 'Super Admin', 'en'),
  ('90000000-0000-0000-0000-000000000001', 'Outsider', 'en');

-- ---------------------------------------------------------------------
-- Restaurants
-- ---------------------------------------------------------------------
insert into public.restaurants (id, name_ar, name_en, slug, status) values
  ('11111111-1111-1111-1111-111111111111', 'مطعم أ', 'Restaurant A', 'restaurant-a', 'active'),
  ('22222222-2222-2222-2222-222222222222', 'مطعم ب', 'Restaurant B', 'restaurant-b', 'active');

-- ---------------------------------------------------------------------
-- Branches (each INSERT fires branches_create_menu -> one menus row per
-- branch automatically)
-- ---------------------------------------------------------------------
insert into public.branches (id, restaurant_id, name_ar, name_en, slug, status) values
  ('aaaaaaaa-1111-1111-1111-111111111111', '11111111-1111-1111-1111-111111111111', 'فرع أ1', 'Branch A1', 'branch-a1', 'active'),
  ('aaaaaaaa-2222-2222-2222-222222222222', '11111111-1111-1111-1111-111111111111', 'فرع أ2', 'Branch A2', 'branch-a2', 'active'),
  ('bbbbbbbb-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222', 'فرع ب1', 'Branch B1', 'branch-b1', 'active');

-- ---------------------------------------------------------------------
-- Membership
-- ---------------------------------------------------------------------
insert into public.restaurant_members (id, restaurant_id, user_id, role, status) values
  ('11110001-0000-0000-0000-000000000001', '11111111-1111-1111-1111-111111111111', 'a0000000-0000-0000-0000-000000000001', 'owner', 'active'),
  ('11110002-0000-0000-0000-000000000002', '11111111-1111-1111-1111-111111111111', 'a0000000-0000-0000-0000-000000000002', 'admin', 'active'),
  ('11110003-0000-0000-0000-000000000003', '11111111-1111-1111-1111-111111111111', 'a0000000-0000-0000-0000-000000000003', 'branch_manager', 'active'),
  ('11110004-0000-0000-0000-000000000004', '11111111-1111-1111-1111-111111111111', 'a0000000-0000-0000-0000-000000000004', 'editor', 'active'),
  ('11110005-0000-0000-0000-000000000005', '11111111-1111-1111-1111-111111111111', 'a0000000-0000-0000-0000-000000000005', 'availability_staff', 'active'),
  ('11110006-0000-0000-0000-000000000006', '11111111-1111-1111-1111-111111111111', 'a0000000-0000-0000-0000-000000000006', 'viewer', 'active'),
  ('11110007-0000-0000-0000-000000000007', '11111111-1111-1111-1111-111111111111', 'a0000000-0000-0000-0000-000000000007', 'branch_manager', 'active'),
  ('11110008-0000-0000-0000-000000000008', '11111111-1111-1111-1111-111111111111', 'a0000000-0000-0000-0000-000000000008', 'branch_manager', 'active'),
  ('22220001-0000-0000-0000-000000000001', '22222222-2222-2222-2222-222222222222', 'b0000000-0000-0000-0000-000000000001', 'owner', 'active');

-- Branch-scoped roles (3,4,5,6) restricted to Branch A1 only. Member 7 is
-- assigned to both A1 and A2 (multi-branch test). Member 8 gets zero rows
-- (zero-access test).
insert into public.member_branch_access (member_id, branch_id) values
  ('11110003-0000-0000-0000-000000000003', 'aaaaaaaa-1111-1111-1111-111111111111'),
  ('11110004-0000-0000-0000-000000000004', 'aaaaaaaa-1111-1111-1111-111111111111'),
  ('11110005-0000-0000-0000-000000000005', 'aaaaaaaa-1111-1111-1111-111111111111'),
  ('11110006-0000-0000-0000-000000000006', 'aaaaaaaa-1111-1111-1111-111111111111'),
  ('11110007-0000-0000-0000-000000000007', 'aaaaaaaa-1111-1111-1111-111111111111'),
  ('11110007-0000-0000-0000-000000000007', 'aaaaaaaa-2222-2222-2222-222222222222');

-- ---------------------------------------------------------------------
-- Menu domain content for Branch A1
-- ---------------------------------------------------------------------
insert into public.categories (id, menu_id, name_ar, name_en, display_order)
select 'cccccccc-1111-1111-1111-111111111111', m.id, 'مشروبات', 'Drinks', 1
from public.menus m where m.branch_id = 'aaaaaaaa-1111-1111-1111-111111111111';

insert into public.products (id, category_id, name_ar, name_en, base_price, availability, display_order) values
  ('dddddddd-1111-1111-1111-111111111111', 'cccccccc-1111-1111-1111-111111111111', 'لاتيه', 'Latte', 18.00, 'available', 1),
  ('dddddddd-2222-2222-2222-222222222222', 'cccccccc-1111-1111-1111-111111111111', 'عصير مانجو', 'Mango Juice', 15.00, 'available', 2);

insert into public.product_variants (product_id, name_ar, name_en, price, display_order) values
  ('dddddddd-1111-1111-1111-111111111111', 'صغير', 'Small', 18.00, 1),
  ('dddddddd-1111-1111-1111-111111111111', 'كبير', 'Large', 22.00, 2);

insert into public.product_allergens (product_id, allergen_id)
select 'dddddddd-1111-1111-1111-111111111111', id from public.allergens where name_en = 'Milk';

insert into public.product_badges (product_id, badge_id)
select 'dddddddd-1111-1111-1111-111111111111', id from public.badges where key = 'best_seller';

-- Branch A2 content (separate menu, must publish independently of A1)
insert into public.categories (id, menu_id, name_ar, name_en, display_order)
select 'cccccccc-2222-2222-2222-222222222222', m.id, 'وجبات خفيفة', 'Snacks', 1
from public.menus m where m.branch_id = 'aaaaaaaa-2222-2222-2222-222222222222';

insert into public.products (id, category_id, name_ar, name_en, base_price, availability, display_order) values
  ('dddddddd-3333-3333-3333-333333333333', 'cccccccc-2222-2222-2222-222222222222', 'بطاطس', 'Fries', 10.00, 'available', 1);

-- Branch B1 content (other restaurant, isolation baseline)
insert into public.categories (id, menu_id, name_ar, name_en, display_order)
select 'cccccccc-3333-3333-3333-333333333333', m.id, 'رئيسي', 'Mains', 1
from public.menus m where m.branch_id = 'bbbbbbbb-1111-1111-1111-111111111111';

insert into public.products (id, category_id, name_ar, name_en, base_price, availability, display_order) values
  ('dddddddd-4444-4444-4444-444444444444', 'cccccccc-3333-3333-3333-333333333333', 'برجر', 'Burger', 25.00, 'available', 1);

-- ---------------------------------------------------------------------
-- Publish Branch A1's menu: one historical (unreferenced) version, then
-- the current published version containing Latte + Mango Juice.
-- ---------------------------------------------------------------------
insert into public.menu_versions (id, menu_id, published_by, snapshot, published_at)
select
  'eeeeeeee-0000-0000-0000-000000000001',
  m.id,
  'a0000000-0000-0000-0000-000000000001',
  jsonb_build_object(
    'categories', jsonb_build_array(
      jsonb_build_object(
        'id', 'cccccccc-1111-1111-1111-111111111111',
        'name_en', 'Drinks',
        'products', jsonb_build_array(
          jsonb_build_object('id', 'dddddddd-1111-1111-1111-111111111111', 'name_en', 'Latte', 'availability', 'available')
        )
      )
    )
  ),
  now() - interval '2 days'
from public.menus m where m.branch_id = 'aaaaaaaa-1111-1111-1111-111111111111';

insert into public.menu_versions (id, menu_id, published_by, snapshot, published_at)
select
  'eeeeeeee-0000-0000-0000-000000000002',
  m.id,
  'a0000000-0000-0000-0000-000000000001',
  jsonb_build_object(
    'categories', jsonb_build_array(
      jsonb_build_object(
        'id', 'cccccccc-1111-1111-1111-111111111111',
        'name_en', 'Drinks',
        'products', jsonb_build_array(
          jsonb_build_object('id', 'dddddddd-1111-1111-1111-111111111111', 'name_en', 'Latte', 'availability', 'available'),
          jsonb_build_object('id', 'dddddddd-2222-2222-2222-222222222222', 'name_en', 'Mango Juice', 'availability', 'available')
        )
      )
    )
  ),
  now()
from public.menus m where m.branch_id = 'aaaaaaaa-1111-1111-1111-111111111111';

update public.menus
   set published_version_id = 'eeeeeeee-0000-0000-0000-000000000002'
 where branch_id = 'aaaaaaaa-1111-1111-1111-111111111111';

-- A draft-only product added AFTER publish, so it is absent from the
-- published snapshot above (used by the micro-publish "not in snapshot"
-- test).
insert into public.products (id, category_id, name_ar, name_en, base_price, availability, display_order) values
  ('dddddddd-5555-5555-5555-555555555555', 'cccccccc-1111-1111-1111-111111111111', 'كوكيز', 'Cookie', 8.00, 'available', 3);

-- Branch A2 and Branch B1 are left unpublished (published_version_id null)
-- for the "no published version -> draft only" test.

-- ---------------------------------------------------------------------
-- Tables and QR
-- ---------------------------------------------------------------------
insert into public.restaurant_tables (id, branch_id, label) values
  ('ffffffff-1111-1111-1111-111111111111', 'aaaaaaaa-1111-1111-1111-111111111111', 'Table 1');

insert into public.qr_codes (restaurant_id, scope) values
  ('11111111-1111-1111-1111-111111111111', 'restaurant');
insert into public.qr_codes (restaurant_id, branch_id, scope) values
  ('11111111-1111-1111-1111-111111111111', 'aaaaaaaa-1111-1111-1111-111111111111', 'branch');
insert into public.qr_codes (restaurant_id, branch_id, table_id, scope) values
  ('11111111-1111-1111-1111-111111111111', 'aaaaaaaa-1111-1111-1111-111111111111', 'ffffffff-1111-1111-1111-111111111111', 'table');

-- ---------------------------------------------------------------------
-- Invitations
-- ---------------------------------------------------------------------
insert into public.invitations (id, restaurant_id, email, role, invited_by) values
  ('99990001-0000-0000-0000-000000000001', '11111111-1111-1111-1111-111111111111', 'new_editor@example.com', 'editor', 'a0000000-0000-0000-0000-000000000001');

insert into public.invitation_branch_access (invitation_id, branch_id) values
  ('99990001-0000-0000-0000-000000000001', 'aaaaaaaa-1111-1111-1111-111111111111');

-- ---------------------------------------------------------------------
-- Notifications, audit log, analytics
-- ---------------------------------------------------------------------
insert into public.notifications (restaurant_id, user_id, type, payload) values
  ('11111111-1111-1111-1111-111111111111', 'a0000000-0000-0000-0000-000000000001', 'invitation_accepted', '{}'::jsonb);

insert into public.audit_logs (actor_user_id, restaurant_id, branch_id, action, entity_type, entity_id) values
  ('a0000000-0000-0000-0000-000000000001', '11111111-1111-1111-1111-111111111111', 'aaaaaaaa-1111-1111-1111-111111111111', 'publish', 'menu_versions', 'eeeeeeee-0000-0000-0000-000000000002');

insert into public.analytics_events (restaurant_id, branch_id, event_type, anon_session_id) values
  ('11111111-1111-1111-1111-111111111111', 'aaaaaaaa-1111-1111-1111-111111111111', 'menu_view', gen_random_uuid());

-- ---------------------------------------------------------------------
-- Super Admin / impersonation
-- ---------------------------------------------------------------------
insert into public.super_admins (user_id) values ('50000000-0000-0000-0000-000000000001');

insert into public.impersonation_sessions (super_admin_id, restaurant_id, reason) values
  ('50000000-0000-0000-0000-000000000001', '11111111-1111-1111-1111-111111111111', 'support ticket #123');
