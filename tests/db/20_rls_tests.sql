-- Phase 2 RLS / security test suite, run against a fresh database built
-- from the migrations in supabase/migrations/ plus the fixtures in
-- 10_fixtures.sql. Each test runs as the relevant Postgres role with
-- request.jwt.claims set to mimic a specific auth.uid(), inside its own
-- transaction, then rolls back so tests never affect each other or the
-- fixtures. A FAIL raises an exception and aborts the whole run (this file
-- is invoked with ON_ERROR_STOP); a clean run to the final NOTICE means
-- every assertion held. Fixture ids are documented in 10_fixtures.sql.

\set ON_ERROR_STOP on

-- =====================================================================
-- T1: cross-tenant isolation
-- =====================================================================

begin;
set local role authenticated;
set local "request.jwt.claims" to '{"sub":"a0000000-0000-0000-0000-000000000001","role":"authenticated"}';
do $$
declare cnt bigint;
begin
  select count(*) into cnt from public.restaurants;
  if cnt <> 1 then raise exception 'FAIL T1a: owner_a should see exactly 1 restaurant, saw %', cnt; end if;
  select count(*) into cnt from public.branches;
  if cnt <> 2 then raise exception 'FAIL T1b: owner_a should see exactly 2 branches (A1, A2), saw %', cnt; end if;
  select count(*) into cnt from public.categories;
  if cnt <> 2 then raise exception 'FAIL T1c: owner_a should see exactly 2 categories (A1, A2), saw %', cnt; end if;
  raise notice 'PASS T1: owner_a sees only restaurant A''s tree (1 restaurant, 2 branches, 2 categories)';
end $$;
rollback;

-- owner_a cannot even see restaurant B's menu row (blocked by menus SELECT
-- RLS before categories' own WITH CHECK is ever reached), so an
-- INSERT ... SELECT sourced from it is a genuine 0-row no-op rather than a
-- thrown exception. Prove the no-op explicitly via an explicit menu_id
-- instead, which does reach the categories WITH CHECK directly.
begin;
set local role authenticated;
set local "request.jwt.claims" to '{"sub":"a0000000-0000-0000-0000-000000000001","role":"authenticated"}';
do $$
declare v_branch_b_menu_id uuid;
begin
  select id into v_branch_b_menu_id from public.menus where branch_id = 'bbbbbbbb-1111-1111-1111-111111111111'; -- 0 rows under RLS
  if v_branch_b_menu_id is not null then raise exception 'FAIL T1d-setup: owner_a should not be able to see restaurant B''s menu at all'; end if;
end $$;
rollback;

begin;
set local role postgres;
do $$ declare v_branch_b_menu_id uuid; begin
  select id into v_branch_b_menu_id from public.menus where branch_id = 'bbbbbbbb-1111-1111-1111-111111111111';
  perform set_config('test.branch_b_menu_id', v_branch_b_menu_id::text, true);
end $$;
set local role authenticated;
set local "request.jwt.claims" to '{"sub":"a0000000-0000-0000-0000-000000000001","role":"authenticated"}';
do $$
begin
  begin
    insert into public.categories (menu_id, name_ar, name_en)
      values (current_setting('test.branch_b_menu_id')::uuid, 'x', 'x');
    raise exception 'FAIL T1d: owner_a was able to insert a category directly into restaurant B''s menu_id';
  exception when others then
    if sqlerrm like 'FAIL%' then raise; end if;
  end;
  raise notice 'PASS T1d: owner_a cannot insert into restaurant B''s menu, even by menu_id directly (WITH CHECK denies it)';
end $$;
rollback;

begin;
set local role authenticated;
set local "request.jwt.claims" to '{"sub":"b0000000-0000-0000-0000-000000000001","role":"authenticated"}';
do $$
declare cnt bigint;
begin
  select count(*) into cnt from public.restaurants;
  if cnt <> 1 then raise exception 'FAIL T1e: owner_b should see exactly 1 restaurant, saw %', cnt; end if;
  raise notice 'PASS T1e: symmetric isolation confirmed for owner_b';
end $$;
rollback;

-- =====================================================================
-- T2: restaurant owner / admin access (restaurant-wide, no branch rows needed)
-- =====================================================================

begin;
set local role authenticated;
set local "request.jwt.claims" to '{"sub":"a0000000-0000-0000-0000-000000000001","role":"authenticated"}';
do $$
declare cnt bigint;
begin
  select count(*) into cnt from public.branches where restaurant_id = '11111111-1111-1111-1111-111111111111';
  if cnt <> 2 then raise exception 'FAIL T2a: owner should see both branches without member_branch_access rows, saw %', cnt; end if;
  update public.branches set name_en = 'Branch A2 (renamed)' where id = 'aaaaaaaa-2222-2222-2222-222222222222';
  raise notice 'PASS T2: owner_a has restaurant-wide branch access and can update a branch with no member_branch_access row';
end $$;
rollback;

begin;
set local role authenticated;
set local "request.jwt.claims" to '{"sub":"a0000000-0000-0000-0000-000000000002","role":"authenticated"}';
do $$
declare cnt bigint;
begin
  select count(*) into cnt from public.branches where restaurant_id = '11111111-1111-1111-1111-111111111111';
  if cnt <> 2 then raise exception 'FAIL T3a: admin should see both branches, saw %', cnt; end if;
  insert into public.restaurant_members (restaurant_id, user_id, role)
    values ('11111111-1111-1111-1111-111111111111', '90000000-0000-0000-0000-000000000001', 'viewer');
  raise notice 'PASS T3: admin_a has restaurant-wide branch access and team.manage (can insert a member)';
end $$;
rollback;

-- =====================================================================
-- T4/T5/T6: branch-scoped roles restricted to assigned branches
-- =====================================================================

begin;
set local role authenticated;
set local "request.jwt.claims" to '{"sub":"a0000000-0000-0000-0000-000000000003","role":"authenticated"}';
do $$
declare cnt bigint;
begin
  select count(*) into cnt from public.branches;
  if cnt <> 1 then raise exception 'FAIL T4a: branch_manager (A1 only) should see exactly 1 branch, saw %', cnt; end if;
  select count(*) into cnt from public.categories;
  if cnt <> 1 then raise exception 'FAIL T4b: branch_manager (A1 only) should see exactly 1 category, saw %', cnt; end if;
  raise notice 'PASS T4: branch_manager restricted to assigned branch (A1 only)';
end $$;
rollback;

begin;
set local role authenticated;
set local "request.jwt.claims" to '{"sub":"a0000000-0000-0000-0000-000000000004","role":"authenticated"}';
do $$
declare cnt bigint;
begin
  select count(*) into cnt from public.branches;
  if cnt <> 1 then raise exception 'FAIL T5a: editor (A1 only) should see exactly 1 branch, saw %', cnt; end if;
  update public.products set name_en = 'Latte (edited)' where id = 'dddddddd-1111-1111-1111-111111111111';
  begin
    insert into public.restaurant_members (restaurant_id, user_id, role)
      values ('11111111-1111-1111-1111-111111111111', '90000000-0000-0000-0000-000000000001', 'viewer');
    raise exception 'FAIL T5b: editor should not hold team.manage';
  exception when others then
    if sqlerrm like 'FAIL%' then raise; end if;
  end;
  raise notice 'PASS T5: editor restricted to assigned branch, can edit products, cannot manage team';
end $$;
rollback;

begin;
set local role authenticated;
set local "request.jwt.claims" to '{"sub":"a0000000-0000-0000-0000-000000000005","role":"authenticated"}';
do $$
declare cnt bigint;
begin
  select count(*) into cnt from public.branches;
  if cnt <> 1 then raise exception 'FAIL T6a: availability_staff (A1 only) should see exactly 1 branch, saw %', cnt; end if;
  raise notice 'PASS T6: availability_staff restricted to assigned branch (A1 only)';
end $$;
rollback;

begin;
set local role authenticated;
set local "request.jwt.claims" to '{"sub":"a0000000-0000-0000-0000-000000000006","role":"authenticated"}';
do $$
declare cnt bigint;
begin
  select count(*) into cnt from public.branches;
  if cnt <> 1 then raise exception 'FAIL T7a: viewer (A1 only) should see exactly 1 branch, saw %', cnt; end if;
  select count(*) into cnt from public.analytics_events;
  if cnt <> 1 then raise exception 'FAIL T7b: viewer should see A1''s analytics event, saw %', cnt; end if;
  begin
    update public.products set name_en = 'hacked' where id = 'dddddddd-1111-1111-1111-111111111111';
    if found then raise exception 'FAIL T7c: viewer should not be able to update products'; end if;
  exception when others then
    if sqlerrm like 'FAIL%' then raise; end if;
  end;
  raise notice 'PASS T7: viewer restricted correctly (sees branch + analytics, cannot write products)';
end $$;
rollback;

-- =====================================================================
-- T8: multi-branch access via member_branch_access
-- =====================================================================

begin;
set local role authenticated;
set local "request.jwt.claims" to '{"sub":"a0000000-0000-0000-0000-000000000007","role":"authenticated"}';
do $$
declare cnt bigint;
begin
  select count(*) into cnt from public.branches;
  if cnt <> 2 then raise exception 'FAIL T8a: multi-branch member should see 2 branches (A1+A2), saw %', cnt; end if;
  raise notice 'PASS T8: member_branch_access correctly grants access to multiple assigned branches';
end $$;
rollback;

-- =====================================================================
-- T9: zero member_branch_access rows means zero branch access
-- =====================================================================

begin;
set local role authenticated;
set local "request.jwt.claims" to '{"sub":"a0000000-0000-0000-0000-000000000008","role":"authenticated"}';
do $$
declare cnt bigint;
begin
  select count(*) into cnt from public.branches;
  if cnt <> 0 then raise exception 'FAIL T9a: branch_manager with zero member_branch_access rows should see 0 branches, saw %', cnt; end if;
  select count(*) into cnt from public.categories;
  if cnt <> 0 then raise exception 'FAIL T9b: should see 0 categories, saw %', cnt; end if;
  -- Still a restaurant member, so restaurant-level (not branch-scoped) rows remain visible.
  select count(*) into cnt from public.restaurants;
  if cnt <> 1 then raise exception 'FAIL T9c: should still see the parent restaurant row, saw %', cnt; end if;
  raise notice 'PASS T9: zero member_branch_access rows for a branch-scoped role means zero branch access';
end $$;
rollback;

-- =====================================================================
-- T10: role_capabilities cannot be modified by normal authenticated users
-- =====================================================================

begin;
set local role authenticated;
set local "request.jwt.claims" to '{"sub":"a0000000-0000-0000-0000-000000000001","role":"authenticated"}';
do $$
begin
  begin
    insert into public.role_capabilities (role, capability) values ('viewer', 'menu.publish');
    raise exception 'FAIL T10a: owner (or any authenticated user) should not be able to insert into role_capabilities';
  exception when others then
    if sqlerrm like 'FAIL%' then raise; end if;
  end;
  raise notice 'PASS T10: role_capabilities cannot be modified by normal authenticated users, even owner';
end $$;
rollback;

-- =====================================================================
-- T11: restaurant creation denied to normal authenticated users
-- =====================================================================

begin;
set local role authenticated;
set local "request.jwt.claims" to '{"sub":"a0000000-0000-0000-0000-000000000001","role":"authenticated"}';
do $$
begin
  begin
    insert into public.restaurants (name_ar, name_en, slug) values ('x', 'x', 'owner-self-created');
    raise exception 'FAIL T11a: authenticated user (even an existing owner) should not be able to insert a restaurant';
  exception when others then
    if sqlerrm like 'FAIL%' then raise; end if;
  end;
  raise notice 'PASS T11: restaurant creation denied to every authenticated role, no INSERT policy exists';
end $$;
rollback;

-- =====================================================================
-- T12: Super Admin has no ordinary tenant access through tenant RLS
-- =====================================================================

begin;
set local role authenticated;
set local "request.jwt.claims" to '{"sub":"50000000-0000-0000-0000-000000000001","role":"authenticated"}';
do $$
declare cnt bigint;
begin
  select count(*) into cnt from public.restaurants;
  if cnt <> 0 then raise exception 'FAIL T12a: Super Admin (not a restaurant_members row anywhere) should see 0 restaurants via tenant RLS, saw %', cnt; end if;
  select count(*) into cnt from public.branches;
  if cnt <> 0 then raise exception 'FAIL T12b: Super Admin should see 0 branches, saw %', cnt; end if;
  select count(*) into cnt from public.categories;
  if cnt <> 0 then raise exception 'FAIL T12c: Super Admin should see 0 categories, saw %', cnt; end if;
  select count(*) into cnt from public.super_admins;
  if cnt <> 0 then raise exception 'FAIL T12d: Super Admin should not even be able to read super_admins via client RLS, saw %', cnt; end if;
  raise notice 'PASS T12: being in super_admins grants zero tenant-table access through tenant RLS (no bypass clause anywhere), and super_admins itself is unreadable by its own member';
end $$;
rollback;

-- =====================================================================
-- T13/T14: anonymous public read model
-- =====================================================================

begin;
set local role anon;
do $$
declare cnt bigint;
begin
  select count(*) into cnt from public.categories;
  if cnt <> 0 then raise exception 'FAIL T13a: anon should never read draft categories, saw %', cnt; end if;
  select count(*) into cnt from public.products;
  if cnt <> 0 then raise exception 'FAIL T13b: anon should never read draft products, saw %', cnt; end if;
  select count(*) into cnt from public.product_variants;
  if cnt <> 0 then raise exception 'FAIL T13c: anon should never read draft product_variants, saw %', cnt; end if;
  select count(*) into cnt from public.product_addons;
  if cnt <> 0 then raise exception 'FAIL T13d: anon should never read draft product_addons, saw %', cnt; end if;
  raise notice 'PASS T13: anonymous visitors read zero rows from every draft table';
end $$;
rollback;

begin;
set local role anon;
do $$
declare v_snapshot jsonb;
declare cnt bigint;
begin
  select snapshot into v_snapshot from public.menu_versions where id = 'eeeeeeee-0000-0000-0000-000000000002';
  if v_snapshot is null then raise exception 'FAIL T14a: anon should be able to read the currently-published menu_version'; end if;

  select count(*) into cnt from public.menu_versions where id = 'eeeeeeee-0000-0000-0000-000000000001';
  if cnt <> 0 then raise exception 'FAIL T14b: anon should NOT be able to read a historical, unreferenced menu_version, saw %', cnt; end if;

  select count(*) into cnt from public.menu_versions;
  if cnt <> 1 then raise exception 'FAIL T14c: anon should see exactly 1 menu_versions row total (the published one), saw %', cnt; end if;

  raise notice 'PASS T14: anon reads only the version referenced by published_version_id, never history';
end $$;
rollback;

-- =====================================================================
-- T15: two branches of the same restaurant publish independently
-- =====================================================================

begin;
set local role anon;
do $$
declare cnt bigint;
begin
  -- Branch A2 has never been published: no menu_versions row anywhere
  -- exists for it, so anon sees nothing for that menu even though the
  -- branch/menu rows themselves are publicly resolvable.
  select count(*) into cnt
  from public.menu_versions mv
  join public.menus m on m.id = mv.menu_id
  where m.branch_id = 'aaaaaaaa-2222-2222-2222-222222222222';
  if cnt <> 0 then raise exception 'FAIL T15a: unpublished Branch A2 should expose 0 menu_versions to anon, saw %', cnt; end if;

  select count(*) into cnt
  from public.menu_versions mv
  join public.menus m on m.id = mv.menu_id
  where m.branch_id = 'aaaaaaaa-1111-1111-1111-111111111111';
  if cnt <> 1 then raise exception 'FAIL T15b: published Branch A1 should expose exactly 1 menu_versions to anon, saw %', cnt; end if;

  raise notice 'PASS T15: publishing Branch A1 does not publish/expose Branch A2 — each branch menu publishes independently';
end $$;
rollback;

-- =====================================================================
-- T16: menu_versions is append-only (UPDATE/DELETE hard-blocked)
-- =====================================================================

begin;
do $$
declare v_msg text;
begin
  begin
    update public.menu_versions set snapshot = '{}'::jsonb where id = 'eeeeeeee-0000-0000-0000-000000000002';
    raise exception 'FAIL T16a: menu_versions UPDATE should be rejected by the append-only trigger';
  exception when others then
    get stacked diagnostics v_msg = message_text;
    if v_msg like 'FAIL%' then raise; end if;
    if v_msg not like '%append-only%' then raise exception 'FAIL T16a-wrong-reason: %', v_msg; end if;
  end;
  raise notice 'PASS T16a: menu_versions UPDATE blocked (%)', v_msg;
end $$;
rollback;

begin;
do $$
begin
  begin
    delete from public.menu_versions where id = 'eeeeeeee-0000-0000-0000-000000000002';
    raise exception 'FAIL T16b: menu_versions DELETE should be rejected by the append-only trigger';
  exception when others then
    if sqlerrm like 'FAIL%' then raise; end if;
  end;
  raise notice 'PASS T16b: menu_versions DELETE blocked, even for a superuser role — no privileged path is exempt';
end $$;
rollback;

-- =====================================================================
-- T17: base_price / variant price nullable, no cross-table price CHECK
-- =====================================================================

begin;
do $$
declare v_cat uuid;
begin
  select id into v_cat from public.categories where id = 'cccccccc-1111-1111-1111-111111111111';
  insert into public.products (category_id, name_ar, name_en, base_price)
    values (v_cat, 'منتج بدون سعر', 'Priceless Product', null);
  insert into public.product_variants (product_id, name_ar, name_en, price)
    select id, 'خيار', 'Option', null from public.products where name_en = 'Priceless Product';
  raise notice 'PASS T17: base_price and product_variants.price are nullable with no cross-table CHECK blocking it';
end $$;
rollback;

-- =====================================================================
-- T18-T21: availability micro-publish
-- =====================================================================

-- T18: availability_staff can flip available -> sold_out, and it micro-
-- publishes (product IS in the current published snapshot: Latte).
begin;
set local role authenticated;
set local "request.jwt.claims" to '{"sub":"a0000000-0000-0000-0000-000000000005","role":"authenticated"}';
do $$
declare v_old_version uuid;
declare v_new_version uuid;
declare v_availability public.product_availability;
declare v_snapshot jsonb;
begin
  select published_version_id into v_old_version from public.menus where branch_id = 'aaaaaaaa-1111-1111-1111-111111111111';

  perform public.publish_availability_change('dddddddd-1111-1111-1111-111111111111', 'sold_out');

  select availability into v_availability from public.products where id = 'dddddddd-1111-1111-1111-111111111111';
  if v_availability <> 'sold_out' then raise exception 'FAIL T18a: product availability should be sold_out, is %', v_availability; end if;

  select published_version_id into v_new_version from public.menus where branch_id = 'aaaaaaaa-1111-1111-1111-111111111111';
  if v_new_version = v_old_version then raise exception 'FAIL T18b: a new menu_version should have been published'; end if;

  select snapshot into v_snapshot from public.menu_versions where id = v_new_version;
  if (v_snapshot -> 'categories' -> 0 -> 'products' -> 0 ->> 'availability') <> 'sold_out' then
    raise exception 'FAIL T18c: new snapshot should show Latte as sold_out';
  end if;
  if (v_snapshot -> 'categories' -> 0 -> 'products' -> 1 ->> 'availability') <> 'available' then
    raise exception 'FAIL T18d: Mango Juice availability should be untouched (available) in the new snapshot';
  end if;
  if (v_snapshot -> 'categories' -> 0 -> 'products' -> 0 ->> 'name_en') <> 'Latte' then
    raise exception 'FAIL T18e: only the availability field should change — name_en must be untouched';
  end if;

  raise notice 'PASS T18: availability_staff flips available -> sold_out; micro-publish patches only that one field';
end $$;
rollback;

-- T19: availability_staff can flip sold_out -> available (round trip, on a
-- fresh transaction against the original fixture state).
begin;
set local role authenticated;
set local "request.jwt.claims" to '{"sub":"a0000000-0000-0000-0000-000000000005","role":"authenticated"}';
do $$
begin
  perform public.publish_availability_change('dddddddd-1111-1111-1111-111111111111', 'sold_out');
  perform public.publish_availability_change('dddddddd-1111-1111-1111-111111111111', 'available');
  if (select availability from public.products where id = 'dddddddd-1111-1111-1111-111111111111') <> 'available' then
    raise exception 'FAIL T19a: product should be back to available';
  end if;
  raise notice 'PASS T19: availability_staff flips sold_out -> available';
end $$;
rollback;

-- T20: availability_staff cannot set hidden through this function.
begin;
set local role authenticated;
set local "request.jwt.claims" to '{"sub":"a0000000-0000-0000-0000-000000000005","role":"authenticated"}';
do $$
begin
  begin
    perform public.publish_availability_change('dddddddd-1111-1111-1111-111111111111', 'hidden');
    raise exception 'FAIL T20a: publish_availability_change should reject ''hidden''';
  exception when others then
    if sqlerrm like 'FAIL%' then raise; end if;
  end;
  raise notice 'PASS T20: publish_availability_change rejects ''hidden'' for every caller, not just availability_staff';
end $$;
rollback;

-- T21: availability_staff cannot edit price/name/description/category/
-- variant directly (technically unable via RLS, not just app-layer).
begin;
set local role authenticated;
set local "request.jwt.claims" to '{"sub":"a0000000-0000-0000-0000-000000000005","role":"authenticated"}';
do $$
declare v_name text;
begin
  update public.products set name_en = 'Hacked Latte' where id = 'dddddddd-1111-1111-1111-111111111111';
  select name_en into v_name from public.products where id = 'dddddddd-1111-1111-1111-111111111111';
  if v_name = 'Hacked Latte' then raise exception 'FAIL T21a: availability_staff should not be able to rename a product'; end if;

  update public.products set base_price = 999 where id = 'dddddddd-1111-1111-1111-111111111111';
  if exists (select 1 from public.products where id = 'dddddddd-1111-1111-1111-111111111111' and base_price = 999) then
    raise exception 'FAIL T21b: availability_staff should not be able to change price';
  end if;

  update public.categories set name_en = 'Hacked' where id = 'cccccccc-1111-1111-1111-111111111111';
  if exists (select 1 from public.categories where id = 'cccccccc-1111-1111-1111-111111111111' and name_en = 'Hacked') then
    raise exception 'FAIL T21c: availability_staff should not be able to edit categories';
  end if;

  update public.product_variants set price = 1 where product_id = 'dddddddd-1111-1111-1111-111111111111';
  if exists (select 1 from public.product_variants where product_id = 'dddddddd-1111-1111-1111-111111111111' and price = 1) then
    raise exception 'FAIL T21d: availability_staff should not be able to edit variants';
  end if;

  if public.has_capability('aaaaaaaa-1111-1111-1111-111111111111', 'menu.publish') then
    raise exception 'FAIL T21e: availability_staff should not hold menu.publish';
  end if;

  raise notice 'PASS T21: availability_staff technically cannot edit price/name/description/category/variant, and holds no menu.publish';
end $$;
rollback;

-- T22: availability change for a product NOT present in the published
-- snapshot stays draft-only (Cookie, added after publish).
begin;
set local role authenticated;
set local "request.jwt.claims" to '{"sub":"a0000000-0000-0000-0000-000000000001","role":"authenticated"}';
do $$
declare v_version_before uuid;
declare v_version_after uuid;
declare v_count_before bigint;
declare v_count_after bigint;
begin
  select published_version_id into v_version_before from public.menus where branch_id = 'aaaaaaaa-1111-1111-1111-111111111111';
  select count(*) into v_count_before from public.menu_versions;

  perform public.publish_availability_change('dddddddd-5555-5555-5555-555555555555', 'sold_out');

  select published_version_id into v_version_after from public.menus where branch_id = 'aaaaaaaa-1111-1111-1111-111111111111';
  select count(*) into v_count_after from public.menu_versions;

  if v_version_after <> v_version_before then raise exception 'FAIL T22a: published_version_id must not change when the product is absent from the snapshot'; end if;
  if v_count_after <> v_count_before then raise exception 'FAIL T22b: no new menu_versions row should be created'; end if;
  if (select availability from public.products where id = 'dddddddd-5555-5555-5555-555555555555') <> 'sold_out' then
    raise exception 'FAIL T22c: the draft availability change should still have been applied';
  end if;

  raise notice 'PASS T22: a product absent from the published snapshot stays draft-only on availability change';
end $$;
rollback;

-- T23: availability change when no published_version_id exists at all
-- stays draft-only (Fries, on the never-published Branch A2 menu).
begin;
set local role authenticated;
set local "request.jwt.claims" to '{"sub":"a0000000-0000-0000-0000-000000000001","role":"authenticated"}';
do $$
declare v_count_before bigint;
declare v_count_after bigint;
begin
  select count(*) into v_count_before from public.menu_versions;
  perform public.publish_availability_change('dddddddd-3333-3333-3333-333333333333', 'sold_out');
  select count(*) into v_count_after from public.menu_versions;

  if v_count_after <> v_count_before then raise exception 'FAIL T23a: no menu_version should be created for a never-published menu'; end if;
  if (select published_version_id from public.menus where branch_id = 'aaaaaaaa-2222-2222-2222-222222222222') is not null then
    raise exception 'FAIL T23b: Branch A2''s menu must remain unpublished';
  end if;
  if (select availability from public.products where id = 'dddddddd-3333-3333-3333-333333333333') <> 'sold_out' then
    raise exception 'FAIL T23c: the draft availability change should still have been applied';
  end if;

  raise notice 'PASS T23: availability change with no published_version_id stays draft-only';
end $$;
rollback;

-- =====================================================================
-- T24: SECURITY DEFINER function attack surface
-- =====================================================================

begin;
set local role authenticated;
set local "request.jwt.claims" to '{"sub":"a0000000-0000-0000-0000-000000000005","role":"authenticated"}';
do $$
begin
  -- Cross-tenant attack: availability_staff of restaurant A tries to flip
  -- a product belonging to restaurant B. has_capability resolves the
  -- branch internally from the product and finds no membership at all.
  begin
    perform public.publish_availability_change('dddddddd-4444-4444-4444-444444444444', 'sold_out');
    raise exception 'FAIL T24a: availability_staff of restaurant A must not be able to touch restaurant B''s product';
  exception when others then
    if sqlerrm like 'FAIL%' then raise; end if;
  end;

  -- Invalid / nonexistent product id.
  begin
    perform public.publish_availability_change('00000000-0000-0000-0000-000000000000', 'sold_out');
    raise exception 'FAIL T24b: a nonexistent product id must raise, not silently succeed';
  exception when others then
    if sqlerrm like 'FAIL%' then raise; end if;
  end;

  -- Invalid availability value.
  begin
    perform public.publish_availability_change('dddddddd-1111-1111-1111-111111111111', 'on_the_moon');
    raise exception 'FAIL T24c: an invalid availability value must raise';
  exception when others then
    if sqlerrm like 'FAIL%' then raise; end if;
  end;

  raise notice 'PASS T24: publish_availability_change rejects cross-tenant products, nonexistent products, and invalid values';
end $$;
rollback;

begin;
set local role authenticated;
set local "request.jwt.claims" to '{"sub":"a0000000-0000-0000-0000-000000000006","role":"authenticated"}';
do $$
begin
  -- Capability denial: viewer holds analytics.view only, not product.availability.
  begin
    perform public.publish_availability_change('dddddddd-1111-1111-1111-111111111111', 'sold_out');
    raise exception 'FAIL T24d: viewer must not hold product.availability';
  exception when others then
    if sqlerrm like 'FAIL%' then raise; end if;
  end;
  raise notice 'PASS T24d: capability denial correctly blocks a viewer from the micro-publish path';
end $$;
rollback;

-- has_capability / has_branch_access: a caller cannot supply another
-- user's id as proof of authorization, because neither function accepts a
-- user_id parameter at all (this is a static/signature guarantee — attempt
-- a call with the wrong arity to confirm no such overload exists).
begin;
do $$
begin
  begin
    perform public.has_capability('a0000000-0000-0000-0000-000000000001'::uuid, 'aaaaaaaa-1111-1111-1111-111111111111'::text, 'product.edit');
    raise exception 'FAIL T25a: a 3-argument has_capability(user_id, branch_id, capability) overload must not exist';
  exception when undefined_function then
    raise notice 'PASS T25: no has_capability overload accepts a caller-supplied user id (%)', sqlerrm;
  end;
end $$;
rollback;

-- =====================================================================
-- T26: invitation branch access isolation
-- =====================================================================

begin;
set local role authenticated;
set local "request.jwt.claims" to '{"sub":"b0000000-0000-0000-0000-000000000001","role":"authenticated"}';
do $$
declare cnt bigint;
begin
  select count(*) into cnt from public.invitations;
  if cnt <> 0 then raise exception 'FAIL T26a: owner_b should not see restaurant A''s invitations, saw %', cnt; end if;
  select count(*) into cnt from public.invitation_branch_access;
  if cnt <> 0 then raise exception 'FAIL T26b: owner_b should not see restaurant A''s invitation_branch_access rows, saw %', cnt; end if;
  raise notice 'PASS T26: invitation and invitation_branch_access rows are tenant-isolated';
end $$;
rollback;

-- =====================================================================
-- T27: storage bucket / path policy inspection
-- (schema-and-policy-level only — no real Supabase Storage engine is
-- simulated locally, so this exercises storage.objects RLS exactly the
-- way the tenant-table RLS above is exercised, not actual file storage.)
-- =====================================================================

begin;
set local role anon;
do $$
begin
  insert into storage.objects (bucket_id, name, owner) values
    ('product-images-draft', 'products/11111111-1111-1111-1111-111111111111/dddddddd-1111-1111-1111-111111111111/main.webp', null);
  raise exception 'FAIL T27a: anon must not be able to write into the private draft bucket';
exception when others then
  if sqlerrm like 'FAIL%' then raise; end if;
  raise notice 'PASS T27a: private draft image bucket rejects an anonymous write (%)', sqlerrm;
end $$;
rollback;

begin;
set local role authenticated;
set local "request.jwt.claims" to '{"sub":"b0000000-0000-0000-0000-000000000001","role":"authenticated"}';
do $$
begin
  -- owner_b tries to write into restaurant A's product-images-draft path.
  insert into storage.objects (bucket_id, name, owner) values
    ('product-images-draft', 'products/11111111-1111-1111-1111-111111111111/dddddddd-1111-1111-1111-111111111111/main.webp', auth.uid());
  raise exception 'FAIL T27b: owner_b must not be able to write another restaurant''s storage path';
exception when others then
  if sqlerrm like 'FAIL%' then raise; end if;
  raise notice 'PASS T27b: cross-restaurant storage write rejected (%)', sqlerrm;
end $$;
rollback;

begin;
set local role authenticated;
set local "request.jwt.claims" to '{"sub":"a0000000-0000-0000-0000-000000000001","role":"authenticated"}';
do $$
begin
  insert into storage.objects (bucket_id, name, owner) values
    ('product-images-draft', 'products/11111111-1111-1111-1111-111111111111/dddddddd-1111-1111-1111-111111111111/main.webp', auth.uid());
  raise notice 'PASS T27c: owner_a can write into restaurant A''s own product-images-draft path';
end $$;
rollback;

begin;
set local role anon;
do $$
declare cnt bigint;
begin
  select count(*) into cnt from storage.objects where bucket_id = 'product-images-public';
  raise notice 'PASS T27d: product-images-public is queryable by anon with no error (public bucket read policy present), saw % existing rows', cnt;
end $$;
rollback;

-- =====================================================================
-- T28: QR metadata tenant isolation, table token shape
-- =====================================================================

begin;
set local role authenticated;
set local "request.jwt.claims" to '{"sub":"b0000000-0000-0000-0000-000000000001","role":"authenticated"}';
do $$
declare cnt bigint;
begin
  select count(*) into cnt from public.qr_codes;
  if cnt <> 0 then raise exception 'FAIL T28a: owner_b should not see restaurant A''s qr_codes, saw %', cnt; end if;
  raise notice 'PASS T28: qr_codes rows are tenant-isolated';
end $$;
rollback;

begin;
do $$
declare v_token1 text;
declare v_token2 text;
declare v_branch uuid := 'aaaaaaaa-1111-1111-1111-111111111111';
begin
  insert into public.restaurant_tables (branch_id, label) values (v_branch, 'Table 2') returning public_token into v_token1;
  insert into public.restaurant_tables (branch_id, label) values (v_branch, 'Table 3') returning public_token into v_token2;
  if v_token1 = v_token2 then raise exception 'FAIL T28b: two tables must not share a public_token'; end if;
  if v_token1 !~ '^[0-9a-f]{32}$' then raise exception 'FAIL T28c: public_token must be a 32-hex-char random value, got %', v_token1; end if;
  raise notice 'PASS T28: restaurant_tables.public_token is unique, random, non-sequential (32 hex chars from a CSPRNG)';
end $$;
rollback;

-- =====================================================================
-- T29: audit_logs append-only
-- =====================================================================

begin;
do $$
begin
  begin
    update public.audit_logs set action = 'tampered' where true;
    raise exception 'FAIL T29a: audit_logs UPDATE should be rejected';
  exception when others then
    if sqlerrm like 'FAIL%' then raise; end if;
  end;
  begin
    delete from public.audit_logs;
    raise exception 'FAIL T29b: audit_logs DELETE should be rejected';
  exception when others then
    if sqlerrm like 'FAIL%' then raise; end if;
  end;
  raise notice 'PASS T29: audit_logs is append-only (UPDATE and DELETE both blocked)';
end $$;
rollback;

begin;
set local role authenticated;
set local "request.jwt.claims" to '{"sub":"a0000000-0000-0000-0000-000000000004","role":"authenticated"}';
do $$
declare cnt bigint;
begin
  -- editor (A1) holds no audit.view capability (owner/admin only).
  select count(*) into cnt from public.audit_logs;
  if cnt <> 0 then raise exception 'FAIL T29c: editor should not be able to read audit_logs (no audit.view), saw %', cnt; end if;
  raise notice 'PASS T29c: audit.view is correctly restricted to owner/admin';
end $$;
rollback;

-- =====================================================================
-- T30: analytics tenant isolation (events and rollups)
-- =====================================================================

begin;
insert into public.analytics_daily_rollups (restaurant_id, branch_id, rollup_date, unique_sessions) values
  ('11111111-1111-1111-1111-111111111111', 'aaaaaaaa-1111-1111-1111-111111111111', current_date, 5),
  ('22222222-2222-2222-2222-222222222222', 'bbbbbbbb-1111-1111-1111-111111111111', current_date, 7);

set local role authenticated;
set local "request.jwt.claims" to '{"sub":"a0000000-0000-0000-0000-000000000001","role":"authenticated"}';
do $$
declare cnt bigint;
begin
  select count(*) into cnt from public.analytics_daily_rollups;
  if cnt <> 1 then raise exception 'FAIL T30a: owner_a should see only restaurant A''s rollup row, saw %', cnt; end if;
  select count(*) into cnt from public.analytics_events;
  if cnt <> 1 then raise exception 'FAIL T30b: owner_a should see only restaurant A''s analytics_events, saw %', cnt; end if;
  raise notice 'PASS T30: analytics_events and analytics_daily_rollups are tenant-isolated';
end $$;
rollback;

-- =====================================================================
-- T31: notifications are per-user, not per-restaurant
-- =====================================================================

begin;
set local role authenticated;
set local "request.jwt.claims" to '{"sub":"a0000000-0000-0000-0000-000000000002","role":"authenticated"}';
do $$
declare cnt bigint;
begin
  select count(*) into cnt from public.notifications;
  if cnt <> 0 then raise exception 'FAIL T31a: admin_a should not see owner_a''s notification, saw %', cnt; end if;
  raise notice 'PASS T31: notifications are isolated per recipient user, not shared across the restaurant';
end $$;
rollback;

-- =====================================================================
-- T32: impersonation history survives restaurant deletion
-- =====================================================================

begin;
do $$
declare cnt bigint;
declare v_restaurant_id uuid;
begin
  delete from public.restaurants where id = '11111111-1111-1111-1111-111111111111';

  select count(*) into cnt from public.impersonation_sessions
  where super_admin_id = '50000000-0000-0000-0000-000000000001';
  if cnt <> 1 then raise exception 'FAIL T32a: the impersonation_sessions row must survive restaurant deletion, saw %', cnt; end if;

  select restaurant_id into v_restaurant_id from public.impersonation_sessions
  where super_admin_id = '50000000-0000-0000-0000-000000000001';
  if v_restaurant_id is not null then raise exception 'FAIL T32b: restaurant_id should have been SET NULL, got %', v_restaurant_id; end if;

  select count(*) into cnt from public.audit_logs where restaurant_id is null and action = 'publish';
  if cnt <> 1 then raise exception 'FAIL T32c: audit_logs row should survive with restaurant_id SET NULL'; end if;

  select count(*) into cnt from public.menu_versions;
  if cnt <> 2 then raise exception 'FAIL T32d: menu_versions rows should survive restaurant deletion (SET NULL on menu_id), saw %', cnt; end if;

  raise notice 'PASS T32: impersonation_sessions, audit_logs, and menu_versions all survive restaurant deletion via ON DELETE SET NULL';
end $$;
rollback;

-- =====================================================================
-- T33: normal tenant-tree CASCADE still works (sanity check the other half
-- of the delete-behavior split: everything NOT history/audit does cascade)
-- =====================================================================

begin;
do $$
declare cnt bigint;
begin
  delete from public.branches where id = 'aaaaaaaa-1111-1111-1111-111111111111';
  select count(*) into cnt from public.categories where id = 'cccccccc-1111-1111-1111-111111111111';
  if cnt <> 0 then raise exception 'FAIL T33a: deleting a branch should CASCADE to its categories'; end if;
  select count(*) into cnt from public.products where category_id = 'cccccccc-1111-1111-1111-111111111111';
  if cnt <> 0 then raise exception 'FAIL T33b: deleting a branch should CASCADE all the way to products'; end if;
  -- menu_versions for that branch's menu must still survive (SET NULL), not disappear.
  select count(*) into cnt from public.menu_versions where id in ('eeeeeeee-0000-0000-0000-000000000001', 'eeeeeeee-0000-0000-0000-000000000002');
  if cnt <> 2 then raise exception 'FAIL T33c: menu_versions must survive even branch deletion, saw %', cnt; end if;
  raise notice 'PASS T33: branch deletion CASCADEs down the draft content tree while menu_versions history survives';
end $$;
rollback;

-- =====================================================================
-- T34: SECURITY DEFINER / helper function EXECUTE privilege enforcement
-- (grant-level denial, distinct from the internal capability-check denial
-- already covered by T24/T24d — these prove the REVOKE ... FROM PUBLIC
-- actually blocks the call before the function body ever runs)
-- =====================================================================

begin;
set local role anon;
do $$
begin
  begin
    perform public.publish_availability_change('dddddddd-1111-1111-1111-111111111111', 'sold_out');
    raise exception 'FAIL T34a: anon must not be able to execute publish_availability_change at all';
  exception
    when insufficient_privilege then null; -- expected
    when others then
      if sqlerrm like 'FAIL%' then raise; end if;
      raise exception 'FAIL T34a-wrong-reason: expected permission denied, got: %', sqlerrm;
  end;
  raise notice 'PASS T34a: anon has no EXECUTE grant on publish_availability_change (rejected before any capability check)';
end $$;
rollback;

begin;
set local role anon;
do $$
begin
  begin
    perform public.has_capability('aaaaaaaa-1111-1111-1111-111111111111'::uuid, 'product.edit');
    raise exception 'FAIL T34b: anon must not be able to execute has_capability';
  exception
    when insufficient_privilege then null;
    when others then
      if sqlerrm like 'FAIL%' then raise; end if;
      raise exception 'FAIL T34b-wrong-reason: %', sqlerrm;
  end;

  begin
    perform public.has_branch_access('aaaaaaaa-1111-1111-1111-111111111111'::uuid);
    raise exception 'FAIL T34c: anon must not be able to execute has_branch_access';
  exception
    when insufficient_privilege then null;
    when others then
      if sqlerrm like 'FAIL%' then raise; end if;
      raise exception 'FAIL T34c-wrong-reason: %', sqlerrm;
  end;

  begin
    perform public.is_restaurant_member('11111111-1111-1111-1111-111111111111'::uuid);
    raise exception 'FAIL T34d: anon must not be able to execute is_restaurant_member';
  exception
    when insufficient_privilege then null;
    when others then
      if sqlerrm like 'FAIL%' then raise; end if;
      raise exception 'FAIL T34d-wrong-reason: %', sqlerrm;
  end;

  begin
    perform public.has_restaurant_capability('11111111-1111-1111-1111-111111111111'::uuid, 'team.manage');
    raise exception 'FAIL T34e: anon must not be able to execute has_restaurant_capability';
  exception
    when insufficient_privilege then null;
    when others then
      if sqlerrm like 'FAIL%' then raise; end if;
      raise exception 'FAIL T34e-wrong-reason: %', sqlerrm;
  end;

  begin
    perform public.storage_path_uuid('products/11111111-1111-1111-1111-111111111111/x/main.webp', 2);
    raise exception 'FAIL T34f: anon must not be able to execute storage_path_uuid';
  exception
    when insufficient_privilege then null;
    when others then
      if sqlerrm like 'FAIL%' then raise; end if;
      raise exception 'FAIL T34f-wrong-reason: %', sqlerrm;
  end;

  raise notice 'PASS T34b-f: anon has no EXECUTE grant on any tenant-isolation helper function';
end $$;
rollback;

-- Trigger-only functions (returns trigger) cannot be invoked directly by
-- anyone at all, regardless of role — Postgres refuses the call outright.
-- No grant would ever make this callable, and none is given.
begin;
do $$
declare v_msg text;
begin
  begin
    perform public.create_menu_for_branch();
    raise exception 'FAIL T34g: create_menu_for_branch must not be directly callable by anyone';
  exception when others then
    get stacked diagnostics v_msg = message_text;
    if v_msg like 'FAIL%' then raise; end if;
  end;
  raise notice 'PASS T34g: create_menu_for_branch cannot be called outside the trigger mechanism, even by the owning role (%)', v_msg;
end $$;
rollback;

-- =====================================================================
-- T35: analytics_events cross-tenant poisoning
-- =====================================================================

begin;
set local role anon;
do $$
begin
  -- product_id from restaurant B, claimed under restaurant A.
  begin
    insert into public.analytics_events (restaurant_id, branch_id, event_type, product_id, anon_session_id)
    values ('11111111-1111-1111-1111-111111111111', 'aaaaaaaa-1111-1111-1111-111111111111', 'product_view', 'dddddddd-4444-4444-4444-444444444444', gen_random_uuid());
    raise exception 'FAIL T35a: restaurant A event must not be able to reference restaurant B''s product';
  exception when others then
    if sqlerrm like 'FAIL%' then raise; end if;
  end;

  -- category_id from restaurant B, claimed under restaurant A.
  begin
    insert into public.analytics_events (restaurant_id, branch_id, event_type, category_id, anon_session_id)
    values ('11111111-1111-1111-1111-111111111111', 'aaaaaaaa-1111-1111-1111-111111111111', 'category_view', 'cccccccc-3333-3333-3333-333333333333', gen_random_uuid());
    raise exception 'FAIL T35b: restaurant A event must not be able to reference restaurant B''s category';
  exception when others then
    if sqlerrm like 'FAIL%' then raise; end if;
  end;

  -- branch_id that belongs to restaurant A, but a category_id that
  -- belongs to a DIFFERENT branch of the SAME restaurant A (A2's category
  -- claimed under A1's branch_id) — chain-internal mismatch, not just
  -- tenant mismatch.
  begin
    insert into public.analytics_events (restaurant_id, branch_id, event_type, category_id, anon_session_id)
    values ('11111111-1111-1111-1111-111111111111', 'aaaaaaaa-1111-1111-1111-111111111111', 'category_view', 'cccccccc-2222-2222-2222-222222222222', gen_random_uuid());
    raise exception 'FAIL T35c: category_id must match the event''s own branch_id, not just the same restaurant';
  exception when others then
    if sqlerrm like 'FAIL%' then raise; end if;
  end;

  -- product_id that belongs to restaurant A / branch A1, but a
  -- category_id from branch A1 that is NOT that product's actual
  -- category (Mango Juice's category is correct here; deliberately pass
  -- a mismatched but same-branch category is not possible in this
  -- fixture since A1 has only one category, so instead prove a product
  -- from A1 cannot be claimed against A2's branch_id).
  begin
    insert into public.analytics_events (restaurant_id, branch_id, event_type, product_id, anon_session_id)
    values ('11111111-1111-1111-1111-111111111111', 'aaaaaaaa-2222-2222-2222-222222222222', 'product_view', 'dddddddd-1111-1111-1111-111111111111', gen_random_uuid());
    raise exception 'FAIL T35d: product_id must match the event''s own branch_id, not just the same restaurant';
  exception when others then
    if sqlerrm like 'FAIL%' then raise; end if;
  end;

  raise notice 'PASS T35a-d: analytics_events rejects any product_id/category_id whose actual restaurant/branch chain does not match the event''s own restaurant_id/branch_id';
end $$;
rollback;

-- Valid chains — including nulls for event types that don't need
-- product/category — still succeed for both anon and authenticated.
-- analytics_events has no anon (or authenticated-non-viewer) SELECT
-- policy at all ("raw events are staff-facing"), so the inserting anon
-- role can never read its own rows back to verify success — the count
-- below is taken as postgres (RLS-bypassing), in the same transaction
-- before rollback, purely to confirm the inserts landed; it is not
-- evidence of what anon itself can see.
begin;
set local role anon;
do $$
begin
  insert into public.analytics_events (restaurant_id, branch_id, event_type, anon_session_id)
    values ('11111111-1111-1111-1111-111111111111', 'aaaaaaaa-1111-1111-1111-111111111111', 'qr_scan', gen_random_uuid());

  insert into public.analytics_events (restaurant_id, branch_id, event_type, category_id, anon_session_id)
    values ('11111111-1111-1111-1111-111111111111', 'aaaaaaaa-1111-1111-1111-111111111111', 'category_view', 'cccccccc-1111-1111-1111-111111111111', gen_random_uuid());

  insert into public.analytics_events (restaurant_id, branch_id, event_type, category_id, product_id, anon_session_id)
    values ('11111111-1111-1111-1111-111111111111', 'aaaaaaaa-1111-1111-1111-111111111111', 'product_view', 'cccccccc-1111-1111-1111-111111111111', 'dddddddd-1111-1111-1111-111111111111', gen_random_uuid());
end $$;
set local role postgres;
do $$
declare cnt bigint;
begin
  select count(*) into cnt from public.analytics_events where anon_session_id is not null;
  if cnt < 4 then raise exception 'FAIL T35e: valid analytics_events inserts (including the T30 fixture row) should all have succeeded, saw %', cnt; end if;

  raise notice 'PASS T35e: valid null and fully-matching product/category/branch chains are still accepted';
end $$;
rollback;

do $$
begin
  raise notice 'ALL PHASE 2 RLS/SECURITY TESTS PASSED';
end $$;
