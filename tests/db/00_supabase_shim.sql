-- Minimal Supabase-equivalent shim for local RLS testing.
-- NOT part of supabase/migrations — a real Supabase project already
-- provides all of this (auth schema, storage schema, anon/authenticated
-- roles, default grants). This file exists only so the Phase 2
-- migrations can be applied and tested against a plain local Postgres 16
-- in this sandbox.

create schema if not exists auth;
create schema if not exists storage;

create table auth.users (
  id uuid primary key default gen_random_uuid(),
  email text unique
);

create or replace function auth.uid() returns uuid
language sql stable
as $$
  select nullif(current_setting('request.jwt.claims', true)::json->>'sub', '')::uuid
$$;

create or replace function auth.jwt() returns jsonb
language sql stable
as $$
  select coalesce(nullif(current_setting('request.jwt.claims', true), ''), '{}')::jsonb
$$;

create or replace function auth.role() returns text
language sql stable
as $$
  select coalesce(current_setting('request.jwt.claims', true)::json->>'role', '')::text
$$;

create table storage.buckets (
  id text primary key,
  name text not null,
  public boolean not null default false
);

create table storage.objects (
  id uuid primary key default gen_random_uuid(),
  bucket_id text references storage.buckets (id),
  name text,
  owner uuid,
  created_at timestamptz not null default now()
);

create or replace function storage.foldername(name text) returns text[]
language sql immutable
as $$
  select (string_to_array(name, '/'))[1 : array_length(string_to_array(name, '/'), 1) - 1];
$$;

-- A real Supabase project has RLS already enabled (and forced) on
-- storage.objects/buckets by the platform itself; migrations only add
-- policies to it. Replicate that here so the storage policies created in
-- migration 13 actually take effect against this local shim.
alter table storage.objects enable row level security;
alter table storage.objects force row level security;
alter table storage.buckets enable row level security;

do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'anon') then
    create role anon nologin noinherit;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then
    create role authenticated nologin noinherit;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'service_role') then
    create role service_role nologin noinherit bypassrls;
  end if;
end
$$;

grant usage on schema public to anon, authenticated;
grant usage on schema auth to anon, authenticated;
grant usage on schema storage to anon, authenticated;

alter default privileges in schema public grant select, insert, update, delete on tables to anon, authenticated;
alter default privileges in schema storage grant select, insert, update, delete on tables to anon, authenticated;

-- storage.buckets/objects already exist above, so the ALTER DEFAULT
-- PRIVILEGES calls (which only apply to tables created *after* them) don't
-- cover them — grant directly, same as a real Supabase project does.
grant select, insert, update, delete on storage.buckets to anon, authenticated;
grant select, insert, update, delete on storage.objects to anon, authenticated;
