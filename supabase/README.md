# supabase/

`migrations/` holds SQL migration files, applied in filename order (the
Supabase CLI convention: `<timestamp>_<description>.sql`).

Phase 1 scope: folder structure only. No schema, no tables, no RLS
policies yet — those are created in the database-schema phase.
