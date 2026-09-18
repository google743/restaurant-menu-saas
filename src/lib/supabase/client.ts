import { createBrowserClient } from "@supabase/ssr";

import { getClientEnv } from "@/lib/validation/env";

/**
 * lib/supabase (browser)
 * -----------------------------------------------------------------------
 * Returns a Supabase client for use in Client Components ("use client").
 * Only ever sees the public URL and anon key — never the service role
 * key, which lives in `getServerEnv()` and must stay server-only.
 *
 * Phase 1 scope: connection wiring only. No auth flows, session
 * handling, or RLS-dependent calls are implemented here.
 */
export function createClient() {
  const { NEXT_PUBLIC_SUPABASE_URL, NEXT_PUBLIC_SUPABASE_ANON_KEY } = getClientEnv();

  return createBrowserClient(NEXT_PUBLIC_SUPABASE_URL, NEXT_PUBLIC_SUPABASE_ANON_KEY);
}
