import { cookies } from "next/headers";
import { createServerClient } from "@supabase/ssr";

import { getClientEnv } from "@/lib/validation/env";

/**
 * lib/supabase (server)
 * -----------------------------------------------------------------------
 * Returns a Supabase client for use in Server Components, Server
 * Actions, and Route Handlers. Reads/writes the Supabase auth cookies
 * via `next/headers`.
 *
 * Phase 1 scope: connection wiring only. No sign-in, sign-out, or
 * session refresh logic lives here — that belongs to the auth phase,
 * alongside `proxy.ts` (Next.js 16's renamed `middleware.ts`) for
 * session refresh on navigation.
 *
 * Always call this per-request; never share a client across requests.
 */
export async function createClient() {
  const cookieStore = await cookies();
  const { NEXT_PUBLIC_SUPABASE_URL, NEXT_PUBLIC_SUPABASE_ANON_KEY } = getClientEnv();

  return createServerClient(NEXT_PUBLIC_SUPABASE_URL, NEXT_PUBLIC_SUPABASE_ANON_KEY, {
    cookies: {
      getAll() {
        return cookieStore.getAll();
      },
      setAll(cookiesToSet) {
        try {
          cookiesToSet.forEach(({ name, value, options }) => cookieStore.set(name, value, options));
        } catch {
          // Called from a Server Component that can't set cookies.
          // Safe to ignore once `proxy.ts` is refreshing sessions
          // (added in the auth phase).
        }
      },
    },
  });
}
