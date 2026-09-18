import { z } from "zod";

/**
 * Environment variable safety
 * -----------------------------------------------------------------------
 * Two schemas, deliberately separate:
 *
 * - `clientEnvSchema` — variables prefixed `NEXT_PUBLIC_`. These are
 *   inlined into the browser bundle by Next.js. Safe to import from
 *   client and server code alike.
 * - `serverEnvSchema` — server-only secrets (never `NEXT_PUBLIC_`). Never
 *   import `getServerEnv` from a "use client" component or any module it
 *   pulls in — doing so would leak a secret into the client bundle.
 *
 * Both are parsed lazily (on call, not on import) so importing this
 * module never throws just because `.env.local` hasn't been created yet
 * (e.g. during `next build` in CI before secrets are provisioned).
 */

const clientEnvSchema = z.object({
  NEXT_PUBLIC_SUPABASE_URL: z.string().url(),
  NEXT_PUBLIC_SUPABASE_ANON_KEY: z.string().min(1),
  NEXT_PUBLIC_SITE_URL: z.string().url().default("http://localhost:3000"),
});

const serverEnvSchema = z.object({
  SUPABASE_SERVICE_ROLE_KEY: z.string().min(1),
  AI_PROVIDER_API_KEY: z.string().min(1).optional(),
});

export type ClientEnv = z.infer<typeof clientEnvSchema>;
export type ServerEnv = z.infer<typeof serverEnvSchema>;

/** Validated public env. Safe for client and server code. */
export function getClientEnv(): ClientEnv {
  return clientEnvSchema.parse({
    NEXT_PUBLIC_SUPABASE_URL: process.env.NEXT_PUBLIC_SUPABASE_URL,
    NEXT_PUBLIC_SUPABASE_ANON_KEY: process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
    NEXT_PUBLIC_SITE_URL: process.env.NEXT_PUBLIC_SITE_URL,
  });
}

/**
 * Validated server-only env. Server code only — importing this from a
 * client component is a mistake, not a supported use case.
 */
export function getServerEnv(): ServerEnv {
  return serverEnvSchema.parse({
    SUPABASE_SERVICE_ROLE_KEY: process.env.SUPABASE_SERVICE_ROLE_KEY,
    AI_PROVIDER_API_KEY: process.env.AI_PROVIDER_API_KEY,
  });
}
