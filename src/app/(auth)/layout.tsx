import type { ReactNode } from "react";

/**
 * Route group: (auth)
 * -----------------------------------------------------------------------
 * Sign-in / sign-up / password-reset surface. No URL segment of its own.
 *
 * Phase 1 scope: layout shell only. No authentication logic — Supabase
 * auth flows, session cookies, and route protection are implemented in
 * the auth phase (alongside `proxy.ts`, Next.js 16's renamed
 * `middleware.ts`, for session refresh on navigation).
 */
export default function AuthLayout({ children }: { children: ReactNode }) {
  return <div className="flex flex-1 flex-col">{children}</div>;
}
