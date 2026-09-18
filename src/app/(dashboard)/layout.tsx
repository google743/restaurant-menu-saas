import type { ReactNode } from "react";

/**
 * Route group: (dashboard)
 * -----------------------------------------------------------------------
 * Authenticated business/owner surface. No URL segment of its own; routes
 * declare their own path (e.g. `(dashboard)/dashboard/page.tsx` -> `/dashboard`).
 *
 * Phase 1 scope: layout shell only. No auth guard, no session check, no
 * dashboard features yet — those land once authentication is implemented.
 */
export default function DashboardLayout({ children }: { children: ReactNode }) {
  return <div className="flex flex-1 flex-col">{children}</div>;
}
