import type { ReactNode } from "react";

/**
 * Route group: (admin)
 * -----------------------------------------------------------------------
 * Internal/administrative surface, separate from the tenant-facing
 * (dashboard) group. No URL segment of its own.
 *
 * Phase 1 scope: layout shell only. No auth guard, no admin features yet.
 */
export default function AdminLayout({ children }: { children: ReactNode }) {
  return <div className="flex flex-1 flex-col">{children}</div>;
}
