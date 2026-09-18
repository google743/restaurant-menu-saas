import type { ReactNode } from "react";

/**
 * Route group: (public)
 * -----------------------------------------------------------------------
 * Unauthenticated, public-facing surface (marketing pages, public menu
 * pages, etc). No URL segment of its own — routes live at their normal
 * paths (e.g. `/`).
 *
 * Phase 1 scope: layout shell only. No public-facing features yet.
 */
export default function PublicLayout({ children }: { children: ReactNode }) {
  return <div className="flex flex-1 flex-col">{children}</div>;
}
