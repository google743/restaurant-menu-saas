# menu

Repository foundation — **Phase 1**. This is scaffolding only: project
structure, route groups, module boundaries, and tooling. No auth, no
database schema, no RLS, no business logic, no ordering/payments/
subscriptions yet. Those land in later, separately approved phases.

## Stack

- [Next.js 16](https://nextjs.org/docs) (App Router, Turbopack by default)
- TypeScript (strict)
- Tailwind CSS v4
- Supabase (`@supabase/supabase-js`, `@supabase/ssr`) — client wiring only
- Zod — env validation now, request/form validation later
- Vitest + Testing Library — unit/integration tests
- ESLint + Prettier (with `prettier-plugin-tailwindcss`)

## Prerequisites

- Node.js **20.9+** (Next.js 16 minimum; this repo was scaffolded on
  Node 22)
- npm (this repo uses `package-lock.json`)

## Local setup

```bash
npm install
cp .env.example .env.local
# fill in .env.local with real Supabase project values
npm run dev
```

The app runs at http://localhost:3000. Every route currently renders a
placeholder page — see [Route groups](#route-groups) below.

## Available scripts

| Script                 | Purpose                            |
| ---------------------- | ---------------------------------- |
| `npm run dev`          | Start the dev server               |
| `npm run build`        | Production build                   |
| `npm run start`        | Run the production build           |
| `npm run lint`         | ESLint                             |
| `npm run lint:fix`     | ESLint with autofix                |
| `npm run typecheck`    | `tsc --noEmit`                     |
| `npm run format`       | Prettier, write mode               |
| `npm run format:check` | Prettier, check mode (CI-friendly) |
| `npm run test`         | Run tests once (Vitest)            |
| `npm run test:watch`   | Run tests in watch mode            |

## Project structure

```
src/
  app/
    (public)/       "/"           — unauthenticated, public-facing pages
    (dashboard)/     "/dashboard"  — authenticated business/owner surface
    (admin)/         "/admin"      — internal/administrative surface
    (auth)/          "/login"      — sign-in/sign-up/password-reset
  components/
    ui/              shared design-system primitives
    public/, dashboard/, admin/    route-group-specific components
    shared/          cross-cutting components too specific for ui/
  lib/
    public/, dashboard/, admin/    route-group-specific data access
    auth/            authentication & authorization (empty — Phase 1 excludes auth)
    ai/              AI-assisted features (empty — no provider chosen yet)
    qr/              QR code generation (empty — no library installed yet)
    validation/       schema validation; ships with env.ts (see below)
    supabase/        Supabase client construction (client.ts, server.ts)
supabase/
  migrations/        SQL migrations (empty — schema is a later phase)
tests/
  unit/, integration/  Vitest — `npm test`
  e2e/                 structure only; Playwright deferred
```

Each `lib/*` folder is a **module boundary**: code for the `(dashboard)`
route group belongs in `lib/dashboard`, not scattered across `app/`.
Route groups (the parenthesized folders) don't add a URL segment — each
one currently contains one real path, listed above.

## Environment variables

See `.env.example` for the full list and comments on which are public
(`NEXT_PUBLIC_*`, safe in the browser bundle) vs. server-only secrets.

`src/lib/validation/env.ts` provides `getClientEnv()` and
`getServerEnv()` — validated, typed access instead of raw
`process.env.FOO!` casts. `getServerEnv()` must never be imported from
client code; `getClientEnv()` is safe everywhere. Both parse lazily (on
call, not on import), so simply importing the module doesn't throw when
env vars aren't set yet.

## Known limitations (intentional, Phase 1 scope)

- No authentication: `lib/auth` and the `(auth)` route group are empty
  shells. No `proxy.ts` (Next.js 16's renamed `middleware.ts`) for
  session refresh yet.
- No database schema or RLS: `supabase/migrations/` is empty.
- No business logic, ordering, payments, or subscriptions.
- No UI beyond placeholder pages per route group.
- `tests/e2e/` has no runner wired up yet (Playwright planned, not
  installed).
- `lib/ai` and `lib/qr` have no dependency installed — boundary only.

## Next.js 16 note for contributors

This project was scaffolded on Next.js 16, which renamed `middleware.ts`
to `proxy.ts` (`export function proxy`) among other changes. See
`node_modules/next/dist/docs/` (bundled with the installed version) for
version-matched documentation before assuming APIs from older Next.js
knowledge.
