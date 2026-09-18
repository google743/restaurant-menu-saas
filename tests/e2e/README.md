# tests/e2e

End-to-end browser tests. Structure only in Phase 1 — no test runner is
wired up yet. Playwright is the intended choice; it's deferred rather
than installed now to avoid pulling in browser binaries before there's
any UI flow worth testing end-to-end.
