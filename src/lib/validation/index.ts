/**
 * lib/validation
 * -----------------------------------------------------------------------
 * Boundary for schema validation: form input, API/route handler payloads,
 * webhook bodies, and (as prepared in Phase 1) environment variables.
 *
 * Phase 1 scope: env validation only (`./env`). Request/form schemas are
 * added alongside the features that need them.
 */
export * from "./env";
