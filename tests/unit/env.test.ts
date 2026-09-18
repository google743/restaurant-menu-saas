import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { getClientEnv, getServerEnv } from "@/lib/validation/env";

/**
 * Exercises the env-safety boundary itself: validated env access should
 * reject missing/invalid values and accept well-formed ones, and the
 * client/server schemas should stay independent of each other.
 */
describe("lib/validation/env", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  it("rejects a missing NEXT_PUBLIC_SUPABASE_URL", () => {
    delete process.env.NEXT_PUBLIC_SUPABASE_URL;
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY = "anon-key";

    expect(() => getClientEnv()).toThrow();
  });

  it("rejects a malformed NEXT_PUBLIC_SUPABASE_URL", () => {
    process.env.NEXT_PUBLIC_SUPABASE_URL = "not-a-url";
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY = "anon-key";

    expect(() => getClientEnv()).toThrow();
  });

  it("parses valid client env and defaults NEXT_PUBLIC_SITE_URL", () => {
    process.env.NEXT_PUBLIC_SUPABASE_URL = "https://example.supabase.co";
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY = "anon-key";
    delete process.env.NEXT_PUBLIC_SITE_URL;

    const env = getClientEnv();

    expect(env.NEXT_PUBLIC_SUPABASE_URL).toBe("https://example.supabase.co");
    expect(env.NEXT_PUBLIC_SITE_URL).toBe("http://localhost:3000");
  });

  it("rejects a missing SUPABASE_SERVICE_ROLE_KEY", () => {
    delete process.env.SUPABASE_SERVICE_ROLE_KEY;

    expect(() => getServerEnv()).toThrow();
  });

  it("parses valid server env and treats AI_PROVIDER_API_KEY as optional", () => {
    process.env.SUPABASE_SERVICE_ROLE_KEY = "service-role-key";
    delete process.env.AI_PROVIDER_API_KEY;

    const env = getServerEnv();

    expect(env.SUPABASE_SERVICE_ROLE_KEY).toBe("service-role-key");
    expect(env.AI_PROVIDER_API_KEY).toBeUndefined();
  });
});
