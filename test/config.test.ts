import { describe, it, expect } from "vitest";
import { parseConfig, ConfigError, type Env } from "../src/config.ts";

function baseEnv(overrides: Partial<Env> = {}): Env {
  return {
    SHARED_KEY: "not-checked-for-shape-here",
    ALLOWED_HOSTS: "api.telegram.org",
    ...overrides,
  };
}

describe("parseConfig allowlist", () => {
  it("parses a comma-separated allowlist (lower-cased, trimmed)", () => {
    const cfg = parseConfig(baseEnv({ ALLOWED_HOSTS: " API.telegram.org , Discord.com " }));
    expect(cfg.allowAllHosts).toBe(false);
    expect([...cfg.allowedHosts].sort()).toEqual(["api.telegram.org", "discord.com"]);
  });

  it('enables wildcard mode for ALLOWED_HOSTS="*"', () => {
    const cfg = parseConfig(baseEnv({ ALLOWED_HOSTS: "*" }));
    expect(cfg.allowAllHosts).toBe(true);
    expect(cfg.allowedHosts.size).toBe(0);
  });

  it("throws when the allowlist is empty and not wildcard", () => {
    expect(() => parseConfig(baseEnv({ ALLOWED_HOSTS: "" }))).toThrow(ConfigError);
  });

  it("throws when SHARED_KEY is missing", () => {
    expect(() => parseConfig(baseEnv({ SHARED_KEY: "" }))).toThrow(ConfigError);
  });
});
