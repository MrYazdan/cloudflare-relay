import { describe, it, expect } from "vitest";
import {
  classifyStatus,
  parseRetryAfterMs,
  backoffDelayMs,
  toDelaySeconds,
} from "../src/retry.ts";

describe("classifyStatus", () => {
  it("acks success and client errors (except 429)", () => {
    for (const status of [200, 201, 204, 301, 400, 401, 403, 404, 413]) {
      expect(classifyStatus(status)).toBe("ack");
    }
  });

  it("retries 429 and 5xx", () => {
    for (const status of [429, 500, 502, 503, 504]) {
      expect(classifyStatus(status)).toBe("retry");
    }
  });
});

describe("parseRetryAfterMs", () => {
  it("parses Retry-After as seconds", () => {
    expect(parseRetryAfterMs("12")).toBe(12_000);
  });

  it("parses Retry-After as an HTTP-date relative to now", () => {
    const now = 1_000_000;
    const date = new Date(now + 5_000).toUTCString();
    expect(parseRetryAfterMs(date, undefined, now)).toBe(5_000);
  });

  it("parses Telegram's parameters.retry_after from the body", () => {
    const body = JSON.stringify({ ok: false, parameters: { retry_after: 7 } });
    expect(parseRetryAfterMs(null, body)).toBe(7_000);
  });

  it("returns undefined when no hint is present", () => {
    expect(parseRetryAfterMs(null, "not json")).toBeUndefined();
    expect(parseRetryAfterMs(undefined)).toBeUndefined();
  });
});

describe("backoffDelayMs", () => {
  it("grows exponentially and is capped", () => {
    const max = () => 1;
    expect(backoffDelayMs(1, 2, 900, max)).toBe(2_000);
    expect(backoffDelayMs(2, 2, 900, max)).toBe(4_000);
    expect(backoffDelayMs(3, 2, 900, max)).toBe(8_000);
    expect(backoffDelayMs(20, 2, 900, max)).toBe(900_000);
  });

  it("never returns less than half the capped delay (equal jitter)", () => {
    const min = () => 0;
    expect(backoffDelayMs(3, 2, 900, min)).toBe(4_000); // half of 8s
  });

  it("stays within [half, capped] for random rng", () => {
    for (let i = 0; i < 100; i++) {
      const ms = backoffDelayMs(4, 2, 900); // capped = 16s
      expect(ms).toBeGreaterThanOrEqual(8_000);
      expect(ms).toBeLessThanOrEqual(16_000);
    }
  });
});

describe("toDelaySeconds", () => {
  it("rounds up to whole seconds with a minimum of 1", () => {
    expect(toDelaySeconds(0)).toBe(1);
    expect(toDelaySeconds(1)).toBe(1);
    expect(toDelaySeconds(1_001)).toBe(2);
    expect(toDelaySeconds(5_000)).toBe(5);
  });
});
