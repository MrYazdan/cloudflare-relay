import { env } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import {
  takeFromBucket,
  takeToken,
  type BucketState,
} from "../src/ratelimiter.ts";

describe("takeFromBucket (pure)", () => {
  const params = { capacity: 3, refillPerSecond: 1 };

  it("starts full and allows the first burst up to capacity", () => {
    let state: BucketState | undefined;
    const now = 1_000;
    for (let i = 0; i < 3; i++) {
      const r = takeFromBucket(state, params, now);
      expect(r.allowed).toBe(true);
      state = r.state;
    }

    const denied = takeFromBucket(state, params, now);
    expect(denied.allowed).toBe(false);
    expect(denied.retryAfterMs).toBeGreaterThan(0);
  });

  it("reports a correct retryAfterMs when empty", () => {
    const empty: BucketState = { tokens: 0, lastRefillMs: 5_000 };
    const r = takeFromBucket(empty, params, 5_000);
    expect(r.allowed).toBe(false);
    expect(r.retryAfterMs).toBe(1_000);
  });

  it("refills over elapsed time and allows again", () => {
    const empty: BucketState = { tokens: 0, lastRefillMs: 0 };
    const r = takeFromBucket(empty, params, 2_000);
    expect(r.allowed).toBe(true);
    expect(r.state.tokens).toBeCloseTo(1, 5); // 2 refilled - 1 consumed
  });

  it("never accrues beyond capacity", () => {
    const empty: BucketState = { tokens: 0, lastRefillMs: 0 };
    const r = takeFromBucket(empty, params, 1_000_000);
    expect(r.state.tokens).toBeCloseTo(2, 5); // capped at 3, minus 1 consumed
  });

  it("returns a huge retry when refill is zero and bucket empty", () => {
    const r = takeFromBucket(
      { tokens: 0, lastRefillMs: 0 },
      { capacity: 1, refillPerSecond: 0 },
      0,
    );
    expect(r.allowed).toBe(false);
    expect(r.retryAfterMs).toBe(Number.MAX_SAFE_INTEGER);
  });
});

describe("takeToken (Durable Object)", () => {
  const params = { capacity: 2, refillPerSecond: 0.001 }; // effectively no refill

  it("allows up to capacity then denies for a key", async () => {
    const key = `test-key-${crypto.randomUUID()}`;
    expect((await takeToken(env.RATE_LIMITER, key, params)).allowed).toBe(true);
    expect((await takeToken(env.RATE_LIMITER, key, params)).allowed).toBe(true);
    const third = await takeToken(env.RATE_LIMITER, key, params);
    expect(third.allowed).toBe(false);
    expect(third.retryAfterMs).toBeGreaterThan(0);
  });

  it("keeps buckets independent per key", async () => {
    const a = `key-a-${crypto.randomUUID()}`;
    const b = `key-b-${crypto.randomUUID()}`;

    await takeToken(env.RATE_LIMITER, a, params);
    await takeToken(env.RATE_LIMITER, a, params);
    expect((await takeToken(env.RATE_LIMITER, a, params)).allowed).toBe(false);
    expect((await takeToken(env.RATE_LIMITER, b, params)).allowed).toBe(true);
  });
});
