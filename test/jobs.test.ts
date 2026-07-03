import { describe, it, expect } from "vitest";
import { buildJob, resolveRateKey } from "../src/jobs.ts";
import { PROTOCOL_VERSION, type ForwardRequest } from "../src/protocol.ts";

function req(overrides: Partial<ForwardRequest> = {}): ForwardRequest {
  return {
    v: PROTOCOL_VERSION,
    ts: 1_700_000_000,
    nonce: "n",
    method: "POST",
    url: "https://api.telegram.org/bot123/sendMessage",
    ...overrides,
  };
}

describe("resolveRateKey", () => {
  it("uses the explicit rate_key when provided", () => {
    expect(resolveRateKey(req({ rate_key: "chat-42" }))).toBe("chat-42");
  });

  it("falls back to the destination host", () => {
    expect(resolveRateKey(req())).toBe("api.telegram.org");
  });

  it("ignores a blank rate_key", () => {
    expect(resolveRateKey(req({ rate_key: "   " }))).toBe("api.telegram.org");
  });
});

describe("buildJob", () => {
  it("builds a job with injected id and clock", () => {
    const job = buildJob(req({ rate_key: "k" }), "ENVELOPE", "id-1", 5_000);
    expect(job).toEqual({
      id: "id-1",
      envelope: "ENVELOPE",
      rateKey: "k",
      enqueuedAt: 5,
    });
  });
});
