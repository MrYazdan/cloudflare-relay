import { env, fetchMock } from "cloudflare:test";
import { beforeAll, afterEach, describe, it, expect, vi } from "vitest";
import { importKey, seal } from "../src/crypto.ts";
import { processMessage } from "../src/queue.ts";
import type { Config } from "../src/config.ts";
import type { QueueJob } from "../src/jobs.ts";
import { PROTOCOL_VERSION } from "../src/protocol.ts";

const enc = new TextEncoder();
let key: CryptoKey;

beforeAll(async () => {
  key = await importKey(env.SHARED_KEY);
});

beforeAll(() => {
  fetchMock.activate();
  fetchMock.disableNetConnect();
});

afterEach(() => fetchMock.assertNoPendingInterceptors());

function makeConfig(overrides: Partial<Config["rate"]> = {}): Config {
  return {
    allowedHosts: new Set(["api.telegram.org"]),
    allowAllHosts: false,
    maxClockSkewSeconds: 300,
    maxBodyBytes: 5 * 1024 * 1024,
    upstreamTimeoutMs: 20_000,
    rateLimiter: env.RATE_LIMITER,
    rate: {
      capacity: 1000,
      refillPerSecond: 1000,
      globalEnabled: false,
      globalCapacity: 1000,
      globalRefillPerSecond: 1000,
      ...overrides,
    },
    retry: { baseDelaySeconds: 2, maxDelaySeconds: 900 },
  };
}

async function makeJob(rateKey: string): Promise<QueueJob> {
  const descriptor = {
    v: PROTOCOL_VERSION,
    ts: Math.floor(Date.now() / 1000),
    nonce: crypto.randomUUID(),
    method: "POST",
    url: "https://api.telegram.org/bot123/sendMessage",
    headers: { "content-type": "application/json" },
  };
  return {
    id: crypto.randomUUID(),
    envelope: await seal(key, enc.encode(JSON.stringify(descriptor))),
    rateKey,
    enqueuedAt: Math.floor(Date.now() / 1000),
  };
}

function makeMessage(job: QueueJob, attempts = 1): Message<QueueJob> {
  return {
    id: job.id,
    timestamp: new Date(),
    body: job,
    attempts,
    ack: vi.fn(),
    retry: vi.fn(),
  } as unknown as Message<QueueJob>;
}

function interceptSendMessage(status: number, body = "{}", headers: Record<string, string> = {}) {
  fetchMock
    .get("https://api.telegram.org")
    .intercept({ path: "/bot123/sendMessage", method: "POST" })
    .reply(status, body, { headers });
}

describe("processMessage", () => {
  it("acks on a successful forward (200)", async () => {
    interceptSendMessage(200, JSON.stringify({ ok: true }));
    const msg = makeMessage(await makeJob(`k-${crypto.randomUUID()}`));
    await processMessage(msg, makeConfig(), key);
    expect(msg.ack).toHaveBeenCalledOnce();
    expect(msg.retry).not.toHaveBeenCalled();
  });

  it("acks on a permanent client error (400)", async () => {
    interceptSendMessage(400, JSON.stringify({ ok: false }));
    const msg = makeMessage(await makeJob(`k-${crypto.randomUUID()}`));
    await processMessage(msg, makeConfig(), key);
    expect(msg.ack).toHaveBeenCalledOnce();
    expect(msg.retry).not.toHaveBeenCalled();
  });

  it("retries on a server error (500) with a backoff delay", async () => {
    interceptSendMessage(500, "boom");
    const msg = makeMessage(await makeJob(`k-${crypto.randomUUID()}`));
    await processMessage(msg, makeConfig(), key);
    expect(msg.retry).toHaveBeenCalledOnce();
    const arg = (msg.retry as ReturnType<typeof vi.fn>).mock.calls[0]?.[0] as
      | { delaySeconds: number }
      | undefined;
    expect(arg?.delaySeconds).toBeGreaterThanOrEqual(1);
    expect(msg.ack).not.toHaveBeenCalled();
  });

  it("retries on 429 honoring Retry-After", async () => {
    interceptSendMessage(429, JSON.stringify({ ok: false }), { "retry-after": "7" });
    const msg = makeMessage(await makeJob(`k-${crypto.randomUUID()}`));
    await processMessage(msg, makeConfig(), key);
    expect(msg.retry).toHaveBeenCalledWith({ delaySeconds: 7 });
  });

  it("retries without forwarding when rate-limited", async () => {
    const config = makeConfig({ capacity: 1, refillPerSecond: 0.0001 });
    const rateKey = `drain-${crypto.randomUUID()}`;

    interceptSendMessage(200);
    const first = makeMessage(await makeJob(rateKey));
    await processMessage(first, config, key);
    expect(first.ack).toHaveBeenCalledOnce();

    const second = makeMessage(await makeJob(rateKey));
    await processMessage(second, config, key);
    expect(second.retry).toHaveBeenCalledOnce();
    expect(second.ack).not.toHaveBeenCalled();
  });
});
