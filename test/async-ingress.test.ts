import { env, SELF } from "cloudflare:test";
import { beforeAll, describe, it, expect } from "vitest";
import { importKey, seal, bytesToBase64 } from "../src/crypto.ts";
import { PROTOCOL_VERSION } from "../src/protocol.ts";

const enc = new TextEncoder();
let key: CryptoKey;

beforeAll(async () => {
  key = await importKey(env.SHARED_KEY);
});

function baseRequest(overrides: Record<string, unknown> = {}) {
  return {
    v: PROTOCOL_VERSION,
    ts: Math.floor(Date.now() / 1000),
    nonce: crypto.randomUUID(),
    method: "POST",
    url: "https://api.telegram.org/bot123/sendMessage",
    headers: { "content-type": "application/json" },
    body_b64: bytesToBase64(enc.encode(JSON.stringify({ chat_id: 1, text: "hi" }))),
    ...overrides,
  };
}

async function sealRequest(descriptor: object): Promise<string> {
  return seal(key, enc.encode(JSON.stringify(descriptor)));
}

async function postAsync(body: string): Promise<Response> {
  return SELF.fetch("https://worker.local/async", { method: "POST", body });
}

describe("POST /async", () => {
  it("accepts a valid request and returns 202 with a job id", async () => {
    const res = await postAsync(await sealRequest(baseRequest()));
    expect(res.status).toBe(202);
    const json = (await res.json()) as { status: string; id: string };
    expect(json.status).toBe("accepted");
    expect(typeof json.id).toBe("string");
    expect(json.id.length).toBeGreaterThan(0);
  });

  it("supports a client-supplied rate_key", async () => {
    const res = await postAsync(await sealRequest(baseRequest({ rate_key: "chat-9" })));
    expect(res.status).toBe(202);
  });

  it("405s non-POST", async () => {
    const res = await SELF.fetch("https://worker.local/async");
    expect(res.status).toBe(405);
  });

  it("rejects an empty body (400)", async () => {
    expect((await postAsync("")).status).toBe(400);
  });

  it("rejects a non-envelope payload (400)", async () => {
    expect((await postAsync("garbage")).status).toBe(400);
  });

  it("rejects a disallowed destination host before enqueueing (403)", async () => {
    const res = await postAsync(
      await sealRequest(baseRequest({ url: "https://evil.example.com/x" })),
    );
    expect(res.status).toBe(403);
  });

  it("rejects a stale timestamp before enqueueing (401)", async () => {
    const res = await postAsync(
      await sealRequest(baseRequest({ ts: Math.floor(Date.now() / 1000) - 10_000 })),
    );
    expect(res.status).toBe(401);
  });
});
