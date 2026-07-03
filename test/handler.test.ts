import { env, SELF, fetchMock } from "cloudflare:test";
import { beforeAll, afterEach, describe, it, expect } from "vitest";
import { importKey, seal, open, bytesToBase64, base64ToBytes } from "../src/crypto.ts";
import { PROTOCOL_VERSION, type ForwardResponse } from "../src/protocol.ts";

const enc = new TextEncoder();
const dec = new TextDecoder();

let key: CryptoKey;

beforeAll(async () => {
  key = await importKey(env.SHARED_KEY);
});

beforeAll(() => {
  fetchMock.activate();
  fetchMock.disableNetConnect();
});

afterEach(() => fetchMock.assertNoPendingInterceptors());

/** Seal an arbitrary request descriptor into the base64 envelope body. */
async function sealRequest(descriptor: object): Promise<string> {
  return seal(key, enc.encode(JSON.stringify(descriptor)));
}

/** A valid, fresh base request descriptor that callers can override. */
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

async function post(body: string): Promise<Response> {
  return SELF.fetch("https://worker.local/", { method: "POST", body });
}

describe("routing", () => {
  it("serves the health probe", async () => {
    const res = await SELF.fetch("https://worker.local/health");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "ok" });
  });

  it("404s unknown paths", async () => {
    const res = await SELF.fetch("https://worker.local/nope");
    expect(res.status).toBe(404);
  });

  it("405s non-POST on the relay endpoint", async () => {
    const res = await SELF.fetch("https://worker.local/");
    expect(res.status).toBe(405);
  });
});

describe("input validation", () => {
  it("rejects an empty body", async () => {
    const res = await post("");
    expect(res.status).toBe(400);
  });

  it("rejects an unauthenticated / non-envelope payload", async () => {
    const res = await post("this-is-not-a-valid-envelope");
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "invalid or unauthenticated payload" });
  });

  it("rejects a request to a disallowed host", async () => {
    const body = await sealRequest(
      baseRequest({ url: "https://evil.example.com/steal" }),
    );
    const res = await post(body);
    expect(res.status).toBe(403);
  });

  it("rejects a non-https destination", async () => {
    const body = await sealRequest(
      baseRequest({ url: "http://api.telegram.org/bot123/x" }),
    );
    const res = await post(body);
    expect(res.status).toBe(400);
  });
});

describe("replay protection", () => {
  it("rejects a stale timestamp", async () => {
    const body = await sealRequest(
      baseRequest({ ts: Math.floor(Date.now() / 1000) - 10_000 }),
    );
    const res = await post(body);
    expect(res.status).toBe(401);
  });
});

describe("happy path", () => {
  it("forwards the request and returns the sealed response", async () => {
    const upstreamBody = JSON.stringify({ ok: true, result: { message_id: 7 } });
    fetchMock
      .get("https://api.telegram.org")
      .intercept({ path: "/bot123/sendMessage", method: "POST" })
      .reply(200, upstreamBody, {
        headers: { "content-type": "application/json" },
      });

    const res = await post(await sealRequest(baseRequest()));
    expect(res.status).toBe(200);

    // Decrypt the response envelope and verify the relayed result.
    const opened = await open(key, (await res.text()).trim());
    const parsed = JSON.parse(dec.decode(opened)) as ForwardResponse;
    expect(parsed.v).toBe(PROTOCOL_VERSION);
    expect(parsed.status).toBe(200);
    expect(dec.decode(base64ToBytes(parsed.body_b64))).toBe(upstreamBody);
  });
});
