/**
 * Worker entry point. Orchestrates the full request lifecycle:
 *
 *   POST / -> decrypt -> validate (freshness/replay) -> forward -> seal
*           response -> return
 *   GET /health -> liveness probe (no secrets, no auth)
 *   anything else -> 404 / 405
 *
 * The only privileged operation (decrypting the payload) requires the shared
 * key, so successful decryption *is* the authentication step.
 */

import { parseConfig, ConfigError, type Env, type Config } from "./config.ts";
import { importKey, seal, open, CryptoError } from "./crypto.ts";
import { forward, prepareForward, ForwardError } from "./forward.ts";
import {
  enqueue,
  consume,
  consumeDlq,
  QueueUnavailableError,
} from "./queue.ts";
import type { QueueJob } from "./jobs.ts";
import { jsonError, sealedResponse } from "./http.ts";
import { PROTOCOL_VERSION, type ForwardRequest } from "./protocol.ts";
import {
  assertFreshTimestamp,
  assertUnusedNonce,
  ReplayError,
} from "./replay.ts";

// Re-export the Durable Object class so the runtime can instantiate it from the
// `durable_objects` binding declared in wrangler.toml.
export { RateLimiter } from "./ratelimiter.ts";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // Intentionally unauthenticated and side effect free reveals nothing.
    if (request.method === "GET" && url.pathname === "/health") {
      return new Response(JSON.stringify({ status: "ok" }), {
        status: 200,
        headers: { "content-type": "application/json; charset=utf-8" },
      });
    }

    // Both relay endpoints accept only POST.
    const isSync = url.pathname === "/";
    const isAsync = url.pathname === "/async";
    if (!isSync && !isAsync) {
      return jsonError(404, "not found");
    }
    if (request.method !== "POST") {
      return jsonError(405, "method not allowed");
    }

    // Configuration
    let config: Config;
    let key: CryptoKey;
    try {
      config = parseConfig(env);
      key = await importKey(env.SHARED_KEY);
    } catch (err) {
      // Misconfiguration is an operator problem; log it and fail closed.
      console.error(
        "configuration error:",
        err instanceof Error ? err.message : err,
      );
      return jsonError(500, "server misconfigured");
    }

    try {
      return isAsync
        ? await handleAsync(request, config, key)
        : await handleSync(request, config, key);
    } catch (err) {
      return toErrorResponse(err);
    }
  },

  /**
   * Queue consumer. Cloudflare routes both the relay-jobs and relay-dlq queues
   * here; we dispatch on `batch.queue`. Errors are allowed to propagate so the
   * platform retries the batch (fail closed).
   */
  async queue(batch: MessageBatch<QueueJob>, env: Env): Promise<void> {
    const config = parseConfig(env);

    if (batch.queue === "relay-dlq") {
      await consumeDlq(batch);
      return;
    }

    const key = await importKey(env.SHARED_KEY);
    await consume(batch, config, key);
  },
} satisfies ExportedHandler<Env, QueueJob>;

/**
 * Read the request body, decrypt+authenticate it, parse the inner descriptor,
 * and run the shared validations (protocol version, freshness, replay nonce).
 * Shared by both the sync and async paths.
 *
 * @returns the validated descriptor and the original sealed envelope.
 */
async function decryptAndValidate(
  request: Request,
  config: Config,
  key: CryptoKey,
): Promise<{ req: ForwardRequest; envelopeB64: string }> {
  // 1. Read the ciphertext envelope (base64) from the request body.
  const envelopeB64 = (await request.text()).trim();
  if (envelopeB64.length === 0) {
    throw new ForwardError(400, "empty request body");
  }

  // 2. Decrypt + authenticate. Any failure here means the message was not
  //    produced by a holder of the shared key (or was tampered with).
  const plaintext = await open(key, envelopeB64); // throws CryptoError

  // 3. Parse the inner JSON request descriptor.
  let req: ForwardRequest;
  try {
    req = JSON.parse(textDecoder.decode(plaintext)) as ForwardRequest;
  } catch {
    throw new ForwardError(400, "decrypted payload is not valid JSON");
  }
  if (req.v !== PROTOCOL_VERSION) {
    throw new ForwardError(400, "unsupported protocol version");
  }

  // 4. Replay protection: timestamp window + (optional) nonce de-duplication.
  //    This is the ONLY place freshness/replay are checked - the async consumer
  //    must not re-check them (a job legitimately delayed by retries would fail).
  assertFreshTimestamp(req.ts, config); // throws ReplayError
  await assertUnusedNonce(req.nonce, config); // throws ReplayError

  return { req, envelopeB64 };
}

/**
 * Synchronous relay: decrypt -> validate -> forward -> seal -> return.
 */
async function handleSync(
  request: Request,
  config: Config,
  key: CryptoKey,
): Promise<Response> {
  const { req } = await decryptAndValidate(request, config, key);

  // Perform the outbound request and seal the response.
  const forwardResponse = await forward(req, config); // throws ForwardError
  const responseJson = JSON.stringify(forwardResponse);
  const sealedB64 = await seal(key, textEncoder.encode(responseJson));
  return sealedResponse(sealedB64);
}

/**
 * Asynchronous relay: decrypt -> validate (incl. destination) -> enqueue -> 202.
 * Fire-and-forget: the consumer performs the forward with retries/backoff.
 */
async function handleAsync(
  request: Request,
  config: Config,
  key: CryptoKey,
): Promise<Response> {
  const { req, envelopeB64 } = await decryptAndValidate(request, config, key);

  // Validate the destination synchronously such bad requests are rejected now
  // (with the same 400/403/413 semantics) rather than failing later on the queue.
  prepareForward(req, config); // throws ForwardError

  const id = await enqueue(config, req, envelopeB64); // throws QueueUnavailableError
  return new Response(JSON.stringify({ status: "accepted", id }), {
    status: 202,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

/**
 * Map internal errors to safe, generic HTTP responses. Decryption failures are
 * deliberately reported as a generic 400, so the endpoint does not behave as an
 * oracle that distinguishes "bad ciphertext" from other client errors.
 */
function toErrorResponse(err: unknown): Response {
  if (err instanceof ForwardError) {
    return jsonError(err.status, err.message);
  }
  if (err instanceof ReplayError) {
    return jsonError(err.status, err.message);
  }
  if (err instanceof QueueUnavailableError) {
    console.error("async relay used but RELAY_QUEUE is not bound");
    return jsonError(err.status, err.message);
  }
  if (err instanceof CryptoError) {
    return jsonError(400, "invalid or unauthenticated payload");
  }
  if (err instanceof ConfigError) {
    console.error("configuration error:", err.message);
    return jsonError(500, "server misconfigured");
  }
  console.error("unexpected error:", err);
  return jsonError(500, "internal error");
}
