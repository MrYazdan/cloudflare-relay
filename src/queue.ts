/**
 * The async relay path. This module currently holds the producer (`enqueue`);
 * the consumer is added in a later phase.
 */

import type { Config } from "./config.ts";
import { base64ToBytes } from "./crypto.ts";
import { open } from "./crypto.ts";
import { forward, ForwardError } from "./forward.ts";
import { buildJob, type QueueJob } from "./jobs.ts";
import type { ForwardRequest, ForwardResponse } from "./protocol.ts";
import { takeToken } from "./ratelimiter.ts";
import {
  classifyStatus,
  parseRetryAfterMs,
  backoffDelayMs,
  toDelaySeconds,
} from "./retry.ts";

const textDecoder = new TextDecoder();

/** Raised when the async path is used but its queue binding is not configured. */
export class QueueUnavailableError extends Error {
  readonly status = 503;
  constructor() {
    super("async relay is not configured");
    this.name = "QueueUnavailableError";
  }
}

/**
 * Enqueue a validated request for asynchronous forwarding.
 *
 * @param config   Worker config (must have `relayQueue` bound).
 * @param req      The validated, decrypted request descriptor.
 * @param envelope The ORIGINAL sealed base64 envelope (stored as-is so the
 *                 payload remains encrypted at rest in the queue).
 * @returns the job's opaque trace id.
 * @throws {QueueUnavailableError} if no queue is bound.
 */
export async function enqueue(
  config: Config,
  req: ForwardRequest,
  envelope: string,
): Promise<string> {
  if (!config.relayQueue) {
    throw new QueueUnavailableError();
  }
  const job = buildJob(req, envelope);
  await config.relayQueue.send(job);
  return job.id;
}

/**
 * Apply the rate limiter for a job. Returns `0` if the job may proceed now, or
 * a positive ms delay if it should be retried later.
 *
 * The optional global gate is checked first (and short-circuits) so a per-key
 * token is not consumed when the global ceiling is the binding constraint.
 */
async function applyRateLimit(
  config: Config,
  job: QueueJob,
): Promise<number> {
  if (!config.rateLimiter) return 0;

  if (config.rate.globalEnabled) {
    const global = await takeToken(config.rateLimiter, "__global__", {
      capacity: config.rate.globalCapacity,
      refillPerSecond: config.rate.globalRefillPerSecond,
    });
    if (!global.allowed) return global.retryAfterMs;
  }

  const perKey = await takeToken(config.rateLimiter, job.rateKey, {
    capacity: config.rate.capacity,
    refillPerSecond: config.rate.refillPerSecond,
  });
  return perKey.allowed ? 0 : perKey.retryAfterMs;
}

/**
 * Decide the retry delay (seconds) for a failed attempt: honor `Retry-After`
 * on a 429, otherwise exponential backoff based on the attempt count.
 */
function retryDelaySeconds(
  response: ForwardResponse | null,
  attempt: number,
  config: Config,
): number {
  if (response && response.status === 429) {
    const headerRetryAfter = response.headers["retry-after"];
    const bodyText = response.body_b64
      ? textDecoder.decode(base64ToBytes(response.body_b64))
      : undefined;
    const ms = parseRetryAfterMs(headerRetryAfter ?? null, bodyText);
    if (ms !== undefined) return toDelaySeconds(ms);
  }
  return toDelaySeconds(
    backoffDelayMs(
      attempt,
      config.retry.baseDelaySeconds,
      config.retry.maxDelaySeconds,
    ),
  );
}

/**
 * Process a single queue message: rate-limit gate -> decrypt -> forward ->
 * ack/retry. Never re-checks freshness/replay (validated at ingress).
 */
export async function processMessage(
  message: Message<QueueJob>,
  config: Config,
  key: CryptoKey,
): Promise<void> {
  const job = message.body;

  // 1. Rate limit. If throttled, retry the whole message later (no forward).
  const throttleMs = await applyRateLimit(config, job);
  if (throttleMs > 0) {
    message.retry({ delaySeconds: toDelaySeconds(throttleMs) });
    return;
  }

  // 2. Decrypt the stored envelope. A failure here means a corrupt job (it was
  //    valid at ingress), so drop it rather than retry forever.
  let req: ForwardRequest;
  try {
    const plaintext = await open(key, job.envelope);
    req = JSON.parse(textDecoder.decode(plaintext)) as ForwardRequest;
  } catch {
    console.error("dropping undecryptable queue job", { id: job.id });
    message.ack();
    return;
  }

  // 3. Forward and classify the outcome.
  let response: ForwardResponse | null = null;
  let status: number;
  try {
    response = await forward(req, config);
    status = response.status;
  } catch (err) {
    if (err instanceof ForwardError) {
      status = err.status;
    } else {
      console.error("unexpected error forwarding queue job", {
        id: job.id,
        err,
      });
      status = 500;
    }
  }

  if (classifyStatus(status) === "ack") {
    // Success, or a permanent (non-retryable) failure - we are done with it.
    message.ack();
    return;
  }

  message.retry({
    delaySeconds: retryDelaySeconds(response, message.attempts, config),
  });
}

/**
 * Queue consumer for the relay-jobs queue: process each message in the batch.
 */
export async function consume(
  batch: MessageBatch<QueueJob>,
  config: Config,
  key: CryptoKey,
): Promise<void> {
  for (const message of batch.messages) {
    await processMessage(message, config, key);
  }
}

/**
 * Dead-letter consumer: jobs that exhausted their retries. Log structured
 * metadata (no payload) for observability, then ack, so they are not retried.
 */
export async function consumeDlq(batch: MessageBatch<QueueJob>): Promise<void> {
  for (const message of batch.messages) {
    const job = message.body;
    console.error("relay job dead-lettered", {
      id: job?.id,
      rateKey: job?.rateKey,
      attempts: message.attempts,
    });
    message.ack();
  }
}
