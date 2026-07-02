/**
 * The queue message shape for the async relay path, plus a pure builder, so the
 * producer (ingress) and consumer agree on the structure, and it can be unit
 * tested without a live queue.
 */

import type { ForwardRequest } from "./protocol.ts";

/**
 * A validated job placed on the relay queue.
 *
 * Note: the job stores the ORIGINAL sealed envelope (still ciphertext), not the
 * decrypted request. The payload therefore stays encrypted at rest in the
 * queue; the consumer re-opens it just before forwarding. Plaintext exists only
 * transiently in memory during the actual forward - the same exposure as the
 * synchronous path.
 */
export interface QueueJob {
  /** Opaque trace id for logs/correlation (not the request nonce). */
  id: string;
  /** The original base64 sealed envelope to forward. */
  envelope: string;
  /** Resolved rate-limit key (req.rate_key, else destination host). */
  rateKey: string;
  /** Unix seconds when the job was enqueued (for metrics, not freshness). */
  enqueuedAt: number;
}

/**
 * Resolve the rate-limit key for a request: the client-supplied `rate_key` if
 * present and non-empty, otherwise the destination host (parsed from the URL).
 * Falls back to "unknown" if the URL cannot be parsed (it has already passed
 * validation upstream, so this is just defensive).
 */
export function resolveRateKey(req: ForwardRequest): string {
  const explicit = req.rate_key?.trim();
  if (explicit) return explicit;
  try {
    return new URL(req.url).hostname.toLowerCase();
  } catch {
    return "unknown";
  }
}

/**
 * Build a {@link QueueJob} from a validated request and its original sealed
 * envelope. Pure (modulo the injectable id/clock) for deterministic tests.
 */
export function buildJob(
  req: ForwardRequest,
  envelope: string,
  id: string = crypto.randomUUID(),
  now: number = Date.now(),
): QueueJob {
  return {
    id,
    envelope,
    rateKey: resolveRateKey(req),
    enqueuedAt: Math.floor(now / 1000),
  };
}
