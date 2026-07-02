/**
 * Replay-attack protection.
 *
 * AES-GCM guarantees that a message was produced by a holder of the shared key,
 * but it does NOT prevent an attacker who captured a valid ciphertext from
 * resending it later. This module adds two complementary defenses:
 *
 *   1. Timestamp window (always on): the client embeds a Unix timestamp; the
 *      Worker rejects anything outside ±MAX_CLOCK_SKEW_SECONDS. This bounds the
 *      window during which a captured message could be replayed.
 *
 *   2. Nonce de-duplication (optional, requires REPLAY_KV): each request carries
 *      unique nonce. The Worker records saw nonce's in KV with a TTL covering
 *      the skew window, so a captured message cannot be replayed even *within*
 *      the time window.
 */

import type { Config } from "./config.ts";

/** Raised when a request fails freshness/replay validation. */
export class ReplayError extends Error {
  readonly status: number;
  constructor(message: string) {
    super(message);
    this.name = "ReplayError";
    // 401: the request is well-formed and decrypted, but not acceptable.
    this.status = 401;
  }
}

/**
 * Verify the request timestamp is within the allowed clock-skew window.
 * @throws {ReplayError} if the timestamp is missing, malformed, or stale.
 */
export function assertFreshTimestamp(ts: unknown, config: Config): void {
  if (typeof ts !== "number" || !Number.isFinite(ts)) {
    throw new ReplayError("missing or invalid timestamp");
  }
  const nowSeconds = Math.floor(Date.now() / 1000);
  if (Math.abs(nowSeconds - ts) > config.maxClockSkewSeconds) {
    throw new ReplayError("request timestamp is outside the allowed window");
  }
}

/**
 * If a REPLAY_KV namespace is bound, atomically reject and record the nonce so
 * it can only be used once. Without KV bound, this is a no-op (timestamp window
 * is the only defense - acceptable for low-volume / trusted-network setups).
 *
 * Note: Workers KV is eventually consistent, so this is a strong-but-not-
 * perfectly-atomic guard. For the threat model here (replaying a captured
 * Telegram call) it is more than sufficient.
 *
 * @throws {ReplayError} if the nonce has already been seen.
 */
export async function assertUnusedNonce(
  nonce: unknown,
  config: Config,
): Promise<void> {
  if (typeof nonce !== "string" || nonce.length === 0 || nonce.length > 128) {
    throw new ReplayError("missing or invalid nonce");
  }
  if (!config.replayKv) return;

  const key = `nonce:${nonce}`;
  const seen = await config.replayKv.get(key);
  if (seen !== null) {
    throw new ReplayError("nonce has already been used");
  }

  // Keep the record slightly longer than the acceptance window so nonce
  // cannot be reused right after it would otherwise expire from the window.
  const ttlSeconds = config.maxClockSkewSeconds * 2;
  await config.replayKv.put(key, "1", { expirationTtl: ttlSeconds });
}
