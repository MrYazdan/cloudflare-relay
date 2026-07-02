/**
 * Pure helpers that decide whether a forwarded request should be retried and,
 * if so, after how long. Kept free of any runtime dependency, so they are
 * trivially unit-testable.
 *
 * Used by the queue consumer (src/queue.ts) to translate a forward outcome into
 * an `ack` (done - success or permanent failure) or a delayed `retry`.
 */

/** What the consumer should do with a queue message after a forward attempt. */
export type Outcome = "ack" | "retry";

/** A retry decision plus an optional explicit delay (e.g., from `Retry-After`). */
export interface Classification {
  outcome: Outcome;
  /** If present, the destination asked us to wait this long before retrying. */
  retryAfterMs?: number;
}

/**
 * Classify an HTTP status code (from either a forwarded response or a
 * {@link ForwardError}) into a retry decision.
 *
 *  - 429 (rate limited) and 5xx (server errors / our 502/504) → retry.
 *  - everything else (2xx, 3xx, 4xx other than 429) → ack (terminal): retrying
 *    a client error or a success would not help.
 */
export function classifyStatus(status: number): Outcome {
  if (status === 429) return "retry";
  if (status >= 500) return "retry";
  return "ack";
}

/**
 * Parse a retry delay hint from a destination's `Retry-After` header and/or
 * response body. Supports:
 *   - `Retry-After` as a number of seconds,
 *   - `Retry-After` as an HTTP date,
 *   - Telegram's `{ "parameters": { "retry_after": N } }` JSON body.
 *
 * @returns delay in milliseconds, or `undefined` if no hint is present.
 */
export function parseRetryAfterMs(
  retryAfterHeader: string | null | undefined,
  bodyText?: string,
  now: number = Date.now(),
): number | undefined {
  if (retryAfterHeader) {
    const seconds = Number(retryAfterHeader);
    if (Number.isFinite(seconds)) {
      return Math.max(0, seconds * 1000);
    }
    const dateMs = Date.parse(retryAfterHeader);
    if (!Number.isNaN(dateMs)) {
      return Math.max(0, dateMs - now);
    }
  }
  if (bodyText) {
    try {
      const parsed = JSON.parse(bodyText) as {
        parameters?: { retry_after?: unknown };
      };
      const retryAfter = parsed.parameters?.retry_after;
      if (typeof retryAfter === "number" && Number.isFinite(retryAfter)) {
        return Math.max(0, retryAfter * 1000);
      }
    } catch {
      // Body is not JSON - no hint available.
    }
  }
  return undefined;
}

/**
 * Compute an exponential backoff delay (in milliseconds) with "equal jitter".
 *
 * The base case (`attempt = 1`) yields `base`, doubling each later attempt,
 * capped at `maxSeconds`. Equal jitter spreads the delay over `[capped/2,
 * capped]` so the result never exceeds the cap while still avoiding thundering
 * herds. `rng` is injectable for deterministic tests.
 *
 * @param attempt 1-based attempt number (the attempt that just failed).
 * @param baseSeconds
 * @param maxSeconds
 * @param rng
 */
export function backoffDelayMs(
  attempt: number,
  baseSeconds: number,
  maxSeconds: number,
  rng: () => number = Math.random,
): number {
  const exponent = Math.max(0, attempt - 1);
  const raw = baseSeconds * 2 ** exponent;
  const cappedSeconds = Math.min(maxSeconds, raw);
  const half = cappedSeconds / 2;
  const seconds = half + rng() * half;
  return Math.round(seconds * 1000);
}

/**
 * Convert a millisecond delay into the integer `delaySeconds` accepted by the
 * Cloudflare Queues `message.retry()` API (minimum 1 second).
 */
export function toDelaySeconds(ms: number): number {
  return Math.max(1, Math.ceil(ms / 1000));
}
