/**
 * A token-bucket rate limiter backed by a Durable Object (DO).
 *
 * Why a Durable Object? A token bucket needs a single, strongly consistent,
 * serialized counter per rate key. Workers' KV is eventually consistent and
 * Workers themselves are stateless, so neither can implement a correct bucket.
 * A DO instance (one per rate key via `idFromName`) gives exactly that: a single
 * authoritative owner of the bucket state, with atomic read-modify-write.
 *
 * The bucket math is factored into the pure {@link takeFromBucket} function so
 * it can be unit-tested deterministically (with an injected clock), while the
 * DO only handles persistence and concurrency.
 */

/** Persisted bucket state. */
export interface BucketState {
  /** Current (fractional) token count. */
  tokens: number;
  /** Timestamp (ms) at which `tokens` was last computed. */
  lastRefillMs: number;
}

/** Token-bucket parameters. */
export interface BucketParams {
  /** Maximum number of tokens (burst capacity). */
  capacity: number;
  /** Tokens added per second (sustained rate). */
  refillPerSecond: number;
}

/** Result of attempting to take a single token. */
export interface TakeResult {
  /** Bucket state to persist after the attempt. */
  state: BucketState;
  /** Whether a token was available and consumed. */
  allowed: boolean;
  /** If denied, ms until a token is expected to be available. */
  retryAfterMs: number;
}

/** Decision returned to the caller of the DO (without the internal state). */
export interface RateDecision {
  allowed: boolean;
  retryAfterMs: number;
}

const STORAGE_KEY = "bucket";

/**
 * Pure token-bucket step: refill based on elapsed time, then try to consume one
 * token. Deterministic given `prev`, `params`, and `now`.
 *
 * @param prev   Previously persisted state, or `undefined` for a fresh bucket
 *               (which starts full).
 * @param params
 * @param now    Current time in milliseconds.
 */
export function takeFromBucket(
  prev: BucketState | undefined,
  params: BucketParams,
  now: number,
): TakeResult {
  const { capacity, refillPerSecond } = params;

  // A fresh bucket starts full so the first burst up to `capacity` is allowed.
  const previousTokens = prev ? prev.tokens : capacity;
  const lastRefillMs = prev ? prev.lastRefillMs : now;

  const elapsedSeconds = Math.max(0, (now - lastRefillMs) / 1000);
  const refilled = Math.min(capacity, previousTokens + elapsedSeconds * refillPerSecond);

  if (refilled >= 1) {
    return {
      state: { tokens: refilled - 1, lastRefillMs: now },
      allowed: true,
      retryAfterMs: 0,
    };
  }

  // Not enough for one token: report how long until one accrues.
  const deficit = 1 - refilled;
  const retryAfterMs =
    refillPerSecond > 0
      ? Math.ceil((deficit / refillPerSecond) * 1000)
      : Number.MAX_SAFE_INTEGER;

  return {
    state: { tokens: refilled, lastRefillMs: now },
    allowed: false,
    retryAfterMs,
  };
}

/**
 * Durable Object owning one token bucket. Reachable only internally (its
 * namespace is never exposed publicly), so the capacity/refill query params are
 * supplied by our own Worker code, not by clients.
 *
 * Request: `GET /take?capacity=<n>&refill=<tokens-per-second>`
 * Response: `{ "allowed": boolean, "retryAfterMs": number }`
 */
export class RateLimiter implements DurableObject {
  private readonly state: DurableObjectState;

  constructor(state: DurableObjectState) {
    this.state = state;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const params: BucketParams = {
      capacity: Number(url.searchParams.get("capacity")),
      refillPerSecond: Number(url.searchParams.get("refill")),
    };

    // Serialize concurrent requests to this key for an atomic
    // read-modify-write of the bucket.
    const decision = await this.state.blockConcurrencyWhile(async () => {
      const prev = await this.state.storage.get<BucketState>(STORAGE_KEY);
      const result = takeFromBucket(prev, params, Date.now());
      await this.state.storage.put(STORAGE_KEY, result.state);
      return { allowed: result.allowed, retryAfterMs: result.retryAfterMs };
    });

    return Response.json(decision satisfies RateDecision);
  }
}

/**
 * Helper for callers: take one token for `key` from the rate-limiter DO.
 *
 * @param namespace The DO namespace binding (e.g. env.RATE_LIMITER).
 * @param key       The rate key (one bucket per distinct key).
 * @param params
 */
export async function takeToken(
  namespace: DurableObjectNamespace,
  key: string,
  params: BucketParams,
): Promise<RateDecision> {
  const stub = namespace.get(namespace.idFromName(key));
  const url =
    `https://rate-limiter.internal/take?capacity=${encodeURIComponent(params.capacity)}` +
    `&refill=${encodeURIComponent(params.refillPerSecond)}`;
  const response = await stub.fetch(url);
  return (await response.json()) as RateDecision;
}
