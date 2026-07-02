/**
 * config.ts
 * ---------
 * Defines the Worker's environment bindings and parses them into a validated,
 * strongly typed configuration object used throughout the request lifecycle.
 */

/**
 * Bindings injected by the Workers runtime. Mirrors `wrangler.toml` ([vars],
 * secrets, and optional KV namespace).
 */
export interface Env {
  /**
   * SECRET. Base64-encoded 32-byte AES-256 key shared with the backend.
   * Set via `wrangler secret put SHARED_KEY`. Never commit this.
   */
  SHARED_KEY: string;

  /** Comma-separated allowlist of permitted destination hostnames. */
  ALLOWED_HOSTS?: string;

  /** Max accepted clock skew (seconds) for replay protection. */
  MAX_CLOCK_SKEW_SECONDS?: string;

  /** Max decrypted body size (bytes) the Worker will forward. */
  MAX_BODY_BYTES?: string;

  /** Upstream request timeout (milliseconds). */
  UPSTREAM_TIMEOUT_MS?: string;

  /**
   * OPTIONAL. KV namespace for nonce de-duplication. When bound, enables strong
   * replay protection (reject already-seen nonce's within the skew window).
   */
  REPLAY_KV?: KVNamespace;

  // --- Async queue relay (optional; required only for the /async path) ------

  /** OPTIONAL. Queue producer binding for async jobs. */
  RELAY_QUEUE?: Queue<unknown>;

  /** OPTIONAL. Durable Object namespace backing the token-bucket rate limiter. */
  RATE_LIMITER?: DurableObjectNamespace;

  /** Per-key token-bucket capacity (burst). */
  RATE_CAPACITY?: string;

  /** Per-key token-bucket refill rate (tokens per second). */
  RATE_REFILL_PER_SECOND?: string;

  /** Enable the service-wide ("global") rate gate ("true"/"false"). */
  RATE_GLOBAL_ENABLED?: string;

  /** Global bucket capacity. */
  RATE_GLOBAL_CAPACITY?: string;

  /** Global bucket refill rate (tokens per second). */
  RATE_GLOBAL_REFILL_PER_SECOND?: string;

  /** Backoff base delay (seconds). */
  RETRY_BASE_DELAY_SECONDS?: string;

  /** Backoff maximum delay (seconds). */
  MAX_RETRY_DELAY_SECONDS?: string;
}

/** Validated, typed configuration derived from {@link Env}. */
export interface Config {
  /** Lower-cased set of hostnames the Worker may forward to. */
  allowedHosts: ReadonlySet<string>;
  /**
   * When true (ALLOWED_HOSTS === "*"), the host allowlist is disabled and any
   * https destination is permitted. This turns the Worker into an open proxy
   * gated only by the shared key - use with care.
   */
  allowAllHosts: boolean;
  /** Replay window in seconds (timestamp must be within ± this value). */
  maxClockSkewSeconds: number;
  /** Maximum forwarded body size in bytes. */
  maxBodyBytes: number;
  /** Upstream request timeout in milliseconds. */
  upstreamTimeoutMs: number;
  /** Optional KV namespace used for nonce replay protection. */
  replayKv?: KVNamespace;

  /** Optional queue producer binding (present only when the /async path is wired). */
  relayQueue?: Queue<unknown>;
  /** Optional rate-limiter DO namespace. */
  rateLimiter?: DurableObjectNamespace;
  /** Per-key token-bucket parameters. */
  rate: {
    capacity: number;
    refillPerSecond: number;
    globalEnabled: boolean;
    globalCapacity: number;
    globalRefillPerSecond: number;
  };
  /** Retry/backoff parameters for the queue consumer. */
  retry: {
    baseDelaySeconds: number;
    maxDelaySeconds: number;
  };
}

/** Raised when the Worker is misconfigured (operator error, not client error). */
export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

/** Defaults applied when a [vars] entry is absent. */
const DEFAULTS = {
  maxClockSkewSeconds: 300,
  maxBodyBytes: 5 * 1024 * 1024, // 5 MiB
  upstreamTimeoutMs: 20_000,
  // Per-key rate: ~20 requests/minute (matches Telegram's per-chat limit).
  rateCapacity: 20,
  rateRefillPerSecond: 0.33,
  // Global gate: ~30 requests/second (matches Telegram's global limit).
  rateGlobalEnabled: false,
  rateGlobalCapacity: 30,
  rateGlobalRefillPerSecond: 30,
  retryBaseDelaySeconds: 2,
  retryMaxDelaySeconds: 900,
} as const;

/**
 * Module-level guard so the "open proxy" warning is logged at most once per
 * isolate instead of on every request (parseConfig runs per request).
 */
let openProxyWarned = false;

/**
 * Parse and validate the environment into a {@link Config}.
 * @throws {ConfigError} if a required binding is missing or a value is invalid.
 */
export function parseConfig(env: Env): Config {
  if (!env.SHARED_KEY || env.SHARED_KEY.trim() === "") {
    throw new ConfigError("SHARED_KEY secret is not configured");
  }

  const rawAllowedHosts = (env.ALLOWED_HOSTS ?? "").trim();

  // Wildcard mode: a literal "*" disables the host allowlist entirely. This is
  // an explicit opt-in to open-proxy behavior (still https-only and still
  // gated by the shared key), so we surface a loud warning once per isolate.
  const allowAllHosts = rawAllowedHosts === "*";
  if (allowAllHosts && !openProxyWarned) {
    openProxyWarned = true;
    console.warn(
      'SECURITY: ALLOWED_HOSTS="*" - host allowlist is DISABLED. The Worker ' +
        "will forward to ANY https destination for any holder of SHARED_KEY. " +
        "Set an explicit allowlist unless you intend an open proxy.",
    );
  }

  const allowedHosts = allowAllHosts
    ? new Set<string>()
    : new Set(
        rawAllowedHosts
          .split(",")
          .map((h) => h.trim().toLowerCase())
          .filter((h) => h.length > 0),
      );
  if (!allowAllHosts && allowedHosts.size === 0) {
    throw new ConfigError(
      'ALLOWED_HOSTS must list at least one destination hostname (or "*")',
    );
  }

  return {
    allowedHosts,
    allowAllHosts,
    maxClockSkewSeconds: parsePositiveInt(
      env.MAX_CLOCK_SKEW_SECONDS,
      DEFAULTS.maxClockSkewSeconds,
      "MAX_CLOCK_SKEW_SECONDS",
    ),
    maxBodyBytes: parsePositiveInt(
      env.MAX_BODY_BYTES,
      DEFAULTS.maxBodyBytes,
      "MAX_BODY_BYTES",
    ),
    upstreamTimeoutMs: parsePositiveInt(
      env.UPSTREAM_TIMEOUT_MS,
      DEFAULTS.upstreamTimeoutMs,
      "UPSTREAM_TIMEOUT_MS",
    ),
    replayKv: env.REPLAY_KV,

    relayQueue: env.RELAY_QUEUE,
    rateLimiter: env.RATE_LIMITER,
    rate: {
      capacity: parsePositiveInt(
        env.RATE_CAPACITY,
        DEFAULTS.rateCapacity,
        "RATE_CAPACITY",
      ),
      refillPerSecond: parsePositiveFloat(
        env.RATE_REFILL_PER_SECOND,
        DEFAULTS.rateRefillPerSecond,
        "RATE_REFILL_PER_SECOND",
      ),
      globalEnabled: parseBool(
        env.RATE_GLOBAL_ENABLED,
        DEFAULTS.rateGlobalEnabled,
        "RATE_GLOBAL_ENABLED",
      ),
      globalCapacity: parsePositiveInt(
        env.RATE_GLOBAL_CAPACITY,
        DEFAULTS.rateGlobalCapacity,
        "RATE_GLOBAL_CAPACITY",
      ),
      globalRefillPerSecond: parsePositiveFloat(
        env.RATE_GLOBAL_REFILL_PER_SECOND,
        DEFAULTS.rateGlobalRefillPerSecond,
        "RATE_GLOBAL_REFILL_PER_SECOND",
      ),
    },
    retry: {
      baseDelaySeconds: parsePositiveInt(
        env.RETRY_BASE_DELAY_SECONDS,
        DEFAULTS.retryBaseDelaySeconds,
        "RETRY_BASE_DELAY_SECONDS",
      ),
      maxDelaySeconds: parsePositiveInt(
        env.MAX_RETRY_DELAY_SECONDS,
        DEFAULTS.retryMaxDelaySeconds,
        "MAX_RETRY_DELAY_SECONDS",
      ),
    },
  };
}

/** Parse a string env var as a positive integer, falling back to `fallback`. */
function parsePositiveInt(
  raw: string | undefined,
  fallback: number,
  name: string,
): number {
  if (raw === undefined || raw.trim() === "") return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value) || value <= 0) {
    throw new ConfigError(`${name} must be a positive integer (got "${raw}")`);
  }
  return value;
}

/** Parse a string env var as a positive (non-zero) float, falling back. */
function parsePositiveFloat(
  raw: string | undefined,
  fallback: number,
  name: string,
): number {
  if (raw === undefined || raw.trim() === "") return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0) {
    throw new ConfigError(`${name} must be a positive number (got "${raw}")`);
  }
  return value;
}

/** Parse a string env var as a boolean ("true"/"false"), falling back. */
function parseBool(
  raw: string | undefined,
  fallback: boolean,
  name: string,
): boolean {
  if (raw === undefined || raw.trim() === "") return fallback;
  const normalised = raw.trim().toLowerCase();
  if (normalised === "true") return true;
  if (normalised === "false") return false;
  throw new ConfigError(`${name} must be "true" or "false" (got "${raw}")`);
}
