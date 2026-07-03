import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";
import { randomBytes } from "node:crypto";

/**
 * A fresh 32-byte AES-256 key is generated for each test run and injected as
 * the SHARED_KEY binding. Test files read it back via `env.SHARED_KEY` so the
 * "client" side of the tests encrypts with the exact same key the Worker uses.
 */
const SHARED_KEY = randomBytes(32).toString("base64");

export default defineWorkersConfig({
  test: {
    poolOptions: {
      workers: {
        main: "./src/index.ts",
        miniflare: {
          compatibilityDate: "2024-09-23",
          // Required by @cloudflare/vitest-pool-workers.
          compatibilityFlags: ["nodejs_compat"],
          bindings: {
            SHARED_KEY,
            ALLOWED_HOSTS: "api.telegram.org",
            MAX_CLOCK_SKEW_SECONDS: "300",
            MAX_BODY_BYTES: "5242880",
            UPSTREAM_TIMEOUT_MS: "20000",
          },
          // Token-bucket rate limiter Durable Object.
          durableObjects: {
            RATE_LIMITER: "RateLimiter",
          },
          queueProducers: {
            RELAY_QUEUE: "relay-jobs",
          },
        },
      },
    },
  },
});
