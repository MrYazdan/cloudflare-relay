declare module "cloudflare:test" {
  interface ProvidedEnv {
    SHARED_KEY: string;
    ALLOWED_HOSTS: string;
    MAX_CLOCK_SKEW_SECONDS: string;
    MAX_BODY_BYTES: string;
    UPSTREAM_TIMEOUT_MS: string;
    RATE_LIMITER: DurableObjectNamespace;
    RELAY_QUEUE: Queue<unknown>;
  }
}
