# Cloudflare Relay

**An end-to-end encrypted relay running on Cloudflare Workers.**

`cloudflare-relay` lets a backend that *can* reach Cloudflare but *cannot* reach a
destination directly (for example, the Telegram Bot API from a network where it
is blocked) forward HTTP requests through a Worker. Every request and response
is encrypted and authenticated with a pre-shared key, so the Worker - and
anyone observing the traffic - only ever sees opaque ciphertext.

It is intentionally small, dependency-free, and inexpensive to run: for low daily
request volumes it fits comfortably inside the Cloudflare Workers free tier.

## How it works

```
                   encrypted (AES-256-GCM)                        plaintext HTTPS
  ┌─────────────┐   POST base64(envelope)   ┌────────────┐    ┌─────────────────────┐
  │    Your     │ ────────────────────────► │ Cloudflare │ ─► │  Destination        │
  │   backend   │                           │    Worker  │    │ (api.telegram.org)  │
  │ (encryptor) │ ◄──────────────────────── │  ( relay ) │ ◄─ │ or etc...           │
  └─────────────┘   base64(sealed response) └────────────┘    └─────────────────────┘
        ▲                                          │
        └────────── shares the 32-byte key ────────┘
```

1. The backend serializes the request it wants to be made into a small JSON
   descriptor (method, URL, headers, body).
2. It seals that JSON with **AES-256-GCM** into a binary envelope and base64
   encodes it, then `POST`s it to the Worker.
3. The Worker decrypts and authenticates the envelope, validates it (freshness,
   replay, destination allowlist), and performs the real HTTPS request.
4. The Worker seals the destination's response the same way and returns it.
5. The backend decrypts the response.

The shared key is the only secret. Because AES-GCM is authenticated
(AEAD), a valid envelope can only be produced by a holder of the key, so
**decryption doubles as authentication**; there is no separate API token.

## Security model

| Concern                     | Mitigation                                                                                                                                                                         |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Confidentiality & integrity | AES-256-GCM (AEAD) with a per-message random 96-bit IV.                                                                                                                            |
| Authentication              | Only a key holder can produce a verifiable envelope.                                                                                                                               |
| Replay (across time)        | Client timestamp must be within `±MAX_CLOCK_SKEW_SECONDS`.                                                                                                                         |
| Replay (within window)      | Optional per-message nonce de-duplication via Workers KV.                                                                                                                          |
| SSRF / open-proxy abuse     | Destination host must be in `ALLOWED_HOSTS`; scheme must be `https`; redirects are not auto-followed. (`ALLOWED_HOSTS="*"` opts out - open-proxy mode, key-gated, logs a warning.) |
| Resource exhaustion         | `MAX_BODY_BYTES` body cap (both directions) and `UPSTREAM_TIMEOUT_MS` upstream timeout.                                                                                            |
| Key exposure                | Key is a Cloudflare **secret**, never committed and never in `[vars]`.                                                                                                             |
| Error oracles               | Protocol errors are generic; decryption failure is reported as a plain `400`.                                                                                                      |

### Wire format

Binary envelope (before base64), identical in both directions:

```
┌─────────┬──────────────┬─────────────────────────────────┐
│ version │      IV      │      ciphertext ‖ tag           │
│ 1 byte  │   12 bytes   │   N bytes (GCM tag is last 16)  │
└─────────┴──────────────┴─────────────────────────────────┘
```

Decrypted **request** JSON (`ForwardRequest`):

```jsonc
{
  "v": 1,                       // protocol version
  "ts": 1730000000,             // unix seconds (replay window)
  "nonce": "…",                 // unique per request
  "method": "POST",
  "url": "https://api.telegram.org/bot<token>/sendMessage",
  "headers": { "content-type": "application/json" },
  "body_b64": "…"               // base64 of the raw body (optional)
}
```

Decrypted **response** JSON (`ForwardResponse`):

```jsonc
{
  "v": 1,
  "ts": 1730000001,
  "status": 200,
  "headers": { "content-type": "application/json" },
  "body_b64": "…"               // base64 of the raw destination body
}
```

## Project layout

```
src/
  index.ts        Worker entry point and request orchestration
  crypto.ts       AES-256-GCM envelope (seal / open) + base64 helpers
  config.ts       Env binding parsing & validation
  protocol.ts     Shared wire-format types and constants
  forward.ts      Destination validation + outbound request
  replay.ts       Timestamp + (optional) nonce replay protection
  http.ts         Response helpers
  queue.ts        Async path: enqueue producer + queue/DLQ consumer
  jobs.ts         Queue job shape + rate-key resolution
  ratelimiter.ts  Token-bucket Durable Object (+ pure bucket math)
  retry.ts        Retry classification + backoff + Retry-After parsing
test/
  crypto.test.ts          Envelope unit tests
  handler.test.ts         Full-pipeline integration tests (with mocked upstream)
  config.test.ts          Configuration parsing & validation tests
  async-ingress.test.ts   Async queue ingress tests
  queue-consumer.test.ts  Queue consumer logic tests
  jobs.test.ts            Queue job logic tests
  ratelimiter.test.ts     Rate limiter logic tests
  retry.test.ts           Retry semantics and backoff tests
examples/           Standalone client examples, one file per language
  go/main.go  
  py/main.py  
  js/main.js  
  rust/main.rs
```

> The `examples/` directory contains **only reference clients**,
> single-file programs, one per language, that show how to seal a request, call
> the Worker, and open the sealed response. They are not part of the deployed
> Worker or its test suite; pick whichever language your backend uses.

## Setup & deployment

### 1. Prerequisites

- Node.js 18+ and a Cloudflare account.
- `npm install` (installs `wrangler` and the test toolchain locally).

```bash
npm install
```

### 2. Generate the shared key

```bash
openssl rand -base64 32
```

### 3. Configure the destination allowlist

Edit `ALLOWED_HOSTS` in `wrangler.toml` (comma-separated). The default is
`api.telegram.org`. The relay is destination-agnostic - list any hosts you
need, e.g. `api.telegram.org,api.openai.com,discord.com`. Keep it as tight as
possible.

Setting `ALLOWED_HOSTS = "*"` disables the allowlist and permits **any** https
destination (open-proxy mode, gated only by `SHARED_KEY`). The Worker logs a
security warning when this is active; prefer an explicit list when you can.

### 4. Local development

```bash
cp .dev.vars.example .dev.vars   # paste the key into .dev.vars
npm run dev                      # wrangler dev on http://localhost:8787
```

### 5. Deploy

```bash
npx wrangler login
npx wrangler secret put SHARED_KEY   # paste the same base64 key
npm run deploy
```

Give the **same** base64 key to your backend (e.g., via an env var).

### 6. (Optional) Strong replay protection with KV

```bash
npx wrangler kv namespace create REPLAY_KV
# paste the returned id into the [[kv_namespaces]] block in wrangler.toml, then redeploy.
```

When `REPLAY_KV` is bound, each `nonce` may be used only once within the skew
window, defeating replays even inside the time window.

## Configuration reference

| Binding                         | Type          | Default            | Description                                                                                                                            |
|---------------------------------|---------------|--------------------|----------------------------------------------------------------------------------------------------------------------------------------|
| `SHARED_KEY`                    | secret        | - (required)       | Base64 32-byte AES-256 key.                                                                                                            |
| `ALLOWED_HOSTS`                 | var           | `api.telegram.org` | Comma-separated allowed destination hosts. Use `*` to disable the allowlist (open-proxy mode, gated only by the key - logs a warning). |
| `MAX_CLOCK_SKEW_SECONDS`        | var           | `300`              | Replay window in seconds.                                                                                                              |
| `MAX_BODY_BYTES`                | var           | `5242880`          | Max body size (both directions), bytes.                                                                                                |
| `UPSTREAM_TIMEOUT_MS`           | var           | `20000`            | Upstream request timeout, ms.                                                                                                          |
| `REPLAY_KV`                     | KV (optional) | unset              | Enables nonce de-duplication.                                                                                                          |
| `RATE_CAPACITY`                 | var           | `20`               | Per-key token-bucket capacity (burst).                                                                                                 |
| `RATE_REFILL_PER_SECOND`        | var           | `0.33`             | Per-key refill (≈20/min).                                                                                                              |
| `RATE_GLOBAL_ENABLED`           | var           | `false`            | Enable the service-wide rate gate.                                                                                                     |
| `RATE_GLOBAL_CAPACITY`          | var           | `30`               | Global bucket capacity.                                                                                                                |
| `RATE_GLOBAL_REFILL_PER_SECOND` | var           | `30`               | Global refill (≈30/s).                                                                                                                 |
| `RETRY_BASE_DELAY_SECONDS`      | var           | `2`                | Backoff base delay.                                                                                                                    |
| `MAX_RETRY_DELAY_SECONDS`       | var           | `900`              | Backoff cap.                                                                                                                           |
| `RELAY_QUEUE`                   | Queue (async) | unset              | Producer binding for `POST /async`.                                                                                                    |
| `RATE_LIMITER`                  | DO (async)    | declared           | Token-bucket Durable Object.                                                                                                           |

## Client examples

Ready-to-run single-file clients live under `examples/<language>/`:

| Language   | File                    | Notes                                      |
|------------|-------------------------|--------------------------------------------|
| Go         | `examples/go/main.go`   | standard library only                      |
| Python     | `examples/py/main.py`   | needs `pip install cryptography`           |
| JavaScript | `examples/js/main.js`   | Web Crypto + fetch; Node 20+               |
| Rust       | `examples/rust/main.rs` | run with `rust-script`, or a Cargo project |

All four do the same thing, seal a Telegram `sendMessage` call, POST it to the
Worker's sync endpoint, and print the decrypted response and take the same
environment variables. For example, the JavaScript client:

```bash
WORKER_URL=https://cloudflare-relay.<acct>.workers.dev/ \
SHARED_KEY=<base64-32-byte-key> \
TELEGRAM_TOKEN=<token> \
CHAT_ID=<chat-id> \
node examples/js/main.js "Hello via Cloudflare Relay @mryazdan"
```

```js
// examples/js/main.js - the core of every client (seal -> POST -> open):
async function seal(key, plaintext) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({name: "AES-GCM", iv}, key, plaintext));
    const envelope = new Uint8Array(1 + iv.length + ct.length);
    envelope[0] = 0x01;                 // version byte
    envelope.set(iv, 1);                // 12-byte IV
    envelope.set(ct, 1 + iv.length);    // ciphertext || 16-byte GCM tag
    return Buffer.from(envelope).toString("base64");
}
```

The wire format is documented above, so porting to any other language is just a
matter of matching the envelope layout and the JSON schema.

## Async (queued) relay

> **Requires the Workers Paid plan ($5/mo)** - Queues and Durable Objects are
> not on the free tier. The synchronous `POST /` path above keeps working on the
> free tier and needs none of the bindings below.

For bursty, fire-and-forget workloads (e.g., sending many Telegram alerts at
once), use `POST /async`. The Worker validates and **enqueues** the request,
returns `202 { "status": "accepted", "id": "..." }` immediately, and a queue
consumer forwards it later - rate-limited per key, retried with backoff, and
dead-lettered on permanent failure. This absorbs bursts the destination's own
rate limits (Telegram: ~30 req/s global, ~20/min per chat) would otherwise
reject.

To use it, seal the **same request descriptor** as the sync path (optionally
adding a `rate_key`, e.g., a chat id) and POST it to `/async` instead of `/`. The
response is a plaintext `202 { "status": "accepted", "id": "..." }` - no sealed
body, since nothing is returned to decrypt.

```jsonc
// the inner descriptor gains one optional field for the async path:
{ "v": 1, "ts": 1730000000, "nonce": "…", "method": "POST",
  "url": "https://api.telegram.org/bot<token>/sendMessage",
  "headers": { "content-type": "application/json" },
  "body_b64": "…",
  "rate_key": "<chat-id>"   // optional; defaults to the destination host
}
```

**Rate limiting** is a token bucket per `rate_key` (a Durable Object), tuned via
the `RATE_*` vars. An optional global gate (`RATE_GLOBAL_ENABLED=true`) caps
total throughput. **Retries** use exponential backoff (honoring `Retry-After` on

429) up to the queue's `max_retries`, after which the job lands in the
     dead-letter queue and is logged.

Setup (after `wrangler login` and setting `SHARED_KEY`):

```bash
npx wrangler queues create relay-jobs
npx wrangler queues create relay-dlq

# the Durable Object + migration are already declared in wrangler.toml
npm run deploy
```

Warning: Cloudflare Queues are **at-least-once**, so a forward that succeeds but
whose ack is lost may be retried, re-sending the request (e.g., a duplicate
Telegram message). Use the sync path when you need exactly-once-ish semantics.

## Testing

```bash
npm test               # run the vitest suite (workers pool)
npm run typecheck      # tsc --noEmit
```

Tests cover the crypto round-trip, tamper/forgery rejection, routing, input
validation, the destination allowlist, replay rejection, a full happy-path relay
with a mocked upstream, the token-bucket rate limiter (pure + real Durable
Object), retry/backoff classification, async ingress (`/async`), and the queue
consumer's ack/retry/rate-limit behavior.

## Operational notes & limitations

- **Clocks must be roughly in sync.** If the backend's clock drifts beyond
  `MAX_CLOCK_SKEW_SECONDS`, requests are rejected. Use NTP.
- **Key rotation.** To rotate, deploy a second Worker (or accept two keys) and
  migrate the backend, then retire the old key. The protocol carries an
  envelope version byte to ease future format changes.
- **KV is eventually consistent**, so nonce de-dup is strong but not perfectly
  atomic - sufficient for this threat model, not for high-stakes idempotency.
- **Not a general SOCKS/HTTP proxy.** It only performs the single, allowlisted
  request described in each (authenticated) envelope.
- **Cost.** Designed for low volume; well within the Workers free tier for a
  handful of requests per day. Watch KV operations if you enable `REPLAY_KV`.

## License

Released under the MIT License. See `LICENSE`.
