/**
 * Wire-format definitions shared between the backend (encryptor) and the
 * Worker (decrypt). Keeping these in one place makes it trivial to keep the
 * Go client and the TypeScript Worker in sync.
 *
 * Transport overview
 * ==================
 * 1. The client serializes a `ForwardRequest` to JSON (UTF-8).
 * 2. It seals that JSON with AES-256-GCM into a binary envelope (see crypto.ts)
 *    and base64-encodes the envelope.
 * 3. The base64 string is sent as the raw HTTP POST body to the Worker.
 * 4. The Worker decrypts, validates, and forwards the described request.
 * 5. The Worker serializes a `ForwardResponse`, seals it the same way, and
 *    returns the base64 envelope as its HTTP response body.
 *
 * Everything between client and Worker is therefore opaque ciphertext; the
 * only plaintext on the wire is the base64 framing.
 */

/**
 * The current envelope/protocol version. Bump this if the binary envelope or
 * the JSON schema below changes in a backwards-incompatible way so both sides
 * can negotiate / reject mismatches early.
 */
export const PROTOCOL_VERSION = 1 as const;

/**
 * Description of the HTTP request the client wants the Worker to perform on its
 * behalf. This is the *inner* (decrypted) payload.
 */
export interface ForwardRequest {
  /** Protocol version. Must equal {@link PROTOCOL_VERSION}. */
  v: number;

  /**
   * Unix time (seconds) at which the client created the request. Used for
   * replay protection: the Worker rejects requests whose timestamp is too far
   * from its own clock.
   */
  ts: number;

  /**
   * Unique, single-use identifier for this request (e.g. a UUID). Used for
   * nonce-based replay protection when a REPLAY_KV namespace is bound.
   */
  nonce: string;

  /** HTTP method to use against the destination, e.g. "POST". */
  method: string;

  /**
   * Absolute destination URL, e.g.
   * "https://api.telegram.org/bot<token>/sendMessage".
   * The host MUST be present in the Worker's ALLOWED_HOSTS allowlist and the
   * scheme MUST be https.
   */
  url: string;

  /**
   * Optional headers to send to the destination. Hop-by-hop and unsafe headers
   * (host, content-length, connection, ...) those are stripped by the Worker.
   */
  headers?: Record<string, string>;

  /**
   * Optional request body, base64-encoded, so arbitrary binary payloads survive
   * the JSON round-trip. Omit (or leave empty) for bodiless methods like GET.
   */
  body_b64?: string;

  /**
   * Optional rate-limit key for the async (queued) path, e.g., a Telegram
   * `chat_id`. Requests sharing a key share one token bucket. When omitted, the
   * destination host is used as the key. Ignored by the synchronous path.
   */
  rate_key?: string;
}

/**
 * The result of the forwarded request, returned (encrypted) to the client.
 * This is the *inner* (decrypted) response payload.
 */
export interface ForwardResponse {
  /** Protocol version. Equals {@link PROTOCOL_VERSION}. */
  v: number;

  /** Unix time (seconds) at which the Worker produced this response. */
  ts: number;

  /** HTTP status code returned by the destination. */
  status: number;

  /** Response headers returned by the destination. */
  headers: Record<string, string>;

  /** Destination response body, base64-encoded (binary-safe). */
  body_b64: string;
}
