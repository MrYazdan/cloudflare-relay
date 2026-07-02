/**
 * http.ts
 * -------
 * Small helpers for building consistent HTTP responses.
 *
 * Design note on error responses: protocol-level failures (bad method, bad
 * payload, replay, disallowed host) are returned as *plaintext* JSON so the
 * operator/client can debug them. The messages are intentionally generic and
 * never reveal key material or whether decryption-vs-parsing failed.
 */

/** Standard JSON error body. */
export interface ErrorBody {
  error: string;
}

/** Build a JSON error response with no caching. */
export function jsonError(status: number, message: string): Response {
  const body: ErrorBody = { error: message };
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

/**
 * Build the success response carrying a sealed (base64) envelope. The body is
 * opaque ciphertext, so it is returned as plain text with no-store caching.
 */
export function sealedResponse(envelopeB64: string): Response {
  return new Response(envelopeB64, {
    status: 200,
    headers: {
      "content-type": "application/octet-stream",
      "cache-control": "no-store",
    },
  });
}
