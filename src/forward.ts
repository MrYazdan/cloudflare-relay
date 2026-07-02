/**
 * Validates a decrypted {@link ForwardRequest} and performs the actual outbound
 * HTTP request to the destination, then captures the result as a
 * {@link ForwardResponse}.
 *
 * Security responsibilities of this module:
 *   - SSRF / open-proxy guard: only https URLs whose host is in the allowlist
 *     are permitted.
 *   - Header hygiene: hop-by-hop and connection-specific headers supplied by
 *     the client are stripped before they reach the destination.
 *   - Resource bounds: enforce a maximum body size and an upstream timeout.
 */

import type { Config } from "./config.ts";
import { base64ToBytes, bytesToBase64 } from "./crypto.ts";
import {
  PROTOCOL_VERSION,
  type ForwardRequest,
  type ForwardResponse,
} from "./protocol.ts";

/**
 * Error carrying an HTTP status code, raised when a forward request is invalid
 * or fails. The `status` is used for the (plaintext) error response sent back
 * to the client.
 */
export class ForwardError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "ForwardError";
    this.status = status;
  }
}

/**
 * Request headers that must never be copied from the client-supplied descriptor
 * to the destination. These are connection/hop-by-hop headers or values the
 * runtime must control itself (host, content-length).
 */
const STRIPPED_REQUEST_HEADERS = new Set([
  "host",
  "content-length",
  "connection",
  "keep-alive",
  "proxy-authorization",
  "proxy-connection",
  "transfer-encoding",
  "te",
  "trailer",
  "upgrade",
  "expect",
]);

/**
 * Response headers that should not be echoed back inside the encrypted
 * response. They describe the Worker↔destination hop and would be misleading or
 * invalid for the client to replay.
 */
const STRIPPED_RESPONSE_HEADERS = new Set([
  "content-encoding",
  "content-length",
  "transfer-encoding",
  "connection",
  "keep-alive",
]);

/**
 * Validate the destination URL and ensure it is allowed.
 * @throws {ForwardError} 400 for malformed URLs, 403 for disallowed hosts.
 */
function validateUrl(rawUrl: string, config: Config): URL {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new ForwardError(400, "invalid destination url");
  }
  if (url.protocol !== "https:") {
    throw new ForwardError(400, "destination scheme must be https");
  }
  // In wildcard mode, the allowlist is bypassed; any https host is permitted.
  // `URL.hostname` excludes the port and is already lower-cased.
  if (
    !config.allowAllHosts &&
    !config.allowedHosts.has(url.hostname.toLowerCase())
  ) {
    throw new ForwardError(403, "destination host is not allowed");
  }
  return url;
}

/** Build the sanitized header set forwarded to the destination. */
function buildRequestHeaders(
  source: Record<string, string> | undefined,
): Headers {
  const headers = new Headers();
  if (!source) return headers;
  for (const [name, value] of Object.entries(source)) {
    if (STRIPPED_REQUEST_HEADERS.has(name.toLowerCase())) continue;
    headers.set(name, value);
  }
  return headers;
}

/**
 * Decode the optional base64 request body and enforce the size limit.
 * @throws {ForwardError} 400 on invalid base64, 413 if too large.
 */
function decodeBody(req: ForwardRequest, config: Config): Uint8Array | null {
  if (!req.body_b64) return null;
  let body: Uint8Array;
  try {
    body = base64ToBytes(req.body_b64);
  } catch {
    throw new ForwardError(400, "request body is not valid base64");
  }
  if (body.length > config.maxBodyBytes) {
    throw new ForwardError(413, "request body exceeds the configured limit");
  }
  return body;
}

/** A request that has passed validation and is ready to be sent upstream. */
interface PreparedRequest {
  url: URL;
  method: string;
  headers: Headers;
  body: Uint8Array | null;
}

/**
 * Validate a request descriptor and prepare the pieces needed to send it.
 * Throws the same {@link ForwardError}s as a forward attempt would, so the
 * async ingress path can reject invalid requests synchronously (before
 * enqueueing) by calling this and discarding the result.
 *
 * @throws {ForwardError} for an invalid method, url, host, scheme, or body.
 */
export function prepareForward(
  req: ForwardRequest,
  config: Config,
): PreparedRequest {
  if (req.method.length === 0) {
    throw new ForwardError(400, "method is required");
  }
  return {
    url: validateUrl(req.url, config),
    method: req.method.toUpperCase(),
    headers: buildRequestHeaders(req.headers),
    body: decodeBody(req, config),
  };
}

/**
 * Perform the forwarded request and collect the destination's response.
 *
 * @param req    The validated, decrypted request descriptor.
 * @param config The Worker configuration.
 * @returns A {@link ForwardResponse} ready to be sealed and returned.
 * @throws {ForwardError} for validation failures, timeouts, or network errors.
 */
export async function forward(
  req: ForwardRequest,
  config: Config,
): Promise<ForwardResponse> {
  const { url, method, headers, body } = prepareForward(req, config);

  // Enforce an upstream timeout so a slow/hung destination cannot pin the
  // Worker invocation open indefinitely.
  const controller = new AbortController();
  const timeout = setTimeout(
    () => controller.abort(),
    config.upstreamTimeoutMs,
  );

  let upstream: Response;
  try {
    upstream = await fetch(url.toString(), {
      method,
      headers,
      body: body ?? undefined,
      signal: controller.signal,
      // We forward exactly what we were asked to; never follow cross-origin
      // redirects automatically (a redirect could point at a disallowed host).
      redirect: "manual",
    });
  } catch (err) {
    if (err instanceof Error && err.name === "AbortError") {
      throw new ForwardError(504, "destination timed out");
    }
    throw new ForwardError(502, "failed to reach destination");
  } finally {
    clearTimeout(timeout);
  }

  // Read the full response body up front; enforce the same size cap on the way
  // back so a huge destination response cannot blow past our limit.
  const responseBytes = new Uint8Array(await upstream.arrayBuffer());
  if (responseBytes.length > config.maxBodyBytes) {
    throw new ForwardError(502, "destination response exceeds the limit");
  }

  const responseHeaders: Record<string, string> = {};
  upstream.headers.forEach((value, key) => {
    if (!STRIPPED_RESPONSE_HEADERS.has(key.toLowerCase())) {
      responseHeaders[key] = value;
    }
  });

  return {
    v: PROTOCOL_VERSION,
    ts: Math.floor(Date.now() / 1000),
    status: upstream.status,
    headers: responseHeaders,
    body_b64: bytesToBase64(responseBytes),
  };
}
