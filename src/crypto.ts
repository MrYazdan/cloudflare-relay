/**
 * crypto.ts
 * ---------
 * Authenticated symmetric encryption (AES-256-GCM) used to protect every
 * message exchanged between the backend and the Worker.
 *
 * Why AES-256-GCM?
 *   - It is an AEAD cipher: it provides confidentiality *and* integrity /
 *     authenticity in one primitive. A tampered or forged ciphertext fails to
 *     decrypt, so only a holder of the shared key can produce a message the
 *     Worker will accept. This doubles as authentication - no separate API key
 *     is required.
 *   - It is implemented in hardware on virtually all platforms and is exposed
 *     by the Web Crypto API (`crypto.subtle`) available in the Workers runtime.
 *
 * Binary envelope layout (before base64):
 *
 *   ┌─────────┬──────────────┬──────────────────────────────┐
 *   │ version │      IV      │      ciphertext ‖ tag        │
 *   │ 1 byte  │   12 bytes   │  N bytes (tag is last 16 B)  │
 *   └─────────┴──────────────┴──────────────────────────────┘
 *
 * The 16-byte GCM authentication tag is appended to the ciphertext by Web
 * Crypto automatically, so we do not track it separately.
 */

/** Envelope format version, stored in the first byte of every envelope. */
const ENVELOPE_VERSION = 0x01;

/** AES-GCM nonce length in bytes. 96 bits is the value recommended by NIST. */
const IV_LENGTH = 12;

/** Required raw key length in bytes (AES-256). */
const KEY_LENGTH = 32;

/** GCM authentication tag length in bytes. */
const TAG_LENGTH = 16;

/** Minimum valid envelope size: version + IV + (at least) the auth tag. */
const MIN_ENVELOPE_LENGTH = 1 + IV_LENGTH + TAG_LENGTH;

/**
 * Error thrown for any cryptographic / envelope failure. Callers should treat
 * every instance as "the message is invalid" and avoid surfacing details to
 * the client (to not leak whether decryption vs. parsing failed).
 */
export class CryptoError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CryptoError";
  }
}

/**
 * Import a base64-encoded 32-byte key into a non-extractable {@link CryptoKey}.
 *
 * @param keyB64 Standard base64 encoding of exactly 32 random bytes.
 * @throws {CryptoError} if the key is not valid base64 or not 32 bytes long.
 */
export async function importKey(keyB64: string): Promise<CryptoKey> {
  let raw: Uint8Array;
  try {
    raw = base64ToBytes(keyB64);
  } catch {
    throw new CryptoError("SHARED_KEY is not valid base64");
  }
  if (raw.length !== KEY_LENGTH) {
    throw new CryptoError(
      `SHARED_KEY must decode to ${KEY_LENGTH} bytes (got ${raw.length})`,
    );
  }
  // `extractable = false` so the key material cannot be read back out of the
  // CryptoKey object once imported.
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

/**
 * Encrypt `plaintext` and return the base64-encoded envelope.
 *
 * A fresh random 96-bit IV is generated for every call - this is critical for
 * GCM security (an IV must never be reused with the same key).
 */
export async function seal(
  key: CryptoKey,
  plaintext: Uint8Array,
): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));

  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext),
  );

  const envelope = new Uint8Array(1 + IV_LENGTH + ciphertext.length);
  envelope[0] = ENVELOPE_VERSION;
  envelope.set(iv, 1);
  envelope.set(ciphertext, 1 + IV_LENGTH);

  return bytesToBase64(envelope);
}

/**
 * Decrypt and authenticate a base64-encoded envelope produced by {@link seal}.
 *
 * @returns the original plaintext bytes.
 * @throws {CryptoError} for malformed, truncated, wrong-version, or
 *         tamper/forged (authentication failure) envelopes.
 */
export async function open(
  key: CryptoKey,
  envelopeB64: string,
): Promise<Uint8Array> {
  let envelope: Uint8Array;
  try {
    envelope = base64ToBytes(envelopeB64);
  } catch {
    throw new CryptoError("payload is not valid base64");
  }

  if (envelope.length < MIN_ENVELOPE_LENGTH) {
    throw new CryptoError("envelope is too short");
  }
  if (envelope[0] !== ENVELOPE_VERSION) {
    throw new CryptoError(`unsupported envelope version: ${envelope[0]}`);
  }

  const iv = envelope.subarray(1, 1 + IV_LENGTH);
  const ciphertext = envelope.subarray(1 + IV_LENGTH);

  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      ciphertext,
    );
    return new Uint8Array(plaintext);
  } catch {
    // Web Crypto throws a generic error on tag-mismatch; normalise it.
    throw new CryptoError("decryption/authentication failed");
  }
}

// base64 helpers
//
// The Workers runtime exposes `atob` / `btoa`, which operate on "binary
// strings" (one char per byte). The loops below convert to/from Uint8Array.
// For the low-volume, modestly-sized payloads this service handles, the simple
// per-byte loop is more than fast enough and avoids extra dependencies.

/** Encode bytes as a standard base64 string. */
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary);
}

/**
 * Decode a standard base64 string into bytes.
 * @throws if the input is not valid base64 (propagated from `atob`).
 */
export function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64.trim());
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
