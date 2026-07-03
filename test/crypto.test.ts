import { describe, it, expect } from "vitest";
import {
  importKey,
  seal,
  open,
  bytesToBase64,
  base64ToBytes,
  CryptoError,
} from "../src/crypto.ts";

async function freshKey(): Promise<CryptoKey> {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  return importKey(bytesToBase64(raw));
}

const enc = new TextEncoder();
const dec = new TextDecoder();

describe("crypto envelope", () => {
  it("round-trips plaintext", async () => {
    const key = await freshKey();
    const message = "سلام - hello - 🚀";
    const sealed = await seal(key, enc.encode(message));
    const opened = await open(key, sealed);
    expect(dec.decode(opened)).toBe(message);
  });

  it("produces a different ciphertext each time (random IV)", async () => {
    const key = await freshKey();
    const a = await seal(key, enc.encode("same"));
    const b = await seal(key, enc.encode("same"));
    expect(a).not.toBe(b);
  });

  it("rejects a tampered ciphertext (authentication)", async () => {
    const key = await freshKey();
    const sealed = await seal(key, enc.encode("payload"));
    const bytes = base64ToBytes(sealed);
    const last = bytes.length - 1;
    bytes[last] = (bytes[last] ?? 0) ^ 0xff; // flip bits in the auth tag
    await expect(open(key, bytesToBase64(bytes))).rejects.toBeInstanceOf(
      CryptoError,
    );
  });

  it("rejects decryption with the wrong key", async () => {
    const k1 = await freshKey();
    const k2 = await freshKey();
    const sealed = await seal(k1, enc.encode("secret"));
    await expect(open(k2, sealed)).rejects.toBeInstanceOf(CryptoError);
  });

  it("rejects an unsupported envelope version", async () => {
    const key = await freshKey();
    const bytes = base64ToBytes(await seal(key, enc.encode("x")));
    bytes[0] = 0x99;
    await expect(open(key, bytesToBase64(bytes))).rejects.toBeInstanceOf(
      CryptoError,
    );
  });

  it("rejects a truncated envelope", async () => {
    const key = await freshKey();
    await expect(open(key, bytesToBase64(new Uint8Array(4)))).rejects.toBeInstanceOf(
      CryptoError,
    );
  });

  it("rejects keys of the wrong length", async () => {
    await expect(importKey(bytesToBase64(new Uint8Array(16)))).rejects.toBeInstanceOf(
      CryptoError,
    );
  });
});
