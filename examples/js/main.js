// Single-file example: send a Telegram message through the encrypted
// cloudflare-relay (synchronous POST / path). Uses only the Web Crypto API and the
// global fetch - no dependencies. Run on Node 20+ (use Buffer for base64).
//
// Run:
//   WORKER_URL=https://cloudflare-relay.<acct>.workers.dev/ \
//   SHARED_KEY=<base64-32-byte-key> \
//   TELEGRAM_TOKEN=<token> CHAT_ID=<chat-id> \
//   node main.js "Hello via Cloudflare"
//
// Envelope format (must match the Worker): base64( [0x01][12-byte IV][ciphertext||tag] ).

const WORKER_URL = mustEnv("WORKER_URL");
const TOKEN = mustEnv("TELEGRAM_TOKEN");
const CHAT_ID = mustEnv("CHAT_ID");
const KEY_BYTES = decodeKey(mustEnv("SHARED_KEY"));
const TEXT = process.argv.slice(2).join(" ") || "Hello from the encrypted cloudflare-relay 🚀";

const b64encode = (bytes) => Buffer.from(bytes).toString("base64");
const b64decode = (s) => new Uint8Array(Buffer.from(s.trim(), "base64"));

async function seal(key, plaintext) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext));
    const envelope = new Uint8Array(1 + iv.length + ct.length);
    envelope[0] = 0x01;
    envelope.set(iv, 1);
    envelope.set(ct, 1 + iv.length);
    return b64encode(envelope);
}

async function open(key, envB64) {
    const envelope = b64decode(envB64);
    const iv = envelope.subarray(1, 13);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, envelope.subarray(13));
    return new Uint8Array(pt);
}

async function main() {
    const key = await crypto.subtle.importKey("raw", KEY_BYTES, { name: "AES-GCM" }, false, [
        "encrypt",
        "decrypt",
    ]);
    const enc = new TextEncoder();

    // The request descriptor (inner, encrypted payload).
    const descriptor = enc.encode(
        JSON.stringify({
            v: 1,
            ts: Math.floor(Date.now() / 1000),
            nonce: crypto.randomUUID(),
            method: "POST",
            url: `https://api.telegram.org/bot${TOKEN}/sendMessage`,
            headers: { "content-type": "application/json" },
            body_b64: b64encode(enc.encode(JSON.stringify({ chat_id: CHAT_ID, text: TEXT }))),
        }),
    );

    const res = await fetch(WORKER_URL, {
        method: "POST",
        headers: { "content-type": "application/octet-stream" },
        body: await seal(key, descriptor),
    });
    const raw = await res.text();
    if (res.status !== 200) throw new Error(`worker returned ${res.status}: ${raw}`);

    const out = JSON.parse(new TextDecoder().decode(await open(key, raw)));
    const body = new TextDecoder().decode(b64decode(out.body_b64));
    console.log(`destination status: ${out.status}\ndestination body:   ${body}`);
}

function decodeKey(b64) {
    const key = new Uint8Array(Buffer.from(b64, "base64"));
    if (key.length !== 32) throw new Error("SHARED_KEY must be base64 of 32 bytes");
    return key;
}

function mustEnv(name) {
    const v = process.env[name];
    if (!v) throw new Error(`missing required environment variable ${name}`);
    return v;
}

main().catch((err) => {
    console.error("error:", err.message);
    process.exit(1);
});