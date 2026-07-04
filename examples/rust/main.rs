#!/usr/bin/env python3
"""Single-file example: send a Telegram message through the encrypted
cloudflare-relay (synchronous POST / path).

Dependencies: the `cryptography` package (pip install cryptography). HTTP uses
the standard library (urllib).

Run:
    WORKER_URL=https://cloudflare-relay.<acct>.workers.dev/ \
    SHARED_KEY=<base64-32-byte-key> \
    TELEGRAM_TOKEN=<token> CHAT_ID=<chat-id> \
    python3 main.py "Hello via Cloudflare"

Envelope format (must match the Worker): base64( [0x01][12-byte IV][ciphertext||tag] ).
"""
import base64
import json
import os
import sys
import time
import uuid
import urllib.request

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def seal(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt plaintext into the base64 envelope."""
    iv = os.urandom(12)
    # AESGCM.encrypt appends the 16-byte tag to the ciphertext, matching the
    # Worker's [ciphertext||tag] layout.
    ciphertext = AESGCM(key).encrypt(iv, plaintext, None)
    return base64.standard_b64encode(b"\x01" + iv + ciphertext)


def open_(key: bytes, env_b64: bytes) -> bytes:
    """Decrypt a base64 envelope produced by the Worker."""
    envelope = base64.standard_b64decode(env_b64.strip())
    iv, ciphertext = envelope[1:13], envelope[13:]
    return AESGCM(key).decrypt(iv, ciphertext, None)


def must_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        sys.exit(f"error: missing required environment variable {name}")
    return value


def main() -> None:
    worker_url = must_env("WORKER_URL")
    token = must_env("TELEGRAM_TOKEN")
    chat_id = must_env("CHAT_ID")
    key = base64.standard_b64decode(must_env("SHARED_KEY"))
    if len(key) != 32:
        sys.exit("error: SHARED_KEY must be base64 of 32 bytes")

    text = " ".join(sys.argv[1:]) or "Hello from the encrypted cloudflare-relay 🚀"

    tg_body = json.dumps({"chat_id": chat_id, "text": text}).encode()
    descriptor = json.dumps(
        {
            "v": 1,
            "ts": int(time.time()),
            "nonce": uuid.uuid4().hex,
            "method": "POST",
            "url": f"https://api.telegram.org/bot{token}/sendMessage",
            "headers": {"content-type": "application/json"},
            "body_b64": base64.standard_b64encode(tg_body).decode(),
        }
    ).encode()

    request = urllib.request.Request(
        worker_url,
        data=seal(key, descriptor),
        headers={"content-type": "application/octet-stream"},
        method="POST",
    )
    with urllib.request.urlopen(request) as response:
        raw = response.read()

    out = json.loads(open_(key, raw))
    body = base64.standard_b64decode(out["body_b64"]).decode()
    print(f"destination status: {out['status']}")
    print(f"destination body:   {body}")


if __name__ == "__main__":
    main()