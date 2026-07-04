// Single-file example: send a Telegram message through the encrypted
// cloudflare-relay (synchronous POST / path), using only the Go standard library.
//
// Run:
//
//	cd examples/go
//	go mod init example >/dev/null 2>&1   # only needed once, if no go.mod
//	WORKER_URL=https://cloudflare-relay.<acct>.workers.dev/ \
//	SHARED_KEY=<base64-32-byte-key> \
//	TELEGRAM_TOKEN=<token> CHAT_ID=<chat-id> \
//	go run main.go "Hello via Cloudflare"
//
// Envelope format (must match the Worker): base64( [0x01][12-byte IV][ciphertext||tag] ).
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	workerURL := mustEnv("WORKER_URL")
	key := mustKey(mustEnv("SHARED_KEY"))
	token := mustEnv("TELEGRAM_TOKEN")
	chatID := mustEnv("CHAT_ID")

	text := "Hello from the encrypted cloudflare-relay 🚀"
	if len(os.Args) > 1 {
		text = strings.Join(os.Args[1:], " ")
	}

	// 1. The Telegram API call we want the Worker to perform for us.
	tgBody, _ := json.Marshal(map[string]any{"chat_id": chatID, "text": text})

	// 2. The request descriptor (the inner, encrypted payload).
	nonce := make([]byte, 16)
	rand.Read(nonce)
	descriptor, _ := json.Marshal(map[string]any{
		"v":        1,
		"ts":       time.Now().Unix(),
		"nonce":    hex.EncodeToString(nonce),
		"method":   "POST",
		"url":      fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token),
		"headers":  map[string]string{"content-type": "application/json"},
		"body_b64": base64.StdEncoding.EncodeToString(tgBody),
	})

	// 3. Seal, POST, then open the sealed response.
	resp, err := http.Post(workerURL, "application/octet-stream", bytes.NewReader(seal(key, descriptor)))
	if err != nil {
		fail(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		fail(fmt.Errorf("worker returned %d: %s", resp.StatusCode, bytes.TrimSpace(raw)))
	}

	var out struct {
		Status  int    `json:"status"`
		BodyB64 string `json:"body_b64"`
	}
	if err := json.Unmarshal(open(key, raw), &out); err != nil {
		fail(err)
	}
	body, _ := base64.StdEncoding.DecodeString(out.BodyB64)
	fmt.Printf("destination status: %d\ndestination body:   %s\n", out.Status, body)
}

// seal encrypts plaintext into the base64 envelope.
func seal(key, plaintext []byte) []byte {
	gcm := newGCM(key)
	iv := make([]byte, gcm.NonceSize())
	rand.Read(iv)
	ciphertext := gcm.Seal(nil, iv, plaintext, nil)
	envelope := append(append([]byte{0x01}, iv...), ciphertext...)
	return []byte(base64.StdEncoding.EncodeToString(envelope))
}

// open decrypts a base64 envelope produced by the Worker.
func open(key, envB64 []byte) []byte {
	envelope, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(envB64)))
	if err != nil {
		fail(err)
	}
	gcm := newGCM(key)
	iv := envelope[1 : 1+gcm.NonceSize()]
	plaintext, err := gcm.Open(nil, iv, envelope[1+gcm.NonceSize():], nil)
	if err != nil {
		fail(err)
	}
	return plaintext
}

func newGCM(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		fail(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		fail(err)
	}
	return gcm
}

func mustKey(b64 string) []byte {
	key, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(key) != 32 {
		fail(fmt.Errorf("SHARED_KEY must be base64 of 32 bytes"))
	}
	return key
}

func mustEnv(name string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	fail(fmt.Errorf("missing required environment variable %s", name))
	return ""
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}