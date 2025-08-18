package utils

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

var (
	configDir    = "/var/lib/ultaai/config" //"./test-vm-agent"
	heartbeatCtr uint64                     // monotonic counter
	heartbeatVer = 1                        //"1"  // bump if you change signing format
	agentIDPath  = "/etc/ultaai-agent-id"
)

// type heartbeatPayload struct {
// 	Type      string `json:"type"`      // "heartbeat"
// 	Version   string `json:"version"`   // schema/signature version
// 	AgentID   string `json:"agent_id"`  // unique agent id (UUID)
// 	Counter   uint64 `json:"counter"`   // anti-replay (monotonic per-process)
// 	Nonce     string `json:"nonce"`     // base64 random bytes
// 	Timestamp string `json:"timestamp"` // RFC3339
// 	Signature string `json:"signature"` // base64 HMAC-SHA256 over canonical string
// }

func randBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

func GetAgentID() string {
	if v := strings.TrimSpace(os.Getenv("AGENT_ID")); v != "" {
		return v
	}
	b, err := os.ReadFile(agentIDPath)
	if err == nil {
		id := strings.TrimSpace(string(b))
		if id != "" {
			return id
		}
	}
	return "unknown"
}

// canonical string: fixed order & delimiter to avoid ambiguity
func canonicalString(v int, agent string, ctr uint64, nonceB64, ts string) string {
	// Keep this EXACT order and delimiter consistent across client/server
	return fmt.Sprintf("%s|%s|%d|%s|%s", v, agent, ctr, nonceB64, ts)
}

func signHMACSHA256(secret []byte, msg string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(msg))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func IsTimestampFresh(ts string, skew time.Duration) bool {
	// Try RFC3339Nano, then RFC3339
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		t, err = time.Parse(time.RFC3339, ts)
		if err != nil {
			return false
		}
	}
	// Absolute delta from now (UTC)
	now := time.Now().UTC()
	delta := now.Sub(t.UTC())
	if delta < 0 {
		delta = -delta
	}
	return delta <= skew
}

// Build & sign heartbeat
func PrepareHeartbeatMessage(signatureSecret []byte) string {
	ctr := atomic.AddUint64(&heartbeatCtr, 1)

	nonce, err := randBytes(16) // 128-bit nonce
	if err != nil {
		// if RNG fails, still progress with timestamp-only uniqueness
		nonce = []byte(fmt.Sprintf("fallback-%d", time.Now().UnixNano()))
	}
	nonceB64 := base64.StdEncoding.EncodeToString(nonce)

	ts := time.Now().UTC().Format(time.RFC3339Nano)
	agentID := GetAgentID()

	canon := canonicalString(heartbeatVer, agentID, ctr, nonceB64, ts)
	sig := signHMACSHA256(signatureSecret, canon)

	// collect metrics
	metrics := collectSystemMetrics()

	hb := heartbeatPayload{
		Type:      "heartbeat",
		Version:   heartbeatVer,
		AgentID:   agentID,
		Counter:   ctr,
		Nonce:     nonceB64,
		Timestamp: ts,
		Signature: sig,
		Metrics:   metrics,
	}

	b, _ := json.Marshal(hb) // safe: fields well-formed
	return string(b)
}
