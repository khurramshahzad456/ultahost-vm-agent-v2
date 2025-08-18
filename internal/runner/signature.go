package runner

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	configDir         = "/var/lib/ultaai/config" //"./test-vm-agent" // reuse your existing layout
	signatureFileName = "signature_secret"
	clockSkew         = 5 * time.Minute
)

// canonicalString MUST match assistant-side signing exactly
func canonicalString(task string, args []string, nonce, ts string) string {
	// fixed delimiter + order; args joined safely
	return fmt.Sprintf("v1|%s|%s|%s|%s", task, strings.Join(args, " "), nonce, ts)
}

func readSignatureSecret() ([]byte, error) {
	p := filepath.Join(configDir, signatureFileName)
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("read signature_secret: %w", err)
	}
	return []byte(strings.TrimSpace(string(b))), nil
}

func verifyHMACBase64(secret []byte, msg, b64sig string) (bool, error) {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(msg))
	expected := mac.Sum(nil)
	got, err := base64.StdEncoding.DecodeString(b64sig)
	if err != nil {
		return false, fmt.Errorf("invalid signature encoding: %w", err)
	}
	return hmac.Equal(expected, got), nil
}

func ValidateTaskSignature(req TaskRequest) (bool, error) {
	// timestamp freshness
	ts, err := time.Parse(time.RFC3339, req.Timestamp)
	if err != nil {
		return false, errors.New("bad timestamp format")
	}
	now := time.Now().UTC()
	if ts.Before(now.Add(-clockSkew)) || ts.After(now.Add(clockSkew)) {
		return false, errors.New("timestamp outside allowed skew")
	}
	secret, err := readSignatureSecret()
	if err != nil {
		return false, err
	}
	msg := canonicalString(req.Task, req.Args, req.Nonce, req.Timestamp)
	ok, err := verifyHMACBase64(secret, msg, req.Signature)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, errors.New("HMAC mismatch")
	}
	return true, nil
}
