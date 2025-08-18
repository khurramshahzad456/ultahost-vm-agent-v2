package agent

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// var configDir = "/var/lib/ultaai/config"

var configDir = "ultaai-dev/config"

type RegisterRequest struct {
	InstallToken string `json:"install_token"`
	VPSID        string `json:"vps_id" binding:"required"`
}

type RegisterResponse struct {
	IdentityToken   string `json:"identity_token"`
	SignatureSecret string `json:"signature_secret"`
	Certificate     string `json:"certificate"`
	PrivateKey      string `json:"private_key"`
}

func savePEMFromBase64(b64 string, begin string, end string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		// maybe already PEM
		return []byte(b64), nil
	}

	str := string(decoded)
	if !strings.Contains(str, begin) {
		// wrap into PEM
		body := base64.StdEncoding.EncodeToString(decoded)
		var sb strings.Builder
		sb.WriteString(begin + "\n")
		for i := 0; i < len(body); i += 64 {
			endIndex := i + 64
			if endIndex > len(body) {
				endIndex = len(body)
			}
			sb.WriteString(body[i:endIndex] + "\n")
		}
		sb.WriteString(end + "\n")
		return []byte(sb.String()), nil
	}

	return decoded, nil
}
func RegisterAgent(token string, vpsId string) error {
	reqBody := RegisterRequest{
		InstallToken: token,
		VPSID:        vpsId,
	}
	bodyBytes, _ := json.Marshal(reqBody)
	baseUrl := os.Getenv("BASE_URL")

	req, err := http.NewRequest("POST", baseUrl+"/agent/register", bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to call backend: %w", err)
	}
	defer resp.Body.Close()

	respData, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("registration failed: %s", string(respData))
	}

	encryptedData := respData // this is the encrypted blob

	decryptedData, err := decryptAESGCM(encryptionKey, encryptedData)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	var payload map[string]string
	if err := json.Unmarshal(decryptedData, &payload); err != nil {
		return fmt.Errorf("unmarshal failed: %w", err)
	}

	// Save cert and key securely (PEM strings)
	if err := os.WriteFile(configDir+"/ca.crt", []byte(payload["Cert"]), 0644); err != nil {
		return err
	}
	if err := os.WriteFile(configDir+"/client.crt", []byte(payload["cert"]), 0644); err != nil {
		return err
	}
	if err := os.WriteFile(configDir+"/client.key", []byte(payload["key"]), 0600); err != nil {
		return err
	}
	if err := os.WriteFile(configDir+"/agent_identity_token", []byte(payload["IdentityToken"]), 0644); err != nil {
		return err
	}
	// trim newline from signature secret to avoid HMAC mismatch
	sig := strings.TrimSpace(payload["SignatureSecret"])
	if err := os.WriteFile(configDir+"/signature_secret", []byte(sig), 0600); err != nil {
		return err
	}
	if err := os.WriteFile(configDir+"/fingerprint_sha256", []byte(payload["FingerprintSHA256"]), 0644); err != nil {
		return err
	}

	fmt.Println("✅ Registration successful, cert & key saved")
	return nil
}

var encryptionKey = []byte("0123456789abcdef0123456789abcdef")

func decryptAESGCM(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ct, nil)
}
