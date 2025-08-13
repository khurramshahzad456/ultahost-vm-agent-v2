package agent

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

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
	// authTOken:=os.Getenv("AUTH_TOKEN")

	req, err := http.NewRequest("POST", baseUrl+"/agent/register", bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to call backend: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respData, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("registration failed: %s", string(respData))
	}

	defer resp.Body.Close()

	encryptedData, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	decryptedData, err := decryptAESGCM(encryptionKey, encryptedData)
	if err != nil {
		panic(err)
	}

	// Parse JSON payload
	var payload map[string]string
	err = json.Unmarshal(decryptedData, &payload)
	if err != nil {
		panic(err)
	}

	// Save cert and key securely
	err = os.WriteFile(configDir+"/client.crt", []byte(payload["cert"]), 0644)
	if err != nil {
		panic(err)
	}
	err = os.WriteFile(configDir+"/client.key", []byte(payload["key"]), 0600)
	if err != nil {
		panic(err)
	}
	err = os.WriteFile(configDir+"/agent_token", []byte(payload["IdentityToken"]), 0644)
	if err != nil {
		panic(err)
	}
	err = os.WriteFile(configDir+"/signature_secret", []byte(payload["SignatureSecret"]), 0600)
	if err != nil {
		panic(err)
	}

	fmt.Println("Client certificate and key saved successfully")

	fmt.Println("✅ Registration successful, cert & key saved in")
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
