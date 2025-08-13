package agent

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/gorilla/websocket"
)

var configDir = "./test-vm-agent"

func ConnectAndHeartbeat() error {
	// Load client certificate and private key
	clientCert, err := tls.LoadX509KeyPair(configDir+"/client.crt", configDir+"/client.key")
	if err != nil {
		log.Fatalf("Failed to load client cert/key: %v", err)
	}

	// Load CA certificate (to verify server certificate)
	caCertPEM, err := ioutil.ReadFile("./crts/ca.crt")
	if err != nil {
		log.Fatalf("Failed to read CA cert: %v", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCertPEM) {
		log.Fatalf("Failed to append CA cert to pool")
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{clientCert},
		RootCAs:            caCertPool,
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS13,
	}

	dialer := websocket.Dialer{
		TLSClientConfig: tlsConfig,
	}

	baseUrl := os.Getenv("WS_BASE_URL")

	url := baseUrl + "/agent/connect"

	conn, resp, err := dialer.Dial(url, nil)
	if err != nil {
		if resp != nil {
			log.Fatalf("WebSocket dial error: %v, HTTP status: %v", err, resp.Status)
		} else {
			log.Fatalf("WebSocket dial error: %v, no HTTP response", err)
		}
	}
	defer conn.Close()

	log.Println("WebSocket connection established with mutual TLS!")

	// Example: send a test message to server
	err = conn.WriteMessage(websocket.TextMessage, []byte("Hello from Agent!"))
	if err != nil {
		log.Fatalf("Failed to send message: %v", err)
	}

	// Read response from server
	_, message, err := conn.ReadMessage()
	if err != nil {
		log.Fatalf("Failed to read message: %v", err)
	}

	log.Printf("Received message: %s", message)

	signatureSecret, err := ioutil.ReadFile(configDir + "/signature_secret")
	if err != nil {
		return fmt.Errorf("failed to load signature secret: %w", err)
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			msg := prepareHeartbeatMessage(signatureSecret)
			err := conn.WriteMessage(websocket.TextMessage, []byte(msg))
			if err != nil {
				return fmt.Errorf("failed to send heartbeat: %w", err)
			}
			log.Println("Heartbeat sent")
		}
	}
}

func prepareHeartbeatMessage(signatureSecret []byte) string {
	// TODO: Replace with actual signing using signatureSecret
	return fmt.Sprintf(`{"message":"I'm alive","signature":"%x"}`, signatureSecret[:8])
}
