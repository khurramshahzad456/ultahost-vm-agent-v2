package main

import (
	"log"
	"os"
	"time"

	"ultahost-agent/internal/agent"

	"github.com/joho/godotenv"
)

func main() {
	log.Println("UltaAI Agent starting...")

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// Assume token is passed as an env var or CLI arg; here env var for demo
	installToken := os.Getenv("INSTALL_TOKEN")
	if installToken == "" {
		log.Fatal("INSTALL_TOKEN not provided")
	}

	// Register agent using install token
	err = agent.RegisterAgent(installToken, "483")
	if err != nil {
		log.Fatalf("Agent registration failed: %v", err)
	}
	log.Println("Agent registered successfully")

	time.Sleep(5 * time.Second)
	// Connect to backend WebSocket and start heartbeat
	err = agent.ConnectAndHeartbeat()
	if err != nil {
		log.Fatalf("WebSocket connection failed: %v", err)
	}

}
