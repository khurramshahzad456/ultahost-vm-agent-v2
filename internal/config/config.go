package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	Hash string
	IP   string
}

var appConfig Config

func Load() error {
	err := godotenv.Load("systemd/run-agent.env")

	if err != nil {
		log.Fatalf("err loading: %v", err)
	}

	appConfig.Hash = os.Getenv("RUN_AGENT_HASH")
	appConfig.IP = os.Getenv("WHITELISTED_IP")

	if appConfig.Hash == "" || appConfig.IP == "" {
		log.Fatal("RUN_AGENT_HASH and WHITELISTED_IP must be set")
	}

	return nil
}

func Get() Config {
	return appConfig
}
