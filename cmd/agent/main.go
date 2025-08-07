package main

import (
	"log"

	"ultahost-vm-agent/internal/agent"
	"ultahost-vm-agent/internal/config"
	"ultahost-vm-agent/internal/middleware"

	"github.com/gin-gonic/gin"
)

func main() {
	if err := config.Load(); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	r := gin.Default()
	r.Use(middleware.ValidateIP())
	r.POST("/run-command", agent.RunCommand)

	log.Println("Secure VM agent running on :8080")
	if err := r.Run(":8083"); err != nil {
		log.Fatal(err)
	}
}
