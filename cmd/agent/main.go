package main

import (
	"fmt"
	"log"
	"os"

	"ultahost-agent/internal/runner"
)

func main() {
	os.MkdirAll("logs", os.ModePerm)
	logFile, err := os.OpenFile("logs/ultaai/agent.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)

	if err != nil {
		log.Fatalf("Failed to create log file: %v", err)
	}
	log.SetOutput(logFile)
	fmt.Println(" log for binary excuted successfully  ")

	scriptPath := "scripts/test_file.sh"
	output, err := runner.ExecuteScript(scriptPath)
	if err != nil {
		log.Printf(" Script execution failed: %v", err)
	} else {
		log.Printf(" Script executed successfully:\n%s", output)
	}
}
