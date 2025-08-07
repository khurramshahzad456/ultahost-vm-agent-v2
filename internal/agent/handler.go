package agent

import (
	"os/exec"

	"ultahost-vm-agent/internal/config"
	"ultahost-vm-agent/pkg/models"

	"github.com/gin-gonic/gin"
)

func RunCommand(c *gin.Context) {
	var req models.CommandRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request", "details": err.Error()})
		return
	}
	if req.Hash != config.Get().Hash {
		c.JSON(401, gin.H{"error": "Invalid hash"})
		return
	}
	cmd := exec.Command("bash", "-c", req.Command)
	output, err := cmd.CombinedOutput()

	resp := models.CommandResponse{
		Output: string(output),
	}
	if err != nil {
		resp.Error = err.Error()
	}

	c.JSON(200, resp)
}
