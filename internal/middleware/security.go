package middleware

import (
	"net"
	"net/http"
	"strings"

	"ultahost-vm-agent/internal/config"

	"github.com/gin-gonic/gin"
)

func ValidateIP() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip, _, err := net.SplitHostPort(c.Request.RemoteAddr)
		if err != nil || strings.TrimSpace(ip) != config.Get().IP {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "unauthorized IP"})
			return
		}
		c.Next()
	}
}
