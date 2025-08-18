package agent

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
)

var (
	BaseDir    string
	LogDir     string
	ConfigDir  string
	ScriptsDir string
	ChrootDir  string
)

func InitRuntimeDirs() error {
	// Prefer environment override for tests
	if v := os.Getenv("ULTA_BASE_DIR"); v != "" {
		BaseDir = v
	} else {
		// root → FHS paths; non-root → dev sandbox next to repo
		if os.Geteuid() == 0 {
			BaseDir = "/var/lib/ultaai"
		} else {
			// BaseDir = ".ultaai-dev"
			BaseDir = "/ultaai-dev"

		}
	}
	if os.Geteuid() == 0 {
		LogDir = "/var/log/ultaai"
	} else {
		LogDir = filepath.Join(BaseDir, "logs")
	}

	ConfigDir = filepath.Join(BaseDir, "config")
	ScriptsDir = filepath.Join(BaseDir, "scripts")
	ChrootDir = BaseDir // we chroot into BaseDir (scripts live under /scripts inside chroot)

	for _, d := range []string{BaseDir, LogDir, ConfigDir, ScriptsDir} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
	}

	// create audit log file early (append mode)
	if f, err := os.OpenFile(filepath.Join(LogDir, "audit.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640); err == nil {
		f.Close()
	} else {
		log.Printf("warn: cannot open audit log: %v", err)
	}
	return nil
}

func ReadSignatureSecret() ([]byte, error) {
	// kept compatible with your existing enrollment artifacts
	// pref: ConfigDir/signature_secret; fallback: ./test-vm-agent/signature_secret
	paths := []string{
		filepath.Join(ConfigDir, "signature_secret"),
		"./test-vm-agent/signature_secret",
	}
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil {
			return []byte(string(b)), nil
		}
	}
	return nil, fmt.Errorf("signature_secret not found in %v", paths)
}

func CACertPath() string { return "./crts/ca.crt" }
func ClientCertPath() string {
	return filepath.Join(ConfigDir, "client.crt")
}
func ClientKeyPath() string {
	return filepath.Join(ConfigDir, "client.key")
}
