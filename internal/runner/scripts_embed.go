package runner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

//go:generate echo "(no codegen)"

// Minimal safe scripts (avoid complex deps)
var scriptFiles = map[string]string{
	"check_uptime.sh": `#!/usr/bin/env bash
set -euo pipefail
uptime -p || cat /proc/uptime || true
`,
	"check_diskspace.sh": `#!/usr/bin/env bash
set -euo pipefail
df -hT || true
`,
	// placeholder — in prod you’ll expand with real logic guarded by allowlist
	"install_wordpress.sh": `#!/usr/bin/env bash
set -euo pipefail
echo "install_wordpress invoked with args: $*"
exit 0
`,
}

var expectedSHA = map[string]string{} // populated in init()

func init() {
	for name, body := range scriptFiles {
		sum := sha256.Sum256([]byte(body))
		expectedSHA[name] = hex.EncodeToString(sum[:])
	}
}

func MaterializeScripts(dir string) error {
	for name, body := range scriptFiles {
		full := filepath.Join(dir, name)
		if err := os.WriteFile(full, []byte(body), 0o750); err != nil {
			return fmt.Errorf("write %s: %w", full, err)
		}
	}
	return nil
}

func ExpectedSHA(name string) (string, bool) {
	v, ok := expectedSHA[name]
	return v, ok
}
