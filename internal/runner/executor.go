package runner

import (
	"os/exec"
)

func ExecuteScript(path string) (string, error) {
	cmd := exec.Command("bash", path)
	output, err := cmd.CombinedOutput()
	return string(output), err
}
