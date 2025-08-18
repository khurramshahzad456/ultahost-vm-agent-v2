package runner

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	sandboxRoot  = "/var/lib/ultaai/sandbox" // chroot base
	auditLogPath = "/var/log/ultaai/audit.log"
	cgroupRoot   = "/sys/fs/cgroup"
	cgroupDomain = "ultaai"   // parent path: /sys/fs/cgroup/ultaai
	maxRAMBytes  = 1073741824 // 1 GiB
	maxIOBps     = 104857600  // 100 MB/s
	cpuQuota     = 80000      // in microseconds
	cpuPeriod    = 100000     // in microseconds
	softTimeout  = 30 * time.Minute
	hardTimeout  = 35 * time.Minute
)

func ensureDirs() error {
	for _, p := range []string{sandboxRoot, filepath.Dir(auditLogPath), filepath.Join(cgroupRoot, cgroupDomain)} {
		if err := os.MkdirAll(p, 0755); err != nil {
			return err
		}
	}
	return nil
}

func ensureUltaAIUser() (uid, gid uint32, err error) {
	u, err := user.Lookup("ultaai")
	if err != nil {
		// fallback to nobody if ultaai is not present
		u, err = user.Lookup("nobody")
		if err != nil {
			return 0, 0, errors.New("neither 'ultaai' nor 'nobody' user exists")
		}
	}
	uid64, _ := strconv.ParseUint(u.Uid, 10, 32)
	gid64, _ := strconv.ParseUint(u.Gid, 10, 32)
	return uint32(uid64), uint32(gid64), nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	return os.WriteFile(dst, b, mode)
}

func lddList(bin string) ([]string, error) {
	cmd := exec.Command("ldd", bin)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("ldd %s: %w", bin, err)
	}
	var libs []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		parts := strings.Split(line, "=>")
		// handle lines like: linux-vdso.so.1 (0x00007ff...)
		if len(parts) == 1 && strings.Contains(parts[0], "/") {
			libs = append(libs, strings.Fields(parts[0])[0])
			continue
		}
		if len(parts) < 2 {
			continue
		}
		right := strings.TrimSpace(parts[1])
		if strings.HasPrefix(right, "/") {
			path := strings.Fields(right)[0]
			libs = append(libs, path)
		}
	}
	return libs, nil
}

func ensureMinimalRootfs() error {
	fmt.Printf(" ensureMinimalRootfs100000000---sandbox.go: %+v \n")

	// We need /bin/bash and its libs
	if err := ensureDirs(); err != nil {
		fmt.Printf(" ensureMinimalRootfs000011111---sandbox.go: %+v \n")

		return err
	}
	bash := "/bin/bash"
	fmt.Printf(" ensureMinimalRootfs1111111---sandbox.go: %+v \n")

	destBash := filepath.Join(sandboxRoot, "bin/bash")
	if _, err := os.Stat(destBash); os.IsNotExist(err) {
		fmt.Printf(" ensureMinimalRootfs1222222222---sandbox.go: %+v \n")

		if err := copyFile(bash, destBash, 0755); err != nil {
			fmt.Printf(" ensureMinimalRootfs133333333333---sandbox.go: %+v \n")

			return fmt.Errorf("copy bash: %w", err)
		}
		libs, err := lddList(bash)
		if err != nil {
			return err
		}
		for _, lib := range libs {
			dst := filepath.Join(sandboxRoot, lib)
			if err := copyFile(lib, dst, 0644); err != nil {
				// some libs are symlinks; try to create directories and best-effort copy
				_ = os.MkdirAll(filepath.Dir(dst), 0755)
				_ = copyFile(lib, dst, 0644)
			}
		}
	}
	// temp and proc
	_ = os.MkdirAll(filepath.Join(sandboxRoot, "tmp"), 0777)
	_ = os.MkdirAll(filepath.Join(sandboxRoot, "proc"), 0555)
	return nil
}

func randomID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Attempt to enable controllers; ignore errors if already enabled
func enableControllers() {
	parent := filepath.Join(cgroupRoot)
	_ = os.WriteFile(filepath.Join(parent, "cgroup.subtree_control"), []byte("+cpu +memory +io"), 0644)
	_ = os.MkdirAll(filepath.Join(parent, cgroupDomain), 0755)
	_ = os.WriteFile(filepath.Join(parent, "cgroup.subtree_control"), []byte("+cpu +memory +io"), 0644)
	_ = os.WriteFile(filepath.Join(filepath.Join(parent, cgroupDomain), "cgroup.subtree_control"), []byte("+cpu +memory +io"), 0644)
}

func detectRootDeviceMajorMinor() (string, error) {
	// Use mountinfo to find / major:minor
	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return "", err
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := sc.Text()
		// fields: ... major:minor root mountpoint ...
		parts := strings.Split(line, " - ")
		if len(parts) < 2 {
			continue
		}
		left := strings.Fields(parts[0])
		if len(left) < 5 {
			continue
		}
		mountpoint := left[4]
		if mountpoint == "/" {
			majmin := left[2] // e.g., "259:1"
			return majmin, nil
		}
	}
	return "", errors.New("root device not found")
}

func applyCgroupLimits(taskID string, pid int) (bool, error) {
	enableControllers()
	cg := filepath.Join(cgroupRoot, cgroupDomain, taskID)
	if err := os.MkdirAll(cg, 0755); err != nil {
		return false, err
	}
	// CPU
	if err := os.WriteFile(filepath.Join(cg, "cpu.max"), []byte(fmt.Sprintf("%d %d", cpuQuota, cpuPeriod)), 0644); err != nil {
		// not fatal; continue but note false
	}
	// Memory
	if err := os.WriteFile(filepath.Join(cg, "memory.max"), []byte(fmt.Sprintf("%d", maxRAMBytes)), 0644); err != nil {
	}
	// IO
	if majmin, err := detectRootDeviceMajorMinor(); err == nil {
		line := fmt.Sprintf("%s rbps=%d wbps=%d", majmin, maxIOBps, maxIOBps)
		_ = os.WriteFile(filepath.Join(cg, "io.max"), []byte(line), 0644)
	}
	// Attach
	if err := os.WriteFile(filepath.Join(cg, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0644); err != nil {
		return false, err
	}
	return true, nil
}

func writeAudit(line string) {
	_ = os.MkdirAll(filepath.Dir(auditLogPath), 0755)
	f, err := os.OpenFile(auditLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(line + "\n")
}

func ExecuteSignedTask(req TaskRequest, manifestPath string) (*TaskResult, error) {
	start := time.Now().UTC()
	taskID := randomID()

	// 1) Validate signature
	sigOK, sigErr := ValidateTaskSignature(req)
	if !sigOK {
		writeAudit(fmt.Sprintf(`{"at":"%s","task_id":"%s","event":"reject","reason":"bad_signature","task":"%s"}`, start.Format(time.RFC3339Nano), taskID, req.Task))
		fmt.Printf(" --------------1111111111--sandbox.go: %+v \n", req.Args)

		return nil, sigErr
	}

	// 2) Allowlist + SHA256 match
	m, err := LoadManifest(manifestPath)
	if err != nil {
		return nil, err
	}
	entry, ok := m.Lookup(req.Task)
	if !ok {
		writeAudit(fmt.Sprintf(`{"at":"%s","task_id":"%s","event":"reject","reason":"not_allowlisted","task":"%s"}`, start.Format(time.RFC3339Nano), taskID, req.Task))
		return nil, errors.New("task not allowlisted")
	}
	actualHash, err := SHA256File(entry.Path)
	if err != nil {
		fmt.Printf(" ------------222222222222----sandbox.go: %+v \n", req.Args)

		return nil, fmt.Errorf("hashing script: %w", err)
	}
	if strings.ToLower(actualHash) != strings.ToLower(entry.SHA256) {
		writeAudit(fmt.Sprintf(`{"at":"%s","task_id":"%s","event":"reject","reason":"sha256_mismatch","task":"%s","expected":"%s","got":"%s"}`, start.Format(time.RFC3339Nano), taskID, req.Task, entry.SHA256, actualHash))
		return nil, errors.New("script SHA256 mismatch")
	}

	// 3) Prepare minimal rootfs
	if err := ensureMinimalRootfs(); err != nil {
		fmt.Printf(" ------------33333333333----sandbox.go: %+v \n", req.Args)

		return nil, err
	}

	// 4) Copy script inside chroot
	chrootScript := filepath.Join(sandboxRoot, "sandbox", "task.sh")
	if err := copyFile(entry.Path, chrootScript, 0755); err != nil {
		return nil, fmt.Errorf("copy script: %w", err)
	}

	// 5) Drop privileges (inside child)
	uid, gid, err := ensureUltaAIUser()
	if err != nil {
		fmt.Printf(" -----------44444444444444444444-----sandbox.go: %+v \n", req.Args)

		return nil, err
	}

	fmt.Printf(" --------------5555555555--sandbox.go: %+v \n", req.Args)
	// 6) Build command (chroot + bash)
	args := append([]string{chrootScript}, req.Args...)
	cmd := exec.Command("/bin/bash", args...)
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Chroot:     sandboxRoot,
		Credential: &syscall.Credential{Uid: uid, Gid: gid},
		Setpgid:    true,
		// optionally: Cloneflags: unix.CLONE_NEWUTS|unix.CLONE_NEWIPC|unix.CLONE_NEWNET|unix.CLONE_NEWNS, // extra isolation if allowed
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// 7) Start with soft timeout
	ctx, cancel := context.WithTimeout(context.Background(), softTimeout)
	defer cancel()

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	// 8) Attach cgroup limits
	cgUsed, _ := applyCgroupLimits(taskID, cmd.Process.Pid)

	// 9) Wait (soft timeout)
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()

	var execErr error
	select {
	case execErr = <-waitCh:
		// finished before soft timeout
	case <-ctx.Done():
		// soft timeout reached; try graceful stop then hard kill at hardTimeout
		_ = unix.Kill(-cmd.Process.Pid, unix.SIGTERM) // kill process group
		select {
		case execErr = <-waitCh:
		case <-time.After(hardTimeout - softTimeout):
			_ = unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
			execErr = errors.New("killed after hard timeout")
		}
	}

	exitCode := 0
	if execErr != nil {
		if ee, ok := execErr.(*exec.ExitError); ok {
			if status, ok := ee.Sys().(syscall.WaitStatus); ok {
				exitCode = status.ExitStatus()
			} else {
				exitCode = 1
			}
		} else {
			exitCode = 1
		}
	}

	end := time.Now().UTC()
	res := &TaskResult{
		TaskID:       taskID,
		Task:         req.Task,
		ExitCode:     exitCode,
		Stdout:       stdout.String(),
		Stderr:       stderr.String(),
		StartedAt:    start.Format(time.RFC3339Nano),
		FinishedAt:   end.Format(time.RFC3339Nano),
		DurationSec:  int64(end.Sub(start).Seconds()),
		ChrootUsed:   true,
		CgroupUsed:   cgUsed,
		SignatureOK:  sigOK,
		ScriptSHA256: actualHash,
	}

	// 10) Audit log
	escapedStdout := strings.ReplaceAll(res.Stdout, `"`, `\"`)
	escapedStderr := strings.ReplaceAll(res.Stderr, `"`, `\"`)
	writeAudit(fmt.Sprintf(`{"at":"%s","task_id":"%s","task":"%s","exit":%d,"sig_ok":%t,"sha256":"%s","dur_sec":%d,"stdout":"%s","stderr":"%s"}`,
		end.Format(time.RFC3339Nano), taskID, req.Task, exitCode, sigOK, actualHash, res.DurationSec, escapedStdout, escapedStderr))

	return res, nil
}
