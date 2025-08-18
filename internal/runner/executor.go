// package runner

// import (
// 	"encoding/json"
// 	"errors"
// 	"fmt"
// 	"log"
// 	"os"
// )

// const defaultManifest = "scripts/manifest.json"

// // Public entrypoint used by your WS/HTTP handler
// func ExecuteSignedTaskJSON(reqJSON []byte) ([]byte, error) {
// 	os.MkdirAll("logs", os.ModePerm)
// 	logFile, err := os.OpenFile("logs/ultaai/agent.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
// 	if err != nil {
// 		log.Fatalf("Failed to create log file: %v", err)
// 	}
// 	log.SetOutput(logFile)
// 	var req TaskRequest
// 	if err := json.Unmarshal(reqJSON, &req); err != nil {
// 		return nil, err
// 	}
// 	if req.Type != "task" {
// 		return nil, errors.New("unsupported message type")
// 	}
// 	res, err := ExecuteSignedTask(req, defaultManifest)
// 	if err != nil {

//			fmt.Println(" -------------------- err: ", err)
//			return nil, err
//		}
//		return json.Marshal(res)
//	}
package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type ExecOptions struct {
	TaskName    string   // e.g. "check_uptime"
	ScriptPath  string   // absolute path to script file
	Args        []string // forwarded args
	UseChroot   bool
	ChrootDir   string        // base dir to chroot (script must be inside)
	DropToUser  string        // "ultaai"
	TimeoutSoft time.Duration // default 30m
	TimeoutHard time.Duration // default 35m
	MaxRAMBytes uint64        // e.g. 1<<30
	AuditPath   string        // /var/log/ultaai/audit.log or dev fallback
}

// Result returned to assistant
type TaskResult struct {
	TaskID       string `json:"task_id"`
	Task         string `json:"task"`
	ExitCode     int    `json:"exit_code"`
	Stdout       string `json:"stdout"`
	Stderr       string `json:"stderr"`
	StartedAt    string `json:"started_at"`
	FinishedAt   string `json:"finished_at"`
	DurationSec  int64  `json:"duration_sec"`
	ChrootUsed   bool   `json:"chroot_used"`
	CgroupUsed   bool   `json:"cgroup_used"`
	SignatureOK  bool   `json:"signature_ok"`
	ScriptSHA256 string `json:"script_sha256"`
}

type auditLine struct {
	Time         string   `json:"time"`
	Task         string   `json:"task"`
	Args         []string `json:"args"`
	ExitCode     int      `json:"exit_code"`
	DurationSec  int64    `json:"duration_sec"`
	ChrootUsed   bool     `json:"chroot_used"`
	User         string   `json:"user"`
	ScriptPath   string   `json:"script_path"`
	ScriptSHA256 string   `json:"script_sha256"`
}

func sha256File(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// prlimit helper (works post-Start)
func setRAMLimit(pid int, bytes uint64) error {
	var r unix.Rlimit
	r.Cur = bytes
	r.Max = bytes
	return unix.Prlimit(pid, unix.RLIMIT_AS, &r, nil)
}

func buildBashCommand(script string, args []string, maxRAM uint64) *exec.Cmd {
	// set ulimit in the shell, then exec the script
	// -v sets virtual memory KB; convert bytes to KB
	kb := maxRAM / 1024
	line := fmt.Sprintf("ulimit -v %d; exec /bin/bash %s %s",
		kb, script, strings.Join(quoteArgs(args), " "))
	return exec.Command("/bin/bash", "-lc", line)
}

func quoteArgs(a []string) []string {
	out := make([]string, 0, len(a))
	for _, s := range a {
		if strings.ContainsAny(s, " \t\"'") {
			out = append(out, "'"+strings.ReplaceAll(s, "'", "'\\''")+"'")
		} else {
			out = append(out, s)
		}
	}
	return out
}

func Execute(opts ExecOptions, taskID string) (TaskResult, error) {
	start := time.Now()
	res := TaskResult{
		TaskID:      taskID,
		Task:        opts.TaskName,
		ChrootUsed:  opts.UseChroot,
		CgroupUsed:  false, // not implemented here
		SignatureOK: true,  // set by caller once verified
	}
	res.StartedAt = start.UTC().Format(time.RFC3339Nano)

	// verify script exists & compute sha
	abs, err := filepath.Abs(opts.ScriptPath)
	if err != nil {
		return res, fmt.Errorf("abs path: %w", err)
	}
	if _, err := os.Stat(abs); err != nil {
		return res, fmt.Errorf("script not found: %s", abs)
	}
	sha, err := sha256File(abs)
	if err != nil {
		return res, fmt.Errorf("sha256: %w", err)
	}
	res.ScriptSHA256 = sha

	// timeouts
	soft := opts.TimeoutSoft
	if soft == 0 {
		soft = 30 * time.Minute
	}
	hard := opts.TimeoutHard
	if hard == 0 {
		hard = 35 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), soft)
	defer cancel()

	cmd := buildBashCommand(abs, opts.Args, opts.MaxRAMBytes)

	// credentials (drop privs) and chroot (only if root)
	if os.Geteuid() == 0 {
		cred := &syscall.Credential{}
		if opts.DropToUser != "" {
			if u, err := user.Lookup(opts.DropToUser); err == nil {
				uid := mustAtoi(u.Uid)
				gid := mustAtoi(u.Gid)
				cred.Uid = uint32(uid)
				cred.Gid = uint32(gid)
			}
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: cred,
		}
		if opts.UseChroot {
			if cmd.SysProcAttr == nil {
				cmd.SysProcAttr = &syscall.SysProcAttr{}
			}
			// only works if /bin/bash exists inside chroot; we require scripts live under /scripts
			cmd.SysProcAttr.Chroot = opts.ChrootDir
			// When chrooted to BaseDir, our buildBashCommand must use /bin/bash INSIDE chroot.
			// So override the argv to call /bin/bash from inside the chroot directly:
			insideScript := strings.TrimPrefix(abs, opts.ChrootDir)
			if !strings.HasPrefix(insideScript, "/") {
				insideScript = "/" + insideScript
			}
			cmd = buildBashCommand(insideScript, opts.Args, opts.MaxRAMBytes)
			cmd.SysProcAttr.Credential = cred
			cmd.SysProcAttr.Chroot = opts.ChrootDir
		}
	}

	stdout, stderr := &strings.Builder{}, &strings.Builder{}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	// start
	if err := cmd.Start(); err != nil {
		return res, fmt.Errorf("start: %w", err)
	}

	// set rlimit after Start (best-effort)
	_ = setRAMLimit(cmd.Process.Pid, opts.MaxRAMBytes)

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	// enforce soft timeout, then hard kill window
	var waitErr error
	select {
	case err := <-done:
		waitErr = err
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		select {
		case <-done:
		case <-time.After(hard - soft):
			// ensure it's dead
			_ = cmd.Process.Kill()
		}
		waitErr = fmt.Errorf("timeout: %w", ctx.Err())
	}

	end := time.Now()
	res.FinishedAt = end.UTC().Format(time.RFC3339Nano)
	res.DurationSec = int64(end.Sub(start).Seconds())
	res.Stdout = stdout.String()
	res.Stderr = stderr.String()

	if waitErr != nil {
		// exit code if possible
		if ee, ok := waitErr.(*exec.ExitError); ok {
			if status, ok := ee.Sys().(syscall.WaitStatus); ok {
				res.ExitCode = status.ExitStatus()
			} else {
				res.ExitCode = 1
			}
		} else {
			res.ExitCode = 1
		}
	} else {
		if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok {
			res.ExitCode = status.ExitStatus()
		}
	}

	// audit log
	_ = appendAudit(auditLine{
		Time:         time.Now().UTC().Format(time.RFC3339Nano),
		Task:         opts.TaskName,
		Args:         opts.Args,
		ExitCode:     res.ExitCode,
		DurationSec:  res.DurationSec,
		ChrootUsed:   res.ChrootUsed,
		User:         opts.DropToUser,
		ScriptPath:   abs,
		ScriptSHA256: res.ScriptSHA256,
	}, opts.AuditPath)

	return res, nil
}

func mustAtoi(s string) int {
	var n int
	fmt.Sscanf(s, "%d", &n)
	return n
}

func appendAudit(a auditLine, path string) error {
	dir := filepath.Dir(path)
	_ = os.MkdirAll(dir, 0o750)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	return enc.Encode(a)
}
