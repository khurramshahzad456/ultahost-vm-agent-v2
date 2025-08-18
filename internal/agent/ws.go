package agent

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"ultahost-agent/utils"

	"github.com/gorilla/websocket"
	"golang.org/x/sys/unix"
)

//
// ===== Runtime configuration (env + sane defaults) =====
//

const (
	// websocket timeouts
	pongWait   = 30 * time.Minute
	writeWait  = 10 * time.Second
	pingPeriod = (pongWait * 9) / 10
	readLimit  = 1024 * 1024 // 1MB

	// reconnect/backoff
	initialBackoff = 1 * time.Second
	maxBackoff     = 30 * time.Second
	maxAttempts    = 0 // 0 means infinite attempts (until ctx canceled)
)

// Max allowed clock skew; default 300s (5m)
var maxClockSkew = func() time.Duration {
	if v := os.Getenv("ULTA_MAX_SKEW_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return 5 * time.Minute
}()

var (
	// BASE: prod -> /var/lib/ultaai ; dev (non-root) -> ./.ultaai-dev
	baseDir = func() string {
		if v := os.Getenv("ULTA_BASE_DIR"); v != "" {
			return v
		}
		if os.Geteuid() == 0 {
			return "/var/lib/ultaai"
		}
		// return ".ultaai-dev"
		return "/ultaai-dev"
	}()

	// Scripts dir (can override with ULTA_SCRIPTS_DIR)
	scriptsDir = func() string {
		if v := os.Getenv("ULTA_SCRIPTS_DIR"); v != "" {
			return v
		}
		return filepath.Join(baseDir, "scripts")
	}()

	// Logs (prod -> /var/log/ultaai; dev -> ${BASE}/logs)
	logDir = func() string {
		if os.Geteuid() == 0 {
			return "/var/log/ultaai"
		}
		return filepath.Join(baseDir, "logs")
	}()

	// Config dir
	configDirLocal = filepath.Join(baseDir, "config")

	// Drop-priv user (override with ULTA_RUN_AS)
	runAsUser = func() string {
		if v := os.Getenv("ULTA_RUN_AS"); v != "" {
			return v
		}
		return "ultaai"
	}()

	assistantWS = func() string {
		if v := os.Getenv("ASSISTANT_WS_URL"); v != "" {
			return v
		}
		// sensible default for local dev (adjust as needed)
		return "wss://localhost:8443/agent/connect"
	}()
)

//
// ===== Allowlist & Expected SHA (can be overridden by JSON config) =====
//

// logical task -> script filename
var allowlist = map[string]string{
	"check_uptime":      "check_uptime.sh",
	"check_diskspace":   "check_diskspace.sh",
	"install_wordpress": "install_wordpress.sh",
}

// script filename -> expected sha256 hex
var expectedSHA = map[string]string{}

// optional JSON override file:  ${BASE}/config/scripts_allowlist.json
type allowlistConfig struct {
	Allowlist   map[string]string `json:"allowlist"`
	ExpectedSHA map[string]string `json:"expected_sha"`
}

func loadAllowlistFromConfig() {
	path := filepath.Join(configDirLocal, "scripts_allowlist.json")
	b, err := os.ReadFile(path)
	if err != nil {
		return // optional
	}
	var cfg allowlistConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		log.Printf("warn: invalid scripts_allowlist.json: %v", err)
		return
	}
	if len(cfg.Allowlist) > 0 {
		allowlist = cfg.Allowlist
	}
	if len(cfg.ExpectedSHA) > 0 {
		expectedSHA = cfg.ExpectedSHA
	}
}

//
// ===== Minimal embedded scripts for dev (materialize if missing) =====
//

var embeddedScripts = map[string]string{
	"check_uptime.sh": `#!/usr/bin/env bash
set -euo pipefail
if command -v uptime >/dev/null 2>&1; then uptime -p; else cat /proc/uptime; fi
`,
	"check_diskspace.sh": `#!/usr/bin/env bash
set -euo pipefail
df -hT || true
`,
	"install_wordpress.sh": `#!/usr/bin/env bash
set -euo pipefail
echo "install_wordpress invoked (stub). args: $*"
exit 0
`,
}

func materializeScripts() {
	_ = os.MkdirAll(scriptsDir, 0o750)
	for name, body := range embeddedScripts {
		full := filepath.Join(scriptsDir, name)
		if _, err := os.Stat(full); errors.Is(err, os.ErrNotExist) {
			_ = os.WriteFile(full, []byte(body), 0o750)
			// if expected SHA not set by config, derive from embedded body
			if _, ok := expectedSHA[name]; !ok {
				sum := sha256.Sum256([]byte(body))
				expectedSHA[name] = hex.EncodeToString(sum[:])
			}
		}
	}
}

//
// ===== TLS/mTLS helpers =====
//

func clientTLSConfig(caPath, certPath, keyPath string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read ca: %w", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	}
	// expected server fingerprint (optional) - file may not exist in some installs
	var expectedServerFP string
	if b, err := os.ReadFile(configDir + "/server_fingerprint_sha256"); err == nil {
		expectedServerFP = strings.TrimSpace(string(b))
	}

	// fmt.Println("expectedServerFP: ", expectedServerFP)
	// Read the server fingerprint file used in VerifyPeerCertificate, if available
	// We'll build tls.Config dynamically in each attempt so VerifyPeerCertificate closure can capture expectedServerFP.

	if expectedServerFP != "" {
		// use fingerprint pinning on server cert
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no server cert presented")
			}
			sum := sha256.Sum256(rawCerts[0])
			// fmt.Printf(" rawCerts %+v \n", string(rawCerts[0]))

			if hex.EncodeToString(sum[:]) != expectedServerFP {
				return fmt.Errorf("server certificate fingerprint mismatch")
			}
			return nil
		}
	}
	return tlsConfig, nil
}

// func caCertPath() string { return "./crts/ca.crt" }
func caCertPath() string { return configDirLocal + "/ca.crt" }

func clientCertPath() string { return filepath.Join(configDirLocal, "client.crt") }
func clientKeyPath() string  { return filepath.Join(configDirLocal, "client.key") }

// func clientCertPath() string { return filepath.Join("./test-vm-agent/", "client.crt") }
// func clientKeyPath() string  { return filepath.Join("./test-vm-agent/", "client.key") }

//
// ===== Heartbeat (keep your existing HMAC scheme) =====
//

func readSignatureSecret() ([]byte, error) {
	// prefer ${BASE}/config/signature_secret; fallback to ./test-vm-agent/signature_secret
	paths := []string{
		filepath.Join(configDirLocal, "signature_secret"),
		"./test-vm-agent/signature_secret",
	}
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil {
			return []byte(strings.TrimSpace(string(b))), nil
		}
	}
	return nil, fmt.Errorf("signature_secret not found in %v", paths)
}

func startHeartbeatLoop(conn *websocket.Conn, secret []byte) {
	ticker := time.NewTicker(5 * time.Second)
	go func() {
		defer ticker.Stop()
		for range ticker.C {
			msg := utils.PrepareHeartbeatMessage(secret)
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.WriteMessage(websocket.TextMessage, []byte(msg)); err != nil {
				log.Printf("heartbeat write err: %v", err)
				return
			}
			log.Println("Heartbeat sent")
		}
	}()
}

//
// ===== Task exchange types =====
//

type TaskRequest struct {
	Type      string   `json:"type"` // "task"
	TaskID    string   `json:"task_id"`
	Task      string   `json:"task"` // logical name ("check_uptime")
	Args      []string `json:"args"`
	Timestamp string   `json:"timestamp"`
	Nonce     string   `json:"nonce"`
	Signature string   `json:"signature"`
	// optional: vps_id, agent_id... (ignored here)
}

type TaskResult struct {
	Type        string `json:"type"` // "task_result"
	TaskID      string `json:"task_id"`
	Task        string `json:"task"`
	ExitCode    int    `json:"exit_code"`
	Stdout      string `json:"stdout"`
	Stderr      string `json:"stderr"`
	StartedAt   string `json:"started_at"`
	FinishedAt  string `json:"finished_at"`
	DurationSec int64  `json:"duration_sec"`
	ChrootUsed  bool   `json:"chroot_used"`
	CgroupUsed  bool   `json:"cgroup_used"`
	SignatureOK bool   `json:"signature_ok"`
	ScriptSHA   string `json:"script_sha256"`
}

//
// ===== Task signature (must match assistant side canonicalization) =====
//

func canonicalTaskString(task string, args []string, nonce, ts string) string {
	// Keep EXACTLY this format in both sides
	return fmt.Sprintf("v1|%s|%s|%s|%s", task, strings.Join(args, " "), nonce, ts)
}

func verifyTaskSignature(req TaskRequest, secret []byte) bool {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(canonicalTaskString(req.Task, req.Args, req.Nonce, req.Timestamp)))
	expect := base64.StdEncoding.EncodeToString(m.Sum(nil))
	return hmac.Equal([]byte(expect), []byte(req.Signature))
}

//
// ===== Secure execution helpers =====
//

func ensureDirs() error {
	for _, d := range []string{baseDir, scriptsDir, logDir, configDirLocal} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
	}
	// ensure audit log file exists
	audit := filepath.Join(logDir, "audit.log")
	if f, err := os.OpenFile(audit, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640); err == nil {
		_ = f.Close()
	}
	return nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ensure /bin/bash exists inside chroot (best-effort). If not root, we can't fix it; chroot will be disabled.
func ensureBashInChroot(chroot string) error {
	dest := filepath.Join(chroot, "bin/bash")
	if _, err := os.Stat(dest); err == nil {
		return nil
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("bash missing in chroot and not root")
	}
	if err := os.MkdirAll(filepath.Join(chroot, "bin"), 0o755); err != nil {
		return err
	}
	src := "/bin/bash"
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return os.Chmod(dest, 0o755)
}

// rlimit: set virtual memory (address space) cap to MaxRAM (bytes)
func setRAMLimit(pid int, bytes uint64) {
	rl := unix.Rlimit{Cur: bytes, Max: bytes}
	_ = unix.Prlimit(pid, unix.RLIMIT_AS, &rl, nil)
}

func appendAudit(line map[string]any) {
	path := filepath.Join(logDir, "audit.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		log.Printf("audit open err: %v", err)
		return
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	_ = enc.Encode(line)
}

func dropCredForUser(uName string) *syscall.Credential {
	if uName == "" {
		return nil
	}
	u, err := user.Lookup(uName)
	if err != nil {
		return nil
	}
	var uid, gid int
	_, _ = fmt.Sscanf(u.Uid, "%d", &uid)
	_, _ = fmt.Sscanf(u.Gid, "%d", &gid)
	return &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
}

func buildBashCommand(scriptPathInside string, args []string, maxRAMBytes uint64) *exec.Cmd {
	// Use a shell wrapper to set ulimit then exec the script
	kb := maxRAMBytes / 1024
	line := fmt.Sprintf("ulimit -v %d; exec /bin/bash %s %s", kb, scriptPathInside, strings.Join(quoteArgs(args), " "))
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

func execSecure(taskID, taskName, scriptAbs string, args []string, signatureOK bool) TaskResult {
	start := time.Now()
	res := TaskResult{
		Type:        "task_result",
		TaskID:      taskID,
		Task:        taskName,
		SignatureOK: signatureOK,
		CgroupUsed:  false, // cgroup v2 not implemented here; can be added later
	}
	res.StartedAt = start.UTC().Format(time.RFC3339Nano)

	// compute SHA
	sha, err := sha256File(scriptAbs)
	if err != nil {
		return finishWith(res, 1, "", "sha256: "+err.Error(), start, false, "")
	}
	res.ScriptSHA = sha

	// timeouts
	soft := 30 * time.Minute
	hard := 35 * time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), soft)
	defer cancel()

	useChroot := false
	var cmd *exec.Cmd

	if os.Geteuid() == 0 {
		// Ensure bash exists in chroot base
		if err := ensureBashInChroot(baseDir); err == nil {
			useChroot = true
		}
	}

	if useChroot {
		// translate abs script to inside-chroot path
		inside := strings.TrimPrefix(scriptAbs, baseDir)
		if !strings.HasPrefix(inside, "/") {
			inside = "/" + inside
		}
		cmd = buildBashCommand(inside, args, 1<<30) // 1 GiB
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Chroot:     baseDir,
			Credential: dropCredForUser(runAsUser),
		}
	} else {
		// no chroot (dev non-root): execute script absolutely
		cmd = buildBashCommand(scriptAbs, args, 1<<30)
		if os.Geteuid() == 0 {
			cmd.SysProcAttr = &syscall.SysProcAttr{
				Credential: dropCredForUser(runAsUser),
			}
		}
	}

	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// start
	if err := cmd.Start(); err != nil {
		return finishWith(res, 1, "", "start: "+err.Error(), start, useChroot, sha)
	}

	// enforce RAM after start (best effort)
	setRAMLimit(cmd.Process.Pid, 1<<30)

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	var waitErr error
	select {
	case err := <-done:
		waitErr = err
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		select {
		case <-done:
		case <-time.After(hard - soft):
			_ = cmd.Process.Kill()
		}
		waitErr = fmt.Errorf("timeout: %w", ctx.Err())
	}

	outStr := stdout.String()
	errStr := stderr.String()
	exitCode := 0
	if waitErr != nil {
		if ee, ok := waitErr.(*exec.ExitError); ok {
			if st, ok := ee.Sys().(syscall.WaitStatus); ok {
				exitCode = st.ExitStatus()
			} else {
				exitCode = 1
			}
		} else {
			exitCode = 1
		}
	}

	// audit
	appendAudit(map[string]any{
		"time":         time.Now().UTC().Format(time.RFC3339Nano),
		"task":         taskName,
		"args":         args,
		"exit_code":    exitCode,
		"duration_sec": int64(time.Since(start).Seconds()),
		"chroot_used":  useChroot,
		"user":         runAsUser,
		"script_path":  scriptAbs,
		"script_sha":   sha,
	})

	res.ExitCode = exitCode
	res.Stdout = outStr
	res.Stderr = errStr
	res.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	res.DurationSec = int64(time.Since(start).Seconds())
	res.ChrootUsed = useChroot
	return res
}

func finishWith(res TaskResult, code int, out, errStr string, start time.Time, chroot bool, sha string) TaskResult {
	res.ExitCode = code
	res.Stdout = out
	res.Stderr = errStr
	res.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	res.DurationSec = int64(time.Since(start).Seconds())
	res.ChrootUsed = chroot
	res.ScriptSHA = sha
	return res
}

//
// ===== WebSocket connect & read loop =====
//

func ConnectWithAssistant(ctx context.Context) {
	// prepare dirs & configs
	if err := ensureDirs(); err != nil {
		log.Fatalf("runtime dirs: %v", err)
	}
	// try load allowlist overrides
	loadAllowlistFromConfig()
	// dev convenience: create embedded scripts if missing, and fill SHA when not configured
	materializeScripts()

	// We'll attempt to connect in a loop until ctx is done
	attempt := 0
	backoff := initialBackoff

	for {
		// Check cancel
		select {
		case <-ctx.Done():
			// return ctx.Err()
		default:
		}

		// TLS/mTLS
		tlsCfg, err := clientTLSConfig(caCertPath(), clientCertPath(), clientKeyPath())
		if err != nil {
			log.Fatalf("tls config: %v", err)
		}

		dialer := websocket.Dialer{
			TLSClientConfig:  tlsCfg,
			Proxy:            http.ProxyFromEnvironment,
			HandshakeTimeout: 15 * time.Second,
		}

		conn, resp, err := dialer.Dial(assistantWS, nil)
		if err != nil {
			log.Println("ws dial: %v", err)
			// log http response body if present
			if resp != nil {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				log.Printf("dial error (status=%v): %v - body: %s", resp.Status, err, string(body))
			} else {
				log.Printf("dial error: %v", err)
			}

			// backoff with jitter
			if ctx.Err() != nil {

				return //ctx.Err()
			}
			attempt++
			if maxAttempts > 0 && attempt >= maxAttempts {
				log.Println("max attempts reached: %v", err)

				// return fmt.Errorf("max attempts reached: %v", err)
			}
			// sleep with jitter
			jitter := time.Duration(rand.Intn(500)) * time.Millisecond
			sleep := backoff + jitter
			if sleep > maxBackoff {
				sleep = maxBackoff
			}
			log.Printf("Reconnect sleeping %v before next attempt", sleep)
			time.Sleep(sleep)
			// increase backoff (exponential), cap it
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}

			continue
		}

		log.Printf("connected to assistant ws: %s", assistantWS)
		fmt.Println("✅WebSocket connection established with mutual TLS!")

		// Successfully connected - reset attempt/backoff counters
		attempt = 0
		backoff = initialBackoff

		// Set read limits / handlers
		conn.SetReadLimit(readLimit)
		conn.SetReadDeadline(time.Now().Add(pongWait))
		conn.SetPongHandler(func(string) error {
			conn.SetReadDeadline(time.Now().Add(pongWait))
			return nil
		})

		secret, err := readSignatureSecret()
		if err != nil {
			log.Fatalf("signature secret: %v", err)
		}

		// start heartbeat pinger (signed)
		startHeartbeatLoop(conn, secret)

		errCh := make(chan error, 1)
		// read loop
		go func() {
			for {
				_, payload, err := conn.ReadMessage()
				if err != nil {
					log.Printf("ws read err: %v", err)
					// _ = conn.Close()
					errCh <- err
					return
				}
				// Try to parse as task
				var t TaskRequest
				if err := json.Unmarshal(payload, &t); err == nil && t.Type == "task" {
					go func(tr TaskRequest) {
						res := handleTask(tr, secret)
						b, _ := json.Marshal(res)
						_ = conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
						if err := conn.WriteMessage(websocket.TextMessage, b); err != nil {
							log.Printf("write task_result err: %v", err)
						}
						log.Println("task performed: ", string(b))
					}(t)
					continue
				}

				log.Printf("received non-task: %s", string(payload))
			}
		}()

		connected := true

		for connected {
			select {
			case <-ctx.Done():
				log.Println("context canceled, closing connection")

				// _ = conn.Close()
				return //ctx.Err()
			case rerr := <-errCh:
				// read loop encountered an error (connection closed/unexpected)
				log.Printf("connection read error: %v", rerr)
				// ticker.Stop()
				// pingTicker.Stop()
				_ = conn.Close()
				connected = false
			}
		}
	}
}

func handleTask(tr TaskRequest, secret []byte) TaskResult {
	sigOK := verifyTaskSignature(tr, secret)

	// 1) Timestamp freshness (anti-replay window)
	if !utils.IsTimestampFresh(tr.Timestamp, maxClockSkew) {
		return TaskResult{
			Type:        "task_result",
			TaskID:      tr.TaskID,
			Task:        tr.Task,
			ExitCode:    1,
			Stdout:      "",
			Stderr:      fmt.Sprintf("stale or future task timestamp (>%v)", maxClockSkew),
			StartedAt:   time.Now().UTC().Format(time.RFC3339Nano),
			FinishedAt:  time.Now().UTC().Format(time.RFC3339Nano),
			DurationSec: 0,
			ChrootUsed:  false,
			CgroupUsed:  false,
			SignatureOK: sigOK,
			ScriptSHA:   "",
		}
	}

	// allowlist: logical task -> script name
	scriptName, ok := allowlist[tr.Task]
	if !ok {
		return TaskResult{
			Type:        "task_result",
			TaskID:      tr.TaskID,
			Task:        tr.Task,
			ExitCode:    1,
			Stdout:      "",
			Stderr:      "task not allowlisted",
			StartedAt:   time.Now().UTC().Format(time.RFC3339Nano),
			FinishedAt:  time.Now().UTC().Format(time.RFC3339Nano),
			DurationSec: 0,
			ChrootUsed:  false,
			CgroupUsed:  false,
			SignatureOK: sigOK,
			ScriptSHA:   "",
		}
	}

	full := filepath.Join(scriptsDir, scriptName)

	// SHA‑256 verification against expected map
	want, ok := expectedSHA[scriptName]
	if !ok {
		// compute and set on first run only for embedded scripts; otherwise reject
		if body, okEmb := embeddedScripts[scriptName]; okEmb {
			sum := sha256.Sum256([]byte(body))
			want = hex.EncodeToString(sum[:])
			expectedSHA[scriptName] = want
		} else {
			return TaskResult{
				Type:        "task_result",
				TaskID:      tr.TaskID,
				Task:        tr.Task,
				ExitCode:    1,
				Stderr:      "expected sha for script not configured",
				SignatureOK: sigOK,
			}
		}
	}
	got, err := sha256File(full)
	if err != nil {
		return TaskResult{
			Type:        "task_result",
			TaskID:      tr.TaskID,
			Task:        tr.Task,
			ExitCode:    1,
			Stderr:      "sha256 check failed: " + err.Error(),
			SignatureOK: sigOK,
		}
	}
	if !strings.EqualFold(want, got) {
		return TaskResult{
			Type:        "task_result",
			TaskID:      tr.TaskID,
			Task:        tr.Task,
			ExitCode:    1,
			Stderr:      "script sha256 mismatch",
			SignatureOK: sigOK,
			ScriptSHA:   got,
		}
	}

	// Execute with sandboxing
	return execSecure(tr.TaskID, tr.Task, full, tr.Args, sigOK)
}
