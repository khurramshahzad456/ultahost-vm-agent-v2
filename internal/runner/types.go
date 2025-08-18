package runner

type TaskRequest struct {
	Type      string   `json:"type"`      // must be "task"
	Task      string   `json:"task"`      // allowlisted name (e.g., "install_wordpress")
	Args      []string `json:"args"`      // validated per task
	Timestamp string   `json:"timestamp"` // RFC3339
	Nonce     string   `json:"nonce"`     // random string, unique per request
	Signature string   `json:"signature"` // base64 HMAC-SHA256 over canonical string
}

// type TaskResult struct {
// 	TaskID       string `json:"task_id"`
// 	Task         string `json:"task"`
// 	ExitCode     int    `json:"exit_code"`
// 	Stdout       string `json:"stdout"`
// 	Stderr       string `json:"stderr"`
// 	StartedAt    string `json:"started_at"`
// 	FinishedAt   string `json:"finished_at"`
// 	DurationSec  int64  `json:"duration_sec"`
// 	ChrootUsed   bool   `json:"chroot_used"`
// 	CgroupUsed   bool   `json:"cgroup_used"`
// 	SignatureOK  bool   `json:"signature_ok"`
// 	ScriptSHA256 string `json:"script_sha256"`
// }
