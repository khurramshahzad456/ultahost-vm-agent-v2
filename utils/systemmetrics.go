package utils

import (
	"os/exec"
	"strconv"
	"strings"
)

// System health metrics included in heartbeat
type SystemMetrics struct {
	CPU               float64  `json:"cpu_usage"`
	RAM               float64  `json:"ram_usage"`
	Disk              float64  `json:"disk_usage"`
	Network           float64  `json:"network_usage"`
	OpenPorts         []int    `json:"open_ports"`
	RunningServices   []string `json:"running_services"`
	CronJobs          []string `json:"cron_jobs"`
	InstalledPackages []string `json:"installed_packages"`
	SSLCertificates   []string `json:"ssl_certificates"`
	FirewallRules     []string `json:"firewall_rules"`
}

type heartbeatPayload struct {
	Type      string        `json:"type"`
	Version   int           `json:"version"`
	AgentID   string        `json:"agent_id"`
	Counter   uint64        `json:"counter"`
	Nonce     string        `json:"nonce"`
	Timestamp string        `json:"timestamp"`
	Signature string        `json:"signature"`
	Metrics   SystemMetrics `json:"metrics"`
}

func collectSystemMetrics() SystemMetrics {
	return SystemMetrics{
		CPU:               getCPUUsage(),
		RAM:               getRAMUsage(),
		Disk:              getDiskUsage(),
		Network:           getNetworkUsage(),
		OpenPorts:         getOpenPorts(),
		RunningServices:   getRunningServices(),
		CronJobs:          getCronJobs(),
		InstalledPackages: getInstalledPackages(),
		SSLCertificates:   getSSLCertificates(),
		FirewallRules:     getFirewallRules(),
	}
}

func runCommand(cmd string, args ...string) string {
	out, err := exec.Command(cmd, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func getCPUUsage() float64 {
	out := runCommand("sh", "-c", "top -bn1 | grep 'Cpu(s)' | awk '{print $2+$4}'")
	val, _ := strconv.ParseFloat(out, 64)
	return val
}

func getRAMUsage() float64 {
	out := runCommand("sh", "-c", "free | grep Mem | awk '{print $3/$2 * 100.0}'")
	val, _ := strconv.ParseFloat(out, 64)
	return val
}

func getDiskUsage() float64 {
	out := runCommand("sh", "-c", "df --total | grep total | awk '{print $3/$2 * 100.0}'")
	val, _ := strconv.ParseFloat(out, 64)
	return val
}

func getNetworkUsage() float64 {
	out := runCommand("sh", "-c", "cat /proc/net/dev | awk 'NR>2{rx+=$2;tx+=$10} END{print (rx+tx)/1024/1024}'")
	val, _ := strconv.ParseFloat(out, 64)
	return val
}

func getOpenPorts() []int {
	out := runCommand("sh", "-c", "ss -tuln | awk 'NR>1 {print $5}' | awk -F: '{print $NF}'")
	lines := strings.Split(out, "\n")
	ports := []int{}
	for _, l := range lines {
		if p, err := strconv.Atoi(strings.TrimSpace(l)); err == nil {
			ports = append(ports, p)
		}
	}
	return ports
}

func getRunningServices() []string {
	out := runCommand("systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--no-legend")
	lines := strings.Split(out, "\n")
	services := []string{}
	for _, l := range lines {
		fields := strings.Fields(l)
		if len(fields) > 0 {
			services = append(services, fields[0])
		}
	}
	return services
}

func getCronJobs() []string {
	out := runCommand("sh", "-c", "cat /etc/crontab; ls /var/spool/cron/ 2>/dev/null | xargs -I{} cat /var/spool/cron/{}")
	if out == "" {
		return []string{}
	}
	return strings.Split(out, "\n")
}

func getInstalledPackages() []string {
	out := runCommand("sh", "-c", "if command -v dpkg >/dev/null; then dpkg -l | awk '{print $2}'; elif command -v rpm >/dev/null; then rpm -qa; fi")
	if out == "" {
		return []string{}
	}
	return strings.Split(out, "\n")
}

func getSSLCertificates() []string {
	out := runCommand("sh", "-c", "find /etc/ssl/certs -type f -name '*.pem' -o -name '*.crt' | head -n 20")
	if out == "" {
		return []string{}
	}
	return strings.Split(out, "\n")
}

func getFirewallRules() []string {
	out := runCommand("sh", "-c", "if command -v ufw >/dev/null; then ufw status; elif command -v iptables >/dev/null; then iptables -S; fi")
	if out == "" {
		return []string{}
	}
	return strings.Split(out, "\n")
}
