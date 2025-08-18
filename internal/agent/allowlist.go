package agent

// Allowlist maps logical task -> script filename

var Allowlist = map[string]string{
	"check_uptime":     "check_uptime.sh",

	"check_diskspace":  "check_diskspace.sh",

	"install_wordpress":"install_wordpress.sh",
}
