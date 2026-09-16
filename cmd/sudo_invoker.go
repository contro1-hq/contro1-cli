package cmd

import "os"

// sudoInvoker names the person who ran the command through sudo, or "" when
// the command runs as the person themself (or as a real root login).
func sudoInvoker() string {
	if os.Getenv("SUDO_UID") == "" || os.Getenv("SUDO_UID") == "0" {
		return ""
	}
	if name := os.Getenv("SUDO_USER"); name != "" && name != "root" && isRootProcess() {
		return name
	}
	return ""
}
