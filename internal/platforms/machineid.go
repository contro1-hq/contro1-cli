package platforms

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strings"
)

/*
machineIdentity reads the operating system's own stable id for this computer.

WHY NOT THE HOSTNAME. Claude Code's subject was "claude-code@<hostname>", and
on macOS the hostname is whatever the network last said: "mbp.local" at home,
"mbp.lan" on another router, a DHCP name in an office. Each new name was a new
subject, so the same Claude Code on the same Mac was connected again as a new
agent, with its own approvals and its own access, beside the old one. The ids
read here survive a network change, a rename and a reboot:

  - macOS: IOPlatformUUID from the platform expert (`ioreg`), fixed per machine.
  - Linux: /etc/machine-id (systemd), else /var/lib/dbus/machine-id.
  - Windows: MachineGuid under HKLM\SOFTWARE\Microsoft\Cryptography.

The raw id never leaves this computer. systemd asks applications to use it only
hashed with their own key, so it is: subjects carry a short hash of it, which
is enough to tell two computers apart and says nothing usable about either.
*/
type machineReaders struct {
	goos     string
	runner   Runner
	readFile func(string) ([]byte, error)
}

var ioPlatformUUID = regexp.MustCompile(`"IOPlatformUUID"\s*=\s*"([^"]+)"`)

func (r machineReaders) read(ctx context.Context) (string, error) {
	goos := r.goos
	if goos == "" {
		goos = runtime.GOOS
	}
	readFile := r.readFile
	if readFile == nil {
		readFile = os.ReadFile
	}
	runner := r.runner
	if runner == nil {
		runner = ExecRunner
	}
	var id string
	switch goos {
	case "darwin":
		out, err := runner(ctx, "ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
		if err != nil {
			return "", fmt.Errorf("ioreg: %w", err)
		}
		if m := ioPlatformUUID.FindSubmatch(out); m != nil {
			id = string(m[1])
		}
	case "linux":
		for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
			if raw, err := readFile(path); err == nil && strings.TrimSpace(string(raw)) != "" {
				id = string(raw)
				break
			}
		}
	case "windows":
		out, err := runner(ctx, "reg", "query", `HKLM\SOFTWARE\Microsoft\Cryptography`, "/v", "MachineGuid")
		if err != nil {
			return "", fmt.Errorf("reg query: %w", err)
		}
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 3 && strings.EqualFold(fields[0], "MachineGuid") {
				id = fields[len(fields)-1]
			}
		}
	default:
		return "", fmt.Errorf("no machine id on %s", goos)
	}
	id = strings.ToLower(strings.TrimSpace(id))
	// An all-zero or tiny value is a placeholder some images ship with, and
	// every computer built from that image would share it.
	if len(strings.Trim(id, "0-")) < 8 {
		return "", errors.New("this computer has no usable machine id")
	}
	return id, nil
}

// machineKey is the short, app-specific hash of a machine id used in subjects.
func machineKey(id string) string {
	sum := sha256.Sum256([]byte("contro1/claude-code\x00" + id))
	return hex.EncodeToString(sum[:8])
}
