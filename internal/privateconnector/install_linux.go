//go:build linux

package privateconnector

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

// LinuxServiceName is the systemd unit, LinuxServiceUser the system account it
// runs as: no shell, no home, and no rights outside its own state directory.
const LinuxServiceName = "contro1-private-connector"
const LinuxServiceUser = "contro1-connector"

const unitPath = "/etc/systemd/system/" + LinuxServiceName + ".service"

func runLinux(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func ensureLinuxUser() (*user.User, error) {
	if u, err := user.Lookup(LinuxServiceUser); err == nil {
		return u, nil
	}
	shell := "/usr/sbin/nologin"
	if _, err := os.Stat(shell); err != nil {
		shell = "/bin/false"
	}
	if err := runLinux("useradd", "--system", "--no-create-home", "--home-dir", "/nonexistent",
		"--shell", shell, "--user-group", LinuxServiceUser); err != nil {
		return nil, err
	}
	return user.Lookup(LinuxServiceUser)
}

// ownedDir creates dir with mode 0700, owned by the service account.
func ownedDir(dir string, uid, gid int) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chown(dir, uid, gid); err != nil {
		return err
	}
	return os.Chmod(dir, 0o700)
}

func copySelf(target string) error {
	source, err := os.Executable()
	if err != nil {
		return err
	}
	if source == target {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	// Written beside and renamed, so a running service never sees half a binary.
	staged := target + ".new"
	out, err := os.OpenFile(staged, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(staged, target)
}

// linuxUnit is the systemd unit. The hardening keeps the worker inside its own
// state and log directories: a compromised connector cannot write the rest of
// the host, read home directories or gain privileges.
func linuxUnit(layout Layout) string {
	return fmt.Sprintf(`[Unit]
Description=Contro1 private connector
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=%[1]s
Group=%[1]s
ExecStart=%[2]s private-connector serve
Restart=always
RestartSec=10
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
ReadWritePaths=%[3]s %[4]s

[Install]
WantedBy=multi-user.target
`, LinuxServiceUser, layout.BinaryPath, layout.StateDir, layout.LogDir)
}

func InstallService(input SetupInput) error {
	if os.Geteuid() != 0 {
		return errors.New("root rights are required (run with sudo)")
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return errors.New("systemd was not found; run the connector in Docker instead (see the documentation)")
	}
	if err := input.Validate(); err != nil {
		return err
	}
	u, err := ensureLinuxUser()
	if err != nil {
		return err
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	layout := ProductionLayout()
	if err := CheckCapacity(layout.StateDir, input.InstallationID); err != nil {
		return err
	}
	installationDir := InstallationDir(layout.StateDir, input.InstallationID)
	for _, dir := range []string{layout.StateDir, layout.LogDir, filepath.Join(layout.StateDir, "installations"), installationDir} {
		if err := ownedDir(dir, uid, gid); err != nil {
			return err
		}
	}
	if err := Provision(installationDir, input); err != nil {
		return err
	}
	for _, file := range []string{"config.json", "enrollment-code", "provider-secret"} {
		path := filepath.Join(installationDir, file)
		if _, err := os.Stat(path); err == nil {
			if err := os.Chown(path, uid, gid); err != nil {
				return err
			}
			if err := os.Chmod(path, 0o600); err != nil {
				return err
			}
		}
	}
	if err := copySelf(layout.BinaryPath); err != nil {
		return err
	}
	if err := os.WriteFile(unitPath, []byte(linuxUnit(layout)), 0o644); err != nil {
		return err
	}
	if err := runLinux("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := runLinux("systemctl", "enable", LinuxServiceName); err != nil {
		return err
	}
	// Restart rather than start: a second installation added to a running
	// service is only read when the worker starts.
	return runLinux("systemctl", "restart", LinuxServiceName)
}

func ServiceRunning() (bool, error) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false, nil
	}
	return exec.Command("systemctl", "is-active", "--quiet", LinuxServiceName).Run() == nil, nil
}

func UninstallService() error {
	if os.Geteuid() != 0 {
		return errors.New("root rights are required (run with sudo)")
	}
	if _, err := os.Stat(unitPath); err == nil {
		_ = runLinux("systemctl", "disable", "--now", LinuxServiceName)
	}
	for _, path := range []string{unitPath, ProductionLayout().BinaryPath} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return runLinux("systemctl", "daemon-reload")
}
