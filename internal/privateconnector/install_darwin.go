//go:build darwin

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

const plistPath = "/Library/LaunchDaemons/" + DarwinServiceName + ".plist"

func runCommand(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func ensureDarwinUser() (*user.User, error) {
	if u, err := user.Lookup(DarwinServiceUser); err == nil {
		return u, nil
	}
	out, err := exec.Command("dscl", ".", "-list", "/Users", "UniqueID").Output()
	if err != nil {
		return nil, err
	}
	used := map[int]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 {
			n, _ := strconv.Atoi(fields[1])
			used[n] = true
		}
	}
	uid := 0
	for n := 350; n < 400; n++ {
		if !used[n] {
			uid = n
			break
		}
	}
	if uid == 0 {
		return nil, errors.New("no free local service UID")
	}
	path := "/Users/" + DarwinServiceUser
	steps := [][]string{
		{".", "-create", path}, {".", "-create", path, "UserShell", "/usr/bin/false"},
		{".", "-create", path, "UniqueID", strconv.Itoa(uid)},
		{".", "-create", path, "PrimaryGroupID", "20"},
		{".", "-create", path, "NFSHomeDirectory", "/var/empty"},
		{".", "-create", path, "IsHidden", "1"},
	}
	for _, args := range steps {
		if err := runCommand("dscl", args...); err != nil {
			return nil, err
		}
	}
	return user.Lookup(DarwinServiceUser)
}

func InstallService(input SetupInput) error {
	if os.Geteuid() != 0 {
		return errors.New("root rights are required")
	}
	if err := input.Validate(); err != nil {
		return err
	}
	u, err := ensureDarwinUser()
	if err != nil {
		return err
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	layout := ProductionLayout()
	if err := CheckCapacity(layout.StateDir, input.InstallationID); err != nil {
		return err
	}
	for _, parent := range []string{filepath.Dir(layout.StateDir), filepath.Dir(layout.LogDir)} {
		if err := os.MkdirAll(parent, 0o755); err != nil {
			return err
		}
		if err := os.Chmod(parent, 0o755); err != nil {
			return err
		}
	}
	for _, dir := range []string{layout.StateDir, layout.LogDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		if err := os.Chown(dir, uid, gid); err != nil {
			return err
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return err
		}
	}
	installationsDir := filepath.Join(layout.StateDir, "installations")
	installationDir := InstallationDir(layout.StateDir, input.InstallationID)
	for _, dir := range []string{installationsDir, installationDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		if err := os.Chown(dir, uid, gid); err != nil {
			return err
		}
		if err := os.Chmod(dir, 0o700); err != nil {
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
	loaded := exec.Command("launchctl", "print", "system/"+DarwinServiceName).Run() == nil
	if loaded {
		if err := runCommand("launchctl", "bootout", "system/"+DarwinServiceName); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(layout.BinaryPath), 0o755); err != nil {
		return err
	}
	source, err := os.Executable()
	if err != nil {
		return err
	}
	if source != layout.BinaryPath {
		in, err := os.Open(source)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(layout.BinaryPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
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
		if err := os.Chmod(layout.BinaryPath, 0o755); err != nil {
			return err
		}
	}
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>%s</string>
<key>ProgramArguments</key><array><string>%s</string><string>private-connector</string><string>serve</string></array>
<key>UserName</key><string>%s</string>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>Umask</key><integer>63</integer>
<key>StandardOutPath</key><string>%s</string>
<key>StandardErrorPath</key><string>%s</string>
</dict></plist>
`, DarwinServiceName, layout.BinaryPath, DarwinServiceUser,
		filepath.Join(layout.LogDir, "service.out.log"), filepath.Join(layout.LogDir, "service.err.log"))
	if err := os.WriteFile(plistPath, []byte(plist), 0o644); err != nil {
		return err
	}
	if err := os.Chmod(plistPath, 0o644); err != nil {
		return err
	}
	return runCommand("launchctl", "bootstrap", "system", plistPath)
}

func ServiceRunning() (bool, error) {
	out, err := exec.Command("launchctl", "print", "system/"+DarwinServiceName).Output()
	if err != nil {
		return false, nil
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "pid = ") {
			pid, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "pid = ")))
			return err == nil && pid > 0, nil
		}
	}
	return false, nil
}

// UninstallService keeps local state and the non-login account for recovery.
func UninstallService() error {
	if os.Geteuid() != 0 {
		return errors.New("root rights are required")
	}
	if exec.Command("launchctl", "print", "system/"+DarwinServiceName).Run() == nil {
		if err := runCommand("launchctl", "bootout", "system/"+DarwinServiceName); err != nil {
			return err
		}
	}
	for _, path := range []string{plistPath, ProductionLayout().BinaryPath} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}
