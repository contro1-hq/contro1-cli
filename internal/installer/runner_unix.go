//go:build unix

package installer

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"

	"github.com/contro1-hq/contro1-cli/internal/brokerpaths"
)

// ErrNeedsElevation: the caller reports needs_local_confirmation with a
// `sudo contro1 ...` next command. The CLI never stores or asks for a password.
var ErrNeedsElevation = errors.New("installer: root is required")

func IsElevated() bool { return os.Geteuid() == 0 }

// SystemRunner applies a Linux (systemd) or macOS (launchd, unverified) plan.
type SystemRunner struct{}

func (SystemRunner) Steps(plan InstallPlan) ([]Step, error) {
	if !IsElevated() {
		return nil, ErrNeedsElevation
	}
	var steps []Step
	serviceUser := brokerpaths.LinuxUser
	if runtime.GOOS == "darwin" {
		serviceUser = brokerpaths.DarwinUser
	}
	steps = append(steps, Step{
		ID:      "user",
		Existed: func() (bool, error) { _, err := user.Lookup(serviceUser); return err == nil, nil },
		Do: func() error {
			if runtime.GOOS == "darwin" {
				return createDarwinUser(serviceUser)
			}
			return run("useradd", "--system", "--no-create-home", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", serviceUser)
		},
		Undo: func() error {
			if runtime.GOOS == "darwin" {
				return run("dscl", ".", "-delete", "/Users/"+serviceUser)
			}
			return run("userdel", serviceUser)
		},
	})
	for _, d := range plan.Dirs {
		d := d
		steps = append(steps, Step{
			ID:      "dir:" + d.Path,
			Existed: func() (bool, error) { _, err := os.Stat(d.Path); return err == nil, nil },
			Do: func() error {
				owner := strings.SplitN(d.Owner, ":", 2)[0]
				return run("install", "-d", "-o", owner, "-m", d.Mode, d.Path)
			},
			Undo: func() error { return os.RemoveAll(d.Path) },
		})
	}
	steps = append(steps, Step{
		ID: "binary",
		Do: func() error {
			return run("install", "-D", "-o", "root", "-m", "0755", plan.Binary.Source, plan.Binary.Dest)
		},
		Undo: func() error { return os.Remove(plan.Binary.Dest) },
	})
	for _, f := range plan.Files {
		f := f
		steps = append(steps, Step{
			ID: "file:" + f.Path,
			Existed: func() (bool, error) {
				raw, err := os.ReadFile(f.Path)
				return err == nil && string(raw) == f.Content, nil
			},
			Do:   func() error { return os.WriteFile(f.Path, []byte(f.Content), 0o644) },
			Undo: func() error { return os.Remove(f.Path) },
		})
	}
	if runtime.GOOS == "darwin" {
		steps = append(steps, Step{ID: "launchd", Do: func() error {
			return run("launchctl", "bootstrap", "system", "/Library/LaunchDaemons/com.contro1.broker.plist")
		}, Undo: func() error { return run("launchctl", "bootout", "system/com.contro1.broker") }})
	} else {
		steps = append(steps,
			Step{ID: "daemon-reload", Do: func() error { return run("systemctl", "daemon-reload") }},
			Step{ID: "enable", Do: func() error { return run("systemctl", "enable", "--now", "contro1-broker.service") },
				Undo: func() error { return run("systemctl", "disable", "--now", "contro1-broker.service") }},
		)
	}
	return steps, nil
}

func createDarwinUser(name string) error {
	// UNVERIFIED on macOS: a hidden system account with no shell and no home.
	for _, args := range [][]string{
		{".", "-create", "/Users/" + name},
		{".", "-create", "/Users/" + name, "UserShell", "/usr/bin/false"},
		{".", "-create", "/Users/" + name, "UniqueID", "398"},
		{".", "-create", "/Users/" + name, "PrimaryGroupID", "20"},
		{".", "-create", "/Users/" + name, "NFSHomeDirectory", "/var/empty"},
		{".", "-create", "/Users/" + name, "IsHidden", "1"},
	} {
		if err := run("dscl", args...); err != nil {
			return err
		}
	}
	return nil
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// RunElevated is not used on unix: the command asks the person to re-run with sudo.
func RunElevated([]string) (int, error) { return -1, ErrNeedsElevation }

// SudoHint builds the next command for a person at the terminal.
func SudoHint(command string) string { return "sudo " + command }

// ServiceStatus is used by doctor.
func ServiceStatus() (installed, running, automatic bool, account string) {
	if runtime.GOOS == "darwin" {
		err := exec.Command("launchctl", "print", "system/com.contro1.broker").Run()
		return err == nil, err == nil, err == nil, brokerpaths.DarwinUser
	}
	installed = exec.Command("systemctl", "cat", "contro1-broker.service").Run() == nil
	running = exec.Command("systemctl", "is-active", "--quiet", "contro1-broker.service").Run() == nil
	automatic = exec.Command("systemctl", "is-enabled", "--quiet", "contro1-broker.service").Run() == nil
	return installed, running, automatic, brokerpaths.LinuxUser
}
