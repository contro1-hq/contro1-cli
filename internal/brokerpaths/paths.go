// Package brokerpaths holds the Contro1 service's well-known locations and
// identities, shared by `broker serve`, the installer, doctor and connect.
package brokerpaths

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf16"
)

const (
	// ServiceName is the Windows service and launchd/systemd unit base name.
	ServiceName = "Contro1Broker"
	// UnixUser is the dedicated service identity on Linux; macOS uses _contro1broker.
	LinuxUser  = "contro1-broker"
	DarwinUser = "_contro1broker"
	// ControlPipeName is the production control pipe on Windows.
	ControlPipeName = "contro1-broker-control"
	// DevControlPipePrefix is used by a foreground development broker.
	DevControlPipePrefix = "contro1-broker-control-dev-"
)

// Layout is where one broker keeps its state and endpoints.
type Layout struct {
	StateDir        string
	ControlEndpoint string // npipe:// or unix://
	EndpointDir     string // unix data sockets
	// PlatformsDir holds platform mapping files, readable by agent platforms.
	PlatformsDir string
	LogDir       string
	BinaryPath   string
	Foreground   bool
}

// Production returns the service layout for goos.
func Production(goos string) Layout {
	switch goos {
	case "windows":
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		pf := os.Getenv("ProgramFiles")
		if pf == "" {
			pf = `C:\Program Files`
		}
		return Layout{
			StateDir:        filepath.Join(pd, "Contro1", "broker"),
			ControlEndpoint: "npipe:////./pipe/" + ControlPipeName,
			PlatformsDir:    filepath.Join(pd, "Contro1", "platforms"),
			LogDir:          filepath.Join(pd, "Contro1", "logs"),
			BinaryPath:      filepath.Join(pf, "Contro1", "contro1.exe"),
		}
	case "darwin":
		return Layout{
			StateDir:        "/Library/Application Support/Contro1/broker",
			ControlEndpoint: "unix:///var/run/contro1/control.sock",
			EndpointDir:     "/var/run/contro1/ep",
			PlatformsDir:    "/Library/Application Support/Contro1/platforms",
			LogDir:          "/Library/Logs/Contro1",
			BinaryPath:      "/usr/local/lib/contro1/contro1",
		}
	default:
		return Layout{
			StateDir:        "/var/lib/contro1-broker",
			ControlEndpoint: "unix:///run/contro1/control.sock",
			EndpointDir:     "/run/contro1/ep",
			PlatformsDir:    "/etc/contro1/platforms",
			LogDir:          "/var/log/contro1",
			BinaryPath:      "/usr/local/lib/contro1/contro1",
		}
	}
}

// Development returns a per-user foreground layout. Never used by the service.
func Development() Layout {
	base, err := os.UserConfigDir()
	if err != nil {
		base = os.TempDir()
	}
	state := filepath.Join(base, "contro1", "broker-dev")
	l := Layout{StateDir: state, LogDir: filepath.Join(state, "logs"), PlatformsDir: filepath.Join(state, "platforms"), Foreground: true}
	if runtime.GOOS == "windows" {
		user := strings.ToLower(os.Getenv("USERNAME"))
		l.ControlEndpoint = "npipe:////./pipe/" + DevControlPipePrefix + sanitize(user)
	} else {
		l.ControlEndpoint = "unix://" + filepath.ToSlash(filepath.Join(state, "control.sock"))
		l.EndpointDir = filepath.Join(state, "ep")
	}
	return l
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "user"
	}
	return b.String()
}

// WindowsServiceSID computes the per-service SID Windows assigns to
// `NT SERVICE\<name>`: S-1-5-80 followed by the SHA-1 of the upper-case service
// name in UTF-16LE, read as five little-endian 32-bit values. It is stable
// before the service exists, so descriptors can name it at install time.
func WindowsServiceSID(name string) string {
	units := utf16.Encode([]rune(strings.ToUpper(name)))
	buf := make([]byte, len(units)*2)
	for i, u := range units {
		binary.LittleEndian.PutUint16(buf[i*2:], u)
	}
	sum := sha1.Sum(buf)
	parts := make([]string, 5)
	for i := 0; i < 5; i++ {
		parts[i] = fmt.Sprint(binary.LittleEndian.Uint32(sum[i*4:]))
	}
	return "S-1-5-80-" + strings.Join(parts, "-")
}
