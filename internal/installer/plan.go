// Package installer installs the Contro1 service. The plan is a pure value,
// computed identically on any OS so it can be reviewed (`--dry-run`) and
// tested everywhere; Apply executes it through an injected Runner and rolls
// back only the steps it created.
package installer

import (
	"fmt"
	"path"
	"strings"

	"github.com/contro1-hq/contro1-cli/internal/brokerpaths"
	"github.com/contro1-hq/contro1-cli/internal/localipc"
)

type Options struct {
	// SourceBinary is the running contro1 executable to install.
	SourceBinary string
	SourceSHA256 string
	APIURL       string
	// PlatformUser is the account the agent platform runs as. It must differ
	// from the service identity.
	PlatformUser string
	Version      string
}

type ServiceSpec struct {
	Name        string   `json:"name"`
	DisplayName string   `json:"display_name"`
	Account     string   `json:"account"`
	StartType   string   `json:"start_type"`
	Recovery    string   `json:"recovery"`
	Args        []string `json:"args"`
	SIDType     string   `json:"sid_type,omitempty"`
}

type BinarySpec struct {
	Source string `json:"source"`
	Dest   string `json:"dest"`
	SHA256 string `json:"sha256,omitempty"`
	Owner  string `json:"owner"`
	Mode   string `json:"mode"`
}

type UserSpec struct {
	Name    string `json:"name"`
	Command string `json:"command"`
}

type DirSpec struct {
	Path  string `json:"path"`
	Owner string `json:"owner"`
	Mode  string `json:"mode,omitempty"`
	SDDL  string `json:"sddl,omitempty"`
}

type EndpointSpec struct {
	Path       string   `json:"path"`
	Protection string   `json:"protection"`
	Principals []string `json:"principals"`
}

type FileSpec struct {
	Path    string `json:"path"`
	Mode    string `json:"mode"`
	Content string `json:"content"`
}

// InstallPlan is everything the installer will change, in order.
type InstallPlan struct {
	OS                string         `json:"os"`
	Service           ServiceSpec    `json:"service"`
	Binary            BinarySpec     `json:"binary"`
	Users             []UserSpec     `json:"users,omitempty"`
	Dirs              []DirSpec      `json:"dirs"`
	Endpoints         []EndpointSpec `json:"endpoints"`
	Files             []FileSpec     `json:"files,omitempty"`
	Commands          [][]string     `json:"commands"`
	RequiresElevation bool           `json:"requires_elevation"`
	Summary           []string       `json:"summary"`
	Unverified        bool           `json:"unverified,omitempty"`
}

// Plan builds the install plan for goos.
func Plan(goos string, opts Options) InstallPlan {
	switch goos {
	case "windows":
		return planWindows(opts)
	case "darwin":
		return planDarwin(opts)
	default:
		return planLinux(opts)
	}
}

func planWindows(opts Options) InstallPlan {
	layout := brokerpaths.Production("windows")
	svcSID := brokerpaths.WindowsServiceSID(brokerpaths.ServiceName)
	platformsDir := layout.PlatformsDir
	args := []string{"broker", "serve"}
	if opts.APIURL != "" {
		args = append(args, "--api-url", opts.APIURL)
	}
	p := InstallPlan{
		OS: "windows",
		Service: ServiceSpec{
			Name: brokerpaths.ServiceName, DisplayName: "Contro1 service", Account: `NT SERVICE\` + brokerpaths.ServiceName,
			StartType: "automatic (delayed)", Recovery: "restart after 5s, 30s, 60s", Args: args, SIDType: "unrestricted",
		},
		Binary: BinarySpec{Source: opts.SourceBinary, Dest: layout.BinaryPath, SHA256: opts.SourceSHA256, Owner: "Administrators", Mode: "Administrators full, Users read and execute"},
		Dirs: []DirSpec{
			{Path: layout.StateDir, Owner: "SYSTEM", SDDL: fmt.Sprintf("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;%s)", svcSID)},
			{Path: layout.LogDir, Owner: "SYSTEM", SDDL: fmt.Sprintf("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;%s)", svcSID)},
			{Path: platformsDir, Owner: "SYSTEM", SDDL: fmt.Sprintf("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;%s)(A;OICI;GR;;;BU)", svcSID)},
		},
		Endpoints: []EndpointSpec{{
			Path: layout.ControlEndpoint, Protection: localipc.ControlSDDL(svcSID),
			Principals: []string{"SYSTEM", "Administrators (elevated)", `NT SERVICE\` + brokerpaths.ServiceName},
		}},
		Commands: [][]string{
			{"copy", opts.SourceBinary, layout.BinaryPath},
			{"sc.exe", "create", brokerpaths.ServiceName, "binPath=", quoteArgs(layout.BinaryPath, args), "obj=", `NT SERVICE\` + brokerpaths.ServiceName, "start=", "delayed-auto"},
			{"sc.exe", "sidtype", brokerpaths.ServiceName, "unrestricted"},
			{"sc.exe", "failure", brokerpaths.ServiceName, "reset=", "86400", "actions=", "restart/5000/restart/30000/restart/60000"},
			{"sc.exe", "start", brokerpaths.ServiceName},
		},
		RequiresElevation: true,
	}
	p.Summary = summary(p, "one Windows approval prompt")
	return p
}

func planLinux(opts Options) InstallPlan {
	layout := brokerpaths.Production("linux")
	const bin = "/usr/local/lib/contro1/contro1"
	args := []string{"broker", "serve"}
	if opts.APIURL != "" {
		args = append(args, "--api-url", opts.APIURL)
	}
	unit := strings.Join([]string{
		"[Unit]",
		"Description=Contro1 service (agent connections)",
		"After=network-online.target",
		"Wants=network-online.target",
		"",
		"[Service]",
		"Type=simple",
		"User=" + brokerpaths.LinuxUser,
		"Group=" + brokerpaths.LinuxUser,
		"ExecStart=" + bin + " " + strings.Join(args, " "),
		"StateDirectory=contro1-broker",
		"StateDirectoryMode=0700",
		"RuntimeDirectory=contro1",
		"RuntimeDirectoryMode=0711",
		"LogsDirectory=contro1",
		"ReadWritePaths=/etc/contro1/platforms",
		"UMask=0077",
		"NoNewPrivileges=yes",
		"ProtectSystem=strict",
		"ProtectHome=yes",
		"PrivateTmp=yes",
		"PrivateDevices=yes",
		"ProtectKernelTunables=yes",
		"ProtectKernelModules=yes",
		"ProtectControlGroups=yes",
		"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
		"RestrictNamespaces=yes",
		"RestrictSUIDSGID=yes",
		"CapabilityBoundingSet=",
		"AmbientCapabilities=",
		"LockPersonality=yes",
		"MemoryDenyWriteExecute=yes",
		"SystemCallArchitectures=native",
		"SystemCallFilter=@system-service",
		"Restart=on-failure",
		"RestartSec=5",
		"",
		"[Install]",
		"WantedBy=multi-user.target",
		"",
	}, "\n")
	p := InstallPlan{
		OS:      "linux",
		Service: ServiceSpec{Name: "contro1-broker.service", DisplayName: "Contro1 service", Account: brokerpaths.LinuxUser, StartType: "enabled at boot", Recovery: "Restart=on-failure", Args: args},
		Binary:  BinarySpec{Source: opts.SourceBinary, Dest: bin, SHA256: opts.SourceSHA256, Owner: "root:root", Mode: "0755"},
		Users:   []UserSpec{{Name: brokerpaths.LinuxUser, Command: "useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin " + brokerpaths.LinuxUser}},
		Dirs: []DirSpec{
			{Path: layout.StateDir, Owner: brokerpaths.LinuxUser + ":" + brokerpaths.LinuxUser, Mode: "0700"},
			{Path: "/etc/contro1/platforms", Owner: brokerpaths.LinuxUser + ":root", Mode: "0755"},
		},
		Endpoints: []EndpointSpec{{Path: layout.ControlEndpoint, Protection: "socket 0660 in /run/contro1 (0711), peer credentials checked", Principals: []string{"root", brokerpaths.LinuxUser}}},
		Files:     []FileSpec{{Path: "/etc/systemd/system/contro1-broker.service", Mode: "0644", Content: unit}},
		Commands: [][]string{
			{"useradd", "--system", "--no-create-home", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", brokerpaths.LinuxUser},
			{"install", "-D", "-o", "root", "-g", "root", "-m", "0755", opts.SourceBinary, bin},
			{"install", "-d", "-o", brokerpaths.LinuxUser, "-g", "root", "-m", "0755", "/etc/contro1/platforms"},
			{"systemctl", "daemon-reload"},
			{"systemctl", "enable", "--now", "contro1-broker.service"},
		},
		RequiresElevation: true,
	}
	p.Summary = summary(p, "sudo (or pkexec)")
	return p
}

func planDarwin(opts Options) InstallPlan {
	layout := brokerpaths.Production("darwin")
	const bin = "/usr/local/lib/contro1/contro1"
	args := []string{"broker", "serve"}
	if opts.APIURL != "" {
		args = append(args, "--api-url", opts.APIURL)
	}
	var argXML strings.Builder
	argXML.WriteString("    <string>" + bin + "</string>\n")
	for _, a := range args {
		argXML.WriteString("    <string>" + xmlEscape(a) + "</string>\n")
	}
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.contro1.broker</string>
  <key>ProgramArguments</key>
  <array>
` + argXML.String() + `  </array>
  <key>UserName</key>
  <string>` + brokerpaths.DarwinUser + `</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>Umask</key>
  <integer>63</integer>
  <key>StandardErrorPath</key>
  <string>` + path.Join(layout.LogDir, "broker.err.log") + `</string>
</dict>
</plist>
`
	p := InstallPlan{
		OS:         "darwin",
		Unverified: true,
		Service:    ServiceSpec{Name: "com.contro1.broker", DisplayName: "Contro1 service", Account: brokerpaths.DarwinUser, StartType: "RunAtLoad", Recovery: "KeepAlive", Args: args},
		Binary:     BinarySpec{Source: opts.SourceBinary, Dest: bin, SHA256: opts.SourceSHA256, Owner: "root:wheel", Mode: "0755"},
		Users:      []UserSpec{{Name: brokerpaths.DarwinUser, Command: "dscl . -create /Users/" + brokerpaths.DarwinUser + " (UniqueID below 500, no login shell)"}},
		Dirs: []DirSpec{
			{Path: layout.StateDir, Owner: brokerpaths.DarwinUser, Mode: "0700"},
			{Path: "/var/run/contro1", Owner: brokerpaths.DarwinUser, Mode: "0711"},
			{Path: layout.PlatformsDir, Owner: brokerpaths.DarwinUser, Mode: "0755"},
			{Path: layout.LogDir, Owner: brokerpaths.DarwinUser, Mode: "0700"},
		},
		Endpoints: []EndpointSpec{{Path: layout.ControlEndpoint, Protection: "socket 0660, peer credentials checked (unverified)", Principals: []string{"root", brokerpaths.DarwinUser}}},
		Files:     []FileSpec{{Path: "/Library/LaunchDaemons/com.contro1.broker.plist", Mode: "0644", Content: plist}},
		Commands: [][]string{
			{"dscl", ".", "-create", "/Users/" + brokerpaths.DarwinUser},
			{"dscl", ".", "-create", "/Users/" + brokerpaths.DarwinUser, "UserShell", "/usr/bin/false"},
			{"install", "-o", "root", "-g", "wheel", "-m", "0755", opts.SourceBinary, bin},
			{"launchctl", "bootstrap", "system", "/Library/LaunchDaemons/com.contro1.broker.plist"},
		},
		RequiresElevation: true,
	}
	p.Summary = summary(p, "an administrator password prompt")
	return p
}

// UninstallPlan removes only service components. State (keys, connections)
// is kept unless purge is set, because a reinstall should not force every
// owner to approve again.
func UninstallPlan(goos string, purge bool) InstallPlan {
	install := Plan(goos, Options{})
	p := InstallPlan{OS: goos, Service: install.Service, RequiresElevation: true, Unverified: install.Unverified}
	switch goos {
	case "windows":
		p.Commands = [][]string{{"sc.exe", "stop", brokerpaths.ServiceName}, {"sc.exe", "delete", brokerpaths.ServiceName}, {"del", install.Binary.Dest}}
	case "darwin":
		p.Commands = [][]string{{"launchctl", "bootout", "system/com.contro1.broker"}, {"rm", "/Library/LaunchDaemons/com.contro1.broker.plist"}, {"rm", install.Binary.Dest}}
	default:
		p.Commands = [][]string{{"systemctl", "disable", "--now", "contro1-broker.service"}, {"rm", "/etc/systemd/system/contro1-broker.service"}, {"systemctl", "daemon-reload"}, {"rm", install.Binary.Dest}}
	}
	if purge {
		for _, d := range install.Dirs {
			p.Commands = append(p.Commands, []string{"remove-directory", d.Path})
		}
	}
	p.Summary = []string{fmt.Sprintf("Stop and remove the %s service", install.Service.Name)}
	if purge {
		p.Summary = append(p.Summary, "Delete all local connection state and keys (owners must approve again)")
	} else {
		p.Summary = append(p.Summary, "Keep local connection state so a reinstall reconnects without new approvals")
	}
	return p
}

func summary(p InstallPlan, elevation string) []string {
	out := []string{
		fmt.Sprintf("Install the Contro1 service (%s) to run as %s, starting automatically", p.Service.Name, p.Service.Account),
		fmt.Sprintf("Copy contro1 to %s", p.Binary.Dest),
	}
	for _, u := range p.Users {
		out = append(out, "Create the service account "+u.Name)
	}
	for _, d := range p.Dirs {
		if strings.Contains(d.SDDL, ";;;BU)") || d.Mode == "0755" || d.Mode == "0711" {
			out = append(out, "Create "+d.Path+" (readable by agent platforms, changed only by the service)")
			continue
		}
		out = append(out, "Create "+d.Path+" (only the service and administrators can read it)")
	}
	out = append(out, "Open the Contro1 control endpoint for administrators only")
	out = append(out, "This needs "+elevation)
	return out
}

func quoteArgs(bin string, args []string) string {
	parts := []string{`"` + bin + `"`}
	for _, a := range args {
		if strings.ContainsAny(a, " \t") {
			a = `"` + a + `"`
		}
		parts = append(parts, a)
	}
	return strings.Join(parts, " ")
}

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}
