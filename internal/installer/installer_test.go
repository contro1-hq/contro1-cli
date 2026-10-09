package installer

import (
	"errors"
	"strings"
	"testing"

	"github.com/contro1-hq/contro1-cli/internal/brokerpaths"
)

func TestPlans(t *testing.T) {
	opts := Options{SourceBinary: "/tmp/contro1", APIURL: "https://api.contro1.com"}

	win := Plan("windows", opts)
	if win.Service.Account != `NT SERVICE\Contro1Broker` || win.Service.SIDType != "unrestricted" || !win.RequiresElevation {
		t.Fatalf("windows service spec: %+v", win.Service)
	}
	sid := brokerpaths.WindowsServiceSID(brokerpaths.ServiceName)
	if !strings.Contains(win.Dirs[0].SDDL, sid) || strings.Contains(win.Dirs[0].SDDL, ";;;BU)") {
		t.Fatalf("state directory must be service, SYSTEM and administrators only: %s", win.Dirs[0].SDDL)
	}
	if !strings.Contains(win.Endpoints[0].Protection, "(A;;GA;;;BA)") || strings.Contains(win.Endpoints[0].Protection, "WD") {
		t.Fatalf("control endpoint descriptor: %s", win.Endpoints[0].Protection)
	}

	linux := Plan("linux", opts)
	unit := linux.Files[0].Content
	for _, want := range []string{"User=contro1-broker", "NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes", "CapabilityBoundingSet=CAP_CHOWN", "AmbientCapabilities=CAP_CHOWN", "RuntimeDirectoryMode=0711", "UMask=0077", "ExecStart=/usr/local/lib/contro1/contro1 broker serve --api-url https://api.contro1.com"} {
		if !strings.Contains(unit, want) {
			t.Fatalf("systemd unit is missing %q:\n%s", want, unit)
		}
	}
	if linux.Dirs[0].Mode != "0700" {
		t.Fatal("state directory must be 0700")
	}

	mac := Plan("darwin", opts)
	if !mac.Unverified || !strings.Contains(mac.Files[0].Content, "<string>_contro1broker</string>") {
		t.Fatalf("macOS plan must be marked unverified and run as the service user")
	}
	if mac.Dirs[0].Path != "/usr/local/lib/contro1" || mac.Dirs[0].Owner != "root:wheel" || mac.Dirs[0].Mode != "0755" {
		t.Fatalf("macOS must create the root-owned binary directory first: %+v", mac.Dirs[0])
	}
	if mac.Dirs[1].Path != "/Library/Application Support/Contro1" || mac.Dirs[1].Owner != "root:wheel" || mac.Dirs[1].Mode != "0755" {
		t.Fatalf("macOS broker must be able to traverse its state parent: %+v", mac.Dirs[1])
	}
	if mac.Dirs[2].Path != "/Library/Application Support/Contro1/broker" || mac.Dirs[2].Owner != brokerpaths.DarwinUser || mac.Dirs[2].Mode != "0700" {
		t.Fatalf("macOS broker state must belong to the service account: %+v", mac.Dirs[2])
	}
	if got := strings.Join(mac.Commands[2], " "); got != "install -d -o root -g wheel -m 0755 /usr/local/lib/contro1" {
		t.Fatalf("macOS directory command: %s", got)
	}
	if got := strings.Join(mac.Commands[3], " "); got != "install -o root -g wheel -m 0755 /tmp/contro1 /usr/local/lib/contro1/contro1" {
		t.Fatalf("macOS binary command: %s", got)
	}

	un := UninstallPlan("linux", false)
	for _, c := range un.Commands {
		if c[0] == "remove-directory" {
			t.Fatal("uninstall without purge keeps state")
		}
	}
}

type fakeRunner struct {
	steps []Step
}

func (f fakeRunner) Steps(InstallPlan) ([]Step, error) { return f.steps, nil }

func TestApplyRollsBackOnlyWhatItCreated(t *testing.T) {
	var log []string
	mk := func(id string, existed bool, fail bool) Step {
		return Step{
			ID:      id,
			Existed: func() (bool, error) { return existed, nil },
			Do: func() error {
				if fail {
					return errors.New("boom")
				}
				log = append(log, "do:"+id)
				return nil
			},
			Undo: func() error { log = append(log, "undo:"+id); return nil },
		}
	}
	res, err := Apply(InstallPlan{}, fakeRunner{steps: []Step{
		mk("user", true, false), // already there from a working install
		mk("binary", false, false),
		mk("service", false, false),
		mk("start", false, true),
	}}, "")
	if err == nil || res.Failed != "start" {
		t.Fatalf("expected failure at start: %+v %v", res, err)
	}
	got := strings.Join(log, ",")
	if got != "do:binary,do:service,undo:service,undo:binary" {
		t.Fatalf("rollback order or scope wrong: %s", got)
	}
	for _, id := range res.RolledBack {
		if id == "user" {
			t.Fatal("a pre-existing component must never be rolled back")
		}
	}
}

func TestDeclinedElevationIsDistinguishable(t *testing.T) {
	_, err := Apply(InstallPlan{}, fakeRunner{steps: []Step{{ID: "elevate", Do: func() error { return ErrElevationDeclined }}}}, "")
	if !errors.Is(err, ErrElevationDeclined) {
		t.Fatalf("declined elevation must be recognisable: %v", err)
	}
}
