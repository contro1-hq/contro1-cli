package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/contro1-hq/contro1-cli/internal/broker"
	"github.com/contro1-hq/contro1-cli/internal/brokerpaths"
	"github.com/contro1-hq/contro1-cli/internal/installer"
)

// fakeElevation records every elevated phase a command asks for and answers
// as the elevated process would. No administrator prompt, no service.
func fakeElevation(t *testing.T, answer func(connectPhase) (*connectPhase, error)) *[]connectPhase {
	t.Helper()
	var asked []connectPhase
	old := elevatedPhase
	elevatedPhase = func(_ context.Context, p connectPhase) (*connectPhase, error) {
		asked = append(asked, p)
		return answer(p)
	}
	t.Cleanup(func() { elevatedPhase = old })
	return &asked
}

func outdatedService() *serviceBroker {
	s := &serviceBroker{layout: brokerpaths.Development()}
	s.compare = func() installer.ServiceComparison {
		return installer.CompareService("0.2.28", "0.2.30", nil)
	}
	return s
}

// Disconnect's revoke and the update are one elevation, the update first.
func TestDisconnectUpdatesAnOldServiceInTheSameElevation(t *testing.T) {
	asked := fakeElevation(t, func(p connectPhase) (*connectPhase, error) {
		p.ServiceVersion = "0.2.30"
		return &p, nil
	})
	s := outdatedService()
	if line := s.PendingServiceUpdate(); line != "Update the Contro1 service (from 0.2.28 to 0.2.30)" {
		t.Fatalf("preview: %q", line)
	}
	if err := s.RevokeLocal(context.Background(), "", "codex"); err != nil {
		t.Fatal(err)
	}
	if len(*asked) != 1 || !(*asked)[0].UpdateService || (*asked)[0].RevokePlatform != "codex" {
		t.Fatalf("one phase carrying both: %+v", *asked)
	}
	done, err := s.ServiceUpdateResult()
	if err != nil || !strings.Contains(done, "updated to 0.2.30") {
		t.Fatalf("result: %q %v", done, err)
	}
	if s.PendingServiceUpdate() != "" {
		t.Fatal("once updated, nothing is pending")
	}
}

func TestRegisterCarriesTheUpdate(t *testing.T) {
	asked := fakeElevation(t, func(p connectPhase) (*connectPhase, error) { return &p, nil })
	s := outdatedService()
	if _, err := s.Register(context.Background(), "https://api.example", broker.ControlConnectionsRequest{ConnectionTicket: "ccct_x"}); err != nil {
		t.Fatal(err)
	}
	if len(*asked) != 1 || !(*asked)[0].UpdateService || (*asked)[0].Request.ConnectionTicket != "ccct_x" {
		t.Fatalf("the registration phase carries the update: %+v", *asked)
	}
}

func TestCurrentServiceIsNotUpdated(t *testing.T) {
	asked := fakeElevation(t, func(p connectPhase) (*connectPhase, error) { return &p, nil })
	s := &serviceBroker{layout: brokerpaths.Development()}
	s.compare = func() installer.ServiceComparison { return installer.CompareService("0.2.30", "0.2.30", nil) }
	if s.PendingServiceUpdate() != "" {
		t.Fatal("nothing to update")
	}
	_ = s.RevokeLocal(context.Background(), "", "codex")
	if len(*asked) != 1 || (*asked)[0].UpdateService {
		t.Fatalf("no update asked for: %+v", *asked)
	}
	// A development service is the person's own process: never compared.
	dev := &serviceBroker{development: true, compare: outdatedService().compare}
	if dev.PendingServiceUpdate() != "" {
		t.Fatal("development services are not updated")
	}
}

func TestUpdateFailureSaysTheCommand(t *testing.T) {
	fakeElevation(t, func(p connectPhase) (*connectPhase, error) {
		p.ServiceUpdateError = "the Contro1 service did not answer within 45s after the update"
		p.Error = "the Contro1 service was not updated: " + p.ServiceUpdateError
		return &p, errors.New(p.Error)
	})
	err := outdatedService().UpdateService(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "still runs 0.2.28") || !strings.Contains(err.Error(), "broker install") {
		t.Fatalf("says what runs and the command: %v", err)
	}
	fakeElevation(t, func(connectPhase) (*connectPhase, error) { return nil, installer.ErrElevationDeclined })
	err = outdatedService().UpdateService(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "administrator approval") || !strings.Contains(err.Error(), "broker install") {
		t.Fatalf("a declined prompt names the way to do it later: %v", err)
	}
}

// The elevated side: update first, then the revoke, and a failed update never
// stops the revoke (the previous service was put back and still answers).
func TestElevatedPhaseUpdatesBeforeTheRevoke(t *testing.T) {
	layout := brokerpaths.Development()
	layout.PlatformsDir = t.TempDir()
	layout.ControlEndpoint = "unix:///nonexistent/contro1-test-control.sock"
	oldLayout, oldUpdate := phaseLayout, updateInstalledService
	t.Cleanup(func() { phaseLayout, updateInstalledService = oldLayout, oldUpdate })
	phaseLayout = func() brokerpaths.Layout { return layout }

	var order []string
	mapping := filepath.Join(layout.PlatformsDir, "codex.json")
	updateInstalledService = func(context.Context, brokerpaths.Layout, string) (string, error) {
		if _, err := os.Stat(mapping); err != nil && len(order) == 0 {
			t.Error("the update runs before the revoke")
		}
		order = append(order, "update")
		return "", errors.New("start failed")
	}
	_ = os.WriteFile(mapping, []byte("{}"), 0o644)

	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	path, err := writePhaseFile(connectPhase{RevokePlatform: "codex", UpdateService: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := runRegisterPhase(context.Background(), path); err != nil {
		t.Fatalf("the revoke still ran: %v", err)
	}
	done, _ := readPhaseFile(path)
	if len(order) != 1 || done.ServiceUpdateError != "start failed" || done.Error != "" {
		t.Fatalf("update reported apart from the revoke: %+v", done)
	}
	if _, err := os.Stat(mapping); !os.IsNotExist(err) {
		t.Fatal("the revoke removed the mapping a silent service left")
	}

	// Update alone: its failure is the phase's failure.
	path, _ = writePhaseFile(connectPhase{UpdateService: true})
	if err := runRegisterPhase(context.Background(), path); err == nil || !strings.Contains(err.Error(), "not updated") {
		t.Fatalf("update-only phase fails with the update: %v", err)
	}
	updateInstalledService = func(context.Context, brokerpaths.Layout, string) (string, error) { return "0.2.30", nil }
	path, _ = writePhaseFile(connectPhase{UpdateService: true})
	if err := runRegisterPhase(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	done, _ = readPhaseFile(path)
	raw, _ := json.Marshal(done)
	if done.ServiceVersion != "0.2.30" || strings.Contains(string(raw), "ccct_") {
		t.Fatalf("reports the version it came back as: %s", raw)
	}
}
