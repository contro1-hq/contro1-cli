package connect

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/contro1-hq/contro1-cli/internal/broker"
	"github.com/contro1-hq/contro1-cli/internal/runtimeproto"
)

// updatingBroker is a service due an update. Every elevated phase it is asked
// for is counted, so a test can see the update never costs a second prompt.
type updatingBroker struct {
	*fakeBroker
	line        string
	elevations  int
	standalone  int
	updatedWith string
}

func (u *updatingBroker) PendingServiceUpdate() string { return u.line }
func (u *updatingBroker) Register(ctx context.Context, apiURL string, req broker.ControlConnectionsRequest) ([]broker.ControlItemResult, error) {
	u.elevations++
	if u.line != "" {
		u.updatedWith, u.line = "register", ""
	}
	return u.fakeBroker.Register(ctx, apiURL, req)
}
func (u *updatingBroker) UpdateService(context.Context, string) error {
	u.elevations++
	u.standalone++
	u.updatedWith, u.line = "alone", ""
	return nil
}
func (u *updatingBroker) ServiceUpdateResult() (string, error) {
	if u.updatedWith == "" {
		return "", nil
	}
	return "The Contro1 service was updated to 0.2.30 and is running again.", nil
}

type recordingPrompt struct {
	fakePrompt
	progress []string
}

func (r *recordingPrompt) Progress(line string) { r.progress = append(r.progress, line) }

func withUpdate(t *testing.T) (*Orchestrator, *fakeAPI, *updatingBroker, *recordingPrompt) {
	o, api, br, _, _ := setup(t)
	u := &updatingBroker{fakeBroker: br, line: "Update the Contro1 service (from 0.2.28 to 0.2.30)"}
	prompt := &recordingPrompt{}
	o.Broker, o.Prompt = u, prompt
	return o, api, u, prompt
}

func TestPreviewSaysTheServiceUpdate(t *testing.T) {
	o, _, u, _ := withUpdate(t)
	ns := o.Run(context.Background(), base())
	raw, _ := json.Marshal(ns.Checks)
	if !strings.Contains(string(raw), "Update the Contro1 service (from 0.2.28 to 0.2.30)") {
		t.Fatalf("the preview names the update: %s", raw)
	}
	if u.elevations != 0 {
		t.Fatal("nothing changes before confirmation")
	}
}

// New agents: the update rides on the registration's elevation. One prompt.
func TestUpdateRidesOnTheRegistration(t *testing.T) {
	o, _, u, prompt := withUpdate(t)
	opts := base()
	opts.Yes, opts.NoWait = true, true
	o.Run(context.Background(), opts)
	if u.elevations != 1 || u.standalone != 0 || u.updatedWith != "register" {
		t.Fatalf("one elevation, carrying the update: %+v", u)
	}
	if !strings.Contains(strings.Join(prompt.progress, "\n"), "updated to 0.2.30") {
		t.Fatalf("says it worked: %v", prompt.progress)
	}
}

// Nothing new to register used to mean no elevation, so the service was never
// updated. Now it asks once, for the update alone.
func TestRepairRunUpdatesTheServiceOnce(t *testing.T) {
	o, api, u, _ := withUpdate(t)
	api.nextItems = []PreparedItem{}
	entries := []runtimeproto.MappingEntry{{PlatformSubject: "main", AgentID: "agt_main", EnrollmentID: "enr_a", EndpointMode: runtimeproto.ModeApprovalsOnly, Endpoint: "npipe:////./pipe/contro1-ep-main"}}
	raw, _ := json.Marshal(runtimeproto.MappingFile{SchemaVersion: 1, Platform: "openclaw", Entries: entries, Digest: runtimeproto.MappingDigest(entries)})
	_ = os.WriteFile(u.MappingPath("openclaw"), raw, 0o644)
	opts := base()
	opts.Yes = true
	o.Run(context.Background(), opts)
	if u.elevations != 1 || u.standalone != 1 {
		t.Fatalf("one elevation, for the update: %+v", u)
	}
	// Run again: nothing pending, nothing asked.
	o.Run(context.Background(), opts)
	if u.elevations != 1 {
		t.Fatal("an up-to-date service is not asked about again")
	}
}

func TestDevelopmentServiceIsNeverUpdated(t *testing.T) {
	o, _, u, _ := withUpdate(t)
	opts := base()
	opts.Development = true
	ns := o.Run(context.Background(), opts)
	raw, _ := json.Marshal(ns.Checks)
	if strings.Contains(string(raw), "Update the Contro1 service") || u.standalone != 0 {
		t.Fatalf("development: %s", raw)
	}
}
