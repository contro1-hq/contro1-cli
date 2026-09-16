package connect

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/contro1-hq/contro1-cli/internal/broker"
	"github.com/contro1-hq/contro1-cli/internal/brokerstore"
	"github.com/contro1-hq/contro1-cli/internal/installer"
	"github.com/contro1-hq/contro1-cli/internal/platforms"
	"github.com/contro1-hq/contro1-cli/internal/runtimeproto"
)

// ---- fakes -------------------------------------------------------------------

type fakeAPI struct {
	scopes    []string
	prepares  int
	batch     BatchView
	reports   map[string]string
	noLogin   bool
	nextItems []PreparedItem
}

func (f *fakeAPI) Whoami(context.Context) (*Identity, error) {
	if f.noLogin {
		return nil, errors.New("no login")
	}
	return &Identity{Email: "dana@example.com", Scopes: f.scopes}, nil
}

func (f *fakeAPI) Prepare(_ context.Context, req PrepareRequest) (*PrepareResponse, error) {
	f.prepares++
	items := f.nextItems
	if items == nil {
		for i, it := range req.Items {
			items = append(items, PreparedItem{ItemID: "itm_" + it.PlatformSubject, PlatformSubject: it.PlatformSubject, AgentID: "agt_" + it.PlatformSubject, EnrollmentID: "enr_" + string(rune('a'+i))})
		}
	}
	return &PrepareResponse{BatchID: "con_1", ConnectionTicket: "ccct_secret", ExpiresAt: time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339), Items: items}, nil
}

func (f *fakeAPI) Batch(context.Context, string) (*BatchView, error) { v := f.batch; return &v, nil }

func (f *fakeAPI) ReportItem(_ context.Context, _, itemID, state, _ string) error {
	if f.reports == nil {
		f.reports = map[string]string{}
	}
	f.reports[itemID] = state
	return nil
}

type fakeBroker struct {
	dir         string
	healthy     bool
	registerErr error
	registered  []broker.ControlConnectionsRequest
}

func (f *fakeBroker) Healthy(context.Context) bool { return f.healthy }
func (f *fakeBroker) Register(_ context.Context, _ string, req broker.ControlConnectionsRequest) ([]broker.ControlItemResult, error) {
	if f.registerErr != nil {
		return nil, f.registerErr
	}
	f.registered = append(f.registered, req)
	var out []broker.ControlItemResult
	var entries []runtimeproto.MappingEntry
	for _, it := range req.Items {
		out = append(out, broker.ControlItemResult{ItemID: it.ItemID, State: "awaiting_approval", JKT: "jkt"})
		entries = append(entries, runtimeproto.MappingEntry{PlatformSubject: it.PlatformSubject, AgentID: it.AgentID, EnrollmentID: it.EnrollmentID, EndpointMode: it.EndpointMode, Endpoint: "npipe:////./pipe/contro1-ep-" + it.PlatformSubject})
	}
	m := runtimeproto.MappingFile{SchemaVersion: 1, Platform: "openclaw", Entries: entries, Digest: runtimeproto.MappingDigest(entries)}
	raw, _ := json.Marshal(m)
	_ = os.WriteFile(f.MappingPath("openclaw"), raw, 0o644)
	return out, nil
}
func (f *fakeBroker) PublicStatus() (*brokerstore.PublicStatus, error) { return nil, errors.New("n/a") }
func (f *fakeBroker) MappingPath(p string) string                      { return filepath.Join(f.dir, p+".json") }
func (f *fakeBroker) SetPrincipals(context.Context, string, []broker.ControlPrincipalUpdate) error {
	return nil
}

type fakeVerifier struct{ fail map[string]bool }

func (f fakeVerifier) RuntimeStatus(_ context.Context, e runtimeproto.MappingEntry) (string, error) {
	if f.fail[e.PlatformSubject] {
		return "", errors.New("endpoint not reachable")
	}
	return e.AgentID, nil
}
func (f fakeVerifier) ControlMapPreview(context.Context, runtimeproto.MappingEntry) error { return nil }

type fakePrompt struct {
	interactive bool
	answer      bool
	asked       []string
}

func (f *fakePrompt) Interactive() bool { return f.interactive }
func (f *fakePrompt) Terminal() bool    { return f.interactive }
func (f *fakePrompt) Confirm(title string, _ []string) bool {
	f.asked = append(f.asked, title)
	return f.answer
}
func (f *fakePrompt) Progress(string) {}

type memStates struct{ m map[string]*State }

func (s *memStates) Load(p string) (*State, error) {
	if st, ok := s.m[p]; ok {
		cp := *st
		return &cp, nil
	}
	return nil, nil
}
func (s *memStates) Save(p string, st *State) error { cp := *st; s.m[p] = &cp; return nil }
func (s *memStates) Clear(p string) error           { delete(s.m, p); return nil }

type fakeAdapter struct {
	platforms.Adapter
	subjects []platforms.Subject
	roles    bool
	applied  int
}

func (a *fakeAdapter) Name() string { return "openclaw" }
func (a *fakeAdapter) Discover(context.Context) (platforms.Instance, []platforms.Subject, error) {
	return platforms.Instance{Digest: "inst-1", Label: "OpenClaw"}, a.subjects, nil
}
func (a *fakeAdapter) PlanConfig(string) []platforms.Change {
	return []platforms.Change{{Kind: "file", Path: "/home/dana/.openclaw/contro1.env", Description: "Point OpenClaw at the mapping"}}
}
func (a *fakeAdapter) ApplyConfig(context.Context, string, *runtimeproto.MappingFile, *platforms.Journal) error {
	a.applied++
	return nil
}
func (a *fakeAdapter) RoleChanges(m *runtimeproto.MappingFile) []platforms.Change {
	if !a.roles {
		return nil
	}
	return []platforms.Change{{Kind: "role", RoleChange: true, Description: "grant", After: "ncl roles grant"}}
}
func (a *fakeAdapter) ApplyRoles(context.Context, *runtimeproto.MappingFile, *platforms.Journal) error {
	return nil
}
func (a *fakeAdapter) AllowedPrincipal(string) (string, error) { return "S-1-5-21-dana", nil }
func (a *fakeAdapter) SafeTest() string                        { return "Try it." }

func setup(t *testing.T) (*Orchestrator, *fakeAPI, *fakeBroker, *fakePrompt, *fakeAdapter) {
	api := &fakeAPI{scopes: []string{"runtime:connect"}}
	br := &fakeBroker{dir: t.TempDir(), healthy: true}
	prompt := &fakePrompt{}
	adapter := &fakeAdapter{subjects: []platforms.Subject{{ID: "main", Display: "main"}, {ID: "research", Display: "research"}}}
	o := &Orchestrator{API: api, Broker: br, Verifier: fakeVerifier{}, Adapter: adapter, Prompt: prompt, States: &memStates{m: map[string]*State{}}}
	return o, api, br, prompt, adapter
}

func base() Options {
	return Options{Platform: "openclaw", APIURL: "https://api.contro1.test", PollEvery: time.Millisecond, WaitTimeout: 50 * time.Millisecond}
}

// ---- tests -------------------------------------------------------------------

func TestNeedsLoginWithRuntimeConnect(t *testing.T) {
	o, api, _, _, _ := setup(t)
	api.scopes = []string{"requests:read"}
	ns := o.Run(context.Background(), base())
	if ns.State != runtimeproto.StateBlocked || ns.NextCommand != "contro1 auth login" || ExitCode(ns, false) != 3 {
		t.Fatalf("%+v", ns)
	}
}

func TestJSONWithoutYesStopsForLocalConfirmation(t *testing.T) {
	o, api, br, _, _ := setup(t)
	ns := o.Run(context.Background(), base())
	if ns.State != runtimeproto.StateNeedsLocalConfirmation || ns.NextCommand != "contro1 connect openclaw --yes" || ExitCode(ns, false) != 10 {
		t.Fatalf("%+v", ns)
	}
	if api.prepares != 0 || len(br.registered) != 0 {
		t.Fatal("nothing may change before confirmation")
	}
	if len(ns.Agents) != 2 || len(ns.Checks) == 0 {
		t.Fatal("the preview lists every agent and change")
	}
}

func TestHappyPathAndWaitingForOwner(t *testing.T) {
	o, api, br, _, adapter := setup(t)
	api.batch = BatchView{BatchID: "con_1", State: "pending", UserCode: "K7F2-QX9M", Link: "https://app/connect/con_1", WaitingFor: &struct {
		DisplayName string `json:"display_name"`
		OperatorID  string `json:"operator_id"`
	}{DisplayName: "Dana"}}
	opts := base()
	opts.Yes, opts.NoWait = true, true

	ns := o.Run(context.Background(), opts)
	if ns.State != runtimeproto.StateWaitingForOwner || ns.UserCode != "K7F2-QX9M" || ns.NextCommand != "contro1 connect openclaw --resume con_1" || ExitCode(ns, true) != 0 {
		t.Fatalf("waiting: %+v", ns)
	}
	raw, _ := json.Marshal(ns)
	if strings.Contains(string(raw), "ccct_") {
		t.Fatal("the connection ticket never appears in output")
	}
	if len(br.registered) != 1 || br.registered[0].Items[0].AllowedPrincipals[0] != "S-1-5-21-dana" {
		t.Fatalf("registration: %+v", br.registered)
	}
	st, _ := o.States.Load("openclaw")
	stRaw, _ := json.Marshal(st)
	if strings.Contains(string(stRaw), "ccct_") {
		t.Fatal("persisted state never holds the ticket")
	}

	// Rerun while still pending: no second prepare, no second registration.
	o.Run(context.Background(), opts)
	if api.prepares != 1 || len(br.registered) != 1 {
		t.Fatalf("rerun must be idempotent: prepares=%d registered=%d", api.prepares, len(br.registered))
	}

	// Owner approves.
	api.batch.State = "approved"
	opts.NoWait = false
	ns = o.Run(context.Background(), opts)
	if ns.State != runtimeproto.StateConnected || len(ns.Agents) != 2 || adapter.applied != 1 {
		t.Fatalf("connected: %+v applied=%d", ns, adapter.applied)
	}
	if api.reports["itm_main"] != "configured" || api.reports["itm_research"] != "configured" {
		t.Fatalf("item results reported: %+v", api.reports)
	}
}

func TestDeclinedElevationIsResumable(t *testing.T) {
	o, api, br, _, _ := setup(t)
	br.registerErr = installer.ErrElevationDeclined
	opts := base()
	opts.Yes = true
	ns := o.Run(context.Background(), opts)
	if ns.State != runtimeproto.StateNeedsLocalConfirmation || ns.WaitingFor == nil || ns.WaitingFor.Kind != "local_administrator" {
		t.Fatalf("%+v", ns)
	}
	br.registerErr = nil
	api.batch = BatchView{State: "pending"}
	opts.NoWait = true
	if ns := o.Run(context.Background(), opts); ns.State != runtimeproto.StateWaitingForOwner {
		t.Fatalf("after approving the prompt the run continues: %+v", ns)
	}
	if api.prepares != 2 {
		t.Fatal("a declined elevation discards the unused ticket and prepares again")
	}
}

func TestNanoClawRolesNeedATerminalEvenWithYes(t *testing.T) {
	o, api, _, prompt, adapter := setup(t)
	adapter.roles = true
	api.batch = BatchView{State: "approved"}
	opts := base()
	opts.Yes = true
	ns := o.Run(context.Background(), opts)
	if ns.State != runtimeproto.StateNeedsLocalConfirmation || !strings.Contains(ns.NextCommand, "--confirm-roles") {
		t.Fatalf("roles without a terminal: %+v", ns)
	}
	prompt.interactive, prompt.answer = true, true
	if ns := o.Run(context.Background(), opts); ns.State != runtimeproto.StateConnected {
		t.Fatalf("roles confirmed at a terminal: %+v", ns)
	}
}

func TestPartialFailureReportsPerItem(t *testing.T) {
	o, api, _, _, _ := setup(t)
	o.Verifier = fakeVerifier{fail: map[string]bool{"research": true}}
	api.batch = BatchView{State: "approved"}
	opts := base()
	opts.Yes = true
	ns := o.Run(context.Background(), opts)
	if ns.State != runtimeproto.StateError || api.reports["itm_main"] != "configured" || api.reports["itm_research"] != "failed" {
		t.Fatalf("partial: %+v %+v", ns, api.reports)
	}
}

func TestDeclinedByOwner(t *testing.T) {
	o, api, _, _, _ := setup(t)
	api.batch = BatchView{State: "declined"}
	opts := base()
	opts.Yes = true
	if ns := o.Run(context.Background(), opts); ns.State != runtimeproto.StateBlocked {
		t.Fatalf("%+v", ns)
	}
}
