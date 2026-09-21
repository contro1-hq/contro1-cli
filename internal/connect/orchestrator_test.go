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
	// lastPrepare is what the orchestrator actually put on the wire.
	lastPrepare PrepareRequest
}

func (f *fakeAPI) Whoami(context.Context) (*Identity, error) {
	if f.noLogin {
		return nil, errors.New("no login")
	}
	return &Identity{Email: "dana@example.com", Scopes: f.scopes}, nil
}

func (f *fakeAPI) Prepare(_ context.Context, req PrepareRequest) (*PrepareResponse, error) {
	f.prepares++
	f.lastPrepare = req
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
	subjects  []platforms.Subject
	roles     bool
	applied   int
	reachErr  bool
	remaining []string
}

func (a *fakeAdapter) Name() string             { return "openclaw" }
func (a *fakeAdapter) RemainingSetup() []string { return a.remaining }
func (a *fakeAdapter) Reach(context.Context, string) (runtimeproto.AgentReach, error) {
	if a.reachErr {
		return runtimeproto.AgentReach{}, errors.New("cannot read reach")
	}
	return runtimeproto.AgentReach{
		SchemaVersion: runtimeproto.SchemaVersion,
		Platform:      "openclaw",
		Complete:      true,
		Contexts: []runtimeproto.ReachContext{
			{ContextID: "chat-1", Label: "Berlin trip", Kind: runtimeproto.ReachShared},
		},
	}, nil
}
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
	return Options{
		Platform: "openclaw", APIURL: "https://api.contro1.test",
		// Named, because --yes no longer stands in for "connect whatever
		// discovery found". Scope selection has its own test below.
		Agents:    []string{"main", "research"},
		PollEvery: time.Millisecond, WaitTimeout: 50 * time.Millisecond,
	}
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

// The owner approving a connection has to be able to see who can instruct what
// they are taking responsibility for, so the reach travels with the prepare.
func TestConnectSendsReachAndSurvivesAnAdapterThatCannotReadIt(t *testing.T) {
	o, api, _, _, _ := setup(t)
	opts := base()
	opts.Yes, opts.NoWait = true, true
	_ = o.Run(context.Background(), opts)
	if len(api.lastPrepare.Items) == 0 {
		t.Fatalf("no prepare was sent")
	}
	for _, item := range api.lastPrepare.Items {
		if item.Reach == nil {
			t.Fatalf("reach was not sent for %s", item.PlatformSubject)
		}
		if got := runtimeproto.PostureForReach(item.Reach); got != runtimeproto.PostureSharedSurface {
			t.Fatalf("posture = %q, want shared_surface", got)
		}
	}

	// An adapter that cannot read the reach must not stop the connection: the
	// field is simply absent, and the server reads absence as exposure rather
	// than inventing a verdict.
	o2, api2, _, _, adapter2 := setup(t)
	adapter2.reachErr = true
	_ = o2.Run(context.Background(), opts)
	for _, item := range api2.lastPrepare.Items {
		if item.Reach != nil {
			t.Fatalf("an unreadable reach must be omitted, not invented: %+v", item)
		}
	}
}

// A flag people reach for to skip a file-change prompt must not also decide
// which identities exist on this computer. On a NanoClaw host, discovery
// returns every group, including ones whose owner deliberately left alone.
func TestYesDoesNotStandInForChoosingWhichAgentsToConnect(t *testing.T) {
	o, api, _, _, _ := setup(t)
	opts := base()
	opts.Agents = nil
	opts.Yes, opts.NoWait = true, true

	ns := o.Run(context.Background(), opts)
	if ns.State != runtimeproto.StateNeedsLocalConfirmation {
		t.Fatalf("two discovered agents and no --agent must stop: %+v", ns)
	}
	if api.prepares != 0 {
		t.Fatalf("nothing may be prepared before the scope is chosen, got %d", api.prepares)
	}
	if !strings.Contains(ns.Message, "2 agents") || !strings.Contains(ns.NextCommand, "--agent") {
		t.Fatalf("the refusal must say how many and how to choose: %q / %q", ns.Message, ns.NextCommand)
	}
	// Both are listed, so the person can see what they would have connected.
	if len(ns.Agents) != 2 {
		t.Fatalf("the candidates must be shown: %+v", ns.Agents)
	}

	// Naming them is the way through, and --yes still covers the local changes.
	o2, api2, _, _, _ := setup(t)
	opts.Agents = []string{"main", "research"}
	if ns := o2.Run(context.Background(), opts); api2.prepares != 1 {
		t.Fatalf("named agents should proceed: %d prepares, %+v", api2.prepares, ns)
	}

	// One agent needs no selector: there is nothing to choose between.
	o3, api3, _, _, adapter3 := setup(t)
	adapter3.subjects = []platforms.Subject{{ID: "main", Display: "main"}}
	opts.Agents = nil
	if ns := o3.Run(context.Background(), opts); api3.prepares != 1 {
		t.Fatalf("a single agent should proceed without --agent: %d prepares, %+v", api3.prepares, ns)
	}
}

// The most expensive kind of green: everything reports success while nothing is
// governed. A NanoClaw host is connected long before it routes an approval.
func TestConnectSaysWhatItDidNotFinish(t *testing.T) {
	o, _, _, _, adapter := setup(t)
	adapter.remaining = []string{"Install the Contro1 channel into NanoClaw.", "Make Contro1 an approver."}
	opts := base()
	opts.Yes = true

	ns := o.Run(context.Background(), opts)
	if ns.State != runtimeproto.StateConnected {
		t.Fatalf("the connection itself did succeed: %+v", ns)
	}
	if !strings.Contains(ns.Message, "will not reach Contro1 yet") {
		t.Fatalf("a connection that governs nothing must not read as finished: %q", ns.Message)
	}
	if len(ns.Checks) != 2 || ns.Checks[0].Status != runtimeproto.CheckWaiting {
		t.Fatalf("each remaining step is listed as waiting on a person: %+v", ns.Checks)
	}
	if ns.NextCommand == "" {
		t.Fatal("there must be somewhere to go next")
	}

	// A platform that needs nothing more says nothing more.
	o2, _, _, _, _ := setup(t)
	ns2 := o2.Run(context.Background(), opts)
	if strings.Contains(ns2.Message, "will not reach") || len(ns2.Checks) != 0 {
		t.Fatalf("a finished platform must not invent work: %q %+v", ns2.Message, ns2.Checks)
	}
}
