package doctor

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/contro1-hq/contro1-cli/internal/brokerstore"
	"github.com/contro1-hq/contro1-cli/internal/runtimeproto"
)

type fakeEnv struct {
	installed, running, automatic bool
	account                       string
	controlOpen                   bool
	status                        *brokerstore.PublicStatus
	mapping                       *runtimeproto.MappingFile
	refreshOnStatus               bool
	discovered                    []string
	principals                    map[string][]string
	expected                      map[string]string
	expectedGroup                 map[string]string
	agentFor                      map[string]string
	remediation                   *runtimeproto.Remediation
	development                   bool
	approver                      ApproverStatus
	approverErr                   error
	mcpServers                    []McpServerConfig
	mcpErr                        error
	mounts                        []string
	liveMode                      string
	leaseStored                   bool
	leaseExposed                  []string
	// The MCP server connect installs. mcpName empty is a platform where it
	// does not (NanoClaw), which keeps the older applications checks.
	mcpName      string
	mcpTools     int
	mcpProbeErr  error
	isolation    []IsolationIssue
	isolationErr error
	config       *ConfigState
}

func (f *fakeEnv) McpServerName(_, subject string) string {
	if f.mcpName == "" {
		return ""
	}
	return strings.ReplaceAll(f.mcpName, "<id>", subject)
}

func (f *fakeEnv) McpProbe(context.Context, runtimeproto.MappingEntry) (int, error) {
	return f.mcpTools, f.mcpProbeErr
}

func (f *fakeEnv) McpIsolation(context.Context, string, []string) ([]IsolationIssue, error) {
	if f.isolationErr != nil {
		return nil, f.isolationErr
	}
	return f.isolation, nil
}

func (f *fakeEnv) ConfigStatus(context.Context, string) (ConfigState, error) {
	if f.config == nil {
		return ConfigState{}, ErrNotApplicable
	}
	return *f.config, nil
}

func (f *fakeEnv) LeaseExposure(context.Context, string, string) (bool, []string, error) {
	return f.leaseStored, f.leaseExposed, nil
}

func (f *fakeEnv) McpServers(context.Context, string, string) ([]McpServerConfig, error) {
	if f.mcpErr != nil {
		return nil, f.mcpErr
	}
	return f.mcpServers, nil
}

func (f *fakeEnv) ContainerMounts(context.Context, string, string) ([]string, error) {
	return f.mounts, nil
}

func (f *fakeEnv) ApproverStatus(context.Context, string, string) (ApproverStatus, error) {
	if f.approverErr != nil {
		return ApproverStatus{}, f.approverErr
	}
	return f.approver, nil
}

func (f *fakeEnv) GOOS() string { return "windows" }
func (f *fakeEnv) ServiceStatus() (bool, bool, bool, string) {
	return f.installed, f.running, f.automatic, f.account
}
func (f *fakeEnv) ControlReachableUnelevated(context.Context) bool  { return f.controlOpen }
func (f *fakeEnv) IsElevated() bool                                 { return false }
func (f *fakeEnv) PublicStatus() (*brokerstore.PublicStatus, error) { return f.status, nil }
func (f *fakeEnv) Mapping(string) (*runtimeproto.MappingFile, error) {
	if f.mapping == nil {
		return nil, errors.New("no mapping")
	}
	return f.mapping, nil
}
func (f *fakeEnv) Discover(context.Context, string) ([]string, error) { return f.discovered, nil }
func (f *fakeEnv) EndpointPrincipals(ep string) ([]string, error) {
	p, ok := f.principals[ep]
	if !ok {
		return nil, errors.New("not listening")
	}
	return p, nil
}
func (f *fakeEnv) ExpectedPrincipals(_, subject string) ([]string, error) {
	out := []string{f.expected[subject]}
	if g := f.expectedGroup[subject]; g != "" {
		out = append(out, g)
	}
	return out, nil
}
func (f *fakeEnv) RuntimeStatus(_ context.Context, e runtimeproto.MappingEntry) (string, string, *runtimeproto.Remediation, error) {
	if f.remediation != nil {
		return "", "", f.remediation, errors.New("refused")
	}
	if f.refreshOnStatus && f.mapping != nil && f.liveMode != "" {
		// What the Contro1 service does with a status answer: record the
		// mode and rewrite the mapping file.
		fresh := *f.mapping
		fresh.Entries = append([]runtimeproto.MappingEntry(nil), f.mapping.Entries...)
		for i := range fresh.Entries {
			if fresh.Entries[i].Endpoint == e.Endpoint {
				fresh.Entries[i].EndpointMode = f.liveMode
			}
		}
		f.mapping = &fresh
	}
	// Empty unless a test sets it: an older service does not report the mode.
	return f.agentFor[e.Endpoint], f.liveMode, nil, nil
}
func (f *fakeEnv) ControlMapPreview(context.Context, runtimeproto.MappingEntry) error { return nil }
func (f *fakeEnv) PlatformUser(string) string                                         { return "dana" }
func (f *fakeEnv) Development() bool                                                  { return f.development }

func healthy() *fakeEnv {
	return &fakeEnv{
		installed: true, running: true, automatic: true, account: `NT SERVICE\Contro1Broker`,
		status: &brokerstore.PublicStatus{KeyProtection: "cng_nonexportable"},
		mapping: &runtimeproto.MappingFile{Platform: "nanoclaw", Entries: []runtimeproto.MappingEntry{
			{PlatformSubject: "group-a", AgentID: "agt_a", Endpoint: "ep-a", EndpointMode: runtimeproto.ModeApprovalsOnly},
			{PlatformSubject: "group-b", AgentID: "agt_b", Endpoint: "ep-b", EndpointMode: runtimeproto.ModeApprovalsOnly},
		}},
		discovered: []string{"group-a", "group-b"},
		principals: map[string][]string{"ep-a": {"uid-a"}, "ep-b": {"uid-b"}},
		expected:   map[string]string{"group-a": "uid-a", "group-b": "uid-b"},
		agentFor:   map[string]string{"ep-a": "agt_a", "ep-b": "agt_b"},
		approver:   ApproverStatus{ChannelPresent: true, ApproverExists: true, ApproverMayResolve: true},
	}
}

func find(r Report, id string) runtimeproto.Check {
	for _, c := range r.Checks {
		if c.ID == id {
			return c
		}
	}
	return runtimeproto.Check{}
}

func TestHealthy(t *testing.T) {
	r := Run(context.Background(), healthy(), "nanoclaw")
	if r.State != "connected" {
		t.Fatalf("healthy computer: %+v", r)
	}
}

func TestStoppedServiceIsRepairable(t *testing.T) {
	env := healthy()
	env.running = false
	r := Run(context.Background(), env, "nanoclaw")
	c := find(r, "service_running")
	if c.Status != runtimeproto.CheckRepairable || c.NextCommand != "contro1 connect nanoclaw --repair" || r.State != "repairable" {
		t.Fatalf("stopped service: %+v", c)
	}
}

func TestWrongMapping(t *testing.T) {
	env := healthy()
	env.discovered = []string{"group-a", "group-b", "group-c"}
	r := Run(context.Background(), env, "nanoclaw")
	c := find(r, "mapping_complete")
	// Connecting some agents and not others is a choice: it is reported, with
	// the command to add one, and does not fail doctor.
	if c.Status != runtimeproto.CheckOK || !strings.Contains(c.Message, "group-c") || c.NextCommand != "contro1 connect nanoclaw --agent group-c" || r.State == "repairable" {
		t.Fatalf("an unconnected group is reported, not a failure: %+v state=%s", c, r.State)
	}
	env.mapping.Entries = append(env.mapping.Entries, runtimeproto.MappingEntry{PlatformSubject: "group-gone", AgentID: "agt_gone", Endpoint: "ep-gone", EndpointMode: runtimeproto.ModeApprovalsOnly})
	if c := find(Run(context.Background(), env, "nanoclaw"), "mapping_complete"); c.Status != runtimeproto.CheckRepairable {
		t.Fatalf("a connected agent that disappeared is still a problem: %+v", c)
	}
}

// Every connection ended (disconnected or revoked in Contro1): the service
// empties the mapping, and doctor must not call that "connected".
func TestEmptyMappingIsNotConnected(t *testing.T) {
	env := healthy()
	env.mapping.Entries = nil
	r := Run(context.Background(), env, "nanoclaw")
	c := find(r, "mapping_complete")
	if c.Status != runtimeproto.CheckRepairable || c.NextCommand != "contro1 connect nanoclaw" || r.State != "repairable" {
		t.Fatalf("empty mapping: %+v state=%s", c, r.State)
	}
}

func TestInaccessibleEndpoint(t *testing.T) {
	env := healthy()
	delete(env.principals, "ep-b")
	c := find(Run(context.Background(), env, "nanoclaw"), "endpoint_isolation:group-b")
	if c.Status != runtimeproto.CheckRepairable {
		t.Fatalf("missing endpoint: %+v", c)
	}
}

func TestCrossGroupExposureIsBlockedNotRepaired(t *testing.T) {
	env := healthy()
	env.principals["ep-b"] = []string{"uid-b", "uid-a"}
	r := Run(context.Background(), env, "nanoclaw")
	c := find(r, "endpoint_isolation:group-b")
	if c.Status != runtimeproto.CheckBlocked || r.State != "blocked" {
		t.Fatalf("cross-group exposure must be blocked: %+v", c)
	}
	if strings.Contains(strings.ToLower(c.NextCommand), "chmod") || strings.Contains(strings.ToLower(c.NextCommand), "icacls") {
		t.Fatal("doctor never suggests loosening an ACL")
	}
}

func TestSharedEndpointIsBlocked(t *testing.T) {
	env := healthy()
	env.mapping.Entries[1].Endpoint = "ep-a"
	if c := find(Run(context.Background(), env, "nanoclaw"), "endpoint_isolation:group-b"); c.Status != runtimeproto.CheckBlocked {
		t.Fatalf("shared endpoint: %+v", c)
	}
}

func TestDevelopmentKeysBlockedInProduction(t *testing.T) {
	env := healthy()
	env.status.KeyProtection = "user_file_development"
	if c := find(Run(context.Background(), env, "nanoclaw"), "key_protection"); c.Status != runtimeproto.CheckBlocked {
		t.Fatalf("development keys: %+v", c)
	}
	env.development = true
	if c := find(Run(context.Background(), env, "nanoclaw"), "key_protection"); c.Status != runtimeproto.CheckOK {
		t.Fatalf("development mode accepts development keys: %+v", c)
	}
}

func TestControlOpenToUsersIsBlocked(t *testing.T) {
	env := healthy()
	env.controlOpen = true
	if c := find(Run(context.Background(), env, "nanoclaw"), "control_endpoint_acl"); c.Status != runtimeproto.CheckBlocked {
		t.Fatalf("open control endpoint: %+v", c)
	}
}

func TestServerRefusalCarriesRemediation(t *testing.T) {
	env := healthy()
	env.remediation = &runtimeproto.Remediation{Code: "CONNECTION_APPROVAL_EXPIRED", PublicMessage: "The approval expired.", NextStep: "Ask Dana to renew.", Who: &runtimeproto.Who{DisplayName: "Dana", Role: "accountable_owner"}}
	c := find(Run(context.Background(), env, "nanoclaw"), "runtime_status:group-a")
	if c.Status != runtimeproto.CheckBlocked || c.Actor != "accountable_owner" || c.NextCommand != "Ask Dana to renew." {
		t.Fatalf("server refusal: %+v", c)
	}
}

// On Linux a socket opens to one user through that user's primary group, and
// the kernel-attested peer uid on every accept narrows it to the user. Doctor
// reported that correct setup as blocked, so a working connection looked broken.
func TestUserPrimaryGroupIsNotExposure(t *testing.T) {
	env := healthy()
	env.expectedGroup = map[string]string{"group-b": "gid-b"}
	env.principals["ep-b"] = []string{"gid-b"}
	if c := find(Run(context.Background(), env, "nanoclaw"), "endpoint_isolation:group-b"); c.Status != runtimeproto.CheckOK {
		t.Fatalf("the user's own group is the expected access: %+v", c)
	}
	env.principals["ep-b"] = []string{"gid-b", "everyone"}
	if c := find(Run(context.Background(), env, "nanoclaw"), "endpoint_isolation:group-b"); c.Status != runtimeproto.CheckBlocked {
		t.Fatalf("world access next to the group is still exposure: %+v", c)
	}
	env.principals["ep-b"] = []string{"gid-a"}
	if c := find(Run(context.Background(), env, "nanoclaw"), "endpoint_isolation:group-b"); c.Status != runtimeproto.CheckBlocked {
		t.Fatalf("another user's group is exposure: %+v", c)
	}
}

func findCheck(r Report, id string) (runtimeproto.Check, bool) {
	for _, c := range r.Checks {
		if c.ID == id {
			return c, true
		}
	}
	return runtimeproto.Check{}, false
}

// Both of these were seen in the field, and both are quiet: the agent reports
// that it is connected and answers 401 to everything. Nothing had the whole
// picture, because the MCP entry lives in the platform and the endpoint here.
func TestApplicationsChecksCatchTheQuietFailures(t *testing.T) {
	// No MCP server at all is not a problem. Applications are opt in, and an
	// agent that only asks for approvals is finished and correct.
	env := healthy()
	r := Run(context.Background(), env, "nanoclaw")
	c, ok := findCheck(r, "applications:group-a")
	if !ok || c.Status != runtimeproto.CheckOK || !strings.Contains(c.Message, "approvals only") {
		t.Fatalf("an approvals-only agent must not look broken: %+v", c)
	}

	// The older setup: an entry reaching the public API with a key somebody
	// pasted in. The agent then acts as whoever owns that key, and without one
	// every call is a 401 that reads like a wrong address.
	env = healthy()
	env.mcpServers = []McpServerConfig{{Name: "contro1", URL: "https://api.contro1.com/mcp"}}
	r = Run(context.Background(), env, "nanoclaw")
	c, _ = findCheck(r, "applications:group-a")
	if c.Status != runtimeproto.CheckRepairable || !strings.Contains(c.Message, "401") {
		t.Fatalf("a legacy URL entry must be reported: %+v", c)
	}
	if !strings.Contains(c.NextCommand, "apps enable") {
		t.Fatalf("and it must say how to fix it: %q", c.NextCommand)
	}

	// The entry is right but the socket never reaches inside the container, so
	// it works until the next restart and then never again.
	env = healthy()
	env.mcpServers = []McpServerConfig{{Name: "contro1", Command: "contro1", Args: []string{"mcp", "serve"}}}
	env.mounts = []string{"/some/other/path"}
	r = Run(context.Background(), env, "nanoclaw")
	c, _ = findCheck(r, "applications:group-a")
	if c.Status != runtimeproto.CheckRepairable || !strings.Contains(c.Message, "not mounted") {
		t.Fatalf("a missing mount must be reported: %+v", c)
	}

	// Correctly set up: the entry runs contro1 and this agent's own socket is
	// mounted.
	env = healthy()
	env.mcpServers = []McpServerConfig{{Name: "contro1", Command: "contro1", Args: []string{"mcp", "serve"}}}
	env.mounts = []string{"ep-a"}
	r = Run(context.Background(), env, "nanoclaw")
	c, _ = findCheck(r, "applications:group-a")
	if c.Status != runtimeproto.CheckOK {
		t.Fatalf("a correct setup must pass: %+v", c)
	}

	// A platform that cannot answer produces no finding at all. Reporting a
	// problem we inferred would send somebody to fix the wrong thing.
	env = healthy()
	env.mcpErr = errors.New("not reported by this platform")
	r = Run(context.Background(), env, "nanoclaw")
	if _, ok := findCheck(r, "applications:group-a"); ok {
		t.Fatal("silence from the platform must not become a finding")
	}
}

// Connected is not the same as governed. A NanoClaw host can hold a live
// connection while the channel was never loaded, and then every other check
// passes and not one approval is ever seen.
func TestApproverChecksSeparateConnectedFromGoverned(t *testing.T) {
	env := healthy()
	r := Run(context.Background(), env, "nanoclaw")
	c, ok := findCheck(r, "approvals_reach_contro1:group-a")
	if !ok || c.Status != runtimeproto.CheckOK {
		t.Fatalf("a fully set up host must pass: %+v", c)
	}

	// The channel was never installed. Blocked, not repairable: it copies code
	// into the platform's own source tree and that is the person's to do.
	env = healthy()
	env.approver = ApproverStatus{}
	r = Run(context.Background(), env, "nanoclaw")
	c, _ = findCheck(r, "approvals_reach_contro1:group-a")
	if c.Status != runtimeproto.CheckBlocked || !strings.Contains(c.Message, "no approval will ever reach") {
		t.Fatalf("a missing channel must be blocked and say why: %+v", c)
	}

	// The channel is there but Contro1 is not an approver of this group, so
	// this group's cards go somewhere else while its neighbour's arrive.
	env = healthy()
	env.approver = ApproverStatus{ChannelPresent: true, ApproverExists: true}
	r = Run(context.Background(), env, "nanoclaw")
	c, _ = findCheck(r, "approvals_reach_contro1:group-a")
	if c.Status != runtimeproto.CheckRepairable || !strings.Contains(c.NextCommand, "--confirm-roles") {
		t.Fatalf("a missing role must be repairable and name the command: %+v", c)
	}
	if !strings.Contains(c.NextCommand, "group-a") {
		t.Fatalf("the grant is per group, so the repair must name one: %q", c.NextCommand)
	}

	// A platform that cannot answer produces no finding.
	env = healthy()
	env.approverErr = errors.New("not reported by this platform")
	r = Run(context.Background(), env, "nanoclaw")
	if _, ok := findCheck(r, "approvals_reach_contro1:group-a"); ok {
		t.Fatal("silence from the platform must not become a finding")
	}
}

// Doctor asked the server and then printed the number off the mapping file.
// An owner who had allowed applications an hour earlier still read
// "Approvals only", which is the one line they would have gone to check.
func TestTheModeReportedIsTheOneTheServerGives(t *testing.T) {
	env := healthy()
	env.liveMode = runtimeproto.ModeApplications // the owner widened it
	// The mapping still says what `contro1 connect` wrote.
	env.mapping.Entries[0].EndpointMode = runtimeproto.ModeApprovalsOnly

	r := Run(context.Background(), env, "nanoclaw")
	c, ok := findCheck(r, "runtime_status:group-a")
	if !ok {
		t.Fatal("the recognition check must be present")
	}
	if !strings.Contains(c.Message, runtimeproto.ModeLabel(runtimeproto.ModeApplications)) {
		t.Fatalf("the live mode must lead: %q", c.Message)
	}
	// And the stale file is worth mentioning, because it is what the broker
	// was configured from and somebody will wonder why they differ.
	if !strings.Contains(c.Message, "mapping file on this computer still says") {
		t.Fatalf("a disagreement must be named, not smoothed over: %q", c.Message)
	}
	// And it names what refreshes the file. It used to send people to
	// contro1 connect, which did not refresh it.
	if strings.Contains(c.Message, "refreshed by contro1 connect") || !strings.Contains(c.Message, "renews this agent's credential") {
		t.Fatalf("the stale note must say what actually refreshes it: %q", c.Message)
	}

	// The service rewrote the file from the status answer this check got:
	// nothing stale is left to report.
	env = healthy()
	env.liveMode = runtimeproto.ModeApplications
	env.refreshOnStatus = true
	r = Run(context.Background(), env, "nanoclaw")
	c, _ = findCheck(r, "runtime_status:group-a")
	if strings.Contains(c.Message, "still says") || !strings.Contains(c.Message, runtimeproto.ModeLabel(runtimeproto.ModeApplications)) {
		t.Fatalf("a refreshed mapping is not stale: %q", c.Message)
	}

	// An older service that does not report the mode falls back to the file
	// rather than printing nothing.
	env = healthy()
	env.liveMode = ""
	r = Run(context.Background(), env, "nanoclaw")
	c, _ = findCheck(r, "runtime_status:group-a")
	if !strings.Contains(c.Message, runtimeproto.ModeLabel(runtimeproto.ModeApprovalsOnly)) {
		t.Fatalf("with no live answer the mapping is all there is: %q", c.Message)
	}
	if strings.Contains(c.Message, "still says") {
		t.Fatalf("nothing to disagree with, so nothing to report: %q", c.Message)
	}
}

// A new OneCLI agent starts in "all" mode and receives every secret, including
// another agent's Contro1 lease. Blocked, because that agent can act as this one.
func TestLeaseReceivedByAnotherAgentIsBlocked(t *testing.T) {
	env := healthy()
	r := Run(context.Background(), env, "nanoclaw")
	if _, ok := findCheck(r, "lease_only_this_agent:group-a"); ok {
		t.Fatal("no stored lease means nothing to report")
	}

	env = healthy()
	env.leaseStored = true
	r = Run(context.Background(), env, "nanoclaw")
	c, ok := findCheck(r, "lease_only_this_agent:group-a")
	if !ok || c.Status != runtimeproto.CheckOK {
		t.Fatalf("a lease only this agent receives must pass: %+v", c)
	}

	env = healthy()
	env.leaseStored = true
	env.leaseExposed = []string{`"GroupHelper" (uuid-1)`}
	r = Run(context.Background(), env, "nanoclaw")
	c, _ = findCheck(r, "lease_only_this_agent:group-a")
	if c.Status != runtimeproto.CheckBlocked || !strings.Contains(c.Message, "GroupHelper") || !strings.Contains(c.NextCommand, "set-secret-mode") {
		t.Fatalf("exposure must be blocked, name the agent and the fix: %+v", c)
	}
	if r.State != "blocked" {
		t.Fatalf("report state: %s", r.State)
	}
}

// An OpenClaw host as connect leaves it: two agents, each with its own server.
func openClawHost() *fakeEnv {
	env := healthy()
	env.mapping.Platform = "openclaw"
	env.mcpName = "contro1-<id>"
	env.mcpTools = 12
	env.mcpServers = []McpServerConfig{
		{Name: "contro1-group-a", Command: "/usr/local/bin/contro1", Args: []string{"mcp", "serve", "--agent", "group-a"}},
		{Name: "contro1-group-b", Command: "/usr/local/bin/contro1", Args: []string{"mcp", "serve", "--agent", "group-b"}},
	}
	env.approverErr = errors.New("not reported by this platform")
	return env
}

func TestMcpServerChecksForAPlatformConnectInstallsOn(t *testing.T) {
	env := openClawHost()
	r := Run(context.Background(), env, "openclaw")
	if c, _ := findCheck(r, "mcp_server:group-a"); c.Status != runtimeproto.CheckOK {
		t.Fatalf("an entry pinned to this agent passes: %+v", c)
	}
	if c, _ := findCheck(r, "mcp_live:group-a"); c.Status != runtimeproto.CheckOK || !strings.Contains(c.Message, "12 actions available") {
		t.Fatalf("the live call is reported with what it found: %+v", c)
	}
	if _, ok := findCheck(r, "applications:group-a"); ok {
		t.Fatal("the older applications check is for platforms connect does not set up")
	}
	if r.State != "connected" {
		t.Fatalf("state: %s %+v", r.State, r.Checks)
	}

	// Missing: the agent has no way to Contro1's tools.
	env = openClawHost()
	env.mcpServers = env.mcpServers[1:]
	c, _ := findCheck(Run(context.Background(), env, "openclaw"), "mcp_server:group-a")
	if c.Status != runtimeproto.CheckRepairable || !strings.Contains(c.Message, "contro1-group-a") || c.NextCommand != "contro1 connect openclaw" {
		t.Fatalf("a missing entry names itself and the fix: %+v", c)
	}

	// Present but acting as another agent.
	env = openClawHost()
	env.mcpServers[0].Args = []string{"mcp", "serve", "--agent", "group-b"}
	if c, _ := findCheck(Run(context.Background(), env, "openclaw"), "mcp_server:group-a"); c.Status != runtimeproto.CheckRepairable || !strings.Contains(c.Message, "does not act as this agent") {
		t.Fatalf("an entry for another agent is not this agent's: %+v", c)
	}

	// The live call fails: said in its own words.
	env = openClawHost()
	env.mcpProbeErr = errors.New("MCP initialize failed: This computer is not connected")
	if c, _ := findCheck(Run(context.Background(), env, "openclaw"), "mcp_live:group-a"); c.Status != runtimeproto.CheckRepairable || !strings.Contains(c.Message, "not connected") {
		t.Fatalf("a failed live call is repairable with its reason: %+v", c)
	}
}

// One agent acting as another is exposure: blocked, never "repairable".
func TestMcpIsolationFindings(t *testing.T) {
	env := openClawHost()
	r := Run(context.Background(), env, "openclaw")
	if c, ok := findCheck(r, "mcp_isolation"); !ok || c.Status != runtimeproto.CheckOK {
		t.Fatalf("rules in place pass: %+v", c)
	}

	env = openClawHost()
	env.isolation = []IsolationIssue{
		{Agent: "group-b", Exposure: true, Message: "Agent group-b can use contro1-group-a__*, which act as other agents."},
		{Agent: "group-a", Message: "Agent group-a has a tools.allow list without contro1-group-a__*."},
	}
	r = Run(context.Background(), env, "openclaw")
	if c, _ := findCheck(r, "mcp_isolation:group-b"); c.Status != runtimeproto.CheckBlocked || c.NextCommand != "contro1 connect openclaw" {
		t.Fatalf("exposure is blocked with the command that writes the rules: %+v", c)
	}
	if c, _ := findCheck(r, "mcp_isolation:group-a"); c.Status != runtimeproto.CheckRepairable {
		t.Fatalf("an agent that lost its own server is broken, not exposed: %+v", c)
	}
	if r.State != "blocked" {
		t.Fatalf("state: %s", r.State)
	}

	// Rules that cannot be read on a host with several agents are not assumed fine.
	env = openClawHost()
	env.isolationErr = errors.New("openclaw.json is not plain JSON")
	if c, _ := findCheck(Run(context.Background(), env, "openclaw"), "mcp_isolation"); c.Status != runtimeproto.CheckRepairable || !strings.Contains(c.Message, "contro1-<id>__*") {
		t.Fatalf("unreadable rules are reported with what to check: %+v", c)
	}

	// Claude Code has nothing to isolate and says nothing about it.
	env = openClawHost()
	env.isolationErr = ErrNotApplicable
	if _, ok := findCheck(Run(context.Background(), env, "claude-code"), "mcp_isolation"); ok {
		t.Fatal("not applicable is not a finding")
	}
}

// OpenClaw keeps running the last configuration it accepted, so one it rejects
// means the Contro1 servers never apply while the gateway looks healthy.
func TestARejectedPlatformConfigurationIsReported(t *testing.T) {
	env := openClawHost()
	env.config = &ConfigState{Valid: false, Problem: `agents: Unrecognized key: "list"`}
	c, ok := findCheck(Run(context.Background(), env, "openclaw"), "platform_config_valid")
	if !ok || c.Status != runtimeproto.CheckRepairable || !strings.Contains(c.Message, "Unrecognized key") || c.NextCommand != "openclaw config validate" {
		t.Fatalf("a rejected configuration names the problem and the command: %+v", c)
	}

	env.config = &ConfigState{Valid: true}
	if c, _ := findCheck(Run(context.Background(), env, "openclaw"), "platform_config_valid"); c.Status != runtimeproto.CheckOK {
		t.Fatalf("a valid configuration passes: %+v", c)
	}

	env.config = nil
	if _, ok := findCheck(Run(context.Background(), env, "openclaw"), "platform_config_valid"); ok {
		t.Fatal("a platform that cannot say is not a finding")
	}
	if _, ok := findCheck(Run(context.Background(), env, "openclaw"), "gateway_current"); ok {
		t.Fatal("OpenClaw hot reloads MCP and agents; there is no restart check")
	}
}

// A Claude Code that only uses the approval hook was fine before connect
// installed the MCP server, and still is.
func TestClaudeCodeWithoutTheMcpServerIsNotAFailure(t *testing.T) {
	t.Setenv("CONTRO1_PLATFORMS_DIR", t.TempDir())
	env := openClawHost()
	env.mapping.Platform = "claude-code"
	env.mcpName = "contro1"
	env.mcpServers = nil
	env.mcpProbeErr = errors.New("an older service has no /mcp")
	r := Run(context.Background(), env, "claude-code")
	c, ok := findCheck(r, "mcp_server:group-a")
	if !ok || c.Status != runtimeproto.CheckOK || !strings.Contains(c.Message, "MCP not set up") || c.NextCommand != "contro1 connect claude-code" {
		t.Fatalf("informational, with the command: %+v", c)
	}
	if _, probed := findCheck(r, "mcp_live:group-a"); probed {
		t.Fatal("no live check for a server that is not set up")
	}
	if r.State != "connected" {
		t.Fatalf("doctor stays green: %s %+v", r.State, r.Checks)
	}

	// The docs' local entry without --agent acts as the only agent here.
	env.mcpServers = []McpServerConfig{{Name: "contro1", Command: "contro1", Args: []string{"mcp", "serve"}}}
	env.mapping.Entries = env.mapping.Entries[:1]
	env.discovered = []string{"group-a"}
	env.mcpProbeErr = nil
	if c, _ := findCheck(Run(context.Background(), env, "claude-code"), "mcp_server:group-a"); c.Status != runtimeproto.CheckOK || strings.Contains(c.Message, "not this agent") {
		t.Fatalf("a working unpinned entry is not repair-needed: %+v", c)
	}
}
