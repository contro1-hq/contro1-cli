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
	discovered                    []string
	principals                    map[string][]string
	expected                      map[string]string
	expectedGroup                 map[string]string
	agentFor                      map[string]string
	remediation                   *runtimeproto.Remediation
	development                   bool
	mcpServers                    []McpServerConfig
	mcpErr                        error
	mounts                        []string
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
func (f *fakeEnv) RuntimeStatus(_ context.Context, e runtimeproto.MappingEntry) (string, *runtimeproto.Remediation, error) {
	if f.remediation != nil {
		return "", f.remediation, errors.New("refused")
	}
	return f.agentFor[e.Endpoint], nil, nil
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
