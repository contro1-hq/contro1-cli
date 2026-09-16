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
	agentFor                      map[string]string
	remediation                   *runtimeproto.Remediation
	development                   bool
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
func (f *fakeEnv) ExpectedPrincipal(_, subject string) (string, error) {
	return f.expected[subject], nil
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
	if c.Status != runtimeproto.CheckRepairable || !strings.Contains(c.Message, "group-c") || c.Actor != "accountable_owner" {
		t.Fatalf("new group must need a new approval: %+v", c)
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
