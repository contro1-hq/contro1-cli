package platforms

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

/*
fakeOpenClaw behaves like the parts of the OpenClaw CLI connect uses, with the
rules its source enforces: writers refuse while a gateway runs, config.patch
needs the current hash, the schema has no agents.list and rejects allow with
alsoAllow, and arrays in a merge patch replace.
*/
type fakeOpenClaw struct {
	t        *testing.T
	gateway  bool
	cfg      map[string]any
	hash     int
	path     string
	ran      []string
	patchErr error
	invalid  string
}

func newFakeOpenClaw(t *testing.T, gateway bool, cfg string) *fakeOpenClaw {
	f := &fakeOpenClaw{t: t, gateway: gateway, hash: 1, path: filepath.Join(t.TempDir(), ".openclaw", "openclaw.json")}
	if err := json.Unmarshal([]byte(cfg), &f.cfg); err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(filepath.Dir(f.path), 0o700)
	_ = os.WriteFile(f.path, []byte(cfg), 0o600)
	return f
}

func (f *fakeOpenClaw) adapter() Adapter {
	a, _ := New("openclaw", Options{Home: f.t.TempDir(), Runner: f.run})
	return a
}

func failEnvelope(msg string) ([]byte, error) {
	return []byte(fmt.Sprintf(`{"ok":false,"error":{"type":"cli_error","message":%q}}`, msg)), errors.New("exit status 1")
}

func (f *fakeOpenClaw) get(path string) (any, bool) {
	var cur any = f.cfg
	for _, k := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = m[k]; !ok {
			return nil, false
		}
	}
	return cur, true
}

func mergePatch(target map[string]any, patch map[string]any) {
	for k, v := range patch {
		if v == nil {
			delete(target, k)
			continue
		}
		if pm, ok := v.(map[string]any); ok {
			tm, ok := target[k].(map[string]any)
			if !ok {
				tm = map[string]any{}
				target[k] = tm
			}
			mergePatch(tm, pm)
			continue
		}
		target[k] = v
	}
}

func (f *fakeOpenClaw) apply(raw []byte) error {
	var patch map[string]any
	if err := json.Unmarshal(raw, &patch); err != nil {
		return err
	}
	if agents, ok := patch["agents"].(map[string]any); ok {
		if _, legacy := agents["list"]; legacy {
			return errors.New("agents: Unrecognized key: \"list\"")
		}
	}
	next := map[string]any{}
	before, _ := json.Marshal(f.cfg)
	_ = json.Unmarshal(before, &next)
	mergePatch(next, patch)
	agents, _ := next["agents"].(map[string]any)
	if entries, ok := agents["entries"].(map[string]any); ok {
		for id, e := range entries {
			tools, _ := e.(map[string]any)["tools"].(map[string]any)
			if tools["allow"] != nil && tools["alsoAllow"] != nil {
				return fmt.Errorf("agents.entries.%s.tools: cannot set both allow and alsoAllow", id)
			}
		}
	}
	f.cfg = next
	f.hash++
	raw, _ = json.MarshalIndent(f.cfg, "", "  ")
	return os.WriteFile(f.path, raw, 0o600)
}

func (f *fakeOpenClaw) run(_ context.Context, name string, args ...string) ([]byte, error) {
	line := name + " " + strings.Join(args, " ")
	f.ran = append(f.ran, line)
	if name != "openclaw" {
		return nil, errors.New("unexpected command " + line)
	}
	switch {
	case strings.HasPrefix(line, "openclaw gateway call config.get"):
		if !f.gateway {
			return failEnvelope("gateway closed (1006): no Gateway is running")
		}
		return json.Marshal(map[string]any{"path": f.path, "exists": true, "valid": true, "hash": fmt.Sprintf("h%d", f.hash), "config": f.cfg})
	case strings.HasPrefix(line, "openclaw gateway call config.patch"):
		if !f.gateway {
			return failEnvelope("no Gateway is running")
		}
		if f.patchErr != nil {
			return nil, f.patchErr
		}
		var params struct {
			Raw      string `json:"raw"`
			BaseHash string `json:"baseHash"`
		}
		if err := json.Unmarshal([]byte(args[4]), &params); err != nil {
			f.t.Fatalf("config.patch params are not JSON: %v", err)
		}
		if params.BaseHash != fmt.Sprintf("h%d", f.hash) {
			return failEnvelope("config changed since last load; re-run config.get")
		}
		if err := f.apply([]byte(params.Raw)); err != nil {
			return failEnvelope(err.Error())
		}
		return []byte(`{"ok":true,"changedPaths":["mcp.servers"]}`), nil
	case line == "openclaw config file --json":
		return json.Marshal(map[string]string{"path": f.path})
	case strings.HasPrefix(line, "openclaw config get "):
		v, ok := f.get(args[2])
		if !ok {
			return failEnvelope(args[2] + " is not set")
		}
		return json.Marshal(v)
	case strings.HasPrefix(line, "openclaw config patch --file "):
		if f.gateway {
			return failEnvelope("A running Gateway owns this state directory. Stop it, then retry.")
		}
		raw, err := os.ReadFile(args[3])
		if err != nil {
			f.t.Fatalf("patch file: %v", err)
		}
		if err := f.apply(raw); err != nil {
			return failEnvelope(err.Error())
		}
		return []byte("Change will apply without restarting the gateway."), nil
	case line == "openclaw mcp list --json":
		v, _ := f.get("mcp.servers")
		if v == nil {
			v = map[string]any{}
		}
		return json.Marshal(v)
	case line == "openclaw config validate --json":
		if f.invalid != "" {
			out, _ := json.Marshal(map[string]any{"valid": false, "issues": []map[string]string{{"path": "agents", "message": f.invalid}}})
			return out, errors.New("exit status 1")
		}
		return []byte(`{"valid":true}`), nil
	}
	return nil, errors.New("unexpected command " + line)
}

func (f *fakeOpenClaw) tools(id string) (allow, deny []string) {
	tools, _ := f.get("agents.entries." + id + ".tools")
	m, _ := tools.(map[string]any)
	return asList(m["allow"]), asList(m["deny"])
}

func asList(v any) []string {
	list, _ := v.([]any)
	var out []string
	for _, x := range list {
		out = append(out, x.(string))
	}
	return out
}

func (f *fakeOpenClaw) count(prefix string) int {
	n := 0
	for _, l := range f.ran {
		if strings.HasPrefix(l, prefix) {
			n++
		}
	}
	return n
}

const threeAgents = `{
  "agents": {
    "ownership": "explicit",
    "entries": {
      "main": {"name": "Raziella"},
      "dash": {"tools": {"allow": ["read", "write"]}},
      "michaella": {"tools": {"deny": ["exec"], "alsoAllow": ["web_search"]}}
    }
  },
  "gateway": {"port": 18789}
}`

var threeSubjects = []string{"main", "dash", "michaella"}

func checkThreeAgentRules(t *testing.T, f *fakeOpenClaw) {
	t.Helper()
	servers, _ := f.get("mcp.servers")
	if got := asList(servers.(map[string]any)["contro1-dash"].(map[string]any)["args"]); strings.Join(got, " ") != "mcp serve --agent dash" {
		t.Fatalf("dash's server acts as dash only: %v", got)
	}
	if cmd := servers.(map[string]any)["contro1-main"].(map[string]any)["command"]; cmd != "/usr/local/bin/contro1" {
		t.Fatalf("an absolute path to contro1: %v", cmd)
	}
	if _, deny := f.tools("main"); strings.Join(deny, ",") != "contro1-dash__*,contro1-michaella__*" {
		t.Fatalf("main denies the other two: %v", deny)
	}
	allow, deny := f.tools("dash")
	if strings.Join(allow, ",") != "read,write,contro1-dash__*" || strings.Join(deny, ",") != "contro1-main__*,contro1-michaella__*" {
		t.Fatalf("dash keeps its allow list, adds its own server, denies the others: %v %v", allow, deny)
	}
	allow, deny = f.tools("michaella")
	if len(allow) != 0 || strings.Join(deny, ",") != "exec,contro1-dash__*,contro1-main__*" {
		t.Fatalf("alsoAllow is left alone and the deny list is kept and extended: %v %v", allow, deny)
	}
	if port, _ := f.get("gateway.port"); port.(float64) != 18789 {
		t.Fatal("unrelated settings are untouched")
	}
	if _, legacy := f.get("agents.list"); legacy {
		t.Fatal("agents.list is not in OpenClaw's schema and must never be written")
	}
}

// The field case: a gateway running with three agents. One patch through the
// gateway carries the servers and the rules, based on the hash it handed out.
func TestOpenClawWritesOnePatchThroughTheRunningGateway(t *testing.T) {
	pinHost(t)
	f := newFakeOpenClaw(t, true, threeAgents)
	a := f.adapter()
	installer := a.(McpInstaller)

	changes := installer.McpChanges(context.Background(), threeSubjects)
	var lines []string
	for _, c := range changes {
		lines = append(lines, c.Description+" "+c.After)
	}
	preview := strings.Join(lines, "\n")
	for _, want := range []string{"contro1-main", "contro1-dash", "contro1-michaella", "tool rules", "gateway call config.patch", "without a restart"} {
		if !strings.Contains(preview, want) {
			t.Fatalf("preview is missing %q:\n%s", want, preview)
		}
	}
	if f.hash != 1 {
		t.Fatal("the preview changed the configuration")
	}

	var j Journal
	out, err := installer.InstallMcp(context.Background(), threeSubjects, &j)
	if err != nil {
		t.Fatal(err)
	}
	if f.count("openclaw gateway call config.patch") != 1 {
		t.Fatalf("one patch, not a write per server: %v", f.ran)
	}
	for _, l := range f.ran {
		if strings.HasPrefix(l, "openclaw mcp add") || strings.HasPrefix(l, "openclaw config set") || strings.HasPrefix(l, "launchctl") {
			t.Fatalf("no CLI writer and no restart while the gateway runs: %v", f.ran)
		}
	}
	checkThreeAgentRules(t, f)
	if raw, err := os.ReadFile(f.path + ".bak-contro1-20261020-093000"); err != nil || string(raw) != threeAgents {
		t.Fatalf("the configuration is copied before it changes: %v", err)
	}
	if !strings.Contains(strings.Join(out.Done, " "), "applied it live") || len(out.ToDo) != 0 {
		t.Fatalf("live, nothing left for the person: %+v", out)
	}
	if issues, err := a.(McpInspector).McpIsolation(context.Background(), threeSubjects); err != nil || len(issues) != 0 {
		t.Fatalf("what was written reads back as isolated: %+v %v", issues, err)
	}

	// A second run changes nothing and previews nothing.
	f.ran = nil
	if changes := installer.McpChanges(context.Background(), threeSubjects); len(changes) != 0 {
		t.Fatalf("a finished host previews nothing: %+v", changes)
	}
	if _, err := installer.InstallMcp(context.Background(), threeSubjects, &Journal{}); err != nil {
		t.Fatal(err)
	}
	if f.count("openclaw gateway call config.patch") != 0 {
		t.Fatalf("an idempotent run writes nothing: %v", f.ran)
	}
}

// With no gateway running, the same patch goes through openclaw config patch.
func TestOpenClawWritesThePatchLocallyWhenNoGatewayRuns(t *testing.T) {
	pinHost(t)
	f := newFakeOpenClaw(t, false, threeAgents)
	out, err := f.adapter().(McpInstaller).InstallMcp(context.Background(), threeSubjects, &Journal{})
	if err != nil {
		t.Fatal(err)
	}
	if f.count("openclaw config patch --file ") != 1 || f.count("openclaw mcp add") != 0 {
		t.Fatalf("one local patch: %v", f.ran)
	}
	checkThreeAgentRules(t, f)
	if !strings.Contains(strings.Join(out.Done, " "), "loads the servers when it starts") {
		t.Fatalf("says when it takes effect: %+v", out)
	}
}

// Neither way available: nothing is written, and the person gets the patch.
func TestOpenClawPrintsThePatchAndStopsWhenItCannotWrite(t *testing.T) {
	pinHost(t)
	f := newFakeOpenClaw(t, true, threeAgents)
	f.patchErr = errors.New("UNAVAILABLE: unauthorized")
	_, err := f.adapter().(McpInstaller).InstallMcp(context.Background(), threeSubjects, &Journal{})
	if err == nil || !strings.Contains(err.Error(), "nothing was changed") || !strings.Contains(err.Error(), `"contro1-main"`) || !strings.Contains(err.Error(), "config patch --file") {
		t.Fatalf("the failure carries the exact patch: %v", err)
	}
	if f.hash != 1 {
		t.Fatal("nothing may be written")
	}
}

// A gateway that is slow to apply is not a failure once the change is there.
func TestOpenClawPatchThatLandedLateIsASuccess(t *testing.T) {
	pinHost(t)
	f := newFakeOpenClaw(t, true, threeAgents)
	inner := f.run
	runner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		out, err := inner(ctx, name, args...)
		if err == nil && len(args) > 2 && args[2] == "config.patch" {
			return nil, errors.New("gateway timeout after 120000ms")
		}
		return out, err
	}
	a, _ := New("openclaw", Options{Home: t.TempDir(), Runner: runner})
	out, err := a.(McpInstaller).InstallMcp(context.Background(), threeSubjects, &Journal{})
	if err != nil || !strings.Contains(strings.Join(out.Done, " "), "within a few minutes") {
		t.Fatalf("%+v %v", out, err)
	}
}

// OpenClaw renames unsafe or long server names, which would make the deny
// pattern miss. Names are generated inside its rules.
func TestOpenClawServerNamesAreAlreadySafe(t *testing.T) {
	safe := regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,29}$`)
	seen := map[string]string{}
	for _, id := range []string{"main", "dash", "a.b", "a-b", "research_team_long_agent_identifier_42", "research_team_long_agent_identifier_43"} {
		name := openClawServerName(id)
		if !safe.MatchString(name) || !strings.HasPrefix(name, "contro1-") {
			t.Fatalf("%q -> %q is not a name OpenClaw keeps as it is", id, name)
		}
		if other, dup := seen[strings.ToLower(name)]; dup {
			t.Fatalf("%q and %q share %q", id, other, name)
		}
		seen[strings.ToLower(name)] = id
		if openClawToolPattern(id) != name+"__*" {
			t.Fatal("the pattern is the name OpenClaw prefixes tools with")
		}
	}
	if openClawServerName("main") != "contro1-main" {
		t.Fatal("an ordinary id keeps its readable name")
	}
}

func TestOpenClawIsolationFindsTheLeakAndTheMissingEntry(t *testing.T) {
	pinHost(t)
	f := newFakeOpenClaw(t, true, threeAgents)
	issues, err := f.adapter().(McpInspector).McpIsolation(context.Background(), []string{"main", "dash", "michaella", "ops"})
	if err != nil {
		t.Fatal(err)
	}
	exposed := map[string]bool{}
	for _, is := range issues {
		if is.Exposure {
			exposed[is.Agent] = true
		}
	}
	for _, id := range []string{"main", "dash", "michaella", "ops"} {
		if !exposed[id] {
			t.Fatalf("%s can act as the others without rules: %+v", id, issues)
		}
	}

	// A single agent with no roster has nobody to be isolated from, and the
	// patch creates no agents.entries for it.
	g := newFakeOpenClaw(t, true, `{"gateway":{"port":18789}}`)
	if _, err := g.adapter().(McpInstaller).InstallMcp(context.Background(), []string{"main"}, &Journal{}); err != nil {
		t.Fatal(err)
	}
	if _, ok := g.get("agents"); ok {
		t.Fatal("no roster is invented for a single agent")
	}
	if _, ok := g.get("mcp.servers.contro1-main"); !ok {
		t.Fatal("its server is still added")
	}
}

func TestOpenClawConfigStatusAndServers(t *testing.T) {
	pinHost(t)
	f := newFakeOpenClaw(t, true, threeAgents)
	a := f.adapter()
	if _, err := a.(McpInstaller).InstallMcp(context.Background(), threeSubjects, &Journal{}); err != nil {
		t.Fatal(err)
	}
	servers, err := a.(McpInspector).McpServers(context.Background())
	if err != nil || len(servers) != 3 || !servers[0].ServesAgent("dash") {
		t.Fatalf("mcp list --json is read: %+v %v", servers, err)
	}
	if st, err := a.(McpInspector).ConfigStatus(context.Background()); err != nil || !st.Valid {
		t.Fatalf("valid: %+v %v", st, err)
	}
	f.invalid = `Unrecognized key: "list"`
	if st, err := a.(McpInspector).ConfigStatus(context.Background()); err != nil || st.Valid || !strings.Contains(st.Problem, "Unrecognized key") {
		t.Fatalf("an invalid configuration is reported with its reason: %+v %v", st, err)
	}
}

// Discovery reads the configuration OpenClaw reads, in its current shape.
func TestOpenClawDiscoveryReadsAgentsEntriesAtTheConfiguredPath(t *testing.T) {
	pinHost(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.json")
	_ = os.WriteFile(path, []byte(threeAgents), 0o600)
	t.Setenv("OPENCLAW_CONFIG_PATH", path)
	a, _ := New("openclaw", Options{Home: t.TempDir(), Runner: fakeRunner(nil)})
	_, subjects, err := a.Discover(context.Background())
	if err != nil || len(subjects) != 3 || subjects[0].ID != "dash" || subjects[1].Display != "Raziella" {
		t.Fatalf("agents.entries at OPENCLAW_CONFIG_PATH: %+v %v", subjects, err)
	}
}
