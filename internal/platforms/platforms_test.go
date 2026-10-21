package platforms

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/contro1-hq/contro1-cli/internal/runtimeproto"
)

func fakeRunner(outputs map[string]string) Runner {
	return func(_ context.Context, name string, args ...string) ([]byte, error) {
		key := name + " " + strings.Join(args, " ")
		if out, ok := outputs[key]; ok {
			return []byte(out), nil
		}
		return nil, errors.New("not found: " + key)
	}
}

func TestOpenClawDiscovery(t *testing.T) {
	home := t.TempDir()
	a, _ := New("openclaw", Options{Home: home, Runner: fakeRunner(map[string]string{
		"openclaw agents list --json": `[{"id":"main","name":"Main"},{"id":"research"}]`,
	})})
	_, subjects, err := a.Discover(context.Background())
	if err != nil || len(subjects) != 2 || subjects[0].Display != "Main" || subjects[1].Display != "research" {
		t.Fatalf("CLI discovery: %+v %v", subjects, err)
	}

	// Fallback to the config file when the CLI is absent.
	_ = os.MkdirAll(filepath.Join(home, ".openclaw"), 0o700)
	_ = os.WriteFile(filepath.Join(home, ".openclaw", "openclaw.json"), []byte(`{"agents":{"list":[{"id":"ops"}]}}`), 0o600)
	b, _ := New("openclaw", Options{Home: home, Runner: fakeRunner(nil)})
	_, subjects, err = b.Discover(context.Background())
	if err != nil || len(subjects) != 1 || subjects[0].ID != "ops" {
		t.Fatalf("config discovery: %+v %v", subjects, err)
	}

	c, _ := New("openclaw", Options{Home: t.TempDir(), Runner: fakeRunner(nil)})
	if _, _, err := c.Discover(context.Background()); err == nil || !strings.Contains(err.Error(), "--agent") {
		t.Fatalf("nothing found must say how to continue: %v", err)
	}
}

func TestNanoClawRolesAreSeparate(t *testing.T) {
	a, _ := New("nanoclaw", Options{Home: t.TempDir(), Runner: fakeRunner(map[string]string{
		"ncl groups list --json": `{"groups":[{"id":"g1","name":"Support"},{"folder":"finance"}]}`,
	})})
	_, subjects, err := a.Discover(context.Background())
	if err != nil || len(subjects) != 2 || subjects[1].ID != "finance" {
		t.Fatalf("groups: %+v %v", subjects, err)
	}
	m := &runtimeproto.MappingFile{Entries: []runtimeproto.MappingEntry{{PlatformSubject: "g1"}, {PlatformSubject: "finance"}}}
	for _, c := range a.RoleChanges(m) {
		if !c.RoleChange {
			t.Fatal("every NanoClaw role change is marked for separate confirmation")
		}
	}
	if len(a.PlanConfig("/x")) != 1 || a.PlanConfig("/x")[0].RoleChange {
		t.Fatal("plain config is not a role change")
	}
}

func TestEnvFileJournalRemovesOnlyCreated(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "existing.env")
	_ = os.WriteFile(existing, []byte("OTHER=1\n"), 0o600)
	var j Journal
	if err := writeEnvFile(existing, map[string]string{"CONTRO1_PLATFORM_MAPPING_FILE": "/m.json"}, &j); err != nil {
		t.Fatal(err)
	}
	created := filepath.Join(dir, "new", "contro1.env")
	if err := writeEnvFile(created, map[string]string{"CONTRO1_PLATFORM_MAPPING_FILE": "/m.json"}, &j); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(existing)
	if !strings.Contains(string(raw), "OTHER=1") || !strings.Contains(string(raw), "CONTRO1_PLATFORM_MAPPING_FILE=/m.json") {
		t.Fatalf("existing settings must be kept: %s", raw)
	}
	if err := removeCreated(&j); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(existing); err != nil {
		t.Fatal("a file the person already had is never removed")
	}
	if _, err := os.Stat(created); !os.IsNotExist(err) {
		t.Fatal("a file we created is removed")
	}
}

func TestReadMappingValidates(t *testing.T) {
	dir := t.TempDir()
	entries := []runtimeproto.MappingEntry{{PlatformSubject: "main", AgentID: "agt_1", EnrollmentID: "enr_1", EndpointMode: runtimeproto.ModeApprovalsOnly, Endpoint: "npipe:////./pipe/contro1-ep-x"}}
	good := runtimeproto.MappingFile{SchemaVersion: 1, Platform: "openclaw", Digest: runtimeproto.MappingDigest(entries), Entries: entries}
	write := func(name string, m runtimeproto.MappingFile) string {
		p := filepath.Join(dir, name)
		raw, _ := jsonMarshal(m)
		_ = os.WriteFile(p, raw, 0o644)
		return p
	}
	if _, err := ReadMapping(write("good.json", good)); err != nil {
		t.Fatal(err)
	}
	tampered := good
	tampered.Entries = []runtimeproto.MappingEntry{{PlatformSubject: "main", AgentID: "agt_other", EnrollmentID: "enr_1", EndpointMode: runtimeproto.ModeApprovalsOnly, Endpoint: "npipe:////./pipe/contro1-ep-x"}}
	if _, err := ReadMapping(write("tampered.json", tampered)); err == nil {
		t.Fatal("an edited mapping must fail its digest")
	}
}

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }

// Real ncl --json answers {ok, data: [...]}. Reading only a bare array made
// doctor report "no NanoClaw groups found" on a working install, and the owner
// saw group ids instead of names on the approval screen.
func TestNanoClawDiscoveryReadsNclEnvelope(t *testing.T) {
	for name, out := range map[string]string{
		"envelope": `{"ok":true,"data":[{"id":"ag-1","name":"Nano"},{"id":"ag-2","folder":"memos"}]}`,
		"groups":   `{"groups":[{"id":"ag-1","name":"Nano"},{"id":"ag-2","folder":"memos"}]}`,
		"bare":     `[{"id":"ag-1","name":"Nano"},{"id":"ag-2","folder":"memos"}]`,
	} {
		a, _ := New("nanoclaw", Options{Home: t.TempDir(), Bin: "ncl", Runner: fakeRunner(map[string]string{"ncl groups list --json": out})})
		_, subjects, err := a.Discover(context.Background())
		if err != nil || len(subjects) != 2 || subjects[0].Display != "Nano" || subjects[1].ID != "ag-2" {
			t.Fatalf("%s: %+v %v", name, subjects, err)
		}
	}
	a, _ := New("openclaw", Options{Home: t.TempDir(), Runner: fakeRunner(map[string]string{
		"openclaw agents list --json": `{"ok":true,"data":[{"id":"main","name":"Main"}]}`,
	})})
	if _, subjects, err := a.Discover(context.Background()); err != nil || len(subjects) != 1 || subjects[0].Display != "Main" {
		t.Fatalf("openclaw envelope: %+v %v", subjects, err)
	}
}

// The live shapes this was written against, from a real NanoClaw v2.3.0 install:
// a DM (is_group 0) and a group chat (is_group 1) wired to two agent groups.
func TestNanoClawReachSeparatesGroupsFromDMs(t *testing.T) {
	runner := fakeRunner(map[string]string{
		"ncl wirings list --json": `{"ok":true,"data":[
			{"messaging_group_id":"mg-1788291512617-dnnhf4","agent_group_id":"ag-nano","sender_scope":"all"},
			{"messaging_group_id":"mg-1789143915243-9lrv08","agent_group_id":"ag-nano","sender_scope":"all"},
			{"messaging_group_id":"mg-other","agent_group_id":"ag-someone-else","sender_scope":"all"}
		]}`,
		"ncl messaging-groups get --id mg-1788291512617-dnnhf4 --json": `{"ok":true,"data":{"id":"mg-1788291512617-dnnhf4","name":"Sales","is_group":0,"platform_id":"972500000000@s.whatsapp.net"}}`,
		"ncl messaging-groups get --id mg-1789143915243-9lrv08 --json": `{"ok":true,"data":{"id":"mg-1789143915243-9lrv08","name":"Berlin trip","is_group":1,"platform_id":"120300000000000000@g.us"}}`,
	})

	a, _ := New("nanoclaw", Options{Home: t.TempDir(), Runner: runner})
	reach, err := a.Reach(context.Background(), "ag-nano")
	if err != nil {
		t.Fatalf("reach: %v", err)
	}
	if !reach.Complete || len(reach.Contexts) != 2 {
		t.Fatalf("another agent group's wiring leaked in: %+v", reach)
	}
	// sender_scope "all" is NanoClaw's default and means "answer everyone in the
	// room". In a one to one chat there is only one person who can write, so it
	// is not exposure and must not be read as any.
	if reach.Contexts[0].Kind != runtimeproto.ReachPrivate || !reach.Contexts[0].ParticipantsKnown {
		t.Fatalf("a DM bounds its own participants whatever sender_scope says: %+v", reach.Contexts[0])
	}
	if reach.Contexts[1].Kind != runtimeproto.ReachShared || reach.Contexts[1].Label != "Berlin trip" {
		t.Fatalf("group chat should be shared: %+v", reach.Contexts[1])
	}
	// One group chat is enough to taint the whole agent.
	if got := runtimeproto.PostureForReach(&reach); got != runtimeproto.PostureSharedSurface {
		t.Fatalf("posture = %q, want shared_surface", got)
	}

	// The WhatsApp JID is a phone number or a group address. It must not reach
	// Contro1 through any field.
	blob, _ := json.Marshal(reach)
	for _, leak := range []string{"@s.whatsapp.net", "@g.us", "972500000000", "120300000000000000"} {
		if strings.Contains(string(blob), leak) {
			t.Fatalf("reach carries the platform address %q: %s", leak, blob)
		}
	}
}

func TestNanoClawReachFailsClosedWhenTheGroupCannotBeRead(t *testing.T) {
	// The wiring is known but the conversation behind it is not, so the surface
	// stays unknown rather than being assumed private.
	a, _ := New("nanoclaw", Options{Home: t.TempDir(), Runner: fakeRunner(map[string]string{
		"ncl wirings list --json": `{"ok":true,"data":[{"messaging_group_id":"mg-1","agent_group_id":"ag-nano","sender_scope":"known"}]}`,
	})})
	reach, err := a.Reach(context.Background(), "ag-nano")
	if err != nil || len(reach.Contexts) != 1 || reach.Contexts[0].Kind != runtimeproto.ReachUnknown {
		t.Fatalf("unreadable conversation must stay unknown: %+v %v", reach, err)
	}
	if got := runtimeproto.PostureForReach(&reach); got != runtimeproto.PostureSharedSurface {
		t.Fatalf("posture = %q, want shared_surface", got)
	}

	// No wiring list at all is not an empty reach, it is no answer.
	b, _ := New("nanoclaw", Options{Home: t.TempDir(), Runner: fakeRunner(nil)})
	reach, err = b.Reach(context.Background(), "ag-nano")
	if err == nil || reach.Complete {
		t.Fatalf("a failed listing must not report a complete reach: %+v %v", reach, err)
	}
}

// Claude Code is driven from a terminal by whoever is at the keyboard. There is
// no channel another person can message, so the local claim is a real one.
func TestClaudeCodeReportsAPrivateHost(t *testing.T) {
	a, _ := New("claude-code", Options{Home: t.TempDir(), Principal: "ariel", Runner: fakeRunner(nil)})
	reach, err := a.Reach(context.Background(), "any")
	if err != nil || runtimeproto.PostureForReach(&reach) != runtimeproto.PostureSoleOperator {
		t.Fatalf("a terminal tool with no messageable surface is sole_operator: %+v %v", reach, err)
	}
}

// The mistake this guards against: reading the local socket the bridge uses as
// though it were the surface the assistant answers on. OpenClaw replies on
// WhatsApp, Telegram, Signal and Slack, so running as one OS user says nothing
// about who can instruct it.
func TestOpenClawIsNotPrivateJustBecauseItRunsLocally(t *testing.T) {
	a, _ := New("openclaw", Options{Home: t.TempDir(), Principal: "ariel", Runner: fakeRunner(nil)})
	reach, err := a.Reach(context.Background(), "any")
	if err != nil {
		t.Fatalf("reach: %v", err)
	}
	if reach.Contexts[0].Kind != runtimeproto.ReachUnknown || reach.Contexts[0].ParticipantsKnown {
		t.Fatalf("a local socket protects the credential, not the chat surface: %+v", reach.Contexts[0])
	}
	if got := runtimeproto.PostureForReach(&reach); got != runtimeproto.PostureSharedSurface {
		t.Fatalf("posture = %q, want shared_surface", got)
	}
}

// A published mapping file, as `contro1 connect` writes it.
func writeMapping(t *testing.T, dir, platform string, entries []runtimeproto.MappingEntry) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	file := runtimeproto.MappingFile{
		SchemaVersion: runtimeproto.SchemaVersion,
		Platform:      platform,
		GeneratedAt:   "2026-09-19T08:00:00Z",
		Digest:        runtimeproto.MappingDigest(entries),
		Entries:       entries,
	}
	raw, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, platform+".json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func entry(subject, agentID, endpoint string) runtimeproto.MappingEntry {
	return runtimeproto.MappingEntry{
		PlatformSubject: subject,
		AgentID:         agentID,
		EnrollmentID:    "enr_" + agentID,
		EndpointMode:    runtimeproto.ModeApplications,
		Endpoint:        endpoint,
	}
}

// The whole point: the endpoint is already on disk, so nobody should have to
// paste it anywhere.
func TestASingleConnectionIsFoundWithoutBeingNamed(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CONTRO1_PLATFORMS_DIR", dir)
	writeMapping(t, dir, "claude-code", []runtimeproto.MappingEntry{
		entry("default", "agt_one", "unix:///run/contro1/ep/ep_one.sock"),
	})

	got, err := SelectLocalConnection("")
	if err != nil || got.Endpoint != "unix:///run/contro1/ep/ep_one.sock" || got.AgentID != "agt_one" {
		t.Fatalf("single connection should be selected without a selector: %+v %v", got, err)
	}
}

func TestSeveralConnectionsAreNeverGuessedBetween(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CONTRO1_PLATFORMS_DIR", dir)
	writeMapping(t, dir, "nanoclaw", []runtimeproto.MappingEntry{
		entry("ag-sales", "agt_sales", "unix:///run/contro1/ep/ep_sales.sock"),
		entry("ag-devmemos", "agt_memos", "unix:///run/contro1/ep/ep_memos.sock"),
	})

	// Picking the first would silently make one agent act as another.
	_, err := SelectLocalConnection("")
	var ambiguous *AmbiguousConnectionError
	if !errors.As(err, &ambiguous) || len(ambiguous.Candidates) != 2 {
		t.Fatalf("ambiguity must be reported with the candidates: %v", err)
	}
	if !strings.Contains(err.Error(), "agt_sales") || !strings.Contains(err.Error(), "--agent") {
		t.Fatalf("the error must name the choices and how to make one: %v", err)
	}

	// Either identifier works, because a person reads whichever is on screen.
	byAgent, err := SelectLocalConnection("agt_memos")
	if err != nil || byAgent.PlatformSubject != "ag-devmemos" {
		t.Fatalf("select by Contro1 agent id: %+v %v", byAgent, err)
	}
	bySubject, err := SelectLocalConnection("ag-sales")
	if err != nil || bySubject.AgentID != "agt_sales" {
		t.Fatalf("select by the platform's own id: %+v %v", bySubject, err)
	}

	if _, err := SelectLocalConnection("agt_nothing"); err == nil {
		t.Fatal("a selector that matches nothing must not fall back to any connection")
	}
}

func TestNoConnectionIsAnOrdinaryStateAndATamperedFileIsNot(t *testing.T) {
	empty := t.TempDir()
	t.Setenv("CONTRO1_PLATFORMS_DIR", empty)
	if _, err := SelectLocalConnection(""); !errors.Is(err, ErrNoLocalConnection) {
		t.Fatalf("an unconnected computer is not an error condition: %v", err)
	}

	// A mapping file whose digest no longer matches must not read as "never
	// connected": that would send somebody to reconnect when the real answer is
	// that the file changed underneath them.
	dir := t.TempDir()
	t.Setenv("CONTRO1_PLATFORMS_DIR", dir)
	writeMapping(t, dir, "openclaw", []runtimeproto.MappingEntry{entry("main", "agt_x", "unix:///run/contro1/ep/x.sock")})
	path := filepath.Join(dir, "openclaw.json")
	raw, _ := os.ReadFile(path)
	_ = os.WriteFile(path, []byte(strings.Replace(string(raw), "agt_x", "agt_y", 1)), 0o644)

	_, err := SelectLocalConnection("")
	if err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("a tampered mapping file must be reported as such: %v", err)
	}
}

// One damaged file must not hide the connections that are fine.
func TestOneBadFileDoesNotHideTheGoodOnes(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CONTRO1_PLATFORMS_DIR", dir)
	writeMapping(t, dir, "claude-code", []runtimeproto.MappingEntry{entry("default", "agt_ok", "unix:///run/contro1/ep/ok.sock")})
	if err := os.WriteFile(filepath.Join(dir, "broken.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := SelectLocalConnection("")
	if err != nil || got.AgentID != "agt_ok" {
		t.Fatalf("the healthy connection should still be selectable: %+v %v", got, err)
	}
	connections, problems := LocalConnections()
	if len(connections) != 1 || len(problems) != 1 {
		t.Fatalf("the damaged file should be reported, not swallowed: %d connections, %d problems", len(connections), len(problems))
	}
}

// The live case that exposed this: two one to one conversations, NanoClaw's
// default sender_scope, and an agent only its owner can reach. Marking that a
// shared surface blocked a personal account for no reason.
func TestAnAgentInOnlyDirectMessagesIsSoleOperator(t *testing.T) {
	a, _ := New("nanoclaw", Options{Home: t.TempDir(), Runner: fakeRunner(map[string]string{
		"ncl wirings list --json": `{"ok":true,"data":[
			{"messaging_group_id":"mg-whatsapp","agent_group_id":"ag-nano","sender_scope":"all"},
			{"messaging_group_id":"mg-cli","agent_group_id":"ag-nano","sender_scope":"all"}
		]}`,
		"ncl messaging-groups get --id mg-whatsapp --json": `{"ok":true,"data":{"id":"mg-whatsapp","name":null,"is_group":0}}`,
		"ncl messaging-groups get --id mg-cli --json":      `{"ok":true,"data":{"id":"mg-cli","name":"Local CLI","is_group":0}}`,
	})})
	reach, err := a.Reach(context.Background(), "ag-nano")
	if err != nil {
		t.Fatalf("reach: %v", err)
	}
	if got := runtimeproto.PostureForReach(&reach); got != runtimeproto.PostureSoleOperator {
		t.Fatalf("posture = %q, want sole_operator: %+v", got, reach.Contexts)
	}

	// A group chat with the same default is still exposure, which is the whole
	// distinction: the room decides, not the flag.
	b, _ := New("nanoclaw", Options{Home: t.TempDir(), Runner: fakeRunner(map[string]string{
		"ncl wirings list --json":                      `{"ok":true,"data":[{"messaging_group_id":"mg-trip","agent_group_id":"ag-nano","sender_scope":"all"}]}`,
		"ncl messaging-groups get --id mg-trip --json": `{"ok":true,"data":{"id":"mg-trip","name":"Berlin trip","is_group":1}}`,
	})})
	groupReach, _ := b.Reach(context.Background(), "ag-nano")
	if got := runtimeproto.PostureForReach(&groupReach); got != runtimeproto.PostureSharedSurface {
		t.Fatalf("a group with sender_scope all is still shared: %q", got)
	}
}

/*
A remote MCP server takes a URL and never a credential.

Two wrong versions came before this one. The first mounted the agent's socket
into its container, which NanoClaw's mount rules make impossible. The second put
a bearer in the server's headers, which works and is worse: everything in a
group's config is readable by the agent in that group, so an agent several
people can instruct could be asked to read out the credential that is its own
identity.

So the test that matters is not that the URL is right. It is that nothing
resembling a credential is ever handed to the platform.
*/
func TestNanoClawApplicationsWritesAUrlAndNoCredential(t *testing.T) {
	conn := LocalConnection{
		Platform: "nanoclaw", PlatformSubject: "ag-sales", DisplayName: "Nano ariel",
		AgentID: "agt_sales", EnrollmentID: "enr_1", Endpoint: "unix:///run/contro1/ep/ep_sales.sock",
	}
	var ran [][]string
	a, _ := New("nanoclaw", Options{
		Home:   t.TempDir(),
		McpURL: "https://api.contro1.test/api/centcom/mcp",
		Runner: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			ran = append(ran, args)
			return []byte("{}"), nil
		},
	})

	for _, c := range a.ApplicationChanges(conn) {
		if c.Kind == "mount" || c.Kind == "credential" {
			t.Fatalf("neither a mount nor a credential belongs here: %+v", c)
		}
	}
	if err := a.ApplyApplications(context.Background(), conn, &Journal{}); err != nil {
		t.Fatalf("apply: %v", err)
	}

	joined := ""
	for _, args := range ran {
		joined += strings.Join(args, " ") + "|"
	}
	// Nothing that carries a secret, in any form.
	for _, forbidden := range []string{"--headers", "--env", "Authorization", "Bearer", "ccr_live_", "add-mount"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("%q must never reach the platform config: %s", forbidden, joined)
		}
	}
	if !strings.Contains(joined, "--url https://api.contro1.test/api/centcom/mcp") {
		t.Fatalf("the server is configured by URL: %s", joined)
	}
	// An older entry, including one that did carry a credential, must not
	// survive beside the new one.
	removeAt, addAt := strings.Index(joined, "remove-mcp-server"), strings.Index(joined, "add-mcp-server")
	if removeAt < 0 || addAt < 0 || removeAt > addAt {
		t.Fatalf("the old server must be removed before the new one is added: %s", joined)
	}
	if !strings.HasSuffix(joined, "groups restart --id ag-sales|") {
		t.Fatalf("the group must restart last: %s", joined)
	}
}

// Without an address there is nothing to configure, and configuring an entry
// that points nowhere would leave the agent reporting a server it cannot use.
func TestNanoClawApplicationsRefusesWithoutAnAddress(t *testing.T) {
	var ran int
	a, _ := New("nanoclaw", Options{Home: t.TempDir(), Runner: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		ran++
		return []byte("{}"), nil
	}})
	if err := a.ApplyApplications(context.Background(), LocalConnection{PlatformSubject: "ag-x"}, &Journal{}); err == nil {
		t.Fatal("a missing address must stop")
	}
	if ran != 0 {
		t.Fatalf("nothing may run before the address is known, ran %d", ran)
	}
}

// status.json is the broker's health copy, not a mapping. Reading it as one
// made every ambiguity message end with a digest failure that looked like
// tampering on a computer where nothing was wrong.
func TestStatusFileIsNotAMapping(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CONTRO1_PLATFORMS_DIR", dir)
	writeMapping(t, dir, "openclaw", []runtimeproto.MappingEntry{
		entry("main", "agt_main", "unix:///run/contro1/ep/main.sock"),
		entry("dash", "agt_dash", "unix:///run/contro1/ep/dash.sock"),
	})
	_ = os.WriteFile(filepath.Join(dir, "status.json"), []byte(`{"broker_version":"0.2.20","pid":42,"enrollments":[]}`), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "notes.json"), []byte(`{"anything":"else"}`), 0o644)

	connections, problems := LocalConnections()
	if len(connections) != 2 || len(problems) != 0 {
		t.Fatalf("only mapping files are read: %d connections, problems %v", len(connections), problems)
	}
	_, err := SelectLocalConnection("")
	if err == nil || strings.Contains(err.Error(), "could not be read") || strings.Contains(err.Error(), "digest") {
		t.Fatalf("ambiguity must not mention a damaged file: %v", err)
	}
}

// CLAUDECODE is inherited by everything a Claude Code session starts (Codex,
// an OpenClaw gateway). It may word a suggestion, never pick an identity.
func TestTheCallingPlatformNeverPicksAConnection(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CONTRO1_PLATFORMS_DIR", dir)
	t.Setenv("CLAUDECODE", "1")
	writeMapping(t, dir, "openclaw", []runtimeproto.MappingEntry{
		entry("main", "agt_main", "unix:///run/contro1/ep/main.sock"),
	})
	writeMapping(t, dir, "claude-code", []runtimeproto.MappingEntry{entry("claude-code@abc", "agt_cc", "unix:///run/contro1/ep/cc.sock")})

	if got := ClientPlatform(func(k string) string { return map[string]string{"CLAUDECODE": "1"}[k] }); got != "claude-code" {
		t.Fatalf("CLAUDECODE still names Claude Code for messages: %q", got)
	}
	var ambiguous *AmbiguousConnectionError
	if _, err := SelectLocalConnection(""); !errors.As(err, &ambiguous) {
		t.Fatalf("two connections and none named stay ambiguous, whoever started us: %v", err)
	}
	if got, err := SelectLocalConnection("main"); err != nil || got.AgentID != "agt_main" {
		t.Fatalf("a named agent always wins: %+v %v", got, err)
	}
}

func writeClaudeMapping(t *testing.T, path, instanceDigest string, subjects ...string) {
	t.Helper()
	var entries []runtimeproto.MappingEntry
	for i, s := range subjects {
		entries = append(entries, entry(s, "agt_"+string(rune('a'+i)), "unix:///run/contro1/ep/cc.sock"))
	}
	raw, _ := json.Marshal(runtimeproto.MappingFile{
		SchemaVersion: runtimeproto.SchemaVersion, Platform: "claude-code", PlatformInstanceDigest: instanceDigest,
		Digest: runtimeproto.MappingDigest(entries), Entries: entries,
	})
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

// The same Mac on two networks is one Claude Code. The hostname is what the
// network calls it ("mbp.local", then "mbp.lan"), so it names the agent for a
// person and never identifies it.
func TestClaudeCodeIdentityIsTheMachineNotTheNetwork(t *testing.T) {
	mac := machineReaders{goos: "darwin", runner: fakeRunner(map[string]string{
		"ioreg -rd1 -c IOPlatformExpertDevice": `+-o J314sAP  <class IOPlatformExpertDevice>
    {
      "IOPlatformSerialNumber" = "C02XXXXXX"
      "IOPlatformUUID" = "4C4C4544-0042-3510-8051-B4C04F4D4E32"
    }`,
	})}
	discover := func(host string) Subject {
		t.Helper()
		c := &claudeCode{machine: &mac, hostname: func() (string, error) { return host, nil }, mappingPath: filepath.Join(t.TempDir(), "none.json")}
		_, subjects, err := c.Discover(context.Background())
		if err != nil || len(subjects) != 1 {
			t.Fatalf("discover: %+v %v", subjects, err)
		}
		return subjects[0]
	}
	home, office := discover("MBP.local"), discover("mbp.lan")
	if home.ID != office.ID {
		t.Fatalf("a network change must not change the agent: %q vs %q", home.ID, office.ID)
	}
	if strings.Contains(home.ID, "4c4c4544") || strings.Contains(strings.ToLower(home.ID), "mbp") {
		t.Fatalf("the subject carries a hash of the machine id, not the id or the hostname: %q", home.ID)
	}
	if home.Display != "Claude Code on MBP.local" {
		t.Fatalf("the display name still names the computer: %q", home.Display)
	}

	linux := machineReaders{goos: "linux", readFile: func(p string) ([]byte, error) {
		if p == "/etc/machine-id" {
			return []byte("b08dfa6083e7567a1921a715000001fb\n"), nil
		}
		return nil, os.ErrNotExist
	}}
	windows := machineReaders{goos: "windows", runner: fakeRunner(map[string]string{
		`reg query HKLM\SOFTWARE\Microsoft\Cryptography /v MachineGuid`: "\r\n" + `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography` + "\r\n    MachineGuid    REG_SZ    8f2c1d4e-1111-2222-3333-444455556666\r\n",
	})}
	for name, r := range map[string]machineReaders{"linux": linux, "windows": windows} {
		id, err := r.read(context.Background())
		if err != nil || id == "" {
			t.Fatalf("%s machine id: %q %v", name, id, err)
		}
	}
	if id, _ := windows.read(context.Background()); id != "8f2c1d4e-1111-2222-3333-444455556666" {
		t.Fatalf("windows MachineGuid parsed: %q", id)
	}

	// No machine id: the old hostname subject, so connecting still works.
	none := machineReaders{goos: "linux", readFile: func(string) ([]byte, error) { return nil, os.ErrNotExist }}
	c := &claudeCode{machine: &none, hostname: func() (string, error) { return "Box", nil }, mappingPath: filepath.Join(t.TempDir(), "none.json")}
	if _, subjects, _ := c.Discover(context.Background()); subjects[0].ID != "claude-code@box" {
		t.Fatalf("fallback is the hostname subject: %+v", subjects)
	}
}

// Somebody connected before the machine id existed keeps their agent. Moving
// them to a new subject would create the duplicate this change is for.
func TestClaudeCodeKeepsAnExistingHostnameConnection(t *testing.T) {
	mac := machineReaders{goos: "darwin", runner: fakeRunner(map[string]string{
		"ioreg -rd1 -c IOPlatformExpertDevice": `"IOPlatformUUID" = "4C4C4544-0042-3510-8051-B4C04F4D4E32"`,
	})}
	path := filepath.Join(t.TempDir(), "claude-code.json")
	writeClaudeMapping(t, path, "sha256:olddigest", "claude-code@mbp.local")
	discover := func(host string) (Instance, Subject) {
		t.Helper()
		c := &claudeCode{machine: &mac, hostname: func() (string, error) { return host, nil }, mappingPath: path}
		instance, subjects, err := c.Discover(context.Background())
		if err != nil || len(subjects) != 1 {
			t.Fatalf("discover: %+v %v", subjects, err)
		}
		return instance, subjects[0]
	}

	instance, same := discover("mbp.local")
	if same.ID != "claude-code@mbp.local" || instance.Digest != "sha256:olddigest" {
		t.Fatalf("the existing subject and instance are reused: %+v %+v", same, instance)
	}
	// The hostname changed since; the one existing connection is still this Mac.
	instance, moved := discover("mbp.lan")
	if moved.ID != "claude-code@mbp.local" || instance.Digest != "sha256:olddigest" {
		t.Fatalf("a renamed Mac keeps its connection: %+v %+v", moved, instance)
	}

	// Already connected with the machine id: that one, whatever else is there.
	stable := "claude-code@" + machineKey("4c4c4544-0042-3510-8051-b4c04f4d4e32")
	writeClaudeMapping(t, path, "sha256:new", "claude-code@mbp.local", stable)
	if _, got := discover("mbp.lan"); got.ID != stable {
		t.Fatalf("the machine-id subject wins when it exists: %q", got.ID)
	}
	// Two old duplicates and neither matching: nothing to tell them apart, so
	// the machine id.
	writeClaudeMapping(t, path, "sha256:dup", "claude-code@mbp.local", "claude-code@mbp.lan")
	if _, got := discover("mbp-2.home"); got.ID != stable {
		t.Fatalf("ambiguous old entries fall to the machine id: %q", got.ID)
	}
}
