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

// The container is where this silently fails: the MCP server runs inside it,
// and without the mounts it starts, finds nothing and answers 401 forever while
// the agent reports that it is connected.
func TestNanoClawApplicationsMountsOnlyThisAgentsSocket(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "ep_sales.sock")
	if err := os.WriteFile(socket, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	conn := LocalConnection{
		Platform: "nanoclaw", PlatformSubject: "ag-sales", DisplayName: "Nano ariel",
		AgentID: "agt_sales", Endpoint: "unix://" + socket,
	}

	var ran [][]string
	a, _ := New("nanoclaw", Options{Home: t.TempDir(), Runner: func(_ context.Context, _ string, args ...string) ([]byte, error) {
		ran = append(ran, args)
		return []byte("{}"), nil
	}})

	changes := a.ApplicationChanges(conn)
	if len(changes) != 4 {
		t.Fatalf("mounts, server and restart are all needed: %d changes", len(changes))
	}
	journal := &Journal{}
	if err := a.ApplyApplications(context.Background(), conn, journal); err != nil {
		t.Fatalf("apply: %v", err)
	}

	joined := ""
	for _, args := range ran {
		joined += strings.Join(args, " ") + "\n"
	}
	// `config` is a verb of the groups resource. `ncl config add-mount` exits 1
	// with nothing useful, which is exactly how this shipped once.
	for _, verb := range []string{"add-mount", "add-mcp-server", "remove-mcp-server"} {
		if !strings.Contains(joined, "groups config "+verb) {
			t.Fatalf("%s must be run as `ncl groups config %s`:\n%s", verb, verb, joined)
		}
	}
	// Only this agent's socket. A wider mount would let the group act as another.
	if !strings.Contains(joined, "groups config add-mount --id ag-sales --host "+socket) {
		t.Fatalf("the agent's own socket is not mounted:\n%s", joined)
	}
	if !strings.Contains(joined, "--container /usr/local/bin/contro1 --ro") {
		t.Fatalf("the binary is not mounted read only:\n%s", joined)
	}
	// An older entry, including one holding an API key, must not survive.
	removeAt, addAt := strings.Index(joined, "remove-mcp-server"), strings.Index(joined, "add-mcp-server")
	if removeAt < 0 || addAt < 0 || removeAt > addAt {
		t.Fatalf("the old server must be removed before the new one is added:\n%s", joined)
	}
	if !strings.Contains(joined, `["mcp","serve","--agent","ag-sales"]`) {
		t.Fatalf("the server must be pinned to this agent:\n%s", joined)
	}
	if !strings.HasSuffix(strings.TrimSpace(joined), "groups restart --id ag-sales") {
		t.Fatalf("the group must restart last:\n%s", joined)
	}
	if len(journal.RoleCommands) < 4 {
		t.Fatalf("every applied step is journalled: %v", journal.RoleCommands)
	}
}

// Mounting a path that is not there produces a container that starts and fails
// at the first call, which is the failure mode this command exists to remove.
func TestNanoClawApplicationsRefusesWhenTheEndpointIsMissing(t *testing.T) {
	conn := LocalConnection{Platform: "nanoclaw", PlatformSubject: "ag-x", Endpoint: "unix:///run/contro1/ep/not-there.sock"}
	var ran int
	a, _ := New("nanoclaw", Options{Home: t.TempDir(), Runner: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		ran++
		return nil, nil
	}})
	err := a.ApplyApplications(context.Background(), conn, &Journal{})
	if err == nil || !strings.Contains(err.Error(), "doctor") {
		t.Fatalf("a missing endpoint must stop and point somewhere useful: %v", err)
	}
	if ran != 0 {
		t.Fatalf("nothing may be changed before the endpoint is known to exist, ran %d", ran)
	}
}
