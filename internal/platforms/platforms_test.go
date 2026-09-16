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
