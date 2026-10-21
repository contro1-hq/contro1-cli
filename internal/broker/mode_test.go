package broker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/contro1-hq/contro1-cli/internal/brokerstore"
	"github.com/contro1-hq/contro1-cli/internal/keystore"
	"github.com/contro1-hq/contro1-cli/internal/runtimeproto"
)

// The mapping file follows the server's mode in both directions, so `contro1
// doctor` stops reporting "Approvals only" after the owner allowed
// applications, and a narrowed connection stops claiming applications.
func TestLocalModeFollowsTheServerBothWays(t *testing.T) {
	dir := t.TempDir()
	platformsDir := filepath.Join(dir, "platforms")
	b, err := New(Config{StateDir: dir, APIURL: "https://contro1.test", Version: "test", Foreground: true, PlatformsDir: platformsDir,
		Keys: &keystore.FileStore{Dir: dir + "/keys", Development: true}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.store.Close() })
	if b.provider.ModeObserved == nil {
		t.Fatal("the token provider must report modes to the broker")
	}
	_, err = b.store.UpdateState(func(st *brokerstore.State) error {
		st.Enrollments = []brokerstore.Enrollment{{LocalID: "loc_1", EnrollmentID: "enr_1", AgentID: "agt_main", Platform: "openclaw",
			PlatformSubject: "main", State: "active", EndpointMode: runtimeproto.ModeApprovalsOnly, Endpoint: `npipe:////./pipe/contro1-ep-loc_1`}}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	mappingMode := func() string {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(platformsDir, "openclaw.json"))
		if err != nil {
			return ""
		}
		switch {
		case strings.Contains(string(raw), `"endpoint_mode": "`+runtimeproto.ModeApplications+`"`):
			return runtimeproto.ModeApplications
		case strings.Contains(string(raw), `"endpoint_mode": "`+runtimeproto.ModeApprovalsOnly+`"`):
			return runtimeproto.ModeApprovalsOnly
		}
		return "?"
	}

	b.setLocalMode("loc_1", runtimeproto.ModeApplications)
	if got := mappingMode(); got != runtimeproto.ModeApplications {
		t.Fatalf("widened: mapping says %q", got)
	}
	b.setLocalMode("loc_1", runtimeproto.ModeApprovalsOnly)
	if got := mappingMode(); got != runtimeproto.ModeApprovalsOnly {
		t.Fatalf("narrowed: mapping says %q", got)
	}
	b.setLocalMode("loc_1", "not-a-mode")
	if got := mappingMode(); got != runtimeproto.ModeApprovalsOnly {
		t.Fatalf("an unknown mode changes nothing: %q", got)
	}
}
