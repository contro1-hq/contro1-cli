package broker

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/contro1-hq/contro1-cli/internal/brokerstore"
	"github.com/contro1-hq/contro1-cli/internal/keystore"
	"github.com/contro1-hq/contro1-cli/internal/runtimeproto"
	"github.com/contro1-hq/contro1-cli/internal/tokenprovider"
)

func newTestBroker(t *testing.T, dir, apiURL string, logf func(string, ...any)) *Broker {
	t.Helper()
	b, err := New(Config{StateDir: dir, APIURL: apiURL, Version: "test", Foreground: true, PlatformsDir: filepath.Join(dir, "platforms"),
		Keys: &keystore.FileStore{Dir: dir + "/keys", Development: true}, Logf: logf})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func stateAPIURL(t *testing.T, dir string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		return ""
	}
	var st brokerstore.State
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	return st.APIURL
}

// A service started with --api-url records it, so a later start whose
// definition lost the flag still knows where Contro1 is. Before, the address
// was recorded only by the first connection made while the service had none.
func TestTheStartAddressIsRecorded(t *testing.T) {
	dir := t.TempDir()
	b := newTestBroker(t, dir, "https://api.contro1.test/", nil)
	b.store.Close()
	if got := stateAPIURL(t, dir); got != "https://api.contro1.test" {
		t.Fatalf("state api_url = %q", got)
	}

	// The next start has no flag, as after an install that dropped it.
	b = newTestBroker(t, dir, "", nil)
	defer b.store.Close()
	if b.cfg.APIURL != "https://api.contro1.test" || b.provider.APIURL != "https://api.contro1.test" {
		t.Fatalf("a start without the flag must use the recorded address, got %q", b.cfg.APIURL)
	}
}

// An old service never wrote the address: state has connections and an empty
// api_url. The next start with the flag fills it in.
func TestAnOldStateGetsTheAddressFromTheFlag(t *testing.T) {
	dir := t.TempDir()
	old := brokerstore.OpenReadOnly(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := old.SaveState(&brokerstore.State{Enrollments: []brokerstore.Enrollment{{LocalID: "loc_1", State: "active"}}}); err != nil {
		t.Fatal(err)
	}
	b := newTestBroker(t, dir, "https://api.contro1.test", nil)
	b.store.Close()
	if got := stateAPIURL(t, dir); got != "https://api.contro1.test" {
		t.Fatalf("state api_url = %q", got)
	}
}

// A service with connections and no address says so in its log, with the
// command that fixes it, instead of failing every request without a reason.
func TestNoAddressWithConnectionsIsLogged(t *testing.T) {
	dir := t.TempDir()
	if err := brokerstore.OpenReadOnly(dir).SaveState(&brokerstore.State{Enrollments: []brokerstore.Enrollment{{LocalID: "loc_1", State: "active"}}}); err != nil {
		t.Fatal(err)
	}
	var lines []string
	b := newTestBroker(t, dir, "", func(f string, a ...any) { lines = append(lines, fmt.Sprintf(f, a...)) })
	defer b.store.Close()
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "no Contro1 address") || !strings.Contains(joined, "--api-url") {
		t.Fatalf("log must name the missing address and the fix, got:\n%s", joined)
	}
}

// The refusal names the missing address and the command, not "could not get
// a credential", and no refresh is recorded as interrupted.
func TestNoAddressIsAClearRefusal(t *testing.T) {
	dir := t.TempDir()
	b := newTestBroker(t, dir, "", nil)
	defer b.store.Close()
	if _, err := b.store.UpdateState(func(st *brokerstore.State) error {
		st.Enrollments = []brokerstore.Enrollment{{LocalID: "loc_1", State: "active", KeyRef: "k"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_ = b.store.SaveSecrets("loc_1", brokerstore.Secrets{RefreshToken: "ccrt_x"})

	_, err := b.provider.AccessToken(t.Context(), "loc_1", runtimeproto.ResourceAPI)
	if !errors.Is(err, tokenprovider.ErrNoAPIURL) {
		t.Fatalf("want ErrNoAPIURL, got %v", err)
	}
	if j, _ := b.store.ReadJournal("loc_1"); j != nil {
		t.Fatal("no refresh started, so none may be recorded as interrupted")
	}

	rec := httptest.NewRecorder()
	b.writeTokenError(rec, err)
	var body struct {
		Error       string                    `json:"error"`
		Remediation *runtimeproto.Remediation `json:"remediation"`
	}
	raw := rec.Body.String()
	_ = json.Unmarshal([]byte(raw), &body)
	if rec.Code != 503 || !strings.Contains(raw, MissingAPIURLCode) || !strings.Contains(raw, "--api-url") {
		t.Fatalf("status %d body %s", rec.Code, raw)
	}
}
