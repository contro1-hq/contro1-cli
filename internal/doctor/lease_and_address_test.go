package doctor

import (
	"strings"
	"testing"
	"time"

	"github.com/contro1-hq/contro1-cli/internal/brokerstore"
	"github.com/contro1-hq/contro1-cli/internal/runtimeproto"
)

func TestLeaseExpiryCheck(t *testing.T) {
	now := time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name    string
		expires time.Time
		status  string
		next    string
	}{
		{"valid", now.Add(20 * 24 * time.Hour), runtimeproto.CheckOK, ""},
		{"close", now.Add(3 * 24 * time.Hour), runtimeproto.CheckRepairable, "contro1 apps renew-nanoclaw --agent ag-1 --force"},
		{"expired", now.Add(-time.Hour), runtimeproto.CheckBlocked, "contro1 apps enable nanoclaw --agent ag-1"},
		{"unknown", time.Time{}, runtimeproto.CheckRepairable, "contro1 apps renew-nanoclaw --agent ag-1 --force"},
	}
	for _, c := range cases {
		got := LeaseExpiryCheck("nanoclaw", "ag-1", c.expires, now)
		if got.Status != c.status || got.NextCommand != c.next {
			t.Errorf("%s: status %s next %q (%s)", c.name, got.Status, got.NextCommand, got.Message)
		}
	}
}

func TestAPIURLCheck(t *testing.T) {
	empty, set := "", "https://api.contro1.com"
	if _, ok := APIURLCheck(&brokerstore.PublicStatus{}, 1, "linux"); ok {
		t.Fatal("a service too old to report its address is not a finding")
	}
	if _, ok := APIURLCheck(&brokerstore.PublicStatus{APIURL: &empty}, 0, "linux"); ok {
		t.Fatal("a service with no connections learns the address from the first")
	}
	c, ok := APIURLCheck(&brokerstore.PublicStatus{APIURL: &empty}, 1, "linux")
	if !ok || c.Status != runtimeproto.CheckBlocked || !strings.Contains(c.NextCommand, "sudo contro1 broker install --api-url https://") {
		t.Fatalf("%+v", c)
	}
	c, ok = APIURLCheck(&brokerstore.PublicStatus{APIURL: &set}, 1, "linux")
	if !ok || c.Status != runtimeproto.CheckOK {
		t.Fatalf("%+v", c)
	}
}
