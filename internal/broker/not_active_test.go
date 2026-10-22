package broker

import (
	"errors"
	"strings"
	"testing"

	"github.com/contro1-hq/contro1-cli/internal/brokerstore"
)

func TestConnectionNotActiveSaysHowToComeBack(t *testing.T) {
	got := connectionNotActive(&brokerstore.Enrollment{Platform: "claude-code", State: "revoked"}, nil)
	if got.PublicMessage != "This connection was disconnected in Contro1." || got.NextStep != "To connect it again: contro1 connect claude-code" {
		t.Fatalf("revoked: %+v", got)
	}
	if got.Code != "CONNECTION_NOT_ACTIVE" || got.Retryable {
		t.Fatalf("code and retry must not change: %+v", got)
	}
	if got := connectionNotActive(nil, errors.New("gone")); !strings.Contains(got.NextStep, "contro1 status") {
		t.Fatalf("unknown connection keeps the general step: %+v", got)
	}
}
