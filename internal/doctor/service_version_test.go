package doctor

import (
	"context"
	"strings"
	"testing"

	"github.com/contro1-hq/contro1-cli/internal/installer"
	"github.com/contro1-hq/contro1-cli/internal/runtimeproto"
)

type versionedEnv struct {
	*fakeEnv
	comparison installer.ServiceComparison
}

func (v versionedEnv) ServiceVersion() (installer.ServiceComparison, string) {
	return v.comparison, "contro1 broker install"
}

func TestServiceVersionMatchesTheCLI(t *testing.T) {
	env := versionedEnv{fakeEnv: healthy(), comparison: installer.CompareService("0.2.30", "0.2.30", nil)}
	r := Run(context.Background(), env, "nanoclaw")
	c := find(r, "service_version")
	if c.Status != runtimeproto.CheckOK || c.Label+": "+c.Message != "Contro1 service: version 0.2.30 (matches the CLI)." || r.State != "connected" {
		t.Fatalf("matching service: %+v", c)
	}
}

func TestOlderServiceNamesTheUpdateCommand(t *testing.T) {
	env := versionedEnv{fakeEnv: healthy(), comparison: installer.CompareService("0.2.28", "0.2.30", nil)}
	r := Run(context.Background(), env, "nanoclaw")
	c := find(r, "service_version")
	if c.Status != runtimeproto.CheckRepairable || c.NextCommand != "contro1 broker install" || !strings.Contains(c.Message, "version 0.2.28, older than this CLI (0.2.30)") {
		t.Fatalf("older service: %+v", c)
	}
}

func TestNewerServiceAsksForTheCLI(t *testing.T) {
	c := ServiceVersionCheck(installer.CompareService("0.3.0", "0.2.30", nil), "contro1 broker install")
	if c.NextCommand != "" || !strings.Contains(c.Message, "Update the CLI") {
		t.Fatalf("a newer service is never downgraded: %+v", c)
	}
}

func TestNoVersionCheckForADevelopmentService(t *testing.T) {
	env := versionedEnv{fakeEnv: healthy(), comparison: installer.CompareService("0.2.28", "0.2.30", nil)}
	env.development = true
	if c := find(Run(context.Background(), env, "nanoclaw"), "service_version"); c.ID != "" {
		t.Fatalf("development: %+v", c)
	}
}
