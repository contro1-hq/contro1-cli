package cmd

import (
	"context"
	"testing"

	"github.com/contro1-hq/contro1-cli/internal/brokerpaths"
	"github.com/contro1-hq/contro1-cli/internal/brokerstore"
	"github.com/contro1-hq/contro1-cli/internal/config"
	"github.com/contro1-hq/contro1-cli/internal/installer"
)

/*
The NanoClaw host upgrade, from this side: an old service that is not
answering, whose state has connections and an empty api_url, and whose unit
passes --api-url. `broker install` and the update step keep that address
instead of writing a unit without one.
*/
func TestInstallKeepsTheAddressOfAnOldService(t *testing.T) {
	layout := brokerpaths.Development()
	layout.StateDir = t.TempDir()
	layout.ControlEndpoint = "unix:///nonexistent/contro1-test-control.sock"
	if err := brokerstore.OpenReadOnly(layout.StateDir).SaveState(&brokerstore.State{
		Enrollments: []brokerstore.Enrollment{{LocalID: "loc_1", State: "active"}},
	}); err != nil {
		t.Fatal(err)
	}
	oldUnit := installer.Plan("linux", installer.Options{SourceBinary: "/tmp/contro1", APIURL: "https://api.example.test"}).Files[0].Content
	old := installedServiceDefinition
	t.Cleanup(func() { installedServiceDefinition = old })
	installedServiceDefinition = func() string { return oldUnit }

	sources := installedAPIURLSources(context.Background(), layout)
	if got := installer.ServiceAPIURL("", sources...); got != "https://api.example.test" {
		t.Fatalf("broker install without --api-url must keep the unit's address, got %q", got)
	}
	// The update step passes the caller's address last: the service's own wins.
	withCaller := append(installedAPIURLSources(context.Background(), layout), func() string { return "https://other.test" })
	if got := installer.ServiceAPIURL("", withCaller...); got != "https://api.example.test" {
		t.Fatalf("the update keeps the service's address, got %q", got)
	}
	// What the state recorded is read before the definition.
	if err := brokerstore.OpenReadOnly(layout.StateDir).SaveState(&brokerstore.State{APIURL: "https://state.test"}); err != nil {
		t.Fatal(err)
	}
	if got := installer.ServiceAPIURL("", installedAPIURLSources(context.Background(), layout)...); got != "https://state.test" {
		t.Fatalf("state first, got %q", got)
	}
}

/*
The repair command printed when a renewal meets an old service keeps the
service's address, and with none it is the Contro1 service. Never this CLI's
profile: one pointed at a local development server would have moved a
production service there.
*/
func TestRepairCommandKeepsTheServiceAddressOrContro1(t *testing.T) {
	flagAPIURL = "http://localhost:8080" // as if this CLI talked to a local server
	t.Cleanup(func() { flagAPIURL = "" })
	layout := brokerpaths.Development()
	layout.StateDir = t.TempDir()
	layout.ControlEndpoint = "unix:///nonexistent/contro1-test-control.sock"
	oldUnit := installer.Plan("linux", installer.Options{SourceBinary: "/tmp/contro1", APIURL: "https://api.example.test"}).Files[0].Content
	old := installedServiceDefinition
	t.Cleanup(func() { installedServiceDefinition = old })
	installedServiceDefinition = func() string { return oldUnit }

	if got := serviceRepairAPIURLFrom(context.Background(), layout); got != "https://api.example.test" {
		t.Fatalf("the service's own address is kept, got %q", got)
	}
	installedServiceDefinition = func() string { return "" }
	if got := serviceRepairAPIURLFrom(context.Background(), layout); got != config.DefaultAPIURL {
		t.Fatalf("with no service address it is the Contro1 service, never the profile, got %q", got)
	}
}
