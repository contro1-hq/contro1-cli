package installer

import (
	"strings"
	"testing"

	"github.com/contro1-hq/contro1-cli/internal/config"
)

func TestAPIURLFromDefinition(t *testing.T) {
	unit := Plan("linux", Options{SourceBinary: "/tmp/contro1", APIURL: "https://api.example.test"}).Files[0].Content
	plist := Plan("darwin", Options{SourceBinary: "/tmp/contro1", APIURL: "https://api.example.test"}).Files[0].Content
	cases := map[string]string{
		"systemd unit":   unit,
		"launchd plist":  plist,
		"windows":        `"C:\Program Files\Contro1\contro1.exe" broker serve --api-url https://api.example.test/`,
		"equals form":    "ExecStart=/usr/local/lib/contro1/contro1 broker serve --api-url=https://api.example.test",
		"without a flag": "ExecStart=/usr/local/lib/contro1/contro1 broker serve",
		"not a url":      "ExecStart=/x broker serve --api-url --foreground",
	}
	want := map[string]string{"without a flag": "", "not a url": ""}
	for name, text := range cases {
		expected, ok := want[name]
		if !ok {
			expected = "https://api.example.test"
		}
		if got := APIURLFromDefinition(text); got != expected {
			t.Errorf("%s: got %q, want %q", name, got, expected)
		}
	}
}

func TestServiceAPIURLOrder(t *testing.T) {
	src := func(v string) func() string { return func() string { return v } }
	if got := ServiceAPIURL("https://given.test/", src("https://state.test")); got != "https://given.test" {
		t.Fatalf("an address given on the command line wins, got %q", got)
	}
	if got := ServiceAPIURL("", src(""), src("not a url"), src("https://unit.test")); got != "https://unit.test" {
		t.Fatalf("the first usable recorded address is kept, got %q", got)
	}
	if got := ServiceAPIURL("", src(""), nil); got != config.DefaultAPIURL {
		t.Fatalf("nothing recorded means production, got %q", got)
	}
}

/*
The upgrade that broke a NanoClaw host: a v0.2.0 service ran with --api-url in
its unit and so never wrote the address to its state. `sudo contro1 broker
install` without the flag rewrote the unit with no address. Now the install
reads it back from the unit it is replacing.
*/
func TestUpgradeFromAnOldServiceKeepsTheAddress(t *testing.T) {
	oldUnit := Plan("linux", Options{SourceBinary: "/tmp/contro1", APIURL: "https://api.example.test"}).Files[0].Content
	emptyState := func() string { return "" }
	notRunning := func() string { return "" }
	apiURL := ServiceAPIURL("", notRunning, emptyState, func() string { return APIURLFromDefinition(oldUnit) })
	newUnit := Plan("linux", Options{SourceBinary: "/tmp/contro1", APIURL: apiURL}).Files[0].Content
	if !strings.Contains(newUnit, "broker serve --api-url https://api.example.test\n") {
		t.Fatalf("the new unit lost the address:\n%s", newUnit)
	}
}
