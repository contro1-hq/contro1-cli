package privateconnector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testSetup() SetupInput {
	return SetupInput{ServiceConfig: ServiceConfig{
		APIURL: "https://contro1.example", InstallationID: "pci_" + strings.Repeat("a", 32),
	}, EnrollmentCode: strings.Repeat("B", 43)}
}

func TestDecodeSetupIgnoresLeadingBOM(t *testing.T) {
	raw, _ := json.Marshal(testSetup())
	got, err := DecodeSetup(strings.NewReader("\xef\xbb\xbf" + string(raw)))
	if err != nil || got.InstallationID != testSetup().InstallationID {
		t.Fatalf("setup piped by Windows PowerShell 5.1: %+v, %v", got, err)
	}
}

func TestDecodeSetupAndProvisionSeparateSecrets(t *testing.T) {
	input := testSetup()
	raw, _ := json.Marshal(input)
	got, err := DecodeSetup(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	if err := Provision(state, got); err != nil {
		t.Fatal(err)
	}
	config, err := os.ReadFile(filepath.Join(state, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(config), got.EnrollmentCode) || strings.Contains(string(config), "provider_secret") {
		t.Fatal("registration or provider secret leaked into durable config")
	}
	stored, err := ReadConfig(state)
	if err != nil || stored.InstallationID != input.InstallationID {
		t.Fatalf("config: %+v, %v", stored, err)
	}
	code, err := os.ReadFile(filepath.Join(state, "enrollment-code"))
	if err != nil || string(code) != got.EnrollmentCode {
		t.Fatal("one-use code missing")
	}
	if err := os.Remove(filepath.Join(state, "enrollment-code")); err != nil {
		t.Fatal(err)
	}
	upgrade := got
	upgrade.EnrollmentCode = ""
	if err := Provision(state, upgrade); err != nil {
		t.Fatalf("same-installation upgrade: %v", err)
	}
	upgrade.InstallationID = "pci_" + strings.Repeat("b", 32)
	upgrade.EnrollmentCode = strings.Repeat("C", 43)
	if err := Provision(state, upgrade); err == nil {
		t.Fatal("installation identity unexpectedly changed")
	}
}

func TestSetupRejectsUnsafeEndpointAndUnpinnedProbe(t *testing.T) {
	input := testSetup()
	input.Provider = &LocalProviderConfig{BaseURL: "http://192.168.1.162:3001/api/", AuthMode: "none"}
	if input.Validate() == nil {
		t.Fatal("LAN HTTP should be rejected")
	}
	input.Provider.BaseURL = "https://192.168.1.162:3001/api/"
	input.Provider.Probe = &ProbeConfig{OperationDigest: "sha256:" + strings.Repeat("a", 64), ResultField: "result", Expected: "ok"}
	if input.Validate() == nil {
		t.Fatal("unmapped probe should be rejected")
	}
	input.Provider = nil
	input.APIURL = "http://contro1.example"
	if input.Validate() == nil {
		t.Fatal("cloud HTTP should be rejected")
	}
}

func TestProviderProbeRequiresExpectedResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":"ok"}`))
	}))
	defer server.Close()
	digest := "sha256:" + strings.Repeat("a", 64)
	cfg := &LocalProviderConfig{BaseURL: server.URL + "/", AuthMode: "none",
		Operations: []ProviderOperation{{Digest: digest, Method: "GET", Path: "/check"}},
		Probe:      &ProbeConfig{OperationDigest: digest, ResultField: "result", Expected: "ok"}}
	provider, err := localProvider(cfg, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if got := probeProvider(context.Background(), provider, cfg); got != "reachable" {
		t.Fatalf("got %s", got)
	}
	cfg.Probe.Expected = "another-value"
	if got := probeProvider(context.Background(), provider, cfg); got != "unreachable" {
		t.Fatalf("got %s", got)
	}
}

func TestProviderSecretRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provider-secret")
	if err := WriteSecret(path, "test-only-credential"); err != nil {
		t.Fatal(err)
	}
	got, err := ReadSecret(path)
	if err != nil || got != "test-only-credential" {
		t.Fatalf("credential roundtrip failed: %v", err)
	}
}

func TestServiceAcceptsSeveralIndependentInstallations(t *testing.T) {
	root := t.TempDir()
	first := testSetup()
	second := testSetup()
	second.InstallationID = "pci_" + strings.Repeat("c", 32)
	for _, input := range []SetupInput{first, second} {
		if err := CheckCapacity(root, input.InstallationID); err != nil {
			t.Fatal(err)
		}
		if err := Provision(InstallationDir(root, input.InstallationID), input); err != nil {
			t.Fatal(err)
		}
		stored, err := ReadConfig(InstallationDir(root, input.InstallationID))
		if err != nil || stored.InstallationID != input.InstallationID {
			t.Fatalf("installation isolation: %v", err)
		}
	}
}

func TestReachWithoutProbeTellsAnsweringFromRefused(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("checking reachability sent a request to the application")
	}))
	digest := "sha256:" + strings.Repeat("b", 64)
	cfg := &LocalProviderConfig{BaseURL: server.URL + "/", AuthMode: "none",
		Operations: []ProviderOperation{{Digest: digest, Method: "GET", Path: "/check"}}}
	provider, err := localProvider(cfg, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if status, detail, check := probeProviderDetail(context.Background(), provider, cfg); status != "reachable" || detail != "" || check != "address" {
		t.Fatalf("an answering application was reported %s/%s/%s", status, detail, check)
	}
	server.Close()
	if status, detail, check := probeProviderDetail(context.Background(), provider, cfg); status != "unreachable" || detail != "refused" || check != "address" {
		t.Fatalf("a stopped application was reported %s/%s/%s", status, detail, check)
	}
}

func TestConnectorNameIsCleaned(t *testing.T) {
	t.Setenv("CONTRO1_CONNECTOR_NAME", "SRV FACTORY/01 <b>")
	if got := connectorName(); got != "SRVFACTORY01b" {
		t.Fatalf("got %q", got)
	}
}
