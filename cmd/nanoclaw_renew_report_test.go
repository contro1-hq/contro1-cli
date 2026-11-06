package cmd

import (
	"strings"
	"testing"
)

// The local service answers in its own shape, with the reason under "error".
// It used to print as "HTTP 503" and nothing else.
func TestRenewRefusalNamesTheServiceReason(t *testing.T) {
	raw := []byte(`{"ok":false,"error":{"code":"RUNTIME_API_URL_MISSING","message":"The Contro1 service on this computer has no Contro1 address, so it cannot get a credential.","retryable":false,"remediation":{"code":"RUNTIME_API_URL_MISSING","next_step":"Run: sudo contro1 broker install --api-url https://api.contro1.com"}}}`)
	got := renewRefusal(503, raw, "ag-1").Error()
	for _, want := range []string{"HTTP 503 RUNTIME_API_URL_MISSING", "no Contro1 address", "broker install --api-url"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
}

func TestRenewRefusalFromTheServer(t *testing.T) {
	got := renewRefusal(409, []byte(`{"error":"lease_not_live","message":"This lease has expired."}`), "ag-1").Error()
	if !strings.Contains(got, "contro1 apps enable nanoclaw --agent ag-1") {
		t.Fatalf("an expired lease names the owner's command: %q", got)
	}
	got = renewRefusal(429, []byte(`{"error":"rate_limited","message":"Slow down."}`), "ag-1").Error()
	if !strings.Contains(got, "HTTP 429 rate_limited") || !strings.Contains(got, "Slow down.") {
		t.Fatalf("a plain server refusal keeps its code and message: %q", got)
	}
}

// A service from before the renew route refuses it as a method this agent may
// not call. That is an old service, not a refusal by Contro1.
func TestRenewRefusedByAnOldServiceSaysUpdate(t *testing.T) {
	old := serviceRepairAPIURL
	t.Cleanup(func() { serviceRepairAPIURL = old })
	serviceRepairAPIURL = func() string { return "https://api.example.test" }
	raw := []byte(`{"ok":false,"error":{"code":"ENDPOINT_METHOD_NOT_ALLOWED","message":"This agent's connection cannot use that part of Contro1."}}`)
	got := renewRefusal(403, raw, "ag-1").Error()
	if !strings.Contains(got, "older than this CLI") || !strings.Contains(got, "broker install --api-url https://api.example.test") {
		t.Fatalf("got %q", got)
	}
}

func TestRenewalLineIsLoggedAndUpgradedInPlace(t *testing.T) {
	line := renewCronLine("/usr/local/bin/contro1", "/home/n/.contro1/nanoclaw-renew.log")
	if strings.Contains(line, "/dev/null") || !strings.Contains(line, ">>/home/n/.contro1/nanoclaw-renew.log 2>&1") || !strings.HasSuffix(line, renewCronMarker) {
		t.Fatalf("line %q", line)
	}

	old := "0 1 * * * backup\n17 */6 * * * /usr/local/bin/contro1 apps renew-nanoclaw --quiet >/dev/null 2>&1 " + renewCronMarker + "\n5 5 * * * other\n"
	next, changed := withRenewalLine(old, line)
	if !changed || strings.Contains(next, "/dev/null") || strings.Count(next, renewCronMarker) != 1 {
		t.Fatalf("upgrade:\n%s", next)
	}
	if !strings.HasPrefix(next, "0 1 * * * backup\n") || !strings.HasSuffix(next, "5 5 * * * other\n") {
		t.Fatalf("other entries must stay where they are:\n%s", next)
	}
	if again, changed := withRenewalLine(next, line); changed || again != next {
		t.Fatal("a current line is left alone")
	}
	if added, changed := withRenewalLine("", line); !changed || added != line+"\n" {
		t.Fatalf("empty crontab: %q", added)
	}
}
