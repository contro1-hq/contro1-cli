package mcpbridge

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestResourceURLMatchesTheRemoteMCPAudience(t *testing.T) {
	if got := resourceURL("http://localhost:8080/"); got != "http://localhost:8080/api/centcom/mcp" {
		t.Fatalf("unexpected local MCP resource %q", got)
	}
}

func TestStdioRelayMatchesRemoteJSONRPC(t *testing.T) {
	want := `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/centcom/mcp" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer access-test" {
			t.Fatalf("unexpected authorization %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, want)
	}))
	defer server.Close()

	credentials := &Credentials{AccessToken: "access-test", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	var output bytes.Buffer
	err := serveWithCredentials(
		server.URL,
		"test",
		credentials,
		strings.NewReader("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n"),
		&output,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(output.String()); got != want {
		t.Fatalf("stdio response changed remote JSON-RPC:\nwant %s\n got %s", want, got)
	}
}

func TestStdioRelayReturnsRemoteErrorsWithoutEndingSession(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), `"id":7`) {
			http.Error(w, "refused", http.StatusForbidden)
			return
		}
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":8,"result":{"tools":[]}}`)
	}))
	defer server.Close()

	credentials := &Credentials{AccessToken: "access-test", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	var output bytes.Buffer
	err := serveWithCredentials(server.URL, "test", credentials, strings.NewReader(`{"jsonrpc":"2.0","id":7,"method":"tools/list"}`+"\n"+`{"jsonrpc":"2.0","id":8,"method":"tools/list"}`+"\n"), &output)
	if err != nil {
		t.Fatalf("a remote refusal must stay inside JSON-RPC, got %v", err)
	}
	if got := output.String(); !strings.Contains(got, `"id":7`) || !strings.Contains(got, `"code":-32002`) || !strings.Contains(got, `"id":8`) || !strings.Contains(got, `"result"`) {
		t.Fatalf("expected one JSON-RPC refusal and the next successful response, got %s", got)
	}
}

func TestRevokeReportsServerFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	err := revoke(server.URL, "refresh-token")
	if err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("expected named revocation failure, got %v", err)
	}
}
