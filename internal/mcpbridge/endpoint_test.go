package mcpbridge

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServeViaEndpointAddsNoCredential(t *testing.T) {
	var sawAuth []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = append(sawAuth, r.Header.Get("Authorization"))
		if r.URL.Path != "/mcp" {
			t.Errorf("path %s", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "notifications/initialized") {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		if strings.Contains(string(body), "tools/call") {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"ok":false,"error":{"message":"This agent's connection cannot use that part of Contro1."}}`))
			return
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer srv.Close()
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}` + "\n" + `{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" + `{"jsonrpc":"2.0","id":2,"method":"tools/call"}` + "\n")
	var out bytes.Buffer
	if err := ServeViaEndpoint(srv.Client(), srv.URL, in, &out); err != nil {
		t.Fatal(err)
	}
	for _, a := range sawAuth {
		if a != "" {
			t.Fatal("the stdio shim never sends a credential")
		}
	}
	text := out.String()
	if !strings.Contains(text, `"result":{}`) || !strings.Contains(text, "cannot use that part") || strings.Count(text, "\n") != 2 {
		t.Fatalf("output: %s", text)
	}
}

// Every request is answered. An empty or 202 reply to a request with an id was
// passed on as nothing, and the client waited for that id forever. A
// notification, which has no id, still gets nothing.
func TestEveryRequestGetsAnAnswer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	in := strings.NewReader(`{"jsonrpc":"2.0","id":7,"method":"tools/call"}` + "\n" + `{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n")
	var out bytes.Buffer
	if err := ServeViaEndpoint(srv.Client(), srv.URL, in, &out); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	if !strings.Contains(text, `"id":7`) || !strings.Contains(text, `"error"`) {
		t.Fatalf("the request with id 7 must be answered: %q", text)
	}
	if strings.Count(text, "\n") != 1 {
		t.Fatalf("the notification must not be answered: %q", text)
	}
}
