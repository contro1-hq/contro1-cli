package mcpbridge

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProbeAsksInitializeThenToolsList(t *testing.T) {
	var methods []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var req struct {
			ID     int    `json:"id"`
			Method string `json:"method"`
		}
		_ = json.Unmarshal(raw, &req)
		methods = append(methods, req.Method)
		switch req.Method {
		case "initialize":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}`))
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			if strings.Contains(string(raw), "page-2") {
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":3,"result":{"tools":[{"name":"c"}]}}`))
				return
			}
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"a"},{"name":"b"}],"nextCursor":"page-2"}}`))
		}
	}))
	defer srv.Close()
	n, err := Probe(context.Background(), srv.Client(), srv.URL)
	if err != nil || n != 3 {
		t.Fatalf("every page is counted: %d %v", n, err)
	}
	if strings.Join(methods, ",") != "initialize,notifications/initialized,tools/list,tools/list" {
		t.Fatalf("asked in the order a client asks: %v", methods)
	}
}

// The service's own words reach the person, not "Connection closed".
func TestProbeSaysWhyItFailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32002,"message":"This connection was revoked. Run contro1 connect openclaw."}}`))
	}))
	defer srv.Close()
	_, err := Probe(context.Background(), srv.Client(), srv.URL)
	if err == nil || !strings.Contains(err.Error(), "MCP initialize failed") || !strings.Contains(err.Error(), "was revoked") {
		t.Fatalf("%v", err)
	}
}
