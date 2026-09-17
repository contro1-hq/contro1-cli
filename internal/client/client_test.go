package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/contro1-hq/contro1-cli/internal/output"
)

func TestHttpExitCodeContract(t *testing.T) {
	cases := []struct {
		name   string
		status int
		code   string
		want   int
	}{
		{"auth", 401, "", output.CodeAuth},
		{"insufficient scope", 403, "INSUFFICIENT_SCOPE", output.CodeInsufficient},
		{"other forbidden", 403, "", output.CodeGeneral},
		{"not found", 404, "", output.CodeNotFound},
		{"conflict", 409, "", output.CodeConflict},
		{"precondition", 412, "", output.CodeConflict},
		{"server", 500, "", output.CodeGeneral},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := httpExitCode(c.status, c.code); got != c.want {
				t.Fatalf("httpExitCode(%d, %q) = %d, want %d", c.status, c.code, got, c.want)
			}
		})
	}
}

func TestDoWithHeadersSendsIdempotencyKey(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Idempotency-Key")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "cc_test_x", "test")
	if _, err := c.DoWithHeaders("POST", "/x", map[string]any{}, map[string]string{"Idempotency-Key": "k1"}); err != nil {
		t.Fatal(err)
	}
	if got != "k1" {
		t.Fatalf("Idempotency-Key = %q", got)
	}
}

func TestValidationDetailsAreShown(t *testing.T) {
	var parsed map[string]any
	_ = json.Unmarshal([]byte(`{"error":"validation_error","message":"Invalid request body","details":[{"field":"tool_calls.0","message":"Unrecognized key: \"arguments\""}]}`), &parsed)
	_, msg := extractError(parsed, nil)
	if msg != `Invalid request body (tool_calls.0: Unrecognized key: "arguments")` {
		t.Fatalf("details must name the field: %q", msg)
	}
}
