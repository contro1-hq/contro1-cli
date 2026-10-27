package privateconnector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestProviderPinsMethodPathInputAndCredential(t *testing.T) {
	calls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "GET" || r.URL.EscapedPath() != "/api/machines/A%20B" || r.URL.Query().Get("withStock") != "true" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.String())
		}
		if r.Header.Get("KEY") != "local-secret" {
			t.Error("local credential was not applied")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":[1]}`))
	}))
	defer srv.Close()
	provider, err := NewProvider(ProviderConfig{
		BaseURL:    srv.URL + "/api/",
		Auth:       ProviderAuth{Mode: "header_key", HeaderName: "KEY", Secret: "local-secret"},
		Operations: []ProviderOperation{{Digest: testDigest, Method: "GET", Path: "/machines/{code}", QueryFields: []string{"withStock"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	provider.client = srv.Client() // test server certificate is locally trusted
	status, result, err := provider.Execute(context.Background(), testDigest, map[string]any{"code": "A B", "withStock": true})
	if err != nil || status != 200 || !json.Valid(result) {
		t.Fatalf("status=%d result=%s error=%v", status, result, err)
	}
	for _, input := range []map[string]any{
		{"code": "../../admin"},
		{"code": "A", "url": "https://evil.example"},
	} {
		if _, _, err := provider.Execute(context.Background(), testDigest, input); err == nil {
			t.Error("unsafe input accepted")
		}
	}
	if _, _, err := provider.Execute(context.Background(), "sha256:"+strings.Repeat("b", 64), nil); err == nil {
		t.Error("unknown operation accepted")
	}
	if calls != 1 {
		t.Fatalf("wanted one provider call, got %d", calls)
	}
}

func TestProviderRequiresPinnedAndEncryptedCredentialDestination(t *testing.T) {
	op := []ProviderOperation{{Digest: testDigest, Method: "GET", Path: "/machines"}}
	for _, cfg := range []ProviderConfig{
		{BaseURL: "http://192.168.1.162:3001/api/", Operations: op, Auth: ProviderAuth{Mode: "none"}},
		{BaseURL: "http://127.0.0.1:3001/api/", Operations: op, Auth: ProviderAuth{Mode: "header_key", HeaderName: "KEY", Secret: "s"}},
		{BaseURL: "https://intranet.example/api/", Operations: op, Auth: ProviderAuth{Mode: "none"}},
		{BaseURL: "https://user:pass@intranet.example/api/", PinnedIP: "192.168.1.162", Operations: op, Auth: ProviderAuth{Mode: "none"}},
		{BaseURL: "https://192.168.1.162/api/", Operations: []ProviderOperation{{Digest: testDigest, Method: "GET", Path: "//evil.example"}}, Auth: ProviderAuth{Mode: "none"}},
	} {
		if _, err := NewProvider(cfg); err == nil {
			t.Errorf("unsafe provider config accepted: %s", cfg.BaseURL)
		}
	}
}

func TestProviderRefusesRedirectAndBoundsResult(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/redirect" {
			w.Header().Set("Location", "http://127.0.0.1:9/private")
			w.WriteHeader(302)
			return
		}
		_, _ = w.Write([]byte(`"` + strings.Repeat("x", maxProviderResult) + `"`))
	}))
	defer srv.Close()
	provider, err := NewProvider(ProviderConfig{
		BaseURL: srv.URL + "/api/", Auth: ProviderAuth{Mode: "none"},
		Operations: []ProviderOperation{
			{Digest: testDigest, Method: "GET", Path: "/redirect"},
			{Digest: "sha256:" + strings.Repeat("b", 64), Method: "GET", Path: "/large"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if status, _, err := provider.Execute(context.Background(), testDigest, nil); status != 302 || err == nil {
		t.Fatal("redirect was followed")
	}
	if _, _, err := provider.Execute(context.Background(), "sha256:"+strings.Repeat("b", 64), nil); err == nil {
		t.Fatal("oversize result accepted")
	}
}
