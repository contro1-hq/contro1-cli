package mcpbridge

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// The login used to register a 127.0.0.1 redirect, which the server refuses,
// so `contro1 mcp login` could not connect anything. It now uses the device
// grant, registers no redirect at all, and waits through pending and slow_down.
func TestLoginUsesTheDeviceGrantAndNoRedirect(t *testing.T) {
	restoreInterval, restoreOpen := minPollInterval, openURL
	minPollInterval = 10 * time.Millisecond
	var opened string
	openURL = func(u string) error { opened = u; return nil }
	defer func() { minPollInterval, openURL = restoreInterval, restoreOpen }()

	var mu sync.Mutex
	polls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/centcom/mcp/oauth/register":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if _, present := body["redirect_uris"]; present {
				t.Errorf("a device-only registration must send no redirect_uris, got %v", body["redirect_uris"])
			}
			grants := fmt.Sprint(body["grant_types"])
			if !strings.Contains(grants, deviceCodeGrant) || strings.Contains(grants, "authorization_code") {
				t.Errorf("registration must declare only the device grant (and refresh), got %s", grants)
			}
			if !strings.Contains(fmt.Sprint(body["scope"]), ExecuteScope) {
				t.Errorf("--execute must ask for %s, got scope %v", ExecuteScope, body["scope"])
			}
			fmt.Fprint(w, `{"client_id":"mcp_test"}`)
		case "/api/centcom/mcp/oauth/device_authorization":
			_ = r.ParseForm()
			if r.PostForm.Get("client_id") != "mcp_test" {
				t.Errorf("device authorization must name the registered client")
			}
			fmt.Fprint(w, `{"device_code":"dev-1","user_code":"ABCD-EFGH","verification_uri":"https://contro1.com/connect-app","verification_uri_complete":"https://contro1.com/connect-app?code=ABCD-EFGH","expires_in":600,"interval":0}`)
		case "/api/centcom/mcp/oauth/token":
			_ = r.ParseForm()
			if r.PostForm.Get("grant_type") != deviceCodeGrant || r.PostForm.Get("device_code") != "dev-1" {
				t.Errorf("unexpected token request %v", r.PostForm)
			}
			mu.Lock()
			polls++
			n := polls
			mu.Unlock()
			switch n {
			case 1:
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, `{"error":"authorization_pending"}`)
			case 2:
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, `{"error":"slow_down"}`)
			default:
				fmt.Fprint(w, `{"access_token":"at","refresh_token":"rt","expires_in":3600,"scope":"mcp:whoami mcp:actions:execute"}`)
			}
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	credentials, err := deviceLogin(server.URL, "test adapter", true)
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	if credentials.AccessToken != "at" || credentials.RefreshToken != "rt" || credentials.ClientID != "mcp_test" {
		t.Fatalf("unexpected credentials %+v", credentials)
	}
	if polls != 3 {
		t.Fatalf("expected to poll through pending and slow_down, polled %d times", polls)
	}
	if !strings.Contains(opened, "ABCD-EFGH") {
		t.Fatalf("the approval page should open with the code, opened %q", opened)
	}
}

func TestLoginReportsADeclinedConnection(t *testing.T) {
	restoreInterval, restoreOpen := minPollInterval, openURL
	minPollInterval = 10 * time.Millisecond
	openURL = func(string) error { return nil }
	defer func() { minPollInterval, openURL = restoreInterval, restoreOpen }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/centcom/mcp/oauth/register":
			fmt.Fprint(w, `{"client_id":"mcp_test"}`)
		case "/api/centcom/mcp/oauth/device_authorization":
			fmt.Fprint(w, `{"device_code":"d","user_code":"U","verification_uri":"https://contro1.com/connect-app","expires_in":600,"interval":0}`)
		default:
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"error":"access_denied"}`)
		}
	}))
	defer server.Close()

	_, err := deviceLogin(server.URL, "test adapter", false)
	if err == nil || !strings.Contains(err.Error(), "declined") {
		t.Fatalf("a declined connection must say so, got %v", err)
	}
}
