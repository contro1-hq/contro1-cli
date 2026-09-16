package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/contro1-hq/contro1-cli/internal/keystore"
	"github.com/contro1-hq/contro1-cli/internal/localipc"
	"github.com/contro1-hq/contro1-cli/internal/runtimeproto"
)

// fakeContro1 is just enough of the server: device authorization, the token
// endpoint, and a recorder for resource calls.
type fakeContro1 struct {
	mu       sync.Mutex
	approved bool
	srv      *httptest.Server
	seen     []*http.Request
	bodies   []string
	refresh  int
}

func (f *fakeContro1) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("DPoP-Nonce", "n")
	switch r.URL.Path {
	case runtimeproto.DeviceAuthorizePath:
		if r.Header.Get("DPoP") == "" {
			w.WriteHeader(400)
			return
		}
		_ = r.ParseForm()
		fmt.Fprintf(w, `{"device_code":"ccdc_%s","user_code":"ABCD-EFGH","expires_in":600,"interval":1,"batch_id":"con_1","enrollment_id":"enr_%s","item_id":"%s","sealed":true}`, r.Form.Get("item_id"), r.Form.Get("item_id"), r.Form.Get("item_id"))
	case runtimeproto.TokenPath:
		_ = r.ParseForm()
		if r.Form.Get("grant_type") == runtimeproto.DeviceCodeGrant && !f.approved {
			w.WriteHeader(400)
			fmt.Fprint(w, `{"error":"authorization_pending","interval":1}`)
			return
		}
		f.refresh++
		fmt.Fprintf(w, `{"access_token":"at_%d","token_type":"DPoP","expires_in":300,"refresh_token":"ccrt_%d","agent_id":"agt_main"}`, f.refresh, f.refresh)
	default:
		body, _ := io.ReadAll(r.Body)
		f.seen = append(f.seen, r.Clone(context.Background()))
		f.bodies = append(f.bodies, string(body))
		fmt.Fprint(w, `{"ok":true,"auth":{"agent_id":"agt_main","credential_kind":"agent_runtime"}}`)
	}
}

func TestBrokerEndToEnd(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("named-pipe integration test; unix sockets are exercised on the Linux handoff machine")
	}
	me, err := localipc.CurrentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	api := &fakeContro1{}
	api.srv = httptest.NewServer(api)
	defer api.srv.Close()

	dir := t.TempDir()
	stamp := time.Now().UnixNano()
	control := localipc.PipeEndpoint(fmt.Sprintf("contro1-test-control-%d", stamp))
	b, err := New(Config{
		StateDir: dir, APIURL: api.srv.URL, Version: "test", Foreground: true,
		ControlEndpoint: control, ServicePrincipal: me.User, DevAllowCurrentUserControl: true,
		Keys: &keystore.FileStore{Dir: dir + "/keys", Development: true}, HTTP: api.srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = b.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	cc := localipc.HTTPClient(control, localipc.Principal(me.User))
	var health map[string]any
	waitFor(t, func() bool {
		resp, err := cc.Get(localipc.BaseURL + "/control/v1/health")
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return json.NewDecoder(resp.Body).Decode(&health) == nil
	})
	if health["key_protection"] != "user_file_development" {
		t.Fatalf("health %v", health)
	}

	reqBody, _ := json.Marshal(ControlConnectionsRequest{
		APIURL: api.srv.URL, BatchID: "con_1", ConnectionTicket: "ccct_ticket",
		Items: []ControlItem{{ItemID: "itm_main", AgentID: "agt_main", Platform: "openclaw", PlatformSubject: "main", EndpointMode: runtimeproto.ModeApprovalsOnly, AllowedPrincipals: []string{me.User}}},
	})
	resp, err := cc.Post(localipc.BaseURL+"/control/v1/connections", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	var created struct{ Items []ControlItemResult }
	_ = json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()
	if len(created.Items) != 1 || created.Items[0].State != "awaiting_approval" || created.Items[0].JKT == "" {
		t.Fatalf("connections: %+v", created)
	}
	raw, _ := json.Marshal(created)
	if strings.Contains(string(raw), "ccdc_") || strings.Contains(string(raw), "ccrt_") {
		t.Fatal("control responses never carry a device code or refresh token")
	}
	localID := created.Items[0].LocalID

	api.mu.Lock()
	api.approved = true
	api.mu.Unlock()
	var endpoint string
	waitFor(t, func() bool {
		st, _ := b.Store().LoadState()
		for _, en := range st.Enrollments {
			if en.LocalID == localID && en.State == "active" {
				endpoint = en.Endpoint
				return true
			}
		}
		return false
	})
	ep, err := localipc.ParseEndpoint(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	dc := localipc.HTTPClient(ep, localipc.Principal(me.User))
	waitFor(t, func() bool {
		r, err := dc.Get(localipc.BaseURL + "/broker/v1/endpoint")
		if err != nil {
			return false
		}
		r.Body.Close()
		return r.StatusCode == 200
	})

	// Allowed call: forwarded with a DPoP credential, caller auth stripped.
	req, _ := http.NewRequest("POST", localipc.BaseURL+"/api/centcom/v1/requests", strings.NewReader(`{"type":"approval","question":"q","context":"c"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer cc_live_should_not_leak")
	req.Header.Set("Cookie", "centcom_token=nope")
	out, err := dc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	out.Body.Close()
	if out.StatusCode != 200 {
		t.Fatalf("forwarded status %d", out.StatusCode)
	}
	api.mu.Lock()
	last := api.seen[len(api.seen)-1]
	api.mu.Unlock()
	if !strings.HasPrefix(last.Header.Get("Authorization"), "DPoP at_") || last.Header.Get("DPoP") == "" || last.Header.Get("Cookie") != "" {
		t.Fatalf("upstream headers %v", last.Header)
	}

	check := func(method, path, body string, want int, code string) {
		t.Helper()
		r, _ := http.NewRequest(method, localipc.BaseURL+path, strings.NewReader(body))
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		resp, err := dc.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != want || (code != "" && !strings.Contains(string(raw), code)) {
			t.Fatalf("%s %s = %d %s, want %d %s", method, path, resp.StatusCode, raw, want, code)
		}
	}
	check("POST", "/api/centcom/v1/actions/invoke", `{}`, 403, "APPLICATION_ACTIONS_NOT_ENABLED")
	check("POST", "/api/centcom/v1/agents", `{}`, 403, "ENDPOINT_METHOD_NOT_ALLOWED")
	check("POST", "/control/v1/connections", `{}`, 403, "ENDPOINT_METHOD_NOT_ALLOWED")
	check("GET", "/api/centcom/v1/requests?agent_id=agt_other", "", 400, "IDENTITY_SELECTOR_REJECTED")
	check("POST", "/api/centcom/v1/requests", `{"metadata":{"actor":{"agent_id":"agt_other"}}}`, 403, "AGENT_IDENTITY_MISMATCH")

	// Mapping file: exact subject to endpoint, no secrets.
	resp, err = cc.Post(localipc.BaseURL+"/control/v1/mappings", "application/json", strings.NewReader(`{"platform":"openclaw"}`))
	if err != nil {
		t.Fatal(err)
	}
	mapping, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(mapping), `"platform_subject":"main"`) || strings.Contains(string(mapping), "ccrt_") {
		t.Fatalf("mapping %s", mapping)
	}

	// Revoke locally: the endpoint stops and the connection is gone.
	resp, err = cc.Post(localipc.BaseURL+"/control/v1/enrollments/"+localID+"/revoke", "application/json", strings.NewReader(`{"remote":false}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if conn, err := localipc.Dial(ctx2, ep, ""); err == nil {
		conn.Close()
		t.Fatal("a revoked connection's endpoint must stop listening")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}
