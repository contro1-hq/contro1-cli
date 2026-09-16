//go:build conformance

package broker

// Cross-stack conformance: the real Go broker against the real backend.
//
//   cd backend && npx tsx src/scripts/runtimeConformanceServer.ts --auto-approve
//   # copy api_url and cli_token from its first line, then:
//   CONTRO1_CONFORMANCE_API_URL=... CONTRO1_CONFORMANCE_CLI_TOKEN=... \
//     go test -tags conformance -run Conformance -v ./internal/broker/

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/contro1-hq/contro1-cli/internal/client"
	"github.com/contro1-hq/contro1-cli/internal/keystore"
	"github.com/contro1-hq/contro1-cli/internal/localipc"
	"github.com/contro1-hq/contro1-cli/internal/runtimeproto"
)

func cliCall(t *testing.T, apiURL, token, method, path string, body any) map[string]any {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, apiURL+path, reader)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode >= 300 {
		t.Fatalf("%s %s: %d %v", method, path, resp.StatusCode, out)
	}
	return out
}

func TestConformance(t *testing.T) {
	apiURL := os.Getenv("CONTRO1_CONFORMANCE_API_URL")
	cliToken := os.Getenv("CONTRO1_CONFORMANCE_CLI_TOKEN")
	if apiURL == "" || cliToken == "" {
		t.Skip("set CONTRO1_CONFORMANCE_API_URL and CONTRO1_CONFORMANCE_CLI_TOKEN")
	}
	me, err := localipc.CurrentIdentity()
	if err != nil {
		t.Fatal(err)
	}

	// 1. The developer prepares a two-agent connection with their own login.
	stamp := time.Now().UnixNano()
	prepared := cliCall(t, apiURL, cliToken, "POST", "/api/centcom/v1/runtime/connections/prepare", map[string]any{
		"platform": "openclaw", "host": map[string]string{"label": "conformance-host"},
		"items": []map[string]string{
			{"platform_subject": fmt.Sprintf("main-%d", stamp), "display_name": "main"},
			{"platform_subject": fmt.Sprintf("research-%d", stamp), "display_name": "research"},
		},
	})
	ticket := prepared["connection_ticket"].(string)
	var items []ControlItem
	for _, raw := range prepared["items"].([]any) {
		it := raw.(map[string]any)
		items = append(items, ControlItem{
			ItemID: it["item_id"].(string), AgentID: it["agent_id"].(string), EnrollmentID: it["enrollment_id"].(string),
			Platform: "openclaw", PlatformSubject: it["platform_subject"].(string), EndpointMode: runtimeproto.ModeApprovalsOnly,
			AllowedPrincipals: []string{me.User},
		})
	}

	// 2. The broker registers keys through the control endpoint.
	dir := t.TempDir()
	control := localipc.PipeEndpoint(fmt.Sprintf("contro1-conf-control-%d", stamp))
	b, err := New(Config{
		StateDir: dir, APIURL: apiURL, Version: "conformance", Foreground: true, ControlEndpoint: control,
		ServicePrincipal: me.User, DevAllowCurrentUserControl: true,
		Keys: &keystore.CNGStore{}, Logf: t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = b.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	cc := localipc.HTTPClient(control, localipc.Principal(me.User))
	// Real CNG keys land in the user's key store; remove them when done.
	defer func() {
		st, _ := b.Store().LoadState()
		for _, en := range st.Enrollments {
			if r, err := cc.Post(localipc.BaseURL+"/control/v1/enrollments/"+en.LocalID+"/revoke", "application/json", strings.NewReader(`{"remote":false}`)); err == nil {
				r.Body.Close()
			}
		}
	}()
	waitFor(t, func() bool {
		r, err := cc.Get(localipc.BaseURL + "/control/v1/health")
		if err == nil {
			r.Body.Close()
		}
		return err == nil
	})
	body, _ := json.Marshal(ControlConnectionsRequest{APIURL: apiURL, BatchID: prepared["batch_id"].(string), ConnectionTicket: ticket, Items: items})
	resp, err := cc.Post(localipc.BaseURL+"/control/v1/connections", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var created struct{ Items []ControlItemResult }
	_ = json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()
	for _, it := range created.Items {
		if it.State != "awaiting_approval" {
			t.Fatalf("item %s: %+v", it.ItemID, it)
		}
	}
	if created.Items[len(created.Items)-1].UserCode == "" {
		t.Fatal("the last registered key seals the batch and returns the user code")
	}

	// 3. The (auto-approving) owner approves; both connections become active.
	endpoints := map[string]string{}
	waitFor(t, func() bool {
		st, _ := b.Store().LoadState()
		n := 0
		for _, en := range st.Enrollments {
			if en.State == "active" {
				endpoints[en.AgentID] = en.Endpoint
				n++
			}
		}
		return n == 2
	})

	// 4. A runtime command through the data endpoint, exactly as the CLI does it.
	mainAgent := items[0].AgentID
	ep, _ := localipc.ParseEndpoint(endpoints[mainAgent])
	c := client.NewWithHTTPClient(localipc.BaseURL, "", "conformance", localipc.HTTPClient(ep, localipc.Principal(me.User)))
	waitFor(t, func() bool { _, err := c.Do("GET", "/broker/v1/endpoint", nil); return err == nil })
	status, err := c.Do("GET", "/api/centcom/v1/runtime/status", nil)
	if err != nil {
		t.Fatalf("runtime status through the broker: %v", err)
	}
	auth := status["auth"].(map[string]any)
	if auth["agent_id"] != mainAgent || auth["credential_kind"] != "agent_runtime" || auth["mode_label"] != "Approvals only" {
		t.Fatalf("server saw %v", auth)
	}

	// 5. Approvals only: invoke is refused at the broker.
	if _, err := c.Do("POST", "/api/centcom/v1/actions/invoke", map[string]any{"action_id": "x"}); err == nil || !strings.Contains(fmt.Sprint(err), "applications") {
		t.Fatalf("invoke must be refused locally: %v", err)
	}

	// 6. Concurrency: many callers, at most one refresh per resource.
	localID := ""
	st, _ := b.Store().LoadState()
	for _, en := range st.Enrollments {
		if en.AgentID == mainAgent {
			localID = en.LocalID
		}
	}
	b.Provider().Invalidate(localID, runtimeproto.ResourceAPI)
	before := b.Provider().RefreshCount()
	var wg sync.WaitGroup
	errs := make(chan error, 40)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Do("GET", "/api/centcom/v1/runtime/status", nil); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent call failed: %v", err)
	}
	if delta := b.Provider().RefreshCount() - before; delta != 1 {
		t.Fatalf("40 concurrent calls after expiry made %d refreshes, want 1", delta)
	}

	// 7. Revoke with the developer's login: the next call fails closed with a remediation.
	enrollmentID := items[0].EnrollmentID
	cliCall(t, apiURL, cliToken, "POST", "/api/centcom/v1/runtime/connections/enrollments/"+enrollmentID+"/revoke", map[string]any{"reason": "conformance"})
	_, err = c.Do("GET", "/api/centcom/v1/runtime/status", nil)
	if err == nil {
		t.Fatal("a revoked connection must fail closed")
	}
	t.Logf("after revoke: %v", err)
}
