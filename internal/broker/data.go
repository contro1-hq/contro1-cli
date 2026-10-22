package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/contro1-hq/contro1-cli/internal/brokerstore"
	"github.com/contro1-hq/contro1-cli/internal/localipc"
	"github.com/contro1-hq/contro1-cli/internal/runtimeproto"
)

const maxDataBody = 1 << 20

// forwardedRequestHeaders are the only caller headers passed upstream.
// Contro1-Sub-Agent names a part of THIS endpoint's agent. Forwarding it cannot
// widen anything: the server resolves the part under the credential's own
// agent, so a name can only ever select a part of the agent the broker speaks for.
var forwardedRequestHeaders = []string{"Content-Type", "Accept", "Idempotency-Key", "Mcp-Session-Id", "Mcp-Protocol-Version", "Last-Event-Id", "Contro1-Sub-Agent"}

// hopHeaders are never copied back to the caller.
var hopHeaders = map[string]bool{"Connection": true, "Keep-Alive": true, "Transfer-Encoding": true, "Upgrade": true, "Set-Cookie": true, "Dpop-Nonce": true, "Www-Authenticate": true}

type dataServer struct {
	b       *Broker
	localID string
	srv     *http.Server
	l       net.Listener
}

func newDataServer(b *Broker, localID string, l net.Listener) *dataServer {
	ds := &dataServer{b: b, localID: localID, l: l}
	ds.srv = localipc.NewServer(ds)
	go func() { _ = ds.srv.Serve(l) }()
	return ds
}

func (ds *dataServer) close() { _ = ds.srv.Close() }

// connectionNotActive says why, and the one command that brings the agent back.
// "Run contro1 status" left the person to work out that a connection ended in
// Contro1 is not repaired, only made again.
func connectionNotActive(en *brokerstore.Enrollment, err error) runtimeproto.Remediation {
	out := runtimeproto.Remediation{Code: "CONNECTION_NOT_ACTIVE", PublicMessage: "This connection is not active on this computer.", Missing: "An active connection.", NextStep: "Run contro1 status to see what changed.", Retryable: false}
	if err != nil || en == nil {
		return out
	}
	again := "To connect it again: contro1 connect " + en.Platform
	switch en.State {
	case "revoked":
		out.PublicMessage, out.NextStep = "This connection was disconnected in Contro1.", again
	case "suspended":
		out.PublicMessage, out.NextStep = "This connection is suspended in Contro1.", "Its owner can resume it on the agent's page in Contro1."
	case "expired":
		out.PublicMessage, out.NextStep = "This connection was not approved in time.", again
	case "pending":
		out.PublicMessage, out.NextStep = "This connection is still waiting for its owner to approve it.", "Approve it at the link contro1 connect printed, or run contro1 connect "+en.Platform+" again."
	}
	return out
}

func (ds *dataServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	en, err := ds.b.enrollment(ds.localID)
	if err != nil || (en.State != "active") {
		writeRemediation(w, 401, connectionNotActive(en, err))
		return
	}
	path := r.URL.Path
	if r.Method == "GET" && path == "/broker/v1/endpoint" {
		writeJSON(w, 200, runtimeproto.EndpointInfo{AgentID: en.AgentID, EnrollmentID: en.EnrollmentID, EndpointMode: en.EndpointMode, ModeLabel: runtimeproto.ModeLabel(en.EndpointMode), PlatformSubject: en.PlatformSubject, State: en.State})
		return
	}
	if en.EndpointMode == runtimeproto.ModeApprovalsOnly && !runtimeproto.AllowedRoute(en.EndpointMode, r.Method, path) &&
		runtimeproto.AllowedRoute(runtimeproto.ModeApplications, r.Method, path) {
		/*
		 * THE OWNER'S SWITCH TAKES EFFECT HERE, not after a terminal step.
		 *
		 * The mode was written once, at connect, and nothing ever changed it:
		 * the dashboard told the owner to run a repair that did not touch it,
		 * so allowing applications in Contro1 did nothing on the computer. The
		 * server already holds the live decision and authorizes every one of
		 * these calls against it, so the local list follows it. Only a call
		 * the narrow list refuses asks, so an approvals-only agent costs no
		 * extra round trip.
		 *
		 * Whatever the server says is recorded, narrower included. Every
		 * token refresh records it too (tokenprovider.TokenEndpointMode), so
		 * this is only the fast path for the call that is waiting.
		 */
		if live := ds.liveMode(r.Context()); live != "" && live != en.EndpointMode {
			ds.b.setLocalMode(ds.localID, live)
			en.EndpointMode = live
		}
	}
	if !runtimeproto.AllowedRoute(en.EndpointMode, r.Method, path) {
		code := "ENDPOINT_METHOD_NOT_ALLOWED"
		msg := "This agent's connection cannot use that part of Contro1."
		next := "Use the approval and audit calls only."
		if en.EndpointMode == runtimeproto.ModeApprovalsOnly && runtimeproto.AllowedRoute(runtimeproto.ModeApplications, r.Method, path) {
			code = "APPLICATION_ACTIONS_NOT_ENABLED"
			msg = "I can ask for approvals, but I cannot use organization applications."
			next = "Ask the accountable owner to allow applications: run contro1 apps enable " + en.Platform + " on this computer. It opens the page in Contro1 and finishes the setup here."
		}
		writeRemediation(w, 403, runtimeproto.Remediation{Code: code, PublicMessage: msg, Missing: runtimeproto.ModeLabel(en.EndpointMode) + " does not include this call.", NextStep: next})
		return
	}
	q := r.URL.Query()
	for _, key := range runtimeproto.RejectedQuery {
		if q.Has(key) {
			writeRemediation(w, 400, runtimeproto.Remediation{Code: "IDENTITY_SELECTOR_REJECTED", PublicMessage: "The identity comes from this endpoint and cannot be chosen per request.", Missing: "", NextStep: "Remove the " + key + " parameter."})
			return
		}
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxDataBody))
	if err != nil {
		writeJSON(w, 413, map[string]any{"error": "body_too_large"})
		return
	}
	if claimed := claimedAgent(r.Header.Get("Content-Type"), body); claimed != "" && claimed != en.AgentID {
		ds.b.cfg.Logf("endpoint %s refused a request naming another agent", ds.localID)
		writeRemediation(w, 403, runtimeproto.Remediation{Code: "AGENT_IDENTITY_MISMATCH", PublicMessage: "This endpoint belongs to one agent and cannot act as another.", NextStep: "Use the endpoint mapped to that agent."})
		return
	}

	resource := runtimeproto.ResourceAPI
	upstreamPath := path
	if path == "/mcp" {
		resource = runtimeproto.ResourceMCP
		upstreamPath = "/api/centcom/mcp"
	}
	target := strings.TrimRight(ds.b.cfg.APIURL, "/") + upstreamPath
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}

	resp, err := ds.forward(r.Context(), r, target, body, resource)
	if err != nil {
		ds.b.writeTokenError(w, err)
		return
	}
	defer resp.Body.Close()
	if r.Method == "GET" && path == runtimeStatusPath && resp.StatusCode == http.StatusOK {
		/*
		 * A STATUS CALL IS THE SERVER SAYING THE MODE, so it is recorded.
		 *
		 * `contro1 connect` and `contro1 doctor` both ask for runtime status
		 * through this endpoint. For an agent that was already connected,
		 * connect reuses the connection and changes nothing else, so the
		 * mapping kept the mode it was written with and doctor, right after
		 * connect, still reported it as stale. The answer is already passing
		 * through here; reading the mode off it costs no extra request. The
		 * body is passed on byte for byte.
		 */
		head, _ := io.ReadAll(io.LimitReader(resp.Body, maxStatusBody))
		resp.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(head), resp.Body), resp.Body}
		if live := modeFromStatus(head); live != "" && live != en.EndpointMode {
			ds.b.setLocalMode(ds.localID, live)
		}
	}
	for k, vs := range resp.Header {
		if hopHeaders[http.CanonicalHeaderKey(k)] {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 32<<10)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if readErr != nil {
			return
		}
	}
}

// liveModeView is the one field read from the server's description of a credential.
type liveModeView struct {
	EndpointMode string `json:"endpoint_mode"`
}

// liveMode asks the server which mode this connection has now, or "" when it
// cannot tell. Through forward, so a token minted before the change is refreshed.
func (ds *dataServer) liveMode(ctx context.Context) string {
	target := strings.TrimRight(ds.b.cfg.APIURL, "/") + runtimeStatusPath
	probe, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return ""
	}
	resp, err := ds.forward(ctx, probe, target, nil, runtimeproto.ResourceAPI)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxStatusBody))
	return modeFromStatus(raw)
}

const (
	runtimeStatusPath = "/api/centcom/v1/runtime/status"
	maxStatusBody     = 1 << 20
)

// modeFromStatus reads the mode out of a runtime status answer, or "".
func modeFromStatus(raw []byte) string {
	var body struct {
		Auth       *liveModeView `json:"auth"`
		Credential *liveModeView `json:"credential"`
	}
	if json.Unmarshal(raw, &body) != nil {
		return ""
	}
	for _, c := range []*liveModeView{body.Auth, body.Credential} {
		if c != nil && runtimeproto.ValidMode(c.EndpointMode) {
			return c.EndpointMode
		}
	}
	return ""
}

// forward sends the request with a fresh credential, retrying once for a
// nonce challenge or a token the server no longer accepts.
func (ds *dataServer) forward(ctx context.Context, r *http.Request, target string, body []byte, resource string) (*http.Response, error) {
	var last *http.Response
	for attempt := 0; attempt < 3; attempt++ {
		up, err := http.NewRequestWithContext(ctx, r.Method, target, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		for _, h := range forwardedRequestHeaders {
			if v := r.Header.Get(h); v != "" {
				up.Header.Set(h, v)
			}
		}
		up.Header.Set("User-Agent", "contro1-broker/"+ds.b.cfg.Version)
		if err := ds.b.provider.Authorize(ctx, up, ds.localID, resource); err != nil {
			return nil, err
		}
		resp, err := ds.b.provider.HTTP.Do(up)
		if err != nil {
			return nil, err
		}
		ds.b.provider.ObserveNonce(resp.Header)
		if resp.StatusCode != http.StatusUnauthorized || attempt == 2 {
			return resp, nil
		}
		challenge := resp.Header.Get("WWW-Authenticate")
		switch {
		case strings.Contains(challenge, "use_dpop_nonce"):
			resp.Body.Close()
			continue
		case strings.Contains(challenge, "invalid_token") && attempt == 0:
			// Possibly a token minted before a scope change; refresh once.
			raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
			resp.Body.Close()
			if bytes.Contains(raw, []byte(`"remediation"`)) {
				// Live state refused the connection; a new token will not help.
				resp.Body = io.NopCloser(bytes.NewReader(raw))
				return resp, nil
			}
			ds.b.provider.Invalidate(ds.localID, resource)
			last = nil
			continue
		default:
			return resp, nil
		}
	}
	if last != nil {
		return last, nil
	}
	return nil, errors.New("broker: upstream kept refusing the credential")
}

// claimedAgent finds an agent id named in a JSON body (best effort; the server
// enforces the same rule).
func claimedAgent(contentType string, body []byte) string {
	if len(body) == 0 || !strings.Contains(strings.ToLower(contentType), "json") {
		return ""
	}
	var parsed map[string]any
	if json.Unmarshal(body, &parsed) != nil {
		return ""
	}
	if v, ok := parsed["agent_id"].(string); ok {
		return v
	}
	for _, key := range []string{"metadata", ""} {
		container := parsed
		if key != "" {
			container, _ = parsed[key].(map[string]any)
		}
		if actor, ok := container["actor"].(map[string]any); ok {
			if v, ok := actor["agent_id"].(string); ok {
				return v
			}
		}
	}
	return ""
}
