package cmd

// Production implementations of the connect ports: the Contro1 API (with the
// person's own CLI login), the Contro1 service (elevated phase in production,
// direct control pipe in development), data-endpoint verification, prompts,
// and the secret-free state file.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/contro1-hq/contro1-cli/internal/broker"
	"github.com/contro1-hq/contro1-cli/internal/brokerpaths"
	"github.com/contro1-hq/contro1-cli/internal/brokerstore"
	"github.com/contro1-hq/contro1-cli/internal/client"
	"github.com/contro1-hq/contro1-cli/internal/connect"
	"github.com/contro1-hq/contro1-cli/internal/installer"
	"github.com/contro1-hq/contro1-cli/internal/localipc"
	"github.com/contro1-hq/contro1-cli/internal/platforms"
	"github.com/contro1-hq/contro1-cli/internal/runtimeproto"
)

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

type connectAPI struct{ c *client.Client }

func (a connectAPI) Whoami(context.Context) (*connect.Identity, error) {
	resp, err := a.c.Do("GET", "/api/centcom/v1/cli/whoami", nil)
	if err != nil {
		return nil, err
	}
	data := asMap(client.Data(resp))
	op := asMap(data["operator"])
	auth := asMap(data["auth"])
	id := &connect.Identity{Email: str(op["email"]), DisplayName: str(op["display_name"]), OperatorID: str(op["id"])}
	for _, s := range asSlice(auth["scopes"]) {
		id.Scopes = append(id.Scopes, str(s))
	}
	return id, nil
}

func (a connectAPI) Prepare(_ context.Context, req connect.PrepareRequest) (*connect.PrepareResponse, error) {
	resp, err := a.c.Do("POST", runtimeproto.PreparePath, req)
	if err != nil {
		return nil, err
	}
	var out connect.PrepareResponse
	return &out, remarshal(resp, &out)
}

func (a connectAPI) Batch(_ context.Context, batchID string) (*connect.BatchView, error) {
	resp, err := a.c.Do("GET", "/api/centcom/v1/runtime/connections/"+url.PathEscape(batchID), nil)
	if err != nil {
		return nil, err
	}
	var out connect.BatchView
	return &out, remarshal(resp, &out)
}

func (a connectAPI) ReportItem(_ context.Context, batchID, itemID, state, reason string) error {
	_, err := a.c.Do("POST", "/api/centcom/v1/runtime/connections/"+url.PathEscape(batchID)+"/items/"+url.PathEscape(itemID)+"/result", map[string]string{"state": state, "reason_code": reason})
	return err
}

func remarshal(in any, out any) error {
	raw, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

// ---------------------------------------------------------------------------
// Contro1 service
// ---------------------------------------------------------------------------

type serviceBroker struct {
	layout      brokerpaths.Layout
	development bool
}

func newServiceBroker(development bool) *serviceBroker {
	layout := brokerpaths.Production(runtime.GOOS)
	if development {
		layout = brokerpaths.Development()
	}
	return &serviceBroker{layout: layout, development: development}
}

func (s *serviceBroker) controlClient() (*http.Client, error) {
	ep, err := localipc.ParseEndpoint(s.layout.ControlEndpoint)
	if err != nil {
		return nil, err
	}
	c := localipc.HTTPClient(ep, "")
	c.Timeout = 60 * time.Second
	return c, nil
}

func (s *serviceBroker) Healthy(ctx context.Context) bool {
	if s.development {
		c, err := s.controlClient()
		if err != nil {
			return false
		}
		req, _ := http.NewRequestWithContext(ctx, "GET", localipc.BaseURL+"/control/v1/health", nil)
		resp, err := c.Do(req)
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 200
	}
	st, err := s.PublicStatus()
	if err != nil {
		return false
	}
	updated, err := time.Parse(time.RFC3339, st.UpdatedAt)
	return err == nil && time.Since(updated) < 2*time.Minute
}

func (s *serviceBroker) PublicStatus() (*brokerstore.PublicStatus, error) {
	raw, err := os.ReadFile(filepath.Join(s.layout.PlatformsDir, "status.json"))
	if err != nil {
		return nil, err
	}
	var st brokerstore.PublicStatus
	return &st, json.Unmarshal(raw, &st)
}

func (s *serviceBroker) MappingPath(platform string) string {
	return filepath.Join(s.layout.PlatformsDir, platform+".json")
}

// Register hands the ticket to the service. Development: the current user
// drives the foreground broker's control pipe directly. Production: one
// elevated phase installs the service if needed and registers the keys.
func (s *serviceBroker) Register(ctx context.Context, apiURL string, req broker.ControlConnectionsRequest) ([]broker.ControlItemResult, error) {
	if s.development {
		if !s.Healthy(ctx) {
			return nil, fmt.Errorf("no development Contro1 service is running; start one with: contro1 broker serve --foreground --dev-allow-current-user-control --api-url %s", apiURL)
		}
		return registerOverControl(ctx, s.layout, req)
	}
	phase := connectPhase{APIURL: apiURL, Request: req}
	path, err := writePhaseFile(phase)
	if err != nil {
		return nil, err
	}
	defer os.Remove(path)
	if installer.IsElevated() {
		if err := runRegisterPhase(ctx, path); err != nil {
			return nil, err
		}
	} else {
		if runtime.GOOS != "windows" {
			return nil, installer.ErrNeedsElevation
		}
		args := []string{"broker", "register", "--phase-file", path}
		if apiURL != "" {
			args = append(args, "--api-url", apiURL)
		}
		code, err := installer.RunElevated(args)
		if err != nil {
			return nil, err
		}
		if code != 0 {
			done, _ := readPhaseFile(path)
			if done != nil && done.Error != "" {
				return nil, errors.New(done.Error)
			}
			return nil, fmt.Errorf("the elevated setup exited with code %d", code)
		}
	}
	done, err := readPhaseFile(path)
	if err != nil {
		return nil, err
	}
	if done.Error != "" {
		return nil, errors.New(done.Error)
	}
	return done.Results, nil
}

// connectPhase is the only file that carries the connection ticket, for at
// most the few seconds the elevated phase runs. Mode 0600 in the person's own
// profile, deleted on return.
type connectPhase struct {
	APIURL  string                           `json:"api_url"`
	Request broker.ControlConnectionsRequest `json:"request"`
	Results []broker.ControlItemResult       `json:"results,omitempty"`
	Error   string                           `json:"error,omitempty"`
}

func phaseDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".contro1", "connect")
}

func writePhaseFile(p connectPhase) (string, error) {
	if err := os.MkdirAll(phaseDir(), 0o700); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(phaseDir(), "phase-*.json")
	if err != nil {
		return "", err
	}
	defer f.Close()
	_ = f.Chmod(0o600)
	return f.Name(), json.NewEncoder(f).Encode(p)
}

func readPhaseFile(path string) (*connectPhase, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p connectPhase
	return &p, json.Unmarshal(raw, &p)
}

// runRegisterPhase runs elevated: install the service when it is not running,
// wait for its control endpoint, register the keys, and write back results
// with the ticket removed.
func runRegisterPhase(ctx context.Context, path string) error {
	phase, err := readPhaseFile(path)
	if err != nil {
		return err
	}
	finish := func(results []broker.ControlItemResult, failure error) error {
		phase.Request.ConnectionTicket = ""
		phase.Results = results
		if failure != nil {
			phase.Error = failure.Error()
		}
		raw, _ := json.Marshal(phase)
		_ = os.WriteFile(path, raw, 0o600)
		return failure
	}
	layout := brokerpaths.Production(runtime.GOOS)
	if installed, running, _, _ := installer.ServiceStatus(); !installed || !running {
		exe, _ := os.Executable()
		plan := installer.Plan(runtime.GOOS, installer.Options{SourceBinary: exe, APIURL: phase.APIURL, Version: Version})
		if _, err := installer.Apply(plan, installer.SystemRunner{}, filepath.Join(layout.StateDir, "install-journal.json")); err != nil {
			return finish(nil, err)
		}
	}
	deadline := time.Now().Add(45 * time.Second)
	for {
		results, err := registerOverControl(ctx, layout, phase.Request)
		if err == nil {
			return finish(results, nil)
		}
		if time.Now().After(deadline) {
			return finish(nil, fmt.Errorf("the Contro1 service did not answer: %w", err))
		}
		time.Sleep(time.Second)
	}
}

func registerOverControl(ctx context.Context, layout brokerpaths.Layout, req broker.ControlConnectionsRequest) ([]broker.ControlItemResult, error) {
	ep, err := localipc.ParseEndpoint(layout.ControlEndpoint)
	if err != nil {
		return nil, err
	}
	c := localipc.HTTPClient(ep, "")
	c.Timeout = 90 * time.Second
	body, _ := json.Marshal(req)
	hreq, _ := http.NewRequestWithContext(ctx, "POST", localipc.BaseURL+"/control/v1/connections", strings.NewReader(string(body)))
	hreq.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(hreq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Contro1 service refused the connection (%d): %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out struct {
		Items []broker.ControlItemResult `json:"items"`
	}
	return out.Items, json.Unmarshal(raw, &out)
}

// controlCall is a small helper for disconnect (development or elevated).
func controlCall(ctx context.Context, layout brokerpaths.Layout, method, path string, body any) (map[string]any, error) {
	ep, err := localipc.ParseEndpoint(layout.ControlEndpoint)
	if err != nil {
		return nil, err
	}
	c := localipc.HTTPClient(ep, "")
	c.Timeout = 30 * time.Second
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, method, localipc.BaseURL+path, strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode >= 300 {
		return out, fmt.Errorf("control %s: %d", path, resp.StatusCode)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Verification through the data endpoint
// ---------------------------------------------------------------------------

type endpointVerifier struct{}

func endpointClient(e runtimeproto.MappingEntry) (*client.Client, error) {
	ep, err := localipc.ParseEndpoint(e.Endpoint)
	if err != nil {
		return nil, err
	}
	principal := localipc.Principal(e.ServerPrincipal)
	if p := strings.TrimSpace(os.Getenv("CONTRO1_BROKER_PRINCIPAL")); p != "" {
		principal = localipc.Principal(p)
	}
	return client.NewWithHTTPClient(localipc.BaseURL, "", userAgent(), localipc.HTTPClient(ep, principal)), nil
}

func (endpointVerifier) RuntimeStatus(_ context.Context, e runtimeproto.MappingEntry) (string, error) {
	c, err := endpointClient(e)
	if err != nil {
		return "", err
	}
	resp, err := c.Do("GET", "/api/centcom/v1/runtime/status", nil)
	if err != nil {
		return "", err
	}
	return str(asMap(resp["auth"])["agent_id"]), nil
}

func (endpointVerifier) ControlMapPreview(_ context.Context, e runtimeproto.MappingEntry) error {
	c, err := endpointClient(e)
	if err != nil {
		return err
	}
	_, err = c.Do("POST", "/api/centcom/v1/requests/control-map", map[string]any{
		"type": "approval", "question": "Contro1 connection check", "context": "Preview only. No request is created.",
	})
	return err
}

// ---------------------------------------------------------------------------
// Prompts and state
// ---------------------------------------------------------------------------

type terminalPrompt struct{ json bool }

func (p terminalPrompt) Interactive() bool {
	return !p.json && isTerminal(os.Stdin) && isTerminal(os.Stderr)
}

func (p terminalPrompt) Confirm(title string, lines []string) bool {
	fmt.Fprintln(os.Stderr, title)
	for _, l := range lines {
		fmt.Fprintln(os.Stderr, "  - "+l)
	}
	fmt.Fprint(os.Stderr, "Continue? [y/N] ")
	answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes"
}

func (p terminalPrompt) Progress(line string) {
	if !p.json && !flagQuiet {
		fmt.Fprintln(os.Stderr, line)
	}
}

type fileStates struct{}

func (fileStates) path(platform string) string { return filepath.Join(phaseDir(), platform+".json") }

func (f fileStates) Load(platform string) (*connect.State, error) {
	raw, err := os.ReadFile(f.path(platform))
	if err != nil {
		return nil, nil
	}
	var st connect.State
	if json.Unmarshal(raw, &st) != nil {
		return nil, nil
	}
	return &st, nil
}

func (f fileStates) Save(platform string, st *connect.State) error {
	if err := os.MkdirAll(phaseDir(), 0o700); err != nil {
		return err
	}
	raw, _ := json.MarshalIndent(st, "", "  ")
	return brokerstore.WriteFileAtomic(f.path(platform), raw, 0o600)
}

func (f fileStates) Clear(platform string) error {
	err := os.Remove(f.path(platform))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// platformOptions collects adapter overrides from flags.
func platformOptions() platforms.Options {
	return platforms.Options{Bin: flagConnectBin, ConfigDir: flagConnectConfigDir, Principal: flagConnectPrincipal, Agents: flagConnectAgents}
}
