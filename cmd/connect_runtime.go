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
	// compare is how the installed service is set against this CLI; a field so
	// tests never read the real service.
	compare func() installer.ServiceComparison
	// update is compared once per run, so the preview and the elevated phase
	// that follows it agree on whether the service is updated.
	update        *installer.ServiceComparison
	updateMessage string
	updateErr     error
}

func newServiceBroker(development bool) *serviceBroker {
	layout := brokerpaths.Production(runtime.GOOS)
	if development {
		layout = brokerpaths.Development()
	}
	s := &serviceBroker{layout: layout, development: development}
	s.compare = func() installer.ServiceComparison {
		c, installed, running := compareInstalledService(layout)
		if !installed || !running {
			// The elevated phase installs and starts a missing or stopped
			// service with this CLI's binary anyway; the preview says so.
			return installer.ServiceComparison{To: c.To}
		}
		return c
	}
	return s
}

/*
compareInstalledService sets the installed Contro1 service against the CLI
running now, read without elevation: the version the service publishes in its
status file and, when that cannot decide, the installed binary's hash.
*/
func compareInstalledService(layout brokerpaths.Layout) (c installer.ServiceComparison, installed, running bool) {
	installed, running, _, _ = installer.ServiceStatus()
	version := ""
	for _, dir := range []string{layout.PlatformsDir, layout.StateDir} {
		if st, err := brokerstore.OpenReadOnly(dir).ReadStatus(); err == nil {
			version = st.BrokerVersion
			break
		}
	}
	exe, _ := os.Executable()
	c = installer.CompareService(version, Version, func() (bool, error) {
		if exe == "" || layout.BinaryPath == "" {
			return false, errors.New("no binary to compare")
		}
		return installer.BinaryDiffers(exe, layout.BinaryPath)
	})
	return c, installed, running
}

// serviceUpdateCommand is the command that updates the service by hand here.
func serviceUpdateCommand() string {
	exe, _ := os.Executable()
	return installer.UpdateCommand(runtime.GOOS, exe)
}

func (s *serviceBroker) serviceUpdate() installer.ServiceComparison {
	if s.development || s.compare == nil {
		return installer.ServiceComparison{}
	}
	if s.update == nil {
		c := s.compare()
		s.update = &c
	}
	return *s.update
}

// PendingServiceUpdate is the preview line when the installed service runs an
// older or different binary than this CLI. The next elevated phase updates it.
func (s *serviceBroker) PendingServiceUpdate() string {
	if c := s.serviceUpdate(); c.Needed {
		return c.UpdateLine()
	}
	return ""
}

// UpdateService updates the service in an elevated phase of its own, for a run
// that has nothing else to ask an administrator for.
func (s *serviceBroker) UpdateService(ctx context.Context, apiURL string) error {
	_, err := s.runPhase(ctx, connectPhase{APIURL: apiURL})
	if s.updateErr != nil {
		return s.updateErr
	}
	if errors.Is(err, installer.ErrElevationDeclined) || errors.Is(err, installer.ErrNeedsElevation) {
		return fmt.Errorf("it needs administrator approval, which was not given. Your agents keep working on the installed one; to update it later, run %s", serviceUpdateCommand())
	}
	return err
}

// ServiceUpdateResult is what the last elevated phase did about the update:
// a line to show when it worked, or why it did not.
func (s *serviceBroker) ServiceUpdateResult() (string, error) {
	return s.updateMessage, s.updateErr
}

/*
runPhase runs one elevated phase and, when the service is due an update, the
update with it.

ONE APPROVAL. The update rides on whatever this run already asks an
administrator for (registering keys, moving endpoints, disconnect's revoke),
because a second prompt for the same computer in the same command reads as
something going wrong, and people decline it.
*/
func (s *serviceBroker) runPhase(ctx context.Context, phase connectPhase) (*connectPhase, error) {
	update := s.serviceUpdate()
	phase.UpdateService = update.Needed
	done, err := elevatedPhase(ctx, phase)
	if !phase.UpdateService || done == nil {
		return done, err
	}
	switch {
	case done.ServiceUpdateError != "":
		s.updateErr = fmt.Errorf("%s. It still runs %s; to update it, run %s", done.ServiceUpdateError, orDefault(update.From, "the installed build"), serviceUpdateCommand())
	case done.ServiceVersion != "":
		s.updateMessage = "The Contro1 service was updated to " + done.ServiceVersion + " and is running again."
		s.update = &installer.ServiceComparison{From: done.ServiceVersion, To: update.To}
	}
	return done, err
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
	done, err := s.runPhase(ctx, connectPhase{APIURL: apiURL, Request: req})
	if err != nil {
		return nil, err
	}
	return done.Results, nil
}

/*
RevokeLocal removes this computer's connections for one platform from the
Contro1 service: it stops their endpoints, deletes their keys and republishes
the mapping without them.

WHY. Disconnect revoked the connections in Contro1 and left all of that here,
on the reasoning that the endpoints stop by themselves once the server
revokes. They refuse, but they stay published: a real Codex test then had
`contro1 mcp serve` choose the revoked agent, and be refused, on every start.
The mapping belongs to the service, so removing it takes the same one
administrator approval as connecting; development drives the foreground
service directly.
*/
func (s *serviceBroker) RevokeLocal(ctx context.Context, apiURL, platform string) error {
	if s.development {
		return revokePlatformOverControl(ctx, s.layout, platform)
	}
	_, err := s.runPhase(ctx, connectPhase{APIURL: apiURL, RevokePlatform: platform})
	return err
}

// elevatedPhase is runElevatedPhase; a variable so tests can see the phase a
// command asks for without an administrator prompt.
var elevatedPhase = runElevatedPhase

// runElevatedPhase hands a phase to `contro1 broker register`, elevated unless
// this process already is, and returns what it wrote back. What it wrote back
// is returned with a failure too: it says what happened to the service update.
func runElevatedPhase(ctx context.Context, phase connectPhase) (*connectPhase, error) {
	apiURL := phase.APIURL
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
		args := []string{"broker", "register", "--phase-file", path}
		if apiURL != "" {
			args = append(args, "--api-url", apiURL)
		}
		code, err := installer.RunElevated(args)
		if errors.Is(err, installer.ErrElevationDeclined) {
			// Exit status 1 is also what the elevated phase returns when it ran
			// and failed. Reported as "declined", a real failure sent people to
			// run connect again, which opened a second request. The phase file
			// says which it was.
			if done, _ := readPhaseFile(path); done != nil && done.Error != "" {
				return done, errors.New(done.Error)
			}
		}
		if err != nil {
			return nil, err
		}
		if code != 0 {
			done, _ := readPhaseFile(path)
			if done != nil && done.Error != "" {
				return done, errors.New(done.Error)
			}
			return done, fmt.Errorf("the elevated setup exited with code %d", code)
		}
	}
	done, err := readPhaseFile(path)
	if err != nil {
		return nil, err
	}
	if done.Error != "" {
		return done, errors.New(done.Error)
	}
	return done, nil
}

/*
revokePlatformOverControl revokes, on this computer only, every connection the
service holds for one platform. A service that does not answer has nothing
running to stop, so the mapping it left behind is removed directly.
*/
func revokePlatformOverControl(ctx context.Context, layout brokerpaths.Layout, platform string) error {
	// The platform names a file the elevated phase deletes; only a known one.
	known := false
	for _, p := range platforms.Supported {
		known = known || p == platform
	}
	if !known {
		return fmt.Errorf("unknown platform %q", platform)
	}
	resp, err := controlCall(ctx, layout, "GET", "/control/v1/enrollments", nil)
	if err != nil {
		removeErr := os.Remove(filepath.Join(layout.PlatformsDir, platform+".json"))
		if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return fmt.Errorf("the Contro1 service did not answer (%v) and its mapping could not be removed: %w", err, removeErr)
		}
		return nil
	}
	var errs []error
	for _, raw := range asSlice(resp["enrollments"]) {
		en := asMap(raw)
		if str(en["platform"]) != platform || (str(en["state"]) != "active" && str(en["state"]) != "pending") {
			continue
		}
		if _, err := controlCall(ctx, layout, "POST", "/control/v1/enrollments/"+url.PathEscape(str(en["local_id"]))+"/revoke", map[string]bool{"remote": false}); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// SetPrincipals changes who may reach existing endpoints, through the same one
// elevated step as registration (control is administrators only).
func (s *serviceBroker) SetPrincipals(ctx context.Context, apiURL string, updates []broker.ControlPrincipalUpdate) error {
	if s.development {
		_, err := controlCall(ctx, s.layout, "POST", "/control/v1/principals", map[string]any{"updates": updates})
		return err
	}
	_, err := s.Register(ctx, apiURL, broker.ControlConnectionsRequest{APIURL: apiURL, PrincipalUpdates: updates})
	return err
}

// connectPhase is the only file that carries the connection ticket, for at
// most the few seconds the elevated phase runs. Mode 0600 in the person's own
// profile, deleted on return.
type connectPhase struct {
	APIURL  string                           `json:"api_url"`
	Request broker.ControlConnectionsRequest `json:"request"`
	// RevokePlatform, when set, is disconnect's phase: revoke that platform's
	// connections on this computer and nothing else. No install.
	RevokePlatform string `json:"revoke_platform,omitempty"`
	// UpdateService replaces the installed service's binary with this one
	// (stop, copy, start) before anything else in the phase. Keys, state and
	// mappings are not touched. Alone, with nothing else set, it is the whole
	// phase.
	UpdateService bool `json:"update_service,omitempty"`
	// ServiceVersion is the version the service answered with after the
	// update; ServiceUpdateError is why there was none. An update that fails
	// never fails the rest of the phase: the previous binary is put back.
	ServiceVersion     string                     `json:"service_version,omitempty"`
	ServiceUpdateError string                     `json:"service_update_error,omitempty"`
	Results            []broker.ControlItemResult `json:"results,omitempty"`
	Error              string                     `json:"error,omitempty"`
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
	layout := phaseLayout()
	/*
	 * The update first, so everything after it talks to the new service.
	 *
	 * Disconnect's revoke would work without it: this phase runs in the NEW
	 * CLI, and the control calls it makes (list, revoke) are in every service
	 * version. It still goes first, because only a current service also drops
	 * a connection revoked from Contro1 out of the mapping by itself.
	 */
	if phase.UpdateService {
		version, err := updateInstalledService(ctx, layout, phase.APIURL)
		phase.ServiceVersion = version
		if err != nil {
			phase.ServiceUpdateError = err.Error()
		}
	}
	if phase.RevokePlatform != "" {
		return finish(nil, revokePlatformOverControl(ctx, layout, phase.RevokePlatform))
	}
	if phase.UpdateService && len(phase.Request.Items) == 0 && len(phase.Request.PrincipalUpdates) == 0 {
		var failure error
		if phase.ServiceUpdateError != "" {
			failure = errors.New("the Contro1 service was not updated: " + phase.ServiceUpdateError)
		}
		return finish(nil, failure)
	}
	if installed, running, _, _ := serviceStatus(); !installed || !running {
		exe, _ := os.Executable()
		plan := installer.Plan(runtime.GOOS, installer.Options{SourceBinary: exe, APIURL: phase.APIURL, Version: Version})
		if _, err := installer.Apply(plan, installer.SystemRunner{}, filepath.Join(layout.StateDir, "install-journal.json")); err != nil {
			return finish(nil, err)
		}
	}
	if len(phase.Request.PrincipalUpdates) > 0 {
		_, err := controlCall(ctx, layout, "POST", "/control/v1/principals", map[string]any{"updates": phase.Request.PrincipalUpdates})
		return finish(nil, err)
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

// phaseLayout, serviceStatus and updateInstalledService are what the elevated
// phase acts on; variables so tests run it against a temporary layout and a
// fake service, never this computer's.
var (
	phaseLayout            = func() brokerpaths.Layout { return brokerpaths.Production(runtime.GOOS) }
	serviceStatus          = installer.ServiceStatus
	updateInstalledService = updateServiceBinary
)

/*
updateServiceBinary runs the install step on an installed service: stop it,
copy this binary over its own, start it, then wait until it answers on its
control endpoint as this version. Keys, connections and mappings stay as they
are; the install step never touches them.

The service keeps the Contro1 address it already has. disconnect runs this
without one, and on Linux and macOS the step rewrites the service definition,
so a definition without --api-url would have dropped it.
*/
func updateServiceBinary(ctx context.Context, layout brokerpaths.Layout, apiURL string) (string, error) {
	if health, err := controlCall(ctx, layout, "GET", "/control/v1/health", nil); err == nil && str(health["api_url"]) != "" {
		apiURL = str(health["api_url"])
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	plan := installer.Plan(runtime.GOOS, installer.Options{SourceBinary: exe, APIURL: apiURL, Version: Version})
	if _, err := installer.Apply(plan, installer.SystemRunner{}, filepath.Join(layout.StateDir, "install-journal.json")); err != nil {
		return "", err
	}
	return waitForServiceVersion(ctx, layout, Version, 45*time.Second)
}

// waitForServiceVersion is the check that the update worked: the service is
// back and is the version that was installed, not merely a file copied.
func waitForServiceVersion(ctx context.Context, layout brokerpaths.Layout, want string, within time.Duration) (string, error) {
	deadline := time.Now().Add(within)
	last := ""
	for {
		health, err := controlCall(ctx, layout, "GET", "/control/v1/health", nil)
		if err == nil {
			last = str(health["version"])
			if last == want {
				return last, nil
			}
		}
		if time.Now().After(deadline) {
			if last != "" {
				return last, fmt.Errorf("the Contro1 service came back as %s, not %s", last, want)
			}
			return "", fmt.Errorf("the Contro1 service did not answer within %s after the update", within)
		}
		select {
		case <-ctx.Done():
			return last, ctx.Err()
		case <-time.After(time.Second):
		}
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

// RuntimeStatus returns who the endpoint speaks as and what the SERVER says
// this connection may do. The second one is not in the mapping file: that is
// written when the agent is connected and an owner widens a connection later.
func (endpointVerifier) RuntimeStatus(_ context.Context, e runtimeproto.MappingEntry) (string, string, error) {
	c, err := endpointClient(e)
	if err != nil {
		return "", "", err
	}
	resp, err := c.Do("GET", "/api/centcom/v1/runtime/status", nil)
	if err != nil {
		return "", "", err
	}
	auth := asMap(resp["auth"])
	return str(auth["agent_id"]), str(auth["endpoint_mode"]), nil
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

func (p terminalPrompt) Terminal() bool {
	return isTerminal(os.Stdin)
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

/*
Progress goes to stderr, so stdout stays the one JSON result.

IN JSON MODE IT IS NOT DROPPED. That mode is how a coding assistant runs
connect, and it used to print nothing until the end: the approval link went
nowhere, the assistant waited out its own timeout, and nobody approved
anything. Each line is a small JSON object instead. The approval line is
printed even with --quiet, because without it nothing can finish.
*/
func (p terminalPrompt) Progress(line string) {
	if !p.json {
		if !flagQuiet {
			fmt.Fprintln(os.Stderr, line)
		}
		return
	}
	if flagQuiet && !strings.HasPrefix(line, "Approve at ") {
		return
	}
	encoded, _ := json.Marshal(map[string]string{"progress": line})
	fmt.Fprintln(os.Stderr, string(encoded))
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
	opts := platforms.Options{Bin: flagConnectBin, ConfigDir: flagConnectConfigDir, Principal: flagConnectPrincipal, Agents: flagConnectAgents}
	if flagConnectDevelopment {
		// The development service publishes its own mappings; identity must
		// be read from the service this connection actually uses.
		opts.PlatformsDir = brokerpaths.Development().PlatformsDir
	}
	return opts
}
