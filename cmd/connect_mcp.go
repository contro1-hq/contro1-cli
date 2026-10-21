package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/contro1-hq/contro1-cli/internal/localipc"
	"github.com/contro1-hq/contro1-cli/internal/mcpbridge"
	"github.com/contro1-hq/contro1-cli/internal/platforms"
	"github.com/contro1-hq/contro1-cli/internal/runtimeproto"
)

/*
connectMcp is the last step of `contro1 connect`: the Contro1 MCP server.

Claude Code and OpenClaw install it themselves (platforms.McpInstaller), the
same code `apps enable` runs. NanoClaw's step needs Contro1 too: a lease its
owner approved, held in OneCLI and granted to that one agent. So it runs the
`apps enable` steps as they are, and only once the owner has allowed
applications; before that it names the page where they do.
*/
type connectMcp struct {
	platform string
	adapter  platforms.Adapter
	progress func(string)
	// nano stands in for Contro1, OneCLI and ncl in tests; nil is the system.
	nano *nanoMcpDeps
}

func (m connectMcp) Changes(ctx context.Context, subjects []string) []platforms.Change {
	if installer, ok := m.adapter.(platforms.McpInstaller); ok {
		return installer.McpChanges(ctx, subjects)
	}
	if m.platform != "nanoclaw" {
		return nil
	}
	var out []platforms.Change
	seen := map[string]bool{}
	for _, s := range subjects {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, platforms.Change{Kind: "credential", Description: "Once its owner allows applications: ask Contro1 for a credential for " + s + " and give it to OneCLI for that agent only"})
		out = append(out, m.adapter.ApplicationChanges(platforms.LocalConnection{Platform: m.platform, PlatformSubject: s})...)
	}
	return out
}

func (m connectMcp) Install(ctx context.Context, mapping *runtimeproto.MappingFile, j *platforms.Journal) (platforms.McpOutcome, error) {
	if installer, ok := m.adapter.(platforms.McpInstaller); ok {
		subjects := make([]string, 0, len(mapping.Entries))
		for _, e := range mapping.Entries {
			subjects = append(subjects, e.PlatformSubject)
		}
		return installer.InstallMcp(ctx, subjects, j)
	}
	var out platforms.McpOutcome
	if m.platform != "nanoclaw" {
		return out, nil
	}
	deps := m.nano
	if deps == nil {
		deps = systemNanoMcpDeps()
	}
	for _, e := range mapping.Entries {
		conn := platforms.LocalConnection{Platform: mapping.Platform, PlatformSubject: e.PlatformSubject, DisplayName: e.DisplayName,
			AgentID: e.AgentID, EnrollmentID: e.EnrollmentID, EndpointMode: e.EndpointMode, Endpoint: e.Endpoint}
		if err := installNanoClawMcp(ctx, conn, deps, m.adapter, m.progress, j, &out); err != nil {
			return out, err
		}
	}
	return out, nil
}

/*
nanoMcpDeps is what the NanoClaw MCP step touches, so a test can stand in for
Contro1, OneCLI and ncl.

WHY THE STEP CHECKS BEFORE IT ACTS. connect runs to the end on every run,
--repair and --resume included. Taking the `apps enable` steps as they were
minted a new lease, rewrote OneCLI and restarted every group each time, which
interrupts whatever the agents were doing for nothing. Now a lease that is
still valid and held by OneCLI is kept, a group whose config already points at
Contro1 is left alone, and only a group that changed is restarted.
*/
type nanoMcpDeps struct {
	status       func(ctx context.Context, conn platforms.LocalConnection) (runtimeStatus, error)
	hasOnecli    func() bool
	leaseValid   func(ctx context.Context, subject string) bool
	configHasURL func(ctx context.Context, subject string) bool
	provision    func(ctx context.Context, conn platforms.LocalConnection, progress func(string)) error
}

func systemNanoMcpDeps() *nanoMcpDeps {
	return &nanoMcpDeps{
		status: fetchRuntimeStatus,
		hasOnecli: func() bool {
			_, err := exec.LookPath("onecli")
			return err == nil
		},
		leaseValid:   nanoLeaseStillValid,
		configHasURL: nanoConfigHasContro1URL,
		provision:    provisionNanoClawLease,
	}
}

func installNanoClawMcp(ctx context.Context, conn platforms.LocalConnection, deps *nanoMcpDeps, adapter platforms.Adapter, progress func(string), j *platforms.Journal, out *platforms.McpOutcome) error {
	next := "contro1 apps enable nanoclaw --agent " + conn.PlatformSubject
	status, err := deps.status(ctx, conn)
	if err != nil {
		// The connection itself succeeded; not knowing the mode is a step to
		// retry, not a failed connect.
		out.ToDo = append(out.ToDo, fmt.Sprintf("Applications for %s: could not ask its Contro1 service whether applications are allowed (%v). Run: %s", displayOf(conn), err, next))
		return nil
	}
	if status.EndpointMode != runtimeproto.ModeApplications {
		// The owner's decision, never taken here.
		out.ToDo = append(out.ToDo, fmt.Sprintf("Applications for %s: its owner allows them in Contro1 (%s/agents/setup?ids=%s), then run: %s", displayOf(conn), frontendURL(), conn.AgentID, next))
		return nil
	}
	if !deps.hasOnecli() {
		out.ToDo = append(out.ToDo, "Applications for "+displayOf(conn)+": install OneCLI on this host, then run: "+next)
		return nil
	}
	leaseOK := deps.leaseValid(ctx, conn.PlatformSubject)
	configOK := deps.configHasURL(ctx, conn.PlatformSubject)
	if leaseOK && configOK {
		out.Done = append(out.Done, displayOf(conn)+" already has the Contro1 MCP server and a valid credential in OneCLI.")
		return nil
	}
	if !leaseOK {
		if err := deps.provision(ctx, conn, progress); err != nil {
			return err
		}
	}
	if !configOK {
		// Writes the group's server and restarts that one group.
		if err := adapter.ApplyApplications(ctx, conn, j); err != nil {
			return err
		}
	}
	out.Done = append(out.Done, "Set up the Contro1 MCP server for "+displayOf(conn)+".")
	return nil
}

// nanoLeaseStillValid: the lease recorded for this group is not due for
// renewal and OneCLI still holds a Contro1 credential for it.
func nanoLeaseStillValid(ctx context.Context, subject string) bool {
	path, err := nanoLeasePath()
	if err != nil {
		return false
	}
	state, err := loadNanoLeases(path)
	if err != nil {
		return false
	}
	for _, l := range state.Leases {
		if l.Subject != subject || renewDue(l, time.Now()) {
			continue
		}
		u, err := url.Parse(mcpURL())
		if err != nil || u.Hostname() == "" {
			return false
		}
		return len(staleOnecliLeases(ctx, subject, u.Hostname(), u.Path, "", runOnecliCommand)) > 0
	}
	return false
}

// nanoConfigHasContro1URL: the group's config already has a server named
// contro1 at this Contro1's MCP address, and nothing else under that name.
func nanoConfigHasContro1URL(ctx context.Context, subject string) bool {
	servers, err := nanoclawMcpServers(ctx, subject)
	if err != nil {
		return false
	}
	found := false
	for _, s := range servers {
		if strings.EqualFold(s.Name, "contro1") {
			if s.URL != mcpURL() || s.Command != "" {
				return false
			}
			found = true
		}
	}
	return found
}

// nclCommand is the ncl a person pointed connect at, or the default one.
func nclCommand() string {
	if flagConnectBin != "" {
		return flagConnectBin
	}
	return nclBinary()
}

// nanoclawMcpServers reads a group's MCP servers from `ncl groups config get`.
func nanoclawMcpServers(ctx context.Context, subject string) ([]platforms.McpServer, error) {
	out, err := platforms.ExecRunner(ctx, nclCommand(), "groups", "config", "get", "--id", subject, "--json")
	if err != nil {
		return nil, err
	}
	var frame struct {
		OK   bool `json:"ok"`
		Data struct {
			McpServers []struct {
				Name    string   `json:"name"`
				Command string   `json:"command"`
				Args    []string `json:"args"`
				URL     string   `json:"url"`
			} `json:"mcp_servers"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out, &frame); err != nil || !frame.OK {
		return nil, errors.New("could not read the platform's MCP configuration")
	}
	servers := make([]platforms.McpServer, 0, len(frame.Data.McpServers))
	for _, s := range frame.Data.McpServers {
		servers = append(servers, platforms.McpServer{Name: s.Name, Command: s.Command, Args: s.Args, URL: s.URL})
	}
	return servers, nil
}

func (m connectMcp) Probe(ctx context.Context, e runtimeproto.MappingEntry) (int, error) {
	return probeAgentMcp(ctx, e)
}

// probeAgentMcp asks the agent's own endpoint, as `contro1 mcp serve` would,
// with the same server-identity check as every other call to it.
func probeAgentMcp(ctx context.Context, e runtimeproto.MappingEntry) (int, error) {
	ep, err := localipc.ParseEndpoint(e.Endpoint)
	if err != nil {
		return 0, err
	}
	principal := localipc.Principal(e.ServerPrincipal)
	if p := strings.TrimSpace(os.Getenv("CONTRO1_BROKER_PRINCIPAL")); p != "" {
		principal = localipc.Principal(p)
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	return mcpbridge.Probe(ctx, localipc.HTTPClient(ep, principal), localipc.BaseURL)
}
