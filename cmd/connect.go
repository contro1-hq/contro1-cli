package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/contro1-hq/contro1-cli/internal/brokerpaths"
	"github.com/contro1-hq/contro1-cli/internal/connect"
	"github.com/contro1-hq/contro1-cli/internal/doctor"
	"github.com/contro1-hq/contro1-cli/internal/output"
	"github.com/contro1-hq/contro1-cli/internal/platforms"
	"github.com/contro1-hq/contro1-cli/internal/runtimeproto"
)

var (
	flagConnectOwner        string
	flagConnectResume       string
	flagConnectNoWait       bool
	flagConnectYes          bool
	flagConnectConfirmRoles bool
	flagConnectTest         bool
	flagConnectRepair       bool
	flagConnectDevelopment  bool
	flagConnectBin          string
	flagConnectConfigDir    string
	flagConnectPrincipal    string
	flagConnectAgents       []string
	flagDisconnectRemote    bool
	flagDisconnectLocalOnly bool
	flagDisconnectDryRun    bool
	flagPhaseFile           string
)

var connectCmd = &cobra.Command{
	Use:     "connect <openclaw|nanoclaw|claude-code|cursor|codex>",
	Short:   "Connect the agents on this computer to Contro1, approved by their owner",
	GroupID: groupAgent,
	Long: `Finds the agents on this computer, asks their accountable owner to approve
them once, sets up the Contro1 service, and points the platform at it.

Re-running is safe: it repairs what drifted and never creates duplicates.
With --format json every result is a next-step object for automation.`,
	Args:      cobra.ExactArgs(1),
	ValidArgs: platforms.Supported,
	RunE:      runConnect,
}

var disconnectCmd = &cobra.Command{
	Use:     "disconnect <openclaw|nanoclaw|claude-code|cursor|codex>",
	Short:   "Disconnect this computer's agents from Contro1",
	GroupID: groupAgent,
	Args:    cobra.ExactArgs(1),
	RunE:    runDisconnect,
}

var connectionStatusCmd = &cobra.Command{
	Use:     "status [openclaw|nanoclaw|claude-code|cursor|codex]",
	Short:   "Show whether each connected agent is ready, with the next step",
	GroupID: groupAgent,
	Args:    cobra.MaximumNArgs(1),
	RunE:    runConnectionStatus,
}

var brokerRegisterCmd = &cobra.Command{
	Use:    "register",
	Short:  "Internal: elevated phase of contro1 connect",
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		if flagPhaseFile == "" {
			return output.Errf(output.CodeBadArgs, "--phase-file is required")
		}
		if err := runRegisterPhase(cmd.Context(), flagPhaseFile); err != nil {
			return output.Errf(output.CodeGeneral, "%v", err)
		}
		return nil
	},
}

func init() {
	for _, c := range []*cobra.Command{connectCmd, disconnectCmd, connectionStatusCmd} {
		c.Flags().BoolVar(&flagConnectDevelopment, "development", false, "use a foreground development Contro1 service (not for production agents)")
		// Ours, for working on the CLI itself: nobody connecting an agent needs it.
		_ = c.Flags().MarkHidden("development")
		c.Flags().StringVar(&flagConnectBin, "platform-cli", "", "platform CLI to use (openclaw, ncl or codex path)")
		c.Flags().StringVar(&flagConnectConfigDir, "platform-config-dir", "", "where the platform's Contro1 settings are (for cursor and codex: the folder holding mcp.json or config.toml)")
	}
	connectCmd.Flags().StringVar(&flagConnectOwner, "owner", "", "accountable owner's email (default: you)")
	connectCmd.Flags().StringVar(&flagConnectResume, "resume", "", "continue a connection that is waiting (con_...)")
	connectCmd.Flags().BoolVar(&flagConnectNoWait, "no-wait", false, "return while the owner has not approved yet")
	connectCmd.Flags().BoolVar(&flagConnectYes, "yes", false, "confirm the local changes (never covers NanoClaw role changes)")
	connectCmd.Flags().BoolVar(&flagConnectConfirmRoles, "confirm-roles", false, "confirm NanoClaw role changes (needs a terminal)")
	connectCmd.Flags().BoolVar(&flagConnectTest, "test", false, "only run the no-side-effect checks for connected agents")
	connectCmd.Flags().BoolVar(&flagConnectRepair, "repair", false, "re-apply platform settings and restart what drifted")
	connectCmd.Flags().StringVar(&flagConnectPrincipal, "principal", "", "operating system identity the platform runs as (default: you)")
	connectCmd.Flags().StringArrayVar(&flagConnectAgents, "agent", nil, "platform agent or group id to connect (repeatable; skips discovery)")
	disconnectCmd.Flags().BoolVar(&flagDisconnectRemote, "revoke-remote", true, "also revoke the connections in Contro1")
	disconnectCmd.Flags().BoolVar(&flagDisconnectLocalOnly, "local-only", false, "only remove this computer's settings, endpoints and mapping; leave the connections in Contro1")
	disconnectCmd.Flags().BoolVar(&flagDisconnectDryRun, "dry-run", false, "show what would be removed")
	disconnectCmd.Flags().BoolVar(&flagConnectYes, "yes", false, "also remove the Contro1 MCP server connect installed, without asking")
	brokerRegisterCmd.Flags().StringVar(&flagPhaseFile, "phase-file", "", "phase file written by contro1 connect")
	brokerCmd.AddCommand(brokerRegisterCmd)
	rootCmd.AddCommand(connectCmd, disconnectCmd, connectionStatusCmd)
}

func connectFormatJSON() bool { return flagFormat == "json" }

func renderNextStep(ns runtimeproto.NextStep) error {
	code := connect.ExitCode(ns, flagConnectNoWait)
	if connectFormatJSON() {
		raw, _ := json.MarshalIndent(ns, "", "  ")
		fmt.Println(string(raw))
	} else {
		mark := map[string]string{runtimeproto.StateConnected: "✓", runtimeproto.StateWaitingForOwner: "→"}[ns.State]
		if mark == "" {
			mark = "!"
		}
		fmt.Printf("%s %s\n", mark, ns.Message)
		if ns.ShareThisLink != "" {
			if ns.UserCode != "" {
				fmt.Printf("  Approve at %s   Code: %s\n", ns.ShareThisLink, ns.UserCode)
			} else {
				fmt.Printf("  Approve at %s\n", ns.ShareThisLink)
			}
		}
		for _, c := range ns.Checks {
			if c.Status != runtimeproto.CheckOK {
				fmt.Printf("  - %s\n", c.Message)
			}
		}
		if ns.NextCommand != "" && ns.State != runtimeproto.StateConnected {
			fmt.Printf("  Next: %s\n", ns.NextCommand)
		}
	}
	if code != 0 {
		return &output.ExitError{Code: code, Msg: ns.Message, Remediation: ns.Remediation}
	}
	return nil
}

func runConnect(cmd *cobra.Command, args []string) error {
	platform := args[0]
	popts := platformOptions()
	// NanoClaw's MCP step points the agent at Contro1 by URL.
	popts.McpURL = mcpURL()
	adapter, err := platforms.New(platform, popts)
	if err != nil {
		return output.Errf(output.CodeBadArgs, "%v", err)
	}
	if flagConnectTest {
		return runDoctorPlatform(cmd, platform)
	}
	if invoker := sudoInvoker(); invoker != "" {
		// Run as root, connect would record root as the only identity allowed
		// to reach the agents, keep its state where the person cannot resume
		// it, and run the platform CLI without their PATH. It asks for
		// administrator approval itself, for the one step that needs it.
		ns := runtimeproto.NextStep{SchemaVersion: runtimeproto.SchemaVersion, State: runtimeproto.StateBlocked, Platform: platform,
			Message:     "Run contro1 connect as " + invoker + ", without sudo. It asks for administrator approval itself when it sets up the Contro1 service.",
			NextCommand: "contro1 connect " + platform}
		return renderNextStep(ns)
	}
	c, pr, err := newClient()
	if err != nil {
		ns := runtimeproto.NextStep{SchemaVersion: runtimeproto.SchemaVersion, State: runtimeproto.StateBlocked, Platform: platform, Message: "Sign in to Contro1 on this computer first.", NextCommand: "contro1 auth login"}
		return renderNextStep(ns)
	}
	apiURL := pr.APIURL
	if flagAPIURL != "" {
		apiURL = flagAPIURL
	}
	printDevelopmentServerNote(os.Stderr, flagAPIURL)
	host, _ := os.Hostname()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	prompt := terminalPrompt{json: connectFormatJSON()}
	o := &connect.Orchestrator{
		API:      connectAPI{c: c},
		Broker:   newServiceBroker(flagConnectDevelopment),
		Verifier: endpointVerifier{},
		Adapter:  adapter,
		Prompt:   prompt,
		States:   fileStates{},
		Mcp:      connectMcp{platform: platform, adapter: adapter, progress: prompt.Progress},
	}
	ns := o.Run(ctx, connect.Options{
		Platform: platform, APIURL: strings.TrimRight(apiURL, "/"), Owner: flagConnectOwner, Resume: flagConnectResume,
		NoWait: flagConnectNoWait, Yes: flagConnectYes, Agents: flagConnectAgents, ConfirmRoles: flagConnectConfirmRoles, Development: flagConnectDevelopment,
		Repair: flagConnectRepair, Principal: flagConnectPrincipal, HostLabel: host, HostOS: runtime.GOOS, HostArch: runtime.GOARCH, WaitTimeout: 11 * time.Minute,
	})
	return renderNextStep(ns)
}

// ---------------------------------------------------------------------------
// status: five checks per agent
// ---------------------------------------------------------------------------

func mappingPathsFor(platform string) []string {
	layout := brokerpaths.Production(runtime.GOOS)
	if flagConnectDevelopment {
		layout = brokerpaths.Development()
	}
	if platform != "" {
		return []string{layout.PlatformsDir + string(os.PathSeparator) + platform + ".json"}
	}
	var out []string
	for _, p := range platforms.Supported {
		out = append(out, layout.PlatformsDir+string(os.PathSeparator)+p+".json")
	}
	return out
}

func runConnectionStatus(cmd *cobra.Command, args []string) error {
	platform := ""
	if len(args) == 1 {
		platform = args[0]
	}
	type agentStatus struct {
		Platform string               `json:"platform"`
		Subject  string               `json:"platform_subject"`
		AgentID  string               `json:"agent_id"`
		Checks   []runtimeproto.Check `json:"checks"`
	}
	var agents []agentStatus
	var ids []string
	byAgent := map[string]*agentStatus{}
	for _, path := range mappingPathsFor(platform) {
		m, err := platforms.ReadMapping(path)
		if err != nil {
			continue
		}
		for _, e := range m.Entries {
			agents = append(agents, agentStatus{Platform: m.Platform, Subject: e.PlatformSubject, AgentID: e.AgentID})
			ids = append(ids, e.AgentID)
		}
	}
	for i := range agents {
		byAgent[agents[i].AgentID] = &agents[i]
	}
	if len(agents) == 0 {
		ns := runtimeproto.NextStep{SchemaVersion: runtimeproto.SchemaVersion, State: runtimeproto.StateBlocked, Platform: platform, Message: "No agents are connected on this computer.", NextCommand: "contro1 connect <openclaw|nanoclaw|claude-code|cursor|codex>"}
		return renderNextStep(ns)
	}

	if c, _, err := newClient(); err == nil {
		if resp, err := c.Do("GET", runtimeproto.ConnectionsStatusPath+"?agent_ids="+strings.Join(ids, ","), nil); err == nil {
			for _, raw := range asSlice(resp["agents"]) {
				a := asMap(raw)
				target := byAgent[str(a["agent_id"])]
				if target == nil {
					continue
				}
				for _, rc := range asSlice(a["checks"]) {
					ch := asMap(rc)
					status := map[string]string{"done": runtimeproto.CheckOK, "waiting": runtimeproto.CheckWaiting, "missing": runtimeproto.CheckRepairable, "not_applicable": runtimeproto.CheckNotApplicable}[str(ch["state"])]
					target.Checks = append(target.Checks, runtimeproto.Check{ID: str(ch["id"]), Label: str(ch["label"]), Status: status, Message: str(ch["detail"]), NextCommand: str(ch["next_step"]), ActionURL: str(ch["action_url"])})
				}
			}
		}
	}
	// Not signed in, or the server did not answer: check through each endpoint.
	for _, path := range mappingPathsFor(platform) {
		m, err := platforms.ReadMapping(path)
		if err != nil {
			continue
		}
		for _, e := range m.Entries {
			target := byAgent[e.AgentID]
			if target == nil || len(target.Checks) > 0 {
				continue
			}
			// The mode the server reports, not the one the mapping file was
			// written with: an owner widens a connection after it is connected.
			if agentID, liveMode, err := (endpointVerifier{}).RuntimeStatus(cmd.Context(), e); err == nil && agentID == e.AgentID {
				mode := liveMode
				if mode == "" {
					mode = e.EndpointMode
				}
				target.Checks = append(target.Checks, runtimeproto.Check{ID: "connected_securely", Label: "Connected securely", Status: runtimeproto.CheckOK, Message: runtimeproto.ModeLabel(mode)})
			} else {
				msg := "not reachable"
				if err != nil {
					msg = err.Error()
				}
				target.Checks = append(target.Checks, runtimeproto.Check{ID: "connected_securely", Label: "Connected securely", Status: runtimeproto.CheckRepairable, Message: msg, NextCommand: "contro1 doctor " + m.Platform})
			}
		}
	}
	if connectFormatJSON() {
		return output.Render("json", map[string]any{"schema_version": 1, "agents": agents}, nil)
	}
	for _, a := range agents {
		fmt.Printf("%s (%s)\n", a.Subject, a.Platform)
		for i, c := range a.Checks {
			mark := map[string]string{runtimeproto.CheckOK: "✓", runtimeproto.CheckNotApplicable: "-", runtimeproto.CheckWaiting: "…"}[c.Status]
			if mark == "" {
				mark = "!"
			}
			fmt.Printf("  %d. %s %s: %s\n", i+1, mark, c.Label, c.Message)
			if c.NextCommand != "" && c.Status != runtimeproto.CheckOK && c.Status != runtimeproto.CheckNotApplicable {
				fmt.Printf("     Next: %s\n", c.NextCommand)
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// disconnect
// ---------------------------------------------------------------------------

func runDisconnect(cmd *cobra.Command, args []string) error {
	platform := args[0]
	adapter, err := platforms.New(platform, platformOptions())
	if err != nil {
		return output.Errf(output.CodeBadArgs, "%v", err)
	}
	ctx := cmd.Context()
	paths := mappingPathsFor(platform)
	m, _ := platforms.ReadMapping(paths[0])
	st, _ := fileStates{}.Load(platform)
	preview := map[string]any{"platform": platform, "mapping_file": paths[0]}
	var subjects []string
	if m != nil {
		for _, e := range m.Entries {
			subjects = append(subjects, e.PlatformSubject)
		}
		preview["agents"] = subjects
	}
	if len(subjects) == 0 {
		// Nothing published any more (an older disconnect, or the service
		// already dropped it): the MCP entry may still name this computer's
		// agent, so it is looked for by the subject connect would use.
		if _, found, err := adapter.Discover(ctx); err == nil {
			for _, s := range found {
				subjects = append(subjects, s.ID)
			}
		}
	}
	if st != nil {
		preview["settings_to_remove"] = st.Journal.CreatedFiles
		preview["settings_kept"] = st.Journal.WrittenFiles
	}
	remover, _ := adapter.(platforms.McpRemover)
	var mcpChanges []platforms.Change
	if remover != nil && len(subjects) > 0 {
		mcpChanges = remover.McpRemovalChanges(ctx, subjects)
	}
	var mcpLines []string
	for _, c := range mcpChanges {
		line := c.Description
		if c.Before != "" {
			line += " (now: " + c.Before + ")"
		}
		if c.After != "" {
			line += ": " + c.After
		}
		mcpLines = append(mcpLines, line)
	}
	preview["mcp_to_remove"] = mcpLines
	preview["revoke_in_contro1"] = !flagDisconnectLocalOnly && flagDisconnectRemote
	// An old service is updated in the same approval the revoke asks for. The
	// revoke itself does not need it (see runRegisterPhase); a current service
	// also keeps the mapping right by itself afterwards.
	service := newServiceBroker(flagConnectDevelopment)
	updateLine := ""
	if m != nil && len(m.Entries) > 0 {
		updateLine = service.PendingServiceUpdate()
	}
	if updateLine != "" {
		preview["service_update"] = updateLine
	}
	if flagDisconnectDryRun {
		if connectFormatJSON() {
			return output.Render("json", preview, nil)
		}
		fmt.Printf("Disconnecting %s would:\n", platform)
		if m != nil && len(m.Entries) > 0 {
			fmt.Printf("  - stop the endpoints for: %s, and remove them from this computer's Contro1 service\n", strings.Join(preview["agents"].([]string), ", "))
		}
		if st != nil {
			for _, f := range st.Journal.CreatedFiles {
				fmt.Printf("  - remove %s\n", f)
			}
		}
		for _, l := range mcpLines {
			fmt.Printf("  - %s (asks first; --yes to skip the question)\n", l)
		}
		if preview["revoke_in_contro1"] == true && m != nil {
			fmt.Println("  - revoke these connections in Contro1 (the agents and their history stay)")
		}
		if updateLine != "" {
			fmt.Printf("  - %s, in the same administrator approval\n", lowerFirst(updateLine))
		}
		fmt.Println("  The Contro1 service stays installed while other platforms use it.")
		return nil
	}

	// Asked before anything changes, so a "no" leaves a consistent state.
	removeMcp := false
	if len(mcpChanges) > 0 {
		prompt := terminalPrompt{json: connectFormatJSON()}
		removeMcp = flagConnectYes || (prompt.Interactive() && prompt.Confirm("Also remove the Contro1 MCP server that connect installed?", mcpLines))
	}

	var problems []string
	if m != nil && len(m.Entries) > 0 && !flagDisconnectLocalOnly && flagDisconnectRemote {
		c, _, err := newClient()
		if err != nil {
			return output.Errf(output.CodeAuth, "sign in with contro1 auth login to revoke in Contro1, or use --local-only")
		}
		for _, e := range m.Entries {
			if _, err := c.Do("POST", "/api/centcom/v1/runtime/connections/enrollments/"+e.EnrollmentID+"/revoke", map[string]string{"reason": "disconnected_from_host"}); err != nil {
				problems = append(problems, e.PlatformSubject+": "+err.Error())
			}
		}
	}
	/*
	 * Then this computer's side: the service stops the endpoints, deletes the
	 * keys and republishes the mapping without these agents. Without it the
	 * mapping kept naming a revoked agent and `contro1 mcp serve` kept choosing
	 * it. In production the mapping is the service's, so this is the one
	 * administrator approval disconnect asks for.
	 */
	if m != nil && len(m.Entries) > 0 {
		if !flagConnectDevelopment {
			msg := fmt.Sprintf("Removing %s from the Contro1 service on this computer. It asks for administrator approval.", platform)
			if updateLine != "" {
				msg += " The same approval also does this: " + lowerFirst(updateLine) + "."
			}
			output.Info("%s", msg)
		}
		if err := service.RevokeLocal(ctx, "", platform); err != nil {
			problems = append(problems, fmt.Sprintf("the Contro1 service on this computer still lists %s (%v). Run contro1 disconnect %s --local-only and approve the administrator prompt", platform, err, platform))
		}
		if done, err := service.ServiceUpdateResult(); err != nil {
			output.Info("The Contro1 service was not updated: %v", err)
		} else if done != "" {
			output.Info("%s", done)
		}
	}
	journal := &platforms.Journal{}
	if st != nil {
		journal = &st.Journal
	}
	switch {
	case removeMcp:
		outcome, err := remover.RemoveMcp(ctx, subjects, journal)
		for _, line := range outcome.Done {
			output.Info("%s", line)
		}
		for _, line := range outcome.ToDo {
			output.Info("Still to do: %s", line)
		}
		if err != nil {
			problems = append(problems, "MCP server: "+err.Error())
		}
	case len(mcpChanges) > 0:
		for _, l := range mcpLines {
			output.Info("Kept: %s. To remove it later, run contro1 disconnect %s --yes, or remove it yourself.", l, platform)
		}
	}
	if st != nil {
		if err := adapter.RemoveConfig(ctx, &st.Journal); err != nil {
			problems = append(problems, err.Error())
		}
		_ = fileStates{}.Clear(platform)
	}
	if len(problems) > 0 {
		return output.Errf(output.CodeGeneral, "disconnected with problems: %s", strings.Join(problems, "; "))
	}
	output.Info("Disconnected %s on this computer.", platform)
	return nil
}

// ---------------------------------------------------------------------------
// doctor <platform>
// ---------------------------------------------------------------------------

func runDoctorPlatform(cmd *cobra.Command, platform string) error {
	adapter, err := platforms.New(platform, platformOptions())
	if err != nil {
		return output.Errf(output.CodeBadArgs, "%v", err)
	}
	env := newSystemDoctorEnv(adapter, flagConnectDevelopment)
	report := doctor.Run(cmd.Context(), env, platform)
	if connectFormatJSON() {
		if err := output.Render("json", report, nil); err != nil {
			return err
		}
	} else {
		fmt.Printf("Contro1 doctor: %s is %s\n", platform, report.State)
		for _, c := range report.Checks {
			mark := map[string]string{runtimeproto.CheckOK: "✓", runtimeproto.CheckRepairable: "!", runtimeproto.CheckBlocked: "✗", runtimeproto.CheckNotApplicable: "-", runtimeproto.CheckWaiting: "…"}[c.Status]
			fmt.Printf("  %s %s: %s\n", mark, c.Label, c.Message)
			if c.Status != runtimeproto.CheckOK && c.NextCommand != "" {
				fmt.Printf("    Next (%s): %s\n", orDefault(c.Actor, "you"), c.NextCommand)
			}
		}
	}
	switch report.State {
	case "blocked":
		return &output.ExitError{Code: output.CodeInsufficient, Msg: "blocked"}
	case "repairable":
		return &output.ExitError{Code: output.CodeGeneral, Msg: "repairable"}
	}
	return nil
}

// lowerFirst puts a sentence in the middle of another one.
func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

func orDefault(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}
