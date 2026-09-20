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
	Use:     "connect <openclaw|nanoclaw|claude-code>",
	Short:   "Connect the agents on this computer to Contro1, approved by their owner",
	GroupID: groupAgent,
	Long: `Finds the agents on this computer, asks their accountable owner to approve
them once, sets up the Contro1 service, and points the platform at it.

Re-running is safe: it repairs what drifted and never creates duplicates.
With --format json every result is a next-step object for automation.`,
	Args:      cobra.ExactArgs(1),
	ValidArgs: []string{"openclaw", "nanoclaw", "claude-code"},
	RunE:      runConnect,
}

var disconnectCmd = &cobra.Command{
	Use:     "disconnect <openclaw|nanoclaw|claude-code>",
	Short:   "Disconnect this computer's agents from Contro1",
	GroupID: groupAgent,
	Args:    cobra.ExactArgs(1),
	RunE:    runDisconnect,
}

var connectionStatusCmd = &cobra.Command{
	Use:     "status [openclaw|nanoclaw|claude-code]",
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
		c.Flags().StringVar(&flagConnectBin, "platform-cli", "", "platform CLI to use for discovery (openclaw or ncl path)")
		c.Flags().StringVar(&flagConnectConfigDir, "platform-config-dir", "", "where to write the platform's Contro1 settings")
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
	disconnectCmd.Flags().BoolVar(&flagDisconnectLocalOnly, "local-only", false, "only remove local settings and endpoints")
	disconnectCmd.Flags().BoolVar(&flagDisconnectDryRun, "dry-run", false, "show what would be removed")
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
		if ns.UserCode != "" {
			fmt.Printf("  Approve at %s   Code: %s\n", ns.ShareThisLink, ns.UserCode)
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
	adapter, err := platforms.New(platform, platformOptions())
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
	host, _ := os.Hostname()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	o := &connect.Orchestrator{
		API:      connectAPI{c: c},
		Broker:   newServiceBroker(flagConnectDevelopment),
		Verifier: endpointVerifier{},
		Adapter:  adapter,
		Prompt:   terminalPrompt{json: connectFormatJSON()},
		States:   fileStates{},
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
	for _, p := range []string{"openclaw", "nanoclaw", "claude-code"} {
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
		ns := runtimeproto.NextStep{SchemaVersion: runtimeproto.SchemaVersion, State: runtimeproto.StateBlocked, Platform: platform, Message: "No agents are connected on this computer.", NextCommand: "contro1 connect <openclaw|nanoclaw|claude-code>"}
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
			if agentID, err := (endpointVerifier{}).RuntimeStatus(cmd.Context(), e); err == nil && agentID == e.AgentID {
				target.Checks = append(target.Checks, runtimeproto.Check{ID: "connected_securely", Label: "Connected securely", Status: runtimeproto.CheckOK, Message: runtimeproto.ModeLabel(e.EndpointMode)})
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
	paths := mappingPathsFor(platform)
	m, _ := platforms.ReadMapping(paths[0])
	st, _ := fileStates{}.Load(platform)
	preview := map[string]any{"platform": platform, "mapping_file": paths[0]}
	if m != nil {
		var subjects []string
		for _, e := range m.Entries {
			subjects = append(subjects, e.PlatformSubject)
		}
		preview["agents"] = subjects
	}
	if st != nil {
		preview["settings_to_remove"] = st.Journal.CreatedFiles
		preview["settings_kept"] = st.Journal.WrittenFiles
	}
	preview["revoke_in_contro1"] = !flagDisconnectLocalOnly && flagDisconnectRemote
	if flagDisconnectDryRun {
		if connectFormatJSON() {
			return output.Render("json", preview, nil)
		}
		fmt.Printf("Disconnecting %s would:\n", platform)
		if a, ok := preview["agents"].([]string); ok {
			fmt.Printf("  - stop the endpoints for: %s\n", strings.Join(a, ", "))
		}
		if st != nil {
			for _, f := range st.Journal.CreatedFiles {
				fmt.Printf("  - remove %s\n", f)
			}
		}
		if preview["revoke_in_contro1"] == true {
			fmt.Println("  - revoke these connections in Contro1 (the agents and their history stay)")
		}
		fmt.Println("  The Contro1 service stays installed while other platforms use it.")
		return nil
	}

	var problems []string
	if m != nil && !flagDisconnectLocalOnly && flagDisconnectRemote {
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
	// Local endpoints stop by themselves once the server revokes; in
	// development the control pipe also removes local state immediately.
	if flagConnectDevelopment && m != nil {
		layout := brokerpaths.Development()
		if resp, err := controlCall(cmd.Context(), layout, "GET", "/control/v1/enrollments", nil); err == nil {
			for _, raw := range asSlice(resp["enrollments"]) {
				en := asMap(raw)
				if str(en["platform"]) == platform {
					_, _ = controlCall(cmd.Context(), layout, "POST", "/control/v1/enrollments/"+str(en["local_id"])+"/revoke", map[string]bool{"remote": false})
				}
			}
		}
	}
	if st != nil {
		if err := adapter.RemoveConfig(cmd.Context(), &st.Journal); err != nil {
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

func orDefault(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}
