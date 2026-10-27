package cmd

import (
	"os"

	"github.com/contro1-hq/contro1-cli/internal/output"
	"github.com/pkg/browser"
	"github.com/spf13/cobra"
)

var (
	agentName        string
	agentFramework   string
	agentDescription string
	agentOwner       string
	agentNoBrowser   bool
)

func init() {
	agentsCmd := &cobra.Command{
		Use:     "agents",
		Short:   "Register and inspect agents",
		GroupID: groupAgent,
	}

	registerCmd := &cobra.Command{
		Use:     "register",
		Short:   "Register a caller-declared agent (idempotent on name)",
		Example: `  contro1 agents register --name "Claude Code - Laptop" --type coding-agent`,
		RunE:    runAgentRegister,
	}
	registerCmd.Flags().StringVar(&agentName, "name", "", "agent name (required)")
	registerCmd.Flags().StringVar(&agentFramework, "type", "", "framework/type (e.g. coding-agent, langgraph)")
	registerCmd.Flags().StringVar(&agentFramework, "framework", "", "alias for --type")
	registerCmd.Flags().StringVar(&agentDescription, "description", "", "description")
	registerCmd.Flags().StringVar(&agentOwner, "owner", "", "owner label")
	registerCmd.Flags().BoolVar(&agentNoBrowser, "no-browser", false, "print the setup link instead of opening it")
	_ = registerCmd.MarkFlagRequired("name")

	listCmd := &cobra.Command{Use: "list", Short: "List agents", RunE: runAgentList}
	getCmd := &cobra.Command{Use: "get <agent_id>", Short: "Get one agent", Args: cobra.ExactArgs(1), RunE: runAgentGet}
	trailCmd := &cobra.Command{Use: "trail <agent_id>", Short: "Show an agent's action trail", Args: cobra.ExactArgs(1), RunE: runAgentTrail}

	/*
	 * Telling Contro1 who can instruct this agent.
	 *
	 * Runtime only, on the agent's own connection, because the answer is about
	 * this agent and nobody else's. It is what a platform adapter calls when it
	 * notices the agent was added to a room since it was connected: NanoClaw
	 * asks that in a DM, long after anybody decided what the agent may reach,
	 * and answering it casually is how a private assistant becomes one a group
	 * can instruct.
	 *
	 * The server only ever lets a declaration tighten things. An agent cannot
	 * talk its way back to being private, and this command does not pretend to.
	 */
	reachCmd := &cobra.Command{
		Use:   "reach",
		Short: "Report which conversations this agent answers in",
		Long: "Reads {\"contexts\":[{context_id,label,kind,participants_known}]} from --file. " +
			"Only ever makes this agent stricter: privacy is established by a person, with contro1 connect.",
		RunE: runAgentReach,
	}
	reachCmd.Flags().StringVar(&agentReachFile, "file", "", "JSON file, or - for stdin (required)")
	_ = reachCmd.MarkFlagRequired("file")

	agentsCmd.AddCommand(registerCmd, listCmd, getCmd, trailCmd, reachCmd)
	rootCmd.AddCommand(agentsCmd)
}

func runAgentRegister(_ *cobra.Command, _ []string) error {
	c, pr, err := newClient()
	if err != nil {
		return err
	}
	resp, err := c.Do("POST", "/api/centcom/v1/agents/register", map[string]any{
		"name":        agentName,
		"framework":   agentFramework,
		"description": agentDescription,
		"owner":       agentOwner,
	})
	if err != nil {
		return err
	}
	agent := asMap(resp["agent"])
	if str(resp["created"]) == "true" {
		infof("Registered agent %s", str(agent["agent_id"]))
	} else {
		infof("Agent already existed: %s", str(agent["agent_id"]))
	}
	if err := output.Render(outFormat(pr), agent, agentDetailTable(agent)); err != nil {
		return err
	}
	printRegisterNextSteps(str(resp["setup_url"]), asMap(resp["next_steps"]))
	openSetupLink(str(resp["setup_url"]), str(resp["created"]) == "true", agentNoBrowser)
	return nil
}

// printRegisterNextSteps says what the registered agent needs next, on
// stderr so --output json stays one document. Without it the id was all a
// coding agent got back, and it signed in as its person to find the rest,
// which made a second identity named after this agent.
// openSetupLink opens a new agent's setup page, where its person names the
// owner and chooses what it may do. Printed alone, the link was easy to leave
// for later, and the agent's first approval request then had nobody to go to.
// Opened even when a coding agent runs the command: the person is at this
// computer. Not with --no-browser, JSON output or in CI.
func openSetupLink(setupURL string, created bool, noBrowser bool) {
	if setupURL == "" || !created || noBrowser || flagFormat == "json" || os.Getenv("CI") != "" {
		return
	}
	if err := browser.OpenURL(setupURL); err == nil {
		infof("Opened the setup page in your browser.")
	}
}

func printRegisterNextSteps(setupURL string, next map[string]any) {
	// The setup link first: until a person finishes it the agent has no owner
	// and runs nothing, and it is the one thing to hand them.
	if setupURL != "" {
		infof("Setup: give your person this link. They confirm what the agent is for, its owner and what it may do:")
		infof("  %s", setupURL)
	}
	steps := asSlice(next["steps"])
	if len(steps) == 0 {
		return
	}
	infof("Next:")
	for i, step := range steps {
		infof("  %d. %s", i+1, str(step))
	}
	if note := str(next["not_this"]); note != "" {
		infof("  %s", note)
	}
	if runtime := asMap(next["runtime"]); len(runtime) > 0 {
		if mcp := asMap(runtime["mcp"]); len(mcp) > 0 {
			infof("  MCP (whoami, its Actions, skills, approvals): %s with %s", str(mcp["url"]), str(mcp["header"]))
		}
		if traces := str(runtime["traces"]); traces != "" {
			infof("  Traces (OTLP): %s", traces)
		}
		infof("  Actions: %s", str(runtime["actions"]))
		infof("  Approvals: %s", str(runtime["approvals"]))
		infof("  Activity: %s", str(runtime["activity"]))
	}
}

func runAgentList(_ *cobra.Command, _ []string) error {
	c, pr, err := newClient()
	if err != nil {
		return err
	}
	resp, err := c.Do("GET", "/api/centcom/v1/agents", nil)
	if err != nil {
		return err
	}
	agents := asSlice(resp["agents"])
	tbl := &output.Table{Headers: []string{"AGENT ID", "NAME", "FRAMEWORK", "STATUS", "VERIFIED", "REQUESTS"}}
	for _, a := range agents {
		m := asMap(a)
		tbl.Rows = append(tbl.Rows, []string{
			str(m["agent_id"]), truncate(str(m["name"]), 28), str(m["framework"]),
			str(m["status"]), str(m["verification_status"]), str(m["request_count"]),
		})
	}
	return output.Render(outFormat(pr), agents, tbl)
}

func runAgentGet(_ *cobra.Command, args []string) error {
	c, pr, err := newClient()
	if err != nil {
		return err
	}
	resp, err := c.Do("GET", "/api/centcom/v1/agents/"+args[0], nil)
	if err != nil {
		return err
	}
	agent := asMap(resp["agent"])
	return output.Render(outFormat(pr), agent, agentDetailTable(agent))
}

func runAgentTrail(_ *cobra.Command, args []string) error {
	c, pr, err := newClient()
	if err != nil {
		return err
	}
	resp, err := c.Do("GET", "/api/centcom/v1/agents/"+args[0]+"/trail", nil)
	if err != nil {
		return err
	}
	return output.Render(outFormat(pr), resp, nil)
}

func agentDetailTable(m map[string]any) *output.Table {
	return &output.Table{
		Headers: []string{"FIELD", "VALUE"},
		Rows: [][]string{
			{"agent_id", str(m["agent_id"])},
			{"name", str(m["name"])},
			{"framework", str(m["framework"])},
			{"status", str(m["status"])},
			{"verification", str(m["verification_status"])},
			{"requests", str(m["request_count"])},
		},
	}
}

var agentReachFile string

func runAgentReach(_ *cobra.Command, _ []string) error {
	body, err := readJSONMap(agentReachFile, "reach")
	if err != nil {
		return err
	}
	c, pr, _, err := newRuntimeClient()
	if err != nil {
		return err
	}
	resp, err := c.Do("POST", "/api/centcom/v1/runtime/reach", body)
	if err != nil {
		return err
	}
	return output.Render(outFormat(pr), resp, nil)
}
