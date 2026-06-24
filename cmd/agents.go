package cmd

import (
	"github.com/contro1-hq/contro1-cli/internal/output"
	"github.com/spf13/cobra"
)

var (
	agentName        string
	agentFramework   string
	agentDescription string
	agentOwner       string
)

func init() {
	agentsCmd := &cobra.Command{
		Use:     "agents",
		Short:   "Register and inspect agents",
		GroupID: groupAgent,
	}

	registerCmd := &cobra.Command{
		Use:   "register",
		Short: "Register a caller-declared agent (idempotent on name)",
		Example: `  contro1 agents register --name "Claude Code - Laptop" --type coding-agent`,
		RunE: runAgentRegister,
	}
	registerCmd.Flags().StringVar(&agentName, "name", "", "agent name (required)")
	registerCmd.Flags().StringVar(&agentFramework, "type", "", "framework/type (e.g. coding-agent, langgraph)")
	registerCmd.Flags().StringVar(&agentFramework, "framework", "", "alias for --type")
	registerCmd.Flags().StringVar(&agentDescription, "description", "", "description")
	registerCmd.Flags().StringVar(&agentOwner, "owner", "", "owner label")
	_ = registerCmd.MarkFlagRequired("name")

	listCmd := &cobra.Command{Use: "list", Short: "List agents", RunE: runAgentList}
	getCmd := &cobra.Command{Use: "get <agent_id>", Short: "Get one agent", Args: cobra.ExactArgs(1), RunE: runAgentGet}
	trailCmd := &cobra.Command{Use: "trail <agent_id>", Short: "Show an agent's action trail", Args: cobra.ExactArgs(1), RunE: runAgentTrail}

	agentsCmd.AddCommand(registerCmd, listCmd, getCmd, trailCmd)
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
	return output.Render(outFormat(pr), agent, agentDetailTable(agent))
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
