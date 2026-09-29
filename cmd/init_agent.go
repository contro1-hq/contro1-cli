package cmd

import (
	"strings"

	"github.com/contro1-hq/contro1-cli/internal/client"
	"github.com/contro1-hq/contro1-cli/internal/output"
	"github.com/spf13/cobra"
)

var (
	initAgentName      string
	initAgentFramework string
	initAgentParent    string
)

func init() {
	cmd := &cobra.Command{
		Use:     "init",
		Short:   "Connect this project and register its default agent",
		GroupID: groupAgent,
		RunE:    runInitAgent,
	}
	cmd.Flags().StringVar(&initAgentName, "name", "", "agent name (required)")
	cmd.Flags().StringVar(&initAgentFramework, "framework", "coding-agent", "agent framework/type")
	cmd.Flags().StringVar(&initAgentParent, "parent", "", "agent id this one belongs to, when it is a separate program another agent starts (it gets its own permissions)")
	_ = cmd.MarkFlagRequired("name")
	rootCmd.AddCommand(cmd)
}

func runInitAgent(_ *cobra.Command, _ []string) error {
	cfg, pr, profileName, err := loadCtx()
	if err != nil {
		return err
	}
	c, _, err := newClient()
	if err != nil {
		return err
	}

	identity, err := c.Do("GET", "/api/centcom/v1/cli/whoami", nil)
	if err != nil {
		return output.Errf(output.CodeAuth, "connection or authorization check failed: %v", err)
	}
	authData := asMap(asMap(client.Data(identity))["auth"])
	accessProfile := str(authData["access_profile"])
	if accessProfile != "" && accessProfile != "agent" && accessProfile != "legacy" {
		return output.Errf(output.CodeInsufficient, "contro1 init requires an agent profile; run 'contro1 auth login --mode agent'")
	}

	body := map[string]any{
		"name":      strings.TrimSpace(initAgentName),
		"framework": strings.TrimSpace(initAgentFramework),
	}
	if parent := strings.TrimSpace(initAgentParent); parent != "" {
		body["parent_agent_id"] = parent
	}
	resp, err := c.Do("POST", "/api/centcom/v1/agents/register", body)
	if err != nil {
		return err
	}
	agent := asMap(resp["agent"])
	agentID := str(agent["agent_id"])
	if agentID == "" {
		return output.Errf(output.CodeGeneral, "the API did not return an agent_id")
	}
	pr.DefaultAgent = agentID
	pr.AccessProfile = "agent"
	cfg.Profiles[profileName] = pr
	if err := cfg.Save(); err != nil {
		return output.Errf(output.CodeGeneral, "saving default agent: %v", err)
	}

	infof("Connected and set %s as the default agent for profile %s", agentID, profileName)
	result := map[string]any{"connected": true, "profile": profileName, "agent": agent, "default_agent_id": agentID}
	return output.Render(outFormat(pr), result, agentDetailTable(agent))
}
