package cmd

import (
	"strings"
	"time"

	"github.com/contro1-hq/contro1-cli/internal/output"
	"github.com/spf13/cobra"
)

var (
	askAgent       string
	askRole        string
	askContext     string
	askCallbackURL string
	askWait        bool
	askTimeout     time.Duration
)

func init() {
	cmd := &cobra.Command{
		Use:     "ask <question>",
		Short:   "Ask a human for free-text input",
		GroupID: groupAgent,
		Args:    cobra.ExactArgs(1),
		Example: `  contro1 ask "Which region should I use?" --wait --format json`,
		RunE:    runAsk,
	}
	cmd.Flags().StringVar(&askAgent, "agent", "", "agent_id (defaults to the agent saved by contro1 init)")
	cmd.Flags().StringVar(&askRole, "role", "", "required human role")
	cmd.Flags().StringVar(&askContext, "context", "", "additional context for the human")
	cmd.Flags().StringVar(&askCallbackURL, "callback-url", "", "webhook callback URL")
	cmd.Flags().BoolVar(&askWait, "wait", false, "wait for the human response")
	cmd.Flags().DurationVar(&askTimeout, "timeout", 10*time.Minute, "maximum wait time")
	rootCmd.AddCommand(cmd)
}

func runAsk(_ *cobra.Command, args []string) error {
	c, pr, err := newClient()
	if err != nil {
		return err
	}
	question := strings.TrimSpace(args[0])
	context := strings.TrimSpace(askContext)
	if context == "" {
		context = question
	}
	agentID := strings.TrimSpace(askAgent)
	if agentID == "" {
		agentID = pr.DefaultAgent
	}
	metadata := map[string]any{"source": "cli"}
	if agentID != "" {
		metadata["actor"] = map[string]any{"agent_id": agentID}
	}
	payload := map[string]any{
		"type": "free_text", "question": question, "context": context,
		"priority": "normal", "metadata": metadata,
	}
	if askRole != "" {
		payload["required_role"] = askRole
	}
	if askCallbackURL != "" {
		payload["callback_url"] = askCallbackURL
	}
	resp, err := c.Do("POST", "/api/centcom/v1/requests", payload)
	if err != nil {
		return err
	}
	id := str(firstNonEmpty(resp["request_id"], resp["id"]))
	infof("Asked human. Request: %s", id)
	if askWait {
		final, decision, waitErr := waitForRequest(c, id, askTimeout, 3*time.Second)
		if waitErr != nil {
			return waitErr
		}
		return finishDecision(pr, final, decision)
	}
	return output.Render(outFormat(pr), resp, requestSummaryTable(resp))
}
