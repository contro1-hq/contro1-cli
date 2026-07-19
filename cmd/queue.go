package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/contro1-hq/contro1-cli/internal/client"
	"github.com/contro1-hq/contro1-cli/internal/config"
	"github.com/contro1-hq/contro1-cli/internal/output"
	"github.com/spf13/cobra"
)

var (
	flagDecisionComment string
	flagRespondValue    string
	flagWatchInterval   int
)

func init() {
	queueCmd := &cobra.Command{
		Use:     "queue",
		Short:   "View and answer the approval queue",
		GroupID: groupQueue,
	}
	queueCmd.AddCommand(&cobra.Command{Use: "list", Short: "List open requests", RunE: runQueueList})
	queueCmd.AddCommand(&cobra.Command{Use: "my-requests", Short: "List requests assigned to you", RunE: runMyRequests})
	queueCmd.AddCommand(&cobra.Command{
		Use:   "get <id>",
		Short: "Show one request",
		Args:  cobra.ExactArgs(1),
		RunE:  runRequestGet,
	})
	queueCmd.AddCommand(&cobra.Command{
		Use:   "claim <id>",
		Short: "Claim an open request so you can answer it",
		Args:  cobra.ExactArgs(1),
		RunE:  runQueueClaim,
	})
	approveCmd := &cobra.Command{
		Use:   "approve <id>",
		Short: "Approve a request you claimed",
		Args:  cobra.ExactArgs(1),
		RunE:  runQueueApprove,
	}
	approveCmd.Flags().StringVar(&flagDecisionComment, "comment", "", "decision comment (required when the request policy says so)")
	queueCmd.AddCommand(approveCmd)
	rejectCmd := &cobra.Command{
		Use:   "reject <id>",
		Short: "Reject a request you claimed",
		Args:  cobra.ExactArgs(1),
		RunE:  runQueueReject,
	}
	rejectCmd.Flags().StringVar(&flagDecisionComment, "comment", "", "rejection comment (required when the request policy says so)")
	queueCmd.AddCommand(rejectCmd)
	respondCmd := &cobra.Command{
		Use:   "respond <id>",
		Short: "Answer a yes_no or free_text request you claimed",
		Long:  "Answer a claimed yes_no or free_text request. --value yes|no|true|false is sent as a boolean; anything else is sent as text.",
		Args:  cobra.ExactArgs(1),
		RunE:  runQueueRespond,
	}
	respondCmd.Flags().StringVar(&flagRespondValue, "value", "", "yes|no for yes_no requests, or the free-text answer")
	_ = respondCmd.MarkFlagRequired("value")
	queueCmd.AddCommand(respondCmd)
	watchCmd := &cobra.Command{
		Use:   "watch",
		Short: "Stream new open requests (polls the queue)",
		RunE:  runQueueWatch,
	}
	watchCmd.Flags().IntVar(&flagWatchInterval, "interval", 5, "poll interval in seconds")
	queueCmd.AddCommand(watchCmd)
	rootCmd.AddCommand(queueCmd)
}

func renderQueue(pr *config.Profile, items []any) error {
	tbl := &output.Table{Headers: []string{"ID", "TYPE", "STATE", "PRIORITY", "QUESTION"}}
	for _, it := range items {
		m := asMap(it)
		tbl.Rows = append(tbl.Rows, []string{
			str(m["id"]), str(m["type"]), str(m["state"]), str(m["priority"]), truncate(str(m["question"]), 40),
		})
	}
	return output.Render(outFormat(pr), items, tbl)
}

func runQueueList(_ *cobra.Command, _ []string) error {
	c, pr, err := newClient()
	if err != nil {
		return err
	}
	resp, err := c.Do("GET", "/api/centcom/v1/operator/queue", nil)
	if err != nil {
		return err
	}
	return renderQueue(pr, asSlice(client.Data(resp)))
}

func runQueueClaim(_ *cobra.Command, args []string) error {
	c, pr, err := newClient()
	if err != nil {
		return err
	}
	if err := requireInteractiveOperator(pr); err != nil {
		return err
	}
	resp, err := c.Do("POST", "/api/centcom/v1/operator/queue/"+args[0]+"/claim", nil)
	if err != nil {
		return err
	}
	data := asMap(client.Data(resp))
	infof("Claimed %s (%s): %s", str(data["id"]), str(data["state"]), truncate(str(data["question"]), 60))
	return output.Render(outFormat(pr), data, nil)
}

func runQueueDecision(id string, approved bool) error {
	c, pr, err := newClient()
	if err != nil {
		return err
	}
	body := map[string]any{"approved": approved}
	if strings.TrimSpace(flagDecisionComment) != "" {
		body["comment"] = strings.TrimSpace(flagDecisionComment)
	}
	if err := requireInteractiveOperator(pr); err != nil {
		return err
	}
	resp, err := c.Do("POST", "/api/centcom/v1/operator/queue/"+id+"/respond", body)
	if err != nil {
		return err
	}
	data := asMap(client.Data(resp))
	infof("Decision recorded: %s (state: %s)", str(data["outcome"]), str(data["state"]))
	return output.Render(outFormat(pr), data, nil)
}

func runQueueApprove(_ *cobra.Command, args []string) error {
	return runQueueDecision(args[0], true)
}

func runQueueReject(_ *cobra.Command, args []string) error {
	return runQueueDecision(args[0], false)
}

func runQueueRespond(_ *cobra.Command, args []string) error {
	c, pr, err := newClient()
	if err != nil {
		return err
	}
	if err := requireInteractiveOperator(pr); err != nil {
		return err
	}
	raw := strings.TrimSpace(flagRespondValue)
	var value any = raw
	switch strings.ToLower(raw) {
	case "yes", "true":
		value = true
	case "no", "false":
		value = false
	}
	resp, err := c.Do("POST", "/api/centcom/v1/operator/queue/"+args[0]+"/respond", map[string]any{"value": value})
	if err != nil {
		return err
	}
	data := asMap(client.Data(resp))
	infof("Response recorded (state: %s)", str(data["state"]))
	return output.Render(outFormat(pr), data, nil)
}

func requireInteractiveOperator(pr *config.Profile) error {
	if pr.AccessProfile != "operator" && pr.AccessProfile != "" {
		return output.Errf(output.CodeInsufficient, "queue decisions require an operator profile; run 'contro1 auth login --mode operator' in a separate CLI profile")
	}
	if !isTerminal(os.Stdin) {
		return output.Errf(output.CodeAuth, "operator decisions require an interactive terminal")
	}
	return nil
}

// runQueueWatch polls the open queue and prints one line per newly seen
// request - a terminal-side inbox for on-call reviewers.
func runQueueWatch(_ *cobra.Command, _ []string) error {
	c, _, err := newClient()
	if err != nil {
		return err
	}
	interval := flagWatchInterval
	if interval < 2 {
		interval = 2
	}
	infof("Watching the queue (every %ds). New open requests stream below; Ctrl+C to stop.", interval)
	seen := map[string]bool{}
	first := true
	for {
		resp, err := c.Do("GET", "/api/centcom/v1/operator/queue", nil)
		if err != nil {
			return err
		}
		for _, it := range asSlice(client.Data(resp)) {
			m := asMap(it)
			id := str(m["id"])
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			marker := "+"
			if first {
				marker = "="
			}
			fmt.Printf("%s %s  %-8s %-9s %s  %s\n",
				marker,
				time.Now().Format("15:04:05"),
				str(m["priority"]),
				str(m["state"]),
				id,
				truncate(str(m["question"]), 70),
			)
		}
		first = false
		time.Sleep(time.Duration(interval) * time.Second)
	}
}

func runMyRequests(_ *cobra.Command, _ []string) error {
	c, pr, err := newClient()
	if err != nil {
		return err
	}
	resp, err := c.Do("GET", "/api/centcom/v1/operator/my-requests", nil)
	if err != nil {
		return err
	}
	return renderQueue(pr, asSlice(client.Data(resp)))
}
