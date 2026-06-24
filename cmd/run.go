package cmd

import (
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/contro1-hq/contro1-cli/internal/client"
	"github.com/contro1-hq/contro1-cli/internal/output"
	"github.com/spf13/cobra"
)

var (
	runAgent           string
	runRisk            string
	runReason          string
	runType            string
	runTimeout         time.Duration
	runRequiresApprove bool
)

func init() {
	runCmd := &cobra.Command{
		Use:   "run [flags] -- <command> [args...]",
		Short: "Run a command only after it is approved, then store evidence",
		Long: `run requests human approval for a command, waits for the decision, and only
executes the command if it is approved. The command, working directory, git
context, approver and exit code are recorded as audit-ready evidence.`,
		Example: `  contro1 run --requires-approval -- npm run deploy
  contro1 run --risk high --reason "DB migration" -- npm run migrate`,
		GroupID: groupAgent,
		RunE:    runRun,
	}
	runCmd.Flags().StringVar(&runAgent, "agent", "", "agent_id to attribute this action to")
	runCmd.Flags().StringVar(&runRisk, "risk", "high", "risk level: low|medium|high|critical")
	runCmd.Flags().StringVar(&runReason, "reason", "", "reason shown to the approver")
	runCmd.Flags().StringVar(&runType, "type", "approval", "request type")
	runCmd.Flags().DurationVar(&runTimeout, "timeout", 15*time.Minute, "max time to wait for approval")
	runCmd.Flags().BoolVar(&runRequiresApprove, "requires-approval", true, "require approval before running (always on in v1)")

	rootCmd.AddCommand(runCmd)
}

func runRun(cmd *cobra.Command, args []string) error {
	dash := cmd.ArgsLenAtDash()
	if dash < 0 || dash >= len(args) {
		return output.Errf(output.CodeBadArgs, "provide the command after '--', e.g. contro1 run -- npm run deploy")
	}
	command := args[dash:]
	cmdStr := strings.Join(command, " ")

	c, pr, err := newClient()
	if err != nil {
		return err
	}

	cwd, _ := os.Getwd()
	gitBranch := gitOutput("rev-parse", "--abbrev-ref", "HEAD")
	gitCommit := gitOutput("rev-parse", "HEAD")

	// 1) create approval request
	contextLines := []string{"Command: " + cmdStr, "Working dir: " + cwd}
	if gitBranch != "" {
		contextLines = append(contextLines, "Git branch: "+gitBranch)
	}
	if gitCommit != "" {
		contextLines = append(contextLines, "Git commit: "+gitCommit)
	}
	if runReason != "" {
		contextLines = append(contextLines, "Reason: "+runReason)
	}

	meta := map[string]any{"source": "cli", "run": map[string]any{"command": cmdStr, "cwd": cwd, "git_branch": gitBranch, "git_commit": gitCommit}}
	if runAgent != "" {
		meta["actor"] = map[string]any{"agent_id": runAgent}
	}
	payload := map[string]any{
		"type":           runType,
		"question":       "Approve running: " + truncate(cmdStr, 120),
		"context":        strings.Join(contextLines, "\n"),
		"priority":       "urgent",
		"risk_level":     runRisk,
		"metadata":       meta,
	}
	if runReason != "" {
		payload["policy_trigger"] = runReason
	}

	resp, err := c.Do("POST", "/api/centcom/v1/requests", payload)
	if err != nil {
		return err
	}
	reqID := str(firstNonEmpty(resp["request_id"], resp["id"]))
	infof("Approval required. Request: %s", reqID)

	// 2) wait for decision
	final, decision, werr := waitForRequest(c, reqID, runTimeout, 3*time.Second)
	if werr != nil {
		return werr
	}
	if decision != "approved" {
		// record the (non-execution) outcome too
		recordRunEvidence(c, reqID, cmdStr, cwd, gitBranch, gitCommit, nil, time.Now(), time.Now())
		return finishDecision(pr, final, decision)
	}

	approver := approverName(final)
	infof("Approved%s. Running: %s", approverSuffix(approver), cmdStr)

	// 3) execute
	started := time.Now()
	exitCode := execCommand(command)
	finished := time.Now()

	// 4) store evidence
	evidenceID := recordRunEvidence(c, reqID, cmdStr, cwd, gitBranch, gitCommit, &exitCode, started, finished)

	result := map[string]any{
		"request_id":  reqID,
		"status":      "approved",
		"command":     cmdStr,
		"exit_code":   exitCode,
		"evidence_id": evidenceID,
	}
	if exitCode == 0 {
		infof("Command completed successfully. Evidence (client-reported): %s", evidenceID)
	} else {
		infof("Command exited with code %d. Evidence (client-reported): %s", exitCode, evidenceID)
	}

	if err := output.Render(outFormat(pr), result, runResultTable(result)); err != nil {
		return err
	}
	if exitCode != 0 {
		return output.Errf(output.CodeGeneral, "command exited with code %d", exitCode)
	}
	return nil
}

func execCommand(command []string) int {
	c := exec.Command(command[0], command[1:]...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Stdin = os.Stdin
	if err := c.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		output.Info("failed to start command: %v", err)
		return 127
	}
	return 0
}

func recordRunEvidence(c *client.Client, reqID, command, cwd, branch, commit string, exitCode *int, started, finished time.Time) string {
	body := map[string]any{
		"request_id":  reqID,
		"command":     command,
		"cwd":         cwd,
		"git_branch":  branch,
		"git_commit":  commit,
		"agent_id":    runAgent,
		"started_at":  started.UTC().Format(time.RFC3339),
		"finished_at": finished.UTC().Format(time.RFC3339),
	}
	if exitCode != nil {
		body["exit_code"] = *exitCode
	}
	resp, err := c.Do("POST", "/api/centcom/v1/cli/run-evidence", body)
	if err != nil {
		return ""
	}
	return str(asMap(resp["data"])["evidence_id"])
}

func gitOutput(args ...string) string {
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func approverName(final map[string]any) string {
	r := asMap(final["response"])
	if n := str(r["responded_by"]); n != "" {
		return n
	}
	return str(final["responded_by"])
}

func approverSuffix(name string) string {
	if name == "" {
		return ""
	}
	return " by " + name
}

func runResultTable(m map[string]any) *output.Table {
	return &output.Table{
		Headers: []string{"FIELD", "VALUE"},
		Rows: [][]string{
			{"request_id", str(m["request_id"])},
			{"status", str(m["status"])},
			{"command", truncate(str(m["command"]), 60)},
			{"exit_code", str(m["exit_code"])},
			{"evidence_id", str(m["evidence_id"])},
		},
	}
}
