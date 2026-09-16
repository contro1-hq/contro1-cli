package cmd

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/contro1-hq/contro1-cli/internal/client"
	"github.com/contro1-hq/contro1-cli/internal/config"
	"github.com/contro1-hq/contro1-cli/internal/output"
	"github.com/spf13/cobra"
)

// Terminal invocation states. Nothing moves on from these without a person or a
// new request, so `watch` stops here.
var actionTerminalStates = map[string]bool{
	"executed":                true,
	"execution_failed":        true,
	"execution_indeterminate": true,
	"denied":                  true,
	"expired":                 true,
	"cancelled":               true,
	"binding_mismatch":        true,
}

var (
	actionsWatchInterval time.Duration
	actionsWatchTimeout  time.Duration
	actionPayloadFile    string
	actionIdempotencyKey string
	actionsReadRuntime   bool
)

func init() {
	actionsCmd := &cobra.Command{
		Use:     "actions",
		Short:   "Invoke, inspect and cancel Action invocations",
		GroupID: groupAgent,
		Long: `Inspect Action invocations - what the Gateway was asked to do, what it did,
and what is waiting on a person.

A browser-issued CLI token can read invocations but never invoke or cancel one:
a token minted by clicking a link in a browser should not be able to send mail
from a customer mailbox. ` + "`invoke`" + ` and ` + "`cancel`" + ` are runtime-only. They read an
Agent Credential from CONTRO1_AGENT_TOKEN_FILE, CONTRO1_AGENT_TOKEN or
CONTRO1_TOKEN, never from the keychain, and refuse a cco_cli_ token before any
request is sent. An administrator grants that credential on purpose.`,
	}

	invokeCmd := &cobra.Command{
		Use:   "invoke",
		Short: "Invoke an Action with an Agent Credential (runtime only)",
		Long: `Submits one Action invocation to the Gateway. Contro1 holds the provider
credential and makes the call; this command never talks to a provider.

--idempotency-key is required. Retrying with the same key returns the same
invocation instead of sending a second one; reusing a key with a changed body is
refused (exit 9).`,
		Example: `  contro1 actions invoke --file invocation.json --idempotency-key openclaw:exec:apr_123 --format json --quiet`,
		RunE:    runActionInvoke,
	}
	invokeCmd.Flags().StringVar(&actionPayloadFile, "file", "", "Action invocation JSON body, or '-' for stdin")
	invokeCmd.Flags().StringVar(&actionIdempotencyKey, "idempotency-key", "", "unique key for this intended invocation")
	_ = invokeCmd.MarkFlagRequired("file")
	_ = invokeCmd.MarkFlagRequired("idempotency-key")

	getCmd := &cobra.Command{
		Use:     "get <invocation_id>",
		Short:   "Show one invocation",
		Args:    cobra.ExactArgs(1),
		Example: `  contro1 actions get inv_01HQ...`,
		RunE:    runActionGet,
	}

	watchCmd := &cobra.Command{
		Use:   "watch <invocation_id>",
		Short: "Poll an invocation until it reaches a terminal state",
		Args:  cobra.ExactArgs(1),
		Long: `Polls. It re-reads state and never re-submits: a resubmission on a network
blip would send a second message that nobody could tell apart from the first.`,
		RunE: runActionWatch,
	}
	watchCmd.Flags().DurationVar(&actionsWatchInterval, "interval", 3*time.Second, "poll interval")
	watchCmd.Flags().DurationVar(&actionsWatchTimeout, "timeout", 10*time.Minute, "give up after this long")

	cancelCmd := &cobra.Command{
		Use:   "cancel <invocation_id>",
		Short: "Cancel an invocation that has not executed yet (runtime only)",
		Args:  cobra.ExactArgs(1),
		Long: `Cancels an invocation that is still waiting. An invocation that has already
executed cannot be cancelled - undoing a sent message is not something Contro1
can do, and pretending otherwise would be worse than refusing.`,
		RunE: runActionCancel,
	}

	getCmd.Flags().BoolVar(&actionsReadRuntime, "runtime", false, "read with the host bridge Agent Credential instead of the normal CLI identity")
	watchCmd.Flags().BoolVar(&actionsReadRuntime, "runtime", false, "read with the host bridge Agent Credential instead of the normal CLI identity")

	actionsCmd.AddCommand(invokeCmd, getCmd, watchCmd, cancelCmd)
	rootCmd.AddCommand(actionsCmd)
}

func actionInvocationTable(m map[string]any) *output.Table {
	tbl := &output.Table{Headers: []string{"FIELD", "VALUE"}}
	add := func(label, value string) {
		if value != "" {
			tbl.Rows = append(tbl.Rows, []string{label, value})
		}
	}
	add("Invocation", str(m["invocation_id"]))
	add("Action", fmt.Sprintf("%s@%s", str(m["action_id"]), str(m["action_version"])))
	add("App", str(m["application_connector"]))
	add("Connection", str(m["connection_id"]))
	add("State", str(m["state"]))
	// Always gateway_verified on an invocation: Contro1 held the credential and
	// made the call. An agent's own claim about itself never becomes one of
	// these rows - it lives in the audit ledger as client_reported.
	add("Evidence", str(m["evidence_provenance"]))
	add("Approval request", str(m["approval_request_id"]))
	if errMap := asMap(m["error"]); len(errMap) > 0 {
		add("Error", fmt.Sprintf("%s: %s", str(errMap["code"]), str(errMap["message"])))
	}
	add("Created", str(m["created_at"]))
	add("Updated", str(m["updated_at"]))
	return tbl
}

// Says what the state MEANS, because the one that matters is the one whose name
// does not carry its own instruction.
func explainActionState(state string) string {
	switch state {
	case "awaiting_approval":
		return "Waiting for a human decision. Nothing has been sent."
	case "user_auth_required":
		return "The account this needs is not connected. Its owner must connect it."
	case "ready", "executing":
		return "Accepted and queued. It has not finished."
	case "executed":
		return "Contro1 made the provider call and saw it succeed."
	case "execution_failed":
		return "The provider refused the call. Nothing took effect."
	case "execution_indeterminate":
		return "NEEDS A PERSON. The call may or may not have taken effect, and Contro1 " +
			"will not retry it. Check the provider directly before deciding what to do."
	case "denied":
		return "Refused by policy or by a missing grant. Nothing was sent."
	case "binding_mismatch":
		return "Blocked: the payload changed after it was approved. Nothing was sent."
	case "cancelled":
		return "Cancelled before it ran."
	case "expired":
		return "Nobody decided in time. Nothing was sent."
	}
	return ""
}

func renderInvocation(pr *config.Profile, m map[string]any) error {
	if note := explainActionState(str(m["state"])); note != "" {
		infof("%s", note)
	}
	return output.Render(outFormat(pr), m, actionInvocationTable(m))
}

func fetchInvocation(id string) (map[string]any, *config.Profile, error) {
	var (
		c   *client.Client
		pr  *config.Profile
		err error
	)
	if actionsReadRuntime {
		c, pr, _, err = newRuntimeClient()
		if err == nil {
			_, err = requireRuntimeStatus(c, "actions:read")
		}
	} else {
		c, pr, err = newClient()
	}
	if err != nil {
		return nil, nil, err
	}
	resp, err := c.Do("GET", "/api/centcom/v1/actions/"+url.PathEscape(id), nil)
	if err != nil {
		return nil, nil, err
	}
	return asMap(resp["invocation"]), pr, nil
}

func runActionGet(_ *cobra.Command, args []string) error {
	invocation, pr, err := fetchInvocation(args[0])
	if err != nil {
		return err
	}
	return renderInvocation(pr, invocation)
}

func runActionWatch(_ *cobra.Command, args []string) error {
	deadline := time.Now().Add(actionsWatchTimeout)
	lastState := ""

	for {
		invocation, pr, err := fetchInvocation(args[0])
		if err != nil {
			// The read failed, not the Action. Surfaced rather than swallowed
			// into a silent retry loop that would look like a hung invocation.
			return err
		}

		state := str(invocation["state"])
		if state != lastState {
			infof("state: %s", state)
			lastState = state
		}
		if actionTerminalStates[state] {
			return renderInvocation(pr, invocation)
		}
		if time.Now().After(deadline) {
			// It is still live on the server. Say so, and name the state, so
			// nobody reads a timeout as "it did not happen".
			return fmt.Errorf(
				"timed out after %s; invocation %s is still in state %q and may still execute - "+
					"read it again rather than submitting another",
				actionsWatchTimeout, args[0], state)
		}
		time.Sleep(actionsWatchInterval)
	}
}

func runActionInvoke(_ *cobra.Command, _ []string) error {
	key := strings.TrimSpace(actionIdempotencyKey)
	if key == "" {
		return output.Errf(output.CodeBadArgs, "--idempotency-key must not be empty")
	}
	body, err := readJSONMap(actionPayloadFile, "action invocation")
	if err != nil {
		return err
	}
	c, pr, _, err := newRuntimeClient()
	if err != nil {
		return err
	}
	if _, err := requireRuntimeStatus(c, "actions:execute"); err != nil {
		return err
	}
	resp, err := c.DoWithHeaders("POST", "/api/centcom/v1/actions/invoke", body, map[string]string{"Idempotency-Key": key})
	if err != nil {
		return err
	}
	invocation := asMap(resp["invocation"])
	if len(invocation) == 0 {
		return output.Render(outFormat(pr), resp, nil)
	}
	return renderInvocation(pr, invocation)
}

func runActionCancel(_ *cobra.Command, args []string) error {
	c, pr, _, err := newRuntimeClient()
	if err != nil {
		return err
	}
	if _, err := requireRuntimeStatus(c, "actions:execute"); err != nil {
		return err
	}
	resp, err := c.Do("POST", "/api/centcom/v1/actions/"+url.PathEscape(args[0])+"/cancel", map[string]any{})
	if err != nil {
		return err
	}
	infof("Cancelled invocation %s", args[0])
	return renderInvocation(pr, asMap(resp["invocation"]))
}
