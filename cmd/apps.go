package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pkg/browser"
	"github.com/spf13/cobra"

	"github.com/contro1-hq/contro1-cli/internal/localipc"
	"github.com/contro1-hq/contro1-cli/internal/output"
	"github.com/contro1-hq/contro1-cli/internal/platforms"
)

/*
`contro1 apps enable` is the whole of "let this agent use company applications".

It exists because that used to be five steps across three tools, one of which
asked a person to copy a socket path out of another command's output, and two of
which failed silently when skipped. What happened instead was predictable: the
agent kept an older MCP entry pointing at the public API with no key, answered
401 to everything, and told its owner it was connected. The owner went looking
for a wrong address. Nothing in the system said which of the five steps was
missing, because nothing knew there were five.

The decision that matters is not automated. Allowing applications for a
connection is the owner's, it is made in Contro1 where they are already signed
in, and this command opens that page and waits rather than asking anybody to
paste a token into a terminal. Everything after it is mechanical and is done
here, previewed first, so a person reads four lines instead of running four
commands they will not remember.
*/

// runtimeStatus is the live answer from the agent's own endpoint. Asked through
// the broker rather than read from the mapping file, because the mapping is
// written at connect time and the mode changes afterwards.
type runtimeStatus struct {
	EndpointMode string `json:"endpoint_mode"`
	ModeLabel    string `json:"mode_label"`
	AgentID      string `json:"agent_id"`
}

func fetchRuntimeStatus(ctx context.Context, conn platforms.LocalConnection) (runtimeStatus, error) {
	var out runtimeStatus
	ep, err := localipc.ParseEndpoint(conn.Endpoint)
	if err != nil {
		return out, err
	}
	client := localipc.HTTPClient(ep, brokerServerPrincipal())
	req, err := http.NewRequestWithContext(ctx, "GET", localipc.BaseURL+"/api/centcom/v1/runtime/status", nil)
	if err != nil {
		return out, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return out, fmt.Errorf("could not reach this agent's Contro1 service: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("the Contro1 service answered %d for this agent", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return out, err
	}
	/*
	 * The credential description lives under `auth`. It was read from
	 * `credential` once, which decodes to an empty struct rather than an error,
	 * so a working service produced "did not report this connection's mode" and
	 * sent somebody looking for a broken broker. Both names are accepted now,
	 * and a shape that carries neither says so with what it did receive, which
	 * is the part that was missing.
	 */
	var body struct {
		Auth       *runtimeStatus `json:"auth"`
		Credential *runtimeStatus `json:"credential"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return out, fmt.Errorf("the Contro1 service answered something this version cannot read: %w", err)
	}
	for _, candidate := range []*runtimeStatus{body.Auth, body.Credential} {
		if candidate != nil && candidate.EndpointMode != "" {
			return *candidate, nil
		}
	}
	return out, fmt.Errorf("the Contro1 service did not report this connection's mode. It answered: %s", truncateForError(string(raw)))
}

// truncateForError keeps an unexpected body short enough to read and short
// enough not to paste a wall of JSON into somebody's terminal.
func truncateForError(body string) string {
	body = strings.TrimSpace(body)
	if len(body) > 300 {
		return body[:300] + "..."
	}
	return body
}

func init() {
	appsCmd := &cobra.Command{
		Use:     "apps",
		Short:   "Let a connected agent reach company applications through Contro1",
		GroupID: groupAgent,
		Long: "Applications are a separate, later decision from connecting. Connecting lets an agent ask " +
			"people for approval; this lets it use a mailbox, a calendar or a tracker, and only what its " +
			"owner allowed in Contro1.",
	}

	var (
		appsAgent string
		appsYes   bool
		appsWait  time.Duration
	)

	enable := &cobra.Command{
		Use:   "enable <platform>",
		Short: "Set up the Contro1 MCP server for one agent, end to end",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			platform := args[0]
			ctx := cmd.Context()
			prompt := terminalPrompt{json: flagFormat == "json"}

			conn, err := platforms.SelectLocalConnection(appsAgent)
			if err != nil {
				if errors.Is(err, platforms.ErrNoLocalConnection) {
					return output.Errf(output.CodeBadArgs,
						"this computer has no Contro1 connection yet. Connect the agent first: contro1 connect %s", platform)
				}
				return output.Errf(output.CodeBadArgs, "%v", err)
			}
			if conn.Platform != platform {
				return output.Errf(output.CodeBadArgs,
					"that connection is a %s agent, not %s; name the one you mean with --agent", conn.Platform, platform)
			}

			adapter, err := platforms.New(platform, platforms.Options{McpURL: mcpURL()})
			if err != nil {
				return output.Errf(output.CodeBadArgs, "%v", err)
			}

			// 1. The owner's decision. Asked for, never assumed, and never
			//    taken from a flag: it permits software to read their mail.
			status, err := fetchRuntimeStatus(ctx, conn)
			if err != nil {
				return output.Errf(output.CodeNetwork, "%v", err)
			}
			if status.EndpointMode != "agent_runtime" {
				// The setup page, which is where allowing applications lives. Not a
				// generic agent page: this link exists to get one decision made.
				url := fmt.Sprintf("%s/agents/setup?ids=%s", frontendURL(), conn.AgentID)
				prompt.Progress(fmt.Sprintf(
					"This connection is %q. Its owner has to allow applications, and choose which ones, in Contro1.",
					status.ModeLabel))
				prompt.Progress("  " + url)
				if prompt.Interactive() {
					_ = browser.OpenURL(url)
				}
				status, err = waitForApplications(ctx, conn, appsWait, prompt)
				if err != nil {
					return output.Errf(output.CodeNetwork, "%v", err)
				}
			}
			prompt.Progress("Applications are allowed for this connection.")

			// 2. The local work. Shown before it happens, because two of these
			//    change how a container starts.
			changes := adapter.ApplicationChanges(conn)
			lines := make([]string, 0, len(changes))
			for _, c := range changes {
				lines = append(lines, c.Description)
			}
			if !appsYes {
				if !prompt.Interactive() || !prompt.Confirm(fmt.Sprintf("Set up applications for %s?", displayOf(conn)), lines) {
					fmt.Println(strings.Join(commandsOf(changes), "\n"))
					return output.Errf(output.CodeUnsafeBlocked,
						"review what will change on this computer, then run again with --yes")
				}
			}

			journal := &platforms.Journal{}
			if err := adapter.ApplyApplications(ctx, conn, journal); err != nil {
				return output.Errf(output.CodeNetwork, "%v", err)
			}

			prompt.Progress("Done. " + adapter.SafeTest())
			return renderApplicationsResult(conn, status, journal)
		},
	}
	enable.Flags().StringVar(&appsAgent, "agent", "", "Contro1 agent id or the platform's own id; only needed with more than one connection")
	enable.Flags().BoolVar(&appsYes, "yes", false, "apply the local changes without asking. It never stands in for the owner's decision in Contro1")
	enable.Flags().DurationVar(&appsWait, "wait", 10*time.Minute, "how long to wait for the owner to allow applications")

	appsCmd.AddCommand(enable)
	rootCmd.AddCommand(appsCmd)
}

// waitForApplications polls the agent's own endpoint until its owner widens the
// connection. Polling the endpoint rather than the API because this is the same
// answer the agent itself will get, so a success here cannot be a success the
// agent does not share.
func waitForApplications(ctx context.Context, conn platforms.LocalConnection, wait time.Duration, prompt terminalPrompt) (runtimeStatus, error) {
	deadline := time.Now().Add(wait)
	prompt.Progress("Waiting for that. This page stays valid; nothing here expires.")
	for {
		select {
		case <-ctx.Done():
			return runtimeStatus{}, ctx.Err()
		case <-time.After(3 * time.Second):
		}
		status, err := fetchRuntimeStatus(ctx, conn)
		if err == nil && status.EndpointMode == "agent_runtime" {
			return status, nil
		}
		if time.Now().After(deadline) {
			return runtimeStatus{}, errors.New(
				"applications were not allowed in time. Nothing was changed on this computer; run this again when the owner has done it")
		}
	}
}

/*
frontendURL derives where a person signs in from where the CLI talks to the API.

Derived rather than configured, because one more setting is one more thing to
get wrong for a link whose only job is to open the right page. `api.` is
stripped when it is there; anything else is used as it stands, so a self hosted
deployment on one host still gets a working link. CONTRO1_APP_URL overrides it
for a deployment that splits them differently.
*/
func frontendURL() string {
	if v := strings.TrimSpace(os.Getenv("CONTRO1_APP_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	api := flagAPIURL
	if api == "" {
		if _, profile, _, err := loadCtx(); err == nil {
			api = profile.APIURL
		}
	}
	api = strings.TrimRight(api, "/")
	if api == "" {
		return "https://contro1.com"
	}
	if i := strings.Index(api, "://api."); i >= 0 {
		return api[:i+3] + api[i+7:]
	}
	return api
}

func displayOf(conn platforms.LocalConnection) string {
	if conn.DisplayName != "" {
		return conn.DisplayName
	}
	return conn.PlatformSubject
}

func commandsOf(changes []platforms.Change) []string {
	out := make([]string, 0, len(changes))
	for _, c := range changes {
		if c.After != "" {
			out = append(out, c.After)
		}
	}
	return out
}

func renderApplicationsResult(conn platforms.LocalConnection, status runtimeStatus, j *platforms.Journal) error {
	if flagFormat == "json" {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{
			"agent_id":         conn.AgentID,
			"platform":         conn.Platform,
			"platform_subject": conn.PlatformSubject,
			"endpoint_mode":    status.EndpointMode,
			"applied":          j.RoleCommands,
		})
	}
	fmt.Printf("%s can now reach the applications its owner allowed, through Contro1.\n", displayOf(conn))
	return nil
}

// mcpURL is where a platform that cannot use a local endpoint reaches Contro1.
func mcpURL() string {
	api := flagAPIURL
	if api == "" {
		if _, profile, _, err := loadCtx(); err == nil {
			api = profile.APIURL
		}
	}
	if api == "" {
		api = "https://api.contro1.com"
	}
	return strings.TrimRight(api, "/") + "/api/centcom/mcp"
}
