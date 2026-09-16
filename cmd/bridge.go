package cmd

import (
	"os"
	"os/exec"

	"github.com/contro1-hq/contro1-cli/internal/output"
	"github.com/spf13/cobra"
)

var (
	bridgeTarget string
	bridgeNcl    string
)

func init() {
	bridgeCmd := &cobra.Command{Use: "bridge", Short: "Machine-readable bridge contract for host adapters", GroupID: groupAgent}
	manifestCmd := &cobra.Command{Use: "manifest", Short: "Print the supported bridge manifest", RunE: runBridgeManifest}
	manifestCmd.Flags().StringVar(&bridgeTarget, "target", "", "bridge target: openclaw|nanoclaw")
	doctorCmd := &cobra.Command{Use: "doctor", Short: "Diagnose bridge prerequisites", RunE: runBridgeDoctor}
	doctorCmd.Flags().StringVar(&bridgeTarget, "target", "", "bridge target: openclaw|nanoclaw")
	doctorCmd.Flags().StringVar(&bridgeNcl, "ncl", "ncl", "NanoClaw admin CLI: a command on PATH or a path such as /opt/nanoclaw/bin/ncl")
	bridgeCmd.AddCommand(manifestCmd, doctorCmd)
	rootCmd.AddCommand(bridgeCmd)
}

func normalizeBridgeTarget() (string, error) {
	switch bridgeTarget {
	case "openclaw", "nanoclaw":
		return bridgeTarget, nil
	default:
		return "", output.Errf(output.CodeBadArgs, "--target must be openclaw or nanoclaw")
	}
}

func bridgeManifest(target string) map[string]any {
	return map[string]any{
		"schema_version":   "1.0",
		"cli_version":      Version,
		"runtime_contract": "contro1-cli-runtime-v1",
		"target":           target,
		"commands": []map[string]any{
			{
				"name":            "create_approval",
				"agent_tool_name": "contro1_create_approval",
				"cli":             []string{"contro1", "requests", "create", "--runtime"},
				"mode":            "non_blocking",
				"required_scopes": []string{"requests:create"},
				"safe_for_agent":  true,
			},
			{
				"name":            "get_approval_status",
				"agent_tool_name": "contro1_get_approval_status",
				"cli":             []string{"contro1", "requests", "get", "--runtime"},
				"mode":            "poll",
				"required_scopes": []string{"requests:read"},
				"safe_for_agent":  true,
			},
			{
				"name":            "cancel_approval",
				"agent_tool_name": "contro1_cancel_approval",
				"cli":             []string{"contro1", "requests", "cancel", "--runtime"},
				"mode":            "non_blocking",
				"required_scopes": []string{"requests:cancel_own"},
				"safe_for_agent":  true,
			},
			{
				"name":                      "invoke_action",
				"agent_tool_name":           "contro1_invoke_action",
				"cli":                       []string{"contro1", "actions", "invoke"},
				"mode":                      "non_blocking",
				"required_scopes":           []string{"actions:execute"},
				"requires_agent_credential": true,
				"safe_for_agent":            true,
			},
			{
				"name":            "get_action_status",
				"agent_tool_name": "contro1_get_action_status",
				"cli":             []string{"contro1", "actions", "get", "--runtime"},
				"mode":            "poll",
				"required_scopes": []string{"actions:read"},
				"safe_for_agent":  true,
			},
			{
				"name":                      "cancel_action",
				"agent_tool_name":           "contro1_cancel_action",
				"cli":                       []string{"contro1", "actions", "cancel"},
				"mode":                      "non_blocking",
				"required_scopes":           []string{"actions:execute"},
				"requires_agent_credential": true,
				"safe_for_agent":            true,
			},
			{
				"name":            "report_activity",
				"agent_tool_name": "contro1_report_activity",
				"cli":             []string{"contro1", "activity", "report"},
				"mode":            "non_blocking",
				"required_scopes": []string{"audit:write"},
				"safe_for_agent":  true,
			},
		},
		"forbidden_guidance": []string{
			"Do not expose queue approve to agents.",
			"Do not expose queue reject to agents.",
			"Do not expose auth print-access-token.",
			"Do not expose contro1 run as a generic shell executor.",
			"The manifest is discovery, not an enforcement boundary; server scopes and the host bridge enforce authority.",
		},
	}
}

func runBridgeManifest(_ *cobra.Command, _ []string) error {
	target, err := normalizeBridgeTarget()
	if err != nil {
		return err
	}
	_, pr, _, err := loadCtx()
	if err != nil {
		return err
	}
	return output.Render(outFormat(pr), bridgeManifest(target), nil)
}

func runBridgeDoctor(_ *cobra.Command, _ []string) error {
	target, err := normalizeBridgeTarget()
	if err != nil {
		return err
	}
	c, pr, source, err := newRuntimeClient()
	var checks []checkResult
	add := func(n string, ok bool, detail string) { checks = append(checks, checkResult{n, ok, detail}) }
	add("Manifest schema", true, "1.0")
	add("CLI version", Version != "", Version)
	if err != nil {
		add("Runtime token", false, err.Error())
		return renderDoctor(pr, checks)
	}
	add("Runtime token", true, source)
	// What an approval bridge must be able to do. Gateway Action scopes are only
	// needed when the bridge also exposes Action tools, so they are reported, not required.
	status, statusErr := requireRuntimeStatus(c, "requests:create", "requests:read", "requests:cancel_own", "audit:write")
	if statusErr != nil {
		add("Runtime credential", false, statusErr.Error())
	} else {
		auth := asMap(status["auth"])
		add("Runtime credential", true, str(auth["agent_id"]))
		granted := map[string]bool{}
		for _, s := range asSlice(auth["scopes"]) {
			granted[str(s)] = true
		}
		detail := "not granted (only needed for Gateway Action tools)"
		if granted["actions:execute"] {
			detail = "granted"
		}
		add("Gateway Actions", true, detail)
	}
	switch target {
	case "openclaw":
		_, err := exec.LookPath("openclaw")
		add("OpenClaw CLI", err == nil, "openclaw")
	case "nanoclaw":
		add("NanoClaw CLI", commandAvailable(bridgeNcl), bridgeNcl)
		add("NanoClaw approval resolver", true, "contro1 channel adapter (add-contro1 skill); decisions resolve through NanoClaw's own approval handler")
	}
	return renderDoctor(pr, checks)
}

// commandAvailable accepts a command on PATH or a path to an executable, since
// NanoClaw's ncl usually lives at <checkout>/bin/ncl rather than on PATH.
func commandAvailable(command string) bool {
	if _, err := exec.LookPath(command); err == nil {
		return true
	}
	info, err := os.Stat(command)
	return err == nil && !info.IsDir()
}
