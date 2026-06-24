package cmd

import (
	"github.com/contro1-hq/contro1-cli/internal/config"
	"github.com/contro1-hq/contro1-cli/internal/output"
	"github.com/spf13/cobra"
)

func init() {
	configCmd := &cobra.Command{
		Use:     "config",
		Short:   "Manage CLI configuration and profiles",
		GroupID: groupCore,
	}

	configCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "Show the active profile settings",
		RunE:  runConfigList,
	})

	configCmd.AddCommand(&cobra.Command{
		Use:   "get <key>",
		Short: "Get a config value (api-url|web-url|format)",
		Args:  cobra.ExactArgs(1),
		RunE:  runConfigGet,
	})

	configCmd.AddCommand(&cobra.Command{
		Use:     "set <key> <value>",
		Short:   "Set a config value (api-url|web-url|format)",
		Example: "  contro1 config set api-url https://api.contro1.com",
		Args:    cobra.ExactArgs(2),
		RunE:    runConfigSet,
	})

	profilesCmd := &cobra.Command{Use: "profiles", Short: "Manage configuration profiles"}
	profilesCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List profiles",
		RunE:  runProfilesList,
	})
	profilesCmd.AddCommand(&cobra.Command{
		Use:   "use <name>",
		Short: "Switch the active profile",
		Args:  cobra.ExactArgs(1),
		RunE:  runProfilesUse,
	})
	configCmd.AddCommand(profilesCmd)

	rootCmd.AddCommand(configCmd)
}

func runConfigList(_ *cobra.Command, _ []string) error {
	_, pr, name, err := loadCtx()
	if err != nil {
		return err
	}
	data := map[string]any{
		"profile":        name,
		"api_url":        pr.APIURL,
		"web_url":        pr.WebURL,
		"operator_email": pr.OperatorEmail,
		"org_name":       pr.OrgName,
		"output_format":  outFormat(pr),
	}
	tbl := &output.Table{
		Headers: []string{"FIELD", "VALUE"},
		Rows: [][]string{
			{"profile", name},
			{"api_url", pr.APIURL},
			{"web_url", pr.WebURL},
			{"operator_email", pr.OperatorEmail},
			{"org_name", pr.OrgName},
			{"output_format", outFormat(pr)},
		},
	}
	return output.Render(outFormat(pr), data, tbl)
}

func runConfigGet(_ *cobra.Command, args []string) error {
	_, pr, _, err := loadCtx()
	if err != nil {
		return err
	}
	val, err := readKey(pr, args[0])
	if err != nil {
		return err
	}
	output.Info("%s", val)
	return nil
}

func runConfigSet(_ *cobra.Command, args []string) error {
	cfg, pr, _, err := loadCtx()
	if err != nil {
		return err
	}
	switch args[0] {
	case "api-url", "api_url":
		pr.APIURL = args[1]
	case "web-url", "web_url":
		pr.WebURL = args[1]
	case "format", "output-format", "output_format":
		pr.OutputFormat = args[1]
	default:
		return output.Errf(output.CodeBadArgs, "unknown config key %q (api-url|web-url|format)", args[0])
	}
	if err := cfg.Save(); err != nil {
		return output.Errf(output.CodeGeneral, "saving config: %v", err)
	}
	infof("Set %s.", args[0])
	return nil
}

func readKey(pr *config.Profile, key string) (string, error) {
	switch key {
	case "api-url", "api_url":
		return pr.APIURL, nil
	case "web-url", "web_url":
		return pr.WebURL, nil
	case "format", "output-format", "output_format":
		return pr.OutputFormat, nil
	default:
		return "", output.Errf(output.CodeBadArgs, "unknown config key %q", key)
	}
}

func runProfilesList(_ *cobra.Command, _ []string) error {
	cfg, pr, _, err := loadCtx()
	if err != nil {
		return err
	}
	tbl := &output.Table{Headers: []string{"PROFILE", "ACTIVE", "API URL", "ACCOUNT"}}
	names := make([]any, 0, len(cfg.Profiles))
	for n, p := range cfg.Profiles {
		active := ""
		if n == cfg.CurrentProfile {
			active = "*"
		}
		tbl.Rows = append(tbl.Rows, []string{n, active, p.APIURL, p.OperatorEmail})
		names = append(names, n)
	}
	return output.Render(outFormat(pr), names, tbl)
}

func runProfilesUse(_ *cobra.Command, args []string) error {
	cfg, _, _, err := loadCtx()
	if err != nil {
		return err
	}
	cfg.Profile(args[0]) // ensure it exists
	cfg.CurrentProfile = args[0]
	if err := cfg.Save(); err != nil {
		return output.Errf(output.CodeGeneral, "saving config: %v", err)
	}
	infof("Switched to profile %q.", args[0])
	return nil
}
