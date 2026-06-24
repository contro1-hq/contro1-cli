package cmd

import (
	"github.com/contro1-hq/contro1-cli/internal/client"
	"github.com/contro1-hq/contro1-cli/internal/output"
	"github.com/spf13/cobra"
)

func init() {
	apiKeysCmd := &cobra.Command{
		Use:     "api-keys",
		Short:   "Read API key metadata (read-only in v1)",
		GroupID: groupAdmin,
	}
	apiKeysCmd.AddCommand(&cobra.Command{Use: "list", Short: "List API keys (metadata only)", RunE: runApiKeysList})
	apiKeysCmd.AddCommand(&cobra.Command{
		Use:   "get <id>",
		Short: "Show one API key's metadata",
		Args:  cobra.ExactArgs(1),
		RunE:  runApiKeyGet,
	})
	rootCmd.AddCommand(apiKeysCmd)
}

func fetchApiKeys(c *client.Client) ([]any, error) {
	resp, err := c.Do("GET", "/api/centcom/v1/cli/api-keys", nil)
	if err != nil {
		return nil, err
	}
	return asSlice(client.Data(resp)), nil
}

func runApiKeysList(_ *cobra.Command, _ []string) error {
	c, pr, err := newClient()
	if err != nil {
		return err
	}
	keys, err := fetchApiKeys(c)
	if err != nil {
		return err
	}
	tbl := &output.Table{Headers: []string{"ID", "LABEL", "PREFIX", "INTEGRATION", "ROUTING"}}
	for _, k := range keys {
		m := asMap(k)
		tbl.Rows = append(tbl.Rows, []string{
			str(m["id"]), str(m["label"]), str(m["key_prefix"]), str(m["integration"]), str(m["routing_mode"]),
		})
	}
	return output.Render(outFormat(pr), keys, tbl)
}

func runApiKeyGet(_ *cobra.Command, args []string) error {
	c, pr, err := newClient()
	if err != nil {
		return err
	}
	keys, err := fetchApiKeys(c)
	if err != nil {
		return err
	}
	for _, k := range keys {
		m := asMap(k)
		if str(m["id"]) == args[0] {
			return output.Render(outFormat(pr), m, nil)
		}
	}
	return output.Errf(output.CodeGeneral, "API key %s not found", args[0])
}
