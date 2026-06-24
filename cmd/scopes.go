package cmd

import (
	"github.com/contro1-hq/contro1-cli/internal/client"
	"github.com/contro1-hq/contro1-cli/internal/output"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(&cobra.Command{
		Use:     "scopes",
		Short:   "List the scopes granted to your CLI token",
		GroupID: groupCore,
		RunE:    runScopes,
	})
}

func runScopes(_ *cobra.Command, _ []string) error {
	c, pr, err := newClient()
	if err != nil {
		return err
	}
	resp, err := c.Do("GET", "/api/centcom/v1/cli/whoami", nil)
	if err != nil {
		return err
	}
	authm := asMap(asMap(client.Data(resp))["auth"])
	scopes := asSlice(authm["scopes"])
	tbl := &output.Table{Headers: []string{"SCOPE"}}
	for _, s := range scopes {
		tbl.Rows = append(tbl.Rows, []string{str(s)})
	}
	return output.Render(outFormat(pr), scopes, tbl)
}
