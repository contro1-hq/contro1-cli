package cmd

import "github.com/spf13/cobra"

func init() {
	c := &cobra.Command{
		Use:     "whoami",
		Short:   "Show the current account, org and scopes",
		GroupID: groupCore,
		RunE:    runWhoami,
	}
	c.Flags().BoolVar(&whoamiScopes, "scopes", false, "list granted scopes")
	rootCmd.AddCommand(c)
}
