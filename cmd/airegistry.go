package cmd

import (
	"encoding/json"
	"io"
	"os"

	"github.com/contro1-hq/contro1-cli/internal/client"
	"github.com/contro1-hq/contro1-cli/internal/output"
	"github.com/spf13/cobra"
)

func init() {
	airCmd := &cobra.Command{
		Use:     "ai-registry",
		Short:   "Read and update the AI registry (EU AI Act inventory)",
		GroupID: groupAgent,
	}

	airCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List AI systems and the readiness score",
		RunE:  runAiRegistryList,
	})

	importCmd := &cobra.Command{
		Use:   "import <file.json>",
		Short: "Import an inventory JSON straight from the CLI",
		Long: `Import an AI inventory JSON file into the registry.

Pass a file path, or "-" to read JSON from stdin. The file may be the raw
inventory object (with ai_systems_found / gap arrays) or { "inventory": {...} }.`,
		Example: `  contro1 ai-registry import ./inventory.json
  cat inventory.json | contro1 ai-registry import -`,
		Args: cobra.ExactArgs(1),
		RunE: runAiRegistryImport,
	}
	airCmd.AddCommand(importCmd)

	rootCmd.AddCommand(airCmd)
}

func runAiRegistryList(_ *cobra.Command, _ []string) error {
	c, pr, err := newClient()
	if err != nil {
		return err
	}
	resp, err := c.Do("GET", "/api/centcom/v1/cli/ai-registry", nil)
	if err != nil {
		return err
	}
	data := asMap(client.Data(resp))
	readiness := asMap(data["readiness"])
	systems := asSlice(data["systems"])

	infof("Readiness score: %s", str(firstNonEmpty(readiness["score"], readiness["readiness_score"], "n/a")))
	tbl := &output.Table{Headers: []string{"NAME", "RISK", "ENV", "GAPS"}}
	for _, s := range systems {
		m := asMap(s)
		tbl.Rows = append(tbl.Rows, []string{
			truncate(str(m["name"]), 30), str(m["risk_category"]), str(m["environment"]), gapSummary(asMap(m["gaps"])),
		})
	}
	return output.Render(outFormat(pr), data, tbl)
}

func runAiRegistryImport(_ *cobra.Command, args []string) error {
	raw, err := readInput(args[0])
	if err != nil {
		return output.Errf(output.CodeBadArgs, "reading inventory: %v", err)
	}
	var inventory any
	if err := json.Unmarshal(raw, &inventory); err != nil {
		return output.Errf(output.CodeBadArgs, "inventory is not valid JSON: %v", err)
	}

	c, pr, err := newClient()
	if err != nil {
		return err
	}
	resp, err := c.Do("POST", "/api/centcom/v1/cli/ai-registry/import", inventory)
	if err != nil {
		return err
	}
	data := asMap(client.Data(resp))
	summary := asMap(data["summary"])
	readiness := asMap(data["readiness"])
	created := str(firstNonEmpty(summary["systems_created"], summary["created"], float64(0)))
	updated := str(firstNonEmpty(summary["systems_updated"], summary["updated"], float64(0)))
	score := str(firstNonEmpty(readiness["score"], readiness["readiness_score"], "n/a"))
	infof("Imported. created=%s updated=%s. Readiness score: %s", created, updated, score)
	return output.Render(outFormat(pr), data, &output.Table{
		Headers: []string{"FIELD", "VALUE"},
		Rows: [][]string{
			{"systems_created", created},
			{"systems_updated", updated},
			{"readiness", score},
		},
	})
}

func readInput(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func gapSummary(g map[string]any) string {
	open := ""
	for _, k := range []string{"disclosure", "content_review", "human_approval", "audit_trail"} {
		if b, ok := g[k].(bool); ok && b {
			if open != "" {
				open += ","
			}
			open += k
		}
	}
	if open == "" {
		return "-"
	}
	return open
}
