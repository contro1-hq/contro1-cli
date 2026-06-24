package cmd

import (
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/contro1-hq/contro1-cli/internal/client"
	"github.com/contro1-hq/contro1-cli/internal/config"
	"github.com/contro1-hq/contro1-cli/internal/output"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(&cobra.Command{
		Use:     "doctor",
		Short:   "Diagnose connectivity, authentication and scopes",
		GroupID: groupCore,
		RunE:    runDoctor,
	})
}

type checkResult struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

func runDoctor(_ *cobra.Command, _ []string) error {
	_, pr, name, err := loadCtx()
	if err != nil {
		return err
	}
	apiURL := pr.APIURL
	if flagAPIURL != "" {
		apiURL = flagAPIURL
	}

	var checks []checkResult
	add := func(n string, ok bool, detail string) { checks = append(checks, checkResult{n, ok, detail}) }

	// connectivity
	add("API reachable", httpReachable(strings.TrimRight(apiURL, "/")+"/health"), apiURL)
	if pr.WebURL != "" {
		add("Web reachable", httpReachable(pr.WebURL), pr.WebURL)
	}

	// auth
	tok, terr := resolveToken(name)
	tokenSource := "keychain"
	if os.Getenv("CONTRO1_TOKEN") != "" {
		tokenSource = "CONTRO1_TOKEN env"
	}
	if terr != nil {
		add("Authenticated", false, "run 'contro1 auth login'")
		return renderDoctor(pr, checks)
	}
	add("Token present", true, tokenSource)

	c := client.New(apiURL, tok, userAgent())
	resp, err := c.Do("GET", "/api/centcom/v1/cli/whoami", nil)
	if err != nil {
		add("Token valid", false, err.Error())
		return renderDoctor(pr, checks)
	}
	data := asMap(client.Data(resp))
	op := asMap(data["operator"])
	org := asMap(data["org"])
	authm := asMap(data["auth"])
	add("Token valid", true, "")
	add("Authenticated as", true, str(op["email"]))
	add("Org", str(org["name"]) != "", str(org["name"]))
	add("Token type", true, str(authm["type"]))

	// scope presence for the core workflow
	granted := map[string]bool{}
	for _, s := range asSlice(authm["scopes"]) {
		granted[str(s)] = true
	}
	for _, s := range []string{"requests:create", "requests:wait", "evidence:read", "agents:register"} {
		add("Scope "+s, granted[s], "")
	}

	return renderDoctor(pr, checks)
}

func renderDoctor(pr *config.Profile, checks []checkResult) error {
	if outFormat(pr) == "json" {
		return output.Render("json", checks, nil)
	}
	output.Info("Contro1 CLI Doctor\n")
	allOK := true
	for _, c := range checks {
		mark := "[ok]"
		if !c.OK {
			mark = "[x]"
			allOK = false
		}
		line := mark + " " + c.Name
		if c.Detail != "" {
			line += ": " + c.Detail
		}
		output.Info("%s", line)
	}
	if !allOK {
		return output.Errf(output.CodeGeneral, "one or more checks failed")
	}
	return nil
}

func httpReachable(url string) bool {
	cl := &http.Client{Timeout: 5 * time.Second}
	resp, err := cl.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode < 500
}
