// Package output handles unified CLI rendering (table/json/yaml), exit codes and
// the structured error type used across commands.
package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"gopkg.in/yaml.v3"

	"github.com/contro1-hq/contro1-cli/internal/runtimeproto"
)

// Exit codes (documented contract for scripts and agents).
const (
	CodeOK            = 0
	CodeGeneral       = 1
	CodeBadArgs       = 2
	CodeAuth          = 3
	CodeInsufficient  = 4 // insufficient scope
	CodeRequestDenied = 5
	CodeTimeout       = 6
	CodeNetwork       = 7
	// 8-10 were added for runtime bridges. 0-7 keep their meaning.
	CodeNotFound      = 8
	CodeConflict      = 9  // 409/412, including an idempotency or binding conflict
	CodeUnsafeBlocked = 10 // refused locally before any request was sent
)

// ExitError carries an exit code out to main().
type ExitError struct {
	Code int
	Msg  string
	// Remediation, when present, says what is missing, who can fix it and the
	// next step. JSON output preserves it so agents never parse prose.
	Remediation *runtimeproto.Remediation
}

func (e *ExitError) Error() string { return e.Msg }

// Errf builds an ExitError.
func Errf(code int, format string, args ...any) *ExitError {
	return &ExitError{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// WithRemediation attaches a remediation to an ExitError.
func (e *ExitError) WithRemediation(r *runtimeproto.Remediation) *ExitError {
	e.Remediation = r
	return e
}

// RenderError prints an error. With --format json and a remediation, the
// whole object goes to stderr as JSON; otherwise the classic "error: msg" line,
// followed by the next step when one is known.
func RenderError(format string, e *ExitError) {
	if e.Remediation != nil && format == "json" {
		raw, _ := json.MarshalIndent(map[string]any{
			"error": map[string]any{"exit_code": e.Code, "message": e.Msg, "remediation": e.Remediation},
		}, "", "  ")
		fmt.Fprintln(os.Stderr, string(raw))
		return
	}
	fmt.Fprintln(os.Stderr, "error: "+e.Msg)
	if e.Remediation != nil {
		if e.Remediation.PublicMessage != "" && e.Remediation.PublicMessage != e.Msg {
			fmt.Fprintln(os.Stderr, "  "+e.Remediation.PublicMessage)
		}
		if e.Remediation.NextStep != "" {
			fmt.Fprintln(os.Stderr, "  next: "+e.Remediation.NextStep)
		}
		if e.Remediation.ActionURL != "" {
			fmt.Fprintln(os.Stderr, "  "+e.Remediation.ActionURL)
		}
	}
}

// Table is a simple tabular payload used for the human-friendly format.
type Table struct {
	Headers []string
	Rows    [][]string
}

// Render prints raw (json/yaml) or table depending on format. When format is
// "table" but no table is provided, it falls back to JSON.
func Render(format string, raw any, table *Table) error {
	switch format {
	case "json":
		return printJSON(raw)
	case "yaml":
		return printYAML(raw)
	default: // table
		if table == nil {
			return printJSON(raw)
		}
		return printTable(table)
	}
}

// Success prints the standard {ok,data} envelope payload (data only).
func Success(format string, data any, table *Table) error {
	return Render(format, data, table)
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func printYAML(v any) error {
	data, err := yaml.Marshal(v)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(data)
	return err
}

func printTable(t *Table) error {
	if len(t.Rows) == 0 {
		fmt.Fprintln(os.Stdout, "(no results)")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	if len(t.Headers) > 0 {
		fmt.Fprintln(w, strings.Join(t.Headers, "\t"))
		seps := make([]string, len(t.Headers))
		for i, h := range t.Headers {
			seps[i] = strings.Repeat("-", len(h))
		}
		fmt.Fprintln(w, strings.Join(seps, "\t"))
	}
	for _, row := range t.Rows {
		fmt.Fprintln(w, strings.Join(row, "\t"))
	}
	return w.Flush()
}

// Info prints a status line to stderr (kept out of stdout so json stays clean).
func Info(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}
