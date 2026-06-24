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
)

// Exit codes (documented contract for scripts and agents).
const (
	CodeOK              = 0
	CodeGeneral        = 1
	CodeBadArgs        = 2
	CodeAuth           = 3
	CodeInsufficient   = 4 // insufficient scope
	CodeRequestDenied  = 5
	CodeTimeout        = 6
	CodeNetwork        = 7
)

// ExitError carries an exit code out to main().
type ExitError struct {
	Code int
	Msg  string
}

func (e *ExitError) Error() string { return e.Msg }

// Errf builds an ExitError.
func Errf(code int, format string, args ...any) *ExitError {
	return &ExitError{Code: code, Msg: fmt.Sprintf(format, args...)}
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
