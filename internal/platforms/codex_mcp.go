package platforms

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

/*
Codex's MCP servers, checked against the Codex source (codex-rs/cli/src/mcp_cmd.rs,
2026-10-21) and its config reference:

  - they live in $CODEX_HOME/config.toml (default ~/.codex) as
    [mcp_servers.<name>] with command and args;
  - `codex mcp add <name> -- <command> <args...>` writes one, replacing an
    entry of the same name without asking;
  - `codex mcp get <name> --json` prints {"name", "transport": {"type":
    "stdio", "command", "args", ...}, ...} and fails when there is none;
  - `codex mcp remove <name>` succeeds whether or not it existed.

So connect uses Codex's own command, which knows its file and its format, and
reads the entry back first, because `add` would otherwise replace another
identity without a word. config.toml is backed up before either command runs.
When codex is not on this computer's PATH the exact [mcp_servers.contro1] block
is printed instead; connect does not write TOML it did not have to.

`codex mcp list` shows "Auth: Unsupported" for this server. That is Codex
saying it holds no OAuth sign-in for a stdio server, which is right: the
Contro1 CLI is the one that signs in, as this agent, through the Contro1
service on this computer.
*/

const codexMcpName = "contro1"

var errNoCodex = errors.New("the codex command is not on this computer's PATH")

func (c *codex) bin() string {
	if c.opts.Bin != "" {
		return c.opts.Bin
	}
	return "codex"
}

func (c *codex) home() string {
	if v := strings.TrimSpace(os.Getenv("CODEX_HOME")); v != "" {
		return v
	}
	return filepath.Join(c.opts.Home, ".codex")
}

func (c *codex) configPath() string {
	return filepath.Join(c.mcpConfigDir(c.home()), "config.toml")
}

func codexAddArgs(subject string) []string {
	return append([]string{"mcp", "add", codexMcpName, "--", contro1Binary()}, mcpArgs(subject)...)
}

func (c *codex) addLine(subject string) string {
	return c.bin() + " " + strings.Join(codexAddArgs(subject), " ")
}

// tomlString quotes a value as a TOML literal string when it can be one, so a
// Windows path needs no escaping, and as a basic string otherwise.
func tomlString(s string) string {
	if !strings.ContainsAny(s, "'\n\r") {
		return "'" + s + "'"
	}
	return strconv.Quote(s)
}

// codexBlock is the exact table for config.toml.
func codexBlock(subject string) string {
	args := mcpArgs(subject)
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = strconv.Quote(a)
	}
	return "[mcp_servers." + codexMcpName + "]\ncommand = " + tomlString(contro1Binary()) + "\nargs = [" + strings.Join(quoted, ", ") + "]"
}

/*
registered is the contro1 entry as Codex has it.

Codex is asked first. When it cannot answer (not installed, or a build without
`mcp get --json`), config.toml is read directly, so an entry for another
identity is still seen before anything is written over it.
*/
func (c *codex) registered(ctx context.Context) (server McpServer, found bool, noCodex bool) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, err := c.opts.Runner(ctx, c.bin(), "mcp", "get", codexMcpName, "--json")
	if err == nil {
		if s, ok := parseCodexMcpGet(out); ok {
			return s, true, false
		}
	}
	noCodex = err != nil && errors.Is(err, exec.ErrNotFound)
	if raw, readErr := os.ReadFile(c.configPath()); readErr == nil {
		if s, ok := parseCodexToml(string(raw), codexMcpName); ok {
			return s, true, noCodex
		}
	}
	return McpServer{}, false, noCodex
}

func parseCodexMcpGet(out []byte) (McpServer, bool) {
	var v struct {
		Name      string `json:"name"`
		Transport struct {
			Type    string   `json:"type"`
			Command string   `json:"command"`
			Args    []string `json:"args"`
			URL     string   `json:"url"`
		} `json:"transport"`
	}
	if json.Unmarshal(out, &v) != nil || (v.Transport.Command == "" && v.Transport.URL == "") {
		return McpServer{}, false
	}
	return McpServer{Name: firstNonEmpty(v.Name, codexMcpName), Command: v.Transport.Command, Args: v.Transport.Args, URL: v.Transport.URL, Scope: "user"}, true
}

var tomlTableHeader = regexp.MustCompile(`^\s*\[\s*([^\]]+?)\s*\]\s*(#.*)?$`)

/*
parseCodexToml reads one [mcp_servers.<name>] table out of config.toml: its
command, args and url. Enough to compare an entry, not a TOML parser; a form it
does not understand is reported as no entry, and then the codex command (which
does understand it) is what writes.
*/
func parseCodexToml(text, name string) (McpServer, bool) {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	in := false
	found := false
	s := McpServer{Name: name, Scope: "user"}
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if m := tomlTableHeader.FindStringSubmatch(line); m != nil && !strings.HasPrefix(strings.TrimSpace(line), "[[") {
			header := strings.ReplaceAll(m[1], `"`, "")
			in = header == "mcp_servers."+name
			if in {
				found = true
			}
			continue
		}
		if !in {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case "command":
			s.Command, _ = tomlScalar(value)
		case "url":
			s.URL, _ = tomlScalar(value)
		case "args":
			// An array can span lines.
			for !strings.Contains(stripTomlStrings(value), "]") && i+1 < len(lines) {
				i++
				value += " " + strings.TrimSpace(lines[i])
			}
			s.Args = tomlStringArray(value)
		}
	}
	return s, found && (s.Command != "" || s.URL != "")
}

func tomlScalar(v string) (string, bool) {
	v = strings.TrimSpace(v)
	switch {
	case strings.HasPrefix(v, "'"):
		if end := strings.Index(v[1:], "'"); end >= 0 {
			return v[1 : end+1], true
		}
	case strings.HasPrefix(v, `"`):
		for end := 1; end < len(v); end++ {
			if v[end] == '\\' {
				end++
				continue
			}
			if v[end] == '"' {
				if out, err := strconv.Unquote(v[:end+1]); err == nil {
					return out, true
				}
				return v[1:end], true
			}
		}
	}
	return "", false
}

// stripTomlStrings blanks quoted text, so a "]" inside an argument does not end
// the array.
func stripTomlStrings(v string) string {
	var b strings.Builder
	quote := byte(0)
	for i := 0; i < len(v); i++ {
		ch := v[i]
		switch {
		case quote == 0 && (ch == '"' || ch == '\''):
			quote = ch
		case quote == '"' && ch == '\\':
			i++
		case quote != 0 && ch == quote:
			quote = 0
		case quote == 0:
			b.WriteByte(ch)
		}
	}
	return b.String()
}

func tomlStringArray(v string) []string {
	var out []string
	rest := strings.TrimSpace(v)
	rest = strings.TrimPrefix(rest, "[")
	for {
		rest = strings.TrimLeft(rest, " \t,")
		if rest == "" || rest[0] == ']' || rest[0] == '#' {
			return out
		}
		s, ok := tomlScalar(rest)
		if !ok {
			return out
		}
		out = append(out, s)
		// Skip past the string just read.
		if rest[0] == '\'' {
			rest = rest[strings.Index(rest[1:], "'")+2:]
		} else {
			end := 1
			for end < len(rest) {
				if rest[end] == '\\' {
					end += 2
					continue
				}
				if rest[end] == '"' {
					break
				}
				end++
			}
			rest = rest[min(end+1, len(rest)):]
		}
	}
}

func (c *codex) McpChanges(ctx context.Context, subjects []string) []Change {
	subjects = sortedUnique(subjects)
	if len(subjects) != 1 {
		return nil
	}
	subject := subjects[0]
	current, found, noCodex := c.registered(ctx)
	if found && current.ServesAgent(subject) {
		return nil
	}
	if noCodex {
		return []Change{{Kind: "mcp", Path: c.configPath(), Description: "Codex's codex command was not found from here, so connect names the block to add to Codex's config instead", After: codexBlock(subject)}}
	}
	change := Change{Kind: "mcp", Path: c.configPath(), Description: "Register the Contro1 MCP server with Codex, for every project (config.toml is backed up first)", After: c.addLine(subject)}
	if found {
		// codex mcp add replaces without asking, so this preview is where the
		// person sees what runs now.
		change.Description = "Replace Codex's Contro1 MCP server with one that acts as this agent (config.toml is backed up first)"
		change.Before = current.Describe()
	}
	return []Change{change}
}

func (c *codex) InstallMcp(ctx context.Context, subjects []string, j *Journal) (McpOutcome, error) {
	var out McpOutcome
	subjects = sortedUnique(subjects)
	if len(subjects) != 1 {
		out.ToDo = append(out.ToDo, "Codex has one Contro1 MCP server per computer. Choose the agent it acts as: contro1 apps enable codex --agent <id>")
		return out, nil
	}
	subject := subjects[0]
	current, found, noCodex := c.registered(ctx)
	if found && current.ServesAgent(subject) {
		out.Done = append(out.Done, "Codex already has the Contro1 MCP server for this agent.")
		return out, nil
	}
	if noCodex {
		todo := "Let Codex use Contro1 (the MCP server). The codex command was not found from here, so add this to " + c.configPath() + ":\n" + codexBlock(subject)
		if found {
			todo = "Let Codex use Contro1 (the MCP server). " + c.configPath() + " has a contro1 server that runs " + current.Describe() + ", not this agent, and the codex command was not found from here. Replace that table with:\n" + codexBlock(subject)
		}
		out.ToDo = append(out.ToDo, todo)
		return out, nil
	}
	if err := c.backupConfig(&out); err != nil {
		return out, err
	}
	args := codexAddArgs(subject)
	if _, err := c.opts.Runner(ctx, c.bin(), args...); err != nil {
		return out, fmt.Errorf("%s: %w. To add it yourself, put this in %s:\n%s", c.addLine(subject), err, c.configPath(), codexBlock(subject))
	}
	j.RoleCommands = append(j.RoleCommands, c.addLine(subject))
	if after, ok, _ := c.registered(ctx); !ok || !after.ServesAgent(subject) {
		return out, fmt.Errorf("codex mcp add finished, but Codex does not report a contro1 server for %s. Check %s", subject, c.configPath())
	}
	out.Done = append(out.Done, "Registered the Contro1 MCP server with Codex. New Codex sessions load it; one already open needs a restart. codex mcp list shows its Auth as Unsupported: sign-in is the Contro1 CLI's, not Codex's.")
	return out, nil
}

func (c *codex) backupConfig(out *McpOutcome) error {
	path := c.configPath()
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	backup, err := backupFile(path)
	if err != nil {
		return fmt.Errorf("could not back up %s before changing it: %w", path, err)
	}
	out.Done = append(out.Done, "Saved a copy of "+path+" as "+backup+".")
	return nil
}

// ---------------------------------------------------------------------------
// Removing it (disconnect)
// ---------------------------------------------------------------------------

func (c *codex) McpRemovalChanges(ctx context.Context, subjects []string) []Change {
	current, found, noCodex := c.registered(ctx)
	if !found || !servesAny(current, subjects) {
		return nil
	}
	change := Change{Kind: "mcp", Path: c.configPath(), Description: "Remove Codex's Contro1 MCP server for this agent (config.toml is backed up first)", Before: current.Describe(), After: c.bin() + " mcp remove " + codexMcpName}
	if noCodex {
		change.Description = "Codex's Contro1 MCP server for this agent stays: the codex command was not found from here, so delete the [mcp_servers.contro1] table from Codex's config yourself"
		change.After = ""
	}
	return []Change{change}
}

func (c *codex) RemoveMcp(ctx context.Context, subjects []string, j *Journal) (McpOutcome, error) {
	var out McpOutcome
	current, found, noCodex := c.registered(ctx)
	if !found || !servesAny(current, subjects) {
		return out, nil
	}
	if noCodex {
		out.ToDo = append(out.ToDo, "Delete the [mcp_servers.contro1] table from "+c.configPath()+": it still runs "+current.Describe()+", which was disconnected.")
		return out, nil
	}
	if err := c.backupConfig(&out); err != nil {
		return out, err
	}
	args := []string{"mcp", "remove", codexMcpName}
	if _, err := c.opts.Runner(ctx, c.bin(), args...); err != nil {
		return out, fmt.Errorf("%s %s: %w", c.bin(), strings.Join(args, " "), err)
	}
	j.RoleCommands = append(j.RoleCommands, c.bin()+" "+strings.Join(args, " "))
	out.Done = append(out.Done, "Removed the Contro1 MCP server from Codex.")
	return out, nil
}

// ---------------------------------------------------------------------------
// What doctor asks
// ---------------------------------------------------------------------------

func (c *codex) McpServerName(string) string { return codexMcpName }

func (c *codex) McpServers(ctx context.Context) ([]McpServer, error) {
	current, found, _ := c.registered(ctx)
	if !found {
		return nil, nil
	}
	return []McpServer{current}, nil
}

func (c *codex) McpIsolation(context.Context, []string) ([]McpIsolationIssue, error) {
	return nil, ErrNotReported
}

func (c *codex) ConfigStatus(context.Context) (ConfigState, error) {
	return ConfigState{}, ErrNotReported
}

var (
	_ McpInstaller = (*codex)(nil)
	_ McpInspector = (*codex)(nil)
	_ McpRemover   = (*codex)(nil)
	_ Adapter      = (*codex)(nil)
)
