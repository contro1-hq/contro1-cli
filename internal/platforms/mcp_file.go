package platforms

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

/*
Coding agents whose MCP servers live in one JSON file of the person's. Each is
one agent per computer (localCodingAgent); what differs is only the file, the key
the servers sit under, and the shape of an entry, so they are rows in a table.

Each row comes from that vendor's own documentation, checked 2026-11-04. None of
them was run against a real install except where a test says so: the table is
what the vendor says, and a vendor that moves its file is corrected here.

The rules are the same for all of them:

  - shown in the preview and confirmed (or --yes) before anything changes;
  - every other server, and every other key, is kept in its order: the file is
    the person's, contro1 only owns the entry named contro1;
  - a backup next to it before it is written;
  - an entry that acts as someone else is replaced only after the preview has
    shown what it runs now;
  - a file that is not plain JSON (comments, a trailing comma, a hand edit) is
    not touched at all. Rewriting it would drop the comments or guess at the
    intent, so the exact block to paste is printed instead.

NOT HERE, ON PURPOSE:

  - Claude Cowork. A server in claude_desktop_config.json is not available in
    Cowork, and it runs in the cloud by default, so `contro1 mcp serve` on this
    computer cannot reach it. It adds Contro1 as a connector, like claude.ai.
  - Cline, Roo and Kilo keep MCP settings per editor, inside the editor's own
    storage. Zed and Goose use other formats (JSONC with its own key, YAML).
    Warp's are set in its UI. Junie, Crush, Continue and Trae: not confirmed in
    their documentation yet.
*/

const fileMcpName = "contro1"

// ErrMcpConfigUnreadable is a platform MCP configuration that exists and could
// not be read, which doctor reports instead of skipping.
var ErrMcpConfigUnreadable = errors.New("the MCP configuration could not be read")

type mcpFileSpec struct {
	label string
	// path is relative to the home directory.
	path string
	// alsoPath is another name for the same file, used when it is the one there.
	alsoPath string
	// homeEnv, when set in the environment, replaces the folder of path.
	homeEnv string
	// serversKey is the top-level key the servers sit under.
	serversKey string
	entry      func(command string, args []string) map[string]any
	// loads says how the tool picks up the change.
	loads string
	// tryIt replaces the usual suggestion printed once connected.
	tryIt string
}

func plainEntry(command string, args []string) map[string]any {
	return map[string]any{"command": command, "args": args}
}

func stdioEntry(command string, args []string) map[string]any {
	return map[string]any{"type": "stdio", "command": command, "args": args}
}

// mcpFileAgents is every platform connected through its JSON file.
var mcpFileAgents = map[string]mcpFileSpec{
	// cursor.com/docs/context/mcp
	"cursor": {label: "Cursor", path: ".cursor/mcp.json", serversKey: "mcpServers", entry: stdioEntry,
		loads: "A new Cursor window loads it; if it is off, turn contro1 on in Cursor Settings > MCP.",
		tryIt: "Try it: open a new Cursor agent chat and ask it to call the Contro1 whoami tool. It answers with this agent's name."},
	// antigravity.google/docs/mcp: the same file for the IDE and the CLI.
	"antigravity": {label: "Antigravity", path: ".gemini/config/mcp_config.json", serversKey: "mcpServers", entry: plainEntry,
		loads: "Reload it from /mcp in the Antigravity CLI, or Manage MCP Servers in the IDE."},
	// geminicli.com/docs/tools/mcp-server
	"gemini": {label: "Gemini CLI", path: ".gemini/settings.json", serversKey: "mcpServers", entry: plainEntry,
		loads: "A new Gemini CLI session loads it."},
	// docs.github.com add-mcp-servers, and VS Code reads the same global file.
	"copilot": {label: "GitHub Copilot", path: ".copilot/mcp-config.json", homeEnv: "COPILOT_HOME", serversKey: "mcpServers",
		entry: func(command string, args []string) map[string]any {
			return map[string]any{"type": "local", "command": command, "args": args, "tools": []string{"*"}}
		},
		loads: "A new Copilot session loads it."},
	// opencode.ai/docs/mcp-servers and /docs/config: the command is one array.
	"opencode": {label: "OpenCode", path: ".config/opencode/opencode.json", alsoPath: ".config/opencode/opencode.jsonc", serversKey: "mcp",
		entry: func(command string, args []string) map[string]any {
			return map[string]any{"type": "local", "command": append([]string{command}, args...), "enabled": true}
		},
		loads: "A new OpenCode session loads it."},
	// kiro.dev/docs/mcp/configuration
	"kiro": {label: "Kiro", path: ".kiro/settings/mcp.json", serversKey: "mcpServers", entry: plainEntry,
		loads: "Kiro loads it the next time it starts."},
	// ampcode.com/docs/customize/mcp: one flat key with a dot in it.
	"amp": {label: "Amp", path: ".config/amp/settings.json", serversKey: "amp.mcpServers", entry: plainEntry,
		loads: "A new Amp thread loads it."},
	// docs.factory.com/cli/configuration/mcp
	"factory": {label: "Factory Droid", path: ".factory/mcp.json", serversKey: "mcpServers", entry: stdioEntry,
		loads: "A new Droid session loads it."},
	// qwenlm.github.io/qwen-code-docs developers/tools/mcp-server
	"qwen": {label: "Qwen Code", path: ".qwen/settings.json", serversKey: "mcpServers", entry: plainEntry,
		loads: "A new Qwen Code session loads it."},
	// docs.augmentcode.com/cli/integrations
	"augment": {label: "Augment", path: ".augment/settings.json", serversKey: "mcpServers", entry: plainEntry,
		loads: "A new Auggie session loads it."},
	// docs.devin.ai/cli/extensibility/mcp/configuration
	"devin": {label: "Devin", path: ".config/devin/mcp_config.json", serversKey: "mcpServers", entry: plainEntry,
		loads: "A new Devin session loads it."},
	// docs.windsurf.com/windsurf/cascade/mcp
	"windsurf": {label: "Windsurf", path: ".codeium/windsurf/mcp_config.json", serversKey: "mcpServers", entry: plainEntry,
		loads: "Press refresh in Windsurf's MCP panel to load it."},
}

// fileAgent is a coding agent connected through its JSON file.
type fileAgent struct {
	localCodingAgent
	spec mcpFileSpec
}

type cursor = fileAgent

func newCursor(opts Options) *cursor { return newFileAgent("cursor", opts) }

func newFileAgent(platform string, opts Options) *fileAgent {
	spec := mcpFileAgents[platform]
	return &fileAgent{localCodingAgent{platform: platform, label: spec.label, opts: opts}, spec}
}

func (c *fileAgent) mcpPath() string {
	rel := filepath.FromSlash(c.spec.path)
	dir := filepath.Join(c.opts.Home, filepath.Dir(rel))
	if c.spec.homeEnv != "" {
		if v := strings.TrimSpace(os.Getenv(c.spec.homeEnv)); v != "" {
			dir = v
		}
	}
	dir = c.mcpConfigDir(dir)
	path := filepath.Join(dir, filepath.Base(rel))
	if c.spec.alsoPath != "" {
		other := filepath.Join(dir, filepath.Base(filepath.FromSlash(c.spec.alsoPath)))
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			if _, err := os.Stat(other); err == nil {
				return other
			}
		}
	}
	return path
}

func (c *fileAgent) SafeTest() string {
	if c.spec.tryIt != "" {
		return c.spec.tryIt
	}
	return "Try it: start a new " + c.label + " session and ask it to call the Contro1 whoami tool. It answers with this agent's name."
}

func (c *fileAgent) ApplicationChanges(conn LocalConnection) []Change {
	return c.McpChanges(context.Background(), []string{conn.PlatformSubject})
}

func (c *fileAgent) ApplyApplications(ctx context.Context, conn LocalConnection, j *Journal) error {
	_, err := c.InstallMcp(ctx, []string{conn.PlatformSubject}, j)
	return err
}

// jsonMember is one key of a JSON object, kept in file order.
type jsonMember struct {
	Key   string
	Value json.RawMessage
}

// decodeOrderedObject reads a JSON object without losing its key order. Blank
// input is an empty object: Cursor creates the file empty.
func decodeOrderedObject(raw []byte) ([]jsonMember, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("not a JSON object")
	}
	var out []jsonMember
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, errors.New("not a JSON object")
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		out = append(out, jsonMember{Key: key, Value: value})
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("unexpected content after the JSON object")
	}
	return out, nil
}

// encodeOrderedObject writes members back with two-space indentation.
func encodeOrderedObject(members []jsonMember) ([]byte, error) {
	var compact bytes.Buffer
	compact.WriteByte('{')
	for i, m := range members {
		if i > 0 {
			compact.WriteByte(',')
		}
		key, _ := json.Marshal(m.Key)
		compact.Write(key)
		compact.WriteByte(':')
		if err := json.Compact(&compact, m.Value); err != nil {
			return nil, err
		}
	}
	compact.WriteByte('}')
	var out bytes.Buffer
	if err := json.Indent(&out, compact.Bytes(), "", "  "); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}

func marshalNoEscape(v any) json.RawMessage {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return json.RawMessage(bytes.TrimSpace(b.Bytes()))
}

func (c *fileAgent) entry(subject string) json.RawMessage {
	return marshalNoEscape(c.spec.entry(contro1Binary(), mcpArgs(subject)))
}

// block is the exact text a person pastes under the servers key.
func (c *fileAgent) block(subject string) string {
	return `"` + fileMcpName + `": ` + string(c.entry(subject))
}

type mcpFileState struct {
	exists  bool
	top     []jsonMember
	servers []jsonMember
	err     error // set when the file exists and is not plain JSON in the expected shape
}

func (c *fileAgent) read() mcpFileState {
	raw, err := os.ReadFile(c.mcpPath())
	if errors.Is(err, os.ErrNotExist) {
		return mcpFileState{}
	}
	if err != nil {
		return mcpFileState{exists: true, err: err}
	}
	st := mcpFileState{exists: true}
	if st.top, err = decodeOrderedObject(raw); err != nil {
		st.err = fmt.Errorf("%s is not plain JSON: %v", c.mcpPath(), err)
		return st
	}
	for _, m := range st.top {
		if m.Key == c.spec.serversKey {
			if st.servers, err = decodeOrderedObject(m.Value); err != nil {
				st.err = fmt.Errorf("%s in %s is not a JSON object", c.spec.serversKey, c.mcpPath())
			}
		}
	}
	return st
}

// parseFileServer reads an entry in any of the table's shapes, where the command
// is a string with args beside it or one array holding both.
func parseFileServer(name string, raw json.RawMessage) McpServer {
	var v struct {
		Command json.RawMessage `json:"command"`
		Args    []string        `json:"args"`
		URL     string          `json:"url"`
		Server  string          `json:"serverUrl"`
	}
	_ = json.Unmarshal(raw, &v)
	server := McpServer{Name: name, Args: v.Args, URL: firstNonEmpty(v.URL, v.Server), Scope: "user"}
	var words []string
	if json.Unmarshal(v.Command, &words) == nil && len(words) > 0 {
		server.Command, server.Args = words[0], append(words[1:], v.Args...)
	} else {
		_ = json.Unmarshal(v.Command, &server.Command)
	}
	return server
}

func (st mcpFileState) contro1() (McpServer, bool) {
	for _, m := range st.servers {
		if m.Key == fileMcpName {
			return parseFileServer(m.Key, m.Value), true
		}
	}
	return McpServer{}, false
}

func (c *fileAgent) McpChanges(_ context.Context, subjects []string) []Change {
	subjects = sortedUnique(subjects)
	if len(subjects) != 1 {
		return nil
	}
	subject := subjects[0]
	st := c.read()
	if st.err != nil {
		return []Change{{Kind: "mcp", Path: c.mcpPath(), Description: c.label + "'s MCP config could not be read (" + st.err.Error() + "), so connect leaves it and names the block to add under " + c.spec.serversKey, After: c.block(subject)}}
	}
	current, found := st.contro1()
	if found && current.ServesAgent(subject) {
		return nil
	}
	change := Change{Kind: "mcp", Path: c.mcpPath(), Description: "Register the Contro1 MCP server with " + c.label + ", for every project (other servers are kept; a backup is made first)", After: c.block(subject)}
	switch {
	case !st.exists:
		change.Description = "Register the Contro1 MCP server with " + c.label + ", for every project (creates the file)"
	case found:
		// Never replaced silently: the preview says what runs now.
		change.Description = "Replace " + c.label + "'s Contro1 MCP server with one that acts as this agent (a backup is made first)"
		change.Before = current.Describe()
	}
	return []Change{change}
}

func (c *fileAgent) InstallMcp(_ context.Context, subjects []string, j *Journal) (McpOutcome, error) {
	var out McpOutcome
	subjects = sortedUnique(subjects)
	if len(subjects) != 1 {
		out.ToDo = append(out.ToDo, c.label+" has one Contro1 MCP server per computer. Choose the agent it acts as: contro1 apps enable "+c.platform+" --agent <id>")
		return out, nil
	}
	subject := subjects[0]
	path := c.mcpPath()
	st := c.read()
	if st.err != nil {
		out.ToDo = append(out.ToDo, "Let "+c.label+" use Contro1 (the MCP server): "+st.err.Error()+", so contro1 did not change it. Add this under \""+c.spec.serversKey+"\" in "+path+". "+c.spec.loads+" "+c.block(subject))
		return out, nil
	}
	if current, found := st.contro1(); found && current.ServesAgent(subject) {
		out.Done = append(out.Done, c.label+" already has the Contro1 MCP server for this agent.")
		return out, nil
	}

	servers := append([]jsonMember(nil), st.servers...)
	replaced := false
	for i := range servers {
		if servers[i].Key == fileMcpName {
			servers[i].Value = c.entry(subject)
			replaced = true
		}
	}
	if !replaced {
		servers = append(servers, jsonMember{Key: fileMcpName, Value: c.entry(subject)})
	}
	if err := c.writeServers(st, servers, j, &out); err != nil {
		return out, err
	}
	out.Done = append(out.Done, "Registered the Contro1 MCP server with "+c.label+" ("+path+"). "+c.spec.loads)
	return out, nil
}

// writeServers writes the servers back, keeping every other top-level key, after
// a backup of the file as it was.
func (c *fileAgent) writeServers(st mcpFileState, servers []jsonMember, j *Journal, out *McpOutcome) error {
	path := c.mcpPath()
	encodedServers, err := encodeOrderedObject(servers)
	if err != nil {
		return err
	}
	top := append([]jsonMember(nil), st.top...)
	set := false
	for i := range top {
		if top[i].Key == c.spec.serversKey {
			top[i].Value = encodedServers
			set = true
		}
	}
	if !set {
		top = append(top, jsonMember{Key: c.spec.serversKey, Value: encodedServers})
	}
	content, err := encodeOrderedObject(top)
	if err != nil {
		return err
	}
	mode := os.FileMode(0o600)
	if st.exists {
		if info, err := os.Stat(path); err == nil {
			mode = info.Mode().Perm()
		}
		backup, err := backupFile(path)
		if err != nil {
			return fmt.Errorf("could not back up %s before changing it: %w", path, err)
		}
		out.Done = append(out.Done, "Saved a copy of "+path+" as "+backup+".")
	}
	if err := writeFileReplacing(path, content, mode); err != nil {
		return err
	}
	// Recorded as written, never as created: disconnect removes our entry and
	// must not delete a file other servers have been added to since.
	j.WrittenFiles = append(j.WrittenFiles, path)
	return nil
}

// writeFileReplacing writes through a temporary file in the same directory, so
// a crash leaves the old file or the new one and never half of either.
func writeFileReplacing(path string, content []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".contro1-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	_ = os.Chmod(name, mode)
	return os.Rename(name, path)
}

// ---------------------------------------------------------------------------
// Removing it (disconnect)
// ---------------------------------------------------------------------------

func (c *fileAgent) McpRemovalChanges(_ context.Context, subjects []string) []Change {
	st := c.read()
	current, found := st.contro1()
	if st.err != nil || !found || !servesAny(current, subjects) {
		return nil
	}
	return []Change{{Kind: "mcp", Path: c.mcpPath(), Description: "Remove " + c.label + "'s Contro1 MCP server for this agent (other servers are kept; a backup is made first)", Before: current.Describe()}}
}

func (c *fileAgent) RemoveMcp(_ context.Context, subjects []string, j *Journal) (McpOutcome, error) {
	var out McpOutcome
	st := c.read()
	if st.err != nil {
		out.ToDo = append(out.ToDo, c.label+"'s MCP config could not be read ("+st.err.Error()+"). If it still has a contro1 server for this agent, remove it from "+c.spec.serversKey+" in "+c.mcpPath()+".")
		return out, nil
	}
	current, found := st.contro1()
	if !found || !servesAny(current, subjects) {
		return out, nil
	}
	kept := make([]jsonMember, 0, len(st.servers))
	for _, m := range st.servers {
		if m.Key != fileMcpName {
			kept = append(kept, m)
		}
	}
	if err := c.writeServers(st, kept, j, &out); err != nil {
		return out, err
	}
	out.Done = append(out.Done, "Removed the Contro1 MCP server from "+c.label+" ("+c.mcpPath()+").")
	return out, nil
}

func servesAny(s McpServer, subjects []string) bool {
	for _, subject := range subjects {
		if s.ServesAgent(subject) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// What doctor asks
// ---------------------------------------------------------------------------

func (c *fileAgent) McpServerName(string) string { return fileMcpName }

func (c *fileAgent) McpServers(context.Context) ([]McpServer, error) {
	st := c.read()
	if st.err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMcpConfigUnreadable, st.err)
	}
	out := make([]McpServer, 0, len(st.servers))
	for _, m := range st.servers {
		out = append(out, parseFileServer(m.Key, m.Value))
	}
	return out, nil
}

// One agent per computer: there is nobody to be isolated from.
func (c *fileAgent) McpIsolation(context.Context, []string) ([]McpIsolationIssue, error) {
	return nil, ErrNotReported
}

func (c *fileAgent) ConfigStatus(context.Context) (ConfigState, error) {
	return ConfigState{}, ErrNotReported
}

// The interfaces connect, doctor and disconnect look for.
var (
	_ McpInstaller = (*fileAgent)(nil)
	_ McpInspector = (*fileAgent)(nil)
	_ McpRemover   = (*fileAgent)(nil)
	_ Adapter      = (*fileAgent)(nil)
)
