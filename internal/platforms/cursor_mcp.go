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
)

/*
Cursor's MCP servers, as Cursor documents them (https://cursor.com/docs/context/mcp,
checked 2026-10-21): ~/.cursor/mcp.json for every project, .cursor/mcp.json in a
project for that project, both {"mcpServers": {"<name>": {"type": "stdio",
"command": ..., "args": [...]}}}. Cursor has no command to add one, so connect
edits the user file itself, under the same rules as every other platform:

  - shown in the preview and confirmed (or --yes) before anything changes;
  - every other server, and every other key, is kept in its order: the file is
    the person's, contro1 only owns the entry named contro1;
  - a backup next to it before it is written;
  - an entry that acts as someone else is replaced only after the preview has
    shown what it runs now;
  - a file that is not plain JSON (comments, a trailing comma, a hand edit) is
    not touched at all. Rewriting it would drop the comments or guess at the
    intent, so the exact block to paste is printed instead.
*/

const cursorMcpName = "contro1"

// ErrMcpConfigUnreadable is a platform MCP configuration that exists and could
// not be read, which doctor reports instead of skipping.
var ErrMcpConfigUnreadable = errors.New("the MCP configuration could not be read")

func (c *cursor) mcpPath() string {
	return filepath.Join(c.mcpConfigDir(filepath.Join(c.opts.Home, ".cursor")), "mcp.json")
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

func cursorEntry(subject string) json.RawMessage {
	return marshalNoEscape(map[string]any{"type": "stdio", "command": contro1Binary(), "args": mcpArgs(subject)})
}

// cursorBlock is the exact text a person pastes under "mcpServers".
func cursorBlock(subject string) string {
	return `"contro1": ` + string(cursorEntry(subject))
}

type cursorState struct {
	exists  bool
	top     []jsonMember
	servers []jsonMember
	err     error // set when the file exists and is not plain JSON in the expected shape
}

func (c *cursor) read() cursorState {
	raw, err := os.ReadFile(c.mcpPath())
	if errors.Is(err, os.ErrNotExist) {
		return cursorState{}
	}
	if err != nil {
		return cursorState{exists: true, err: err}
	}
	st := cursorState{exists: true}
	if st.top, err = decodeOrderedObject(raw); err != nil {
		st.err = fmt.Errorf("%s is not plain JSON: %v", c.mcpPath(), err)
		return st
	}
	for _, m := range st.top {
		if m.Key == "mcpServers" {
			if st.servers, err = decodeOrderedObject(m.Value); err != nil {
				st.err = fmt.Errorf("mcpServers in %s is not a JSON object", c.mcpPath())
			}
		}
	}
	return st
}

func parseCursorServer(name string, raw json.RawMessage) McpServer {
	var v struct {
		Command string   `json:"command"`
		Args    []string `json:"args"`
		URL     string   `json:"url"`
	}
	_ = json.Unmarshal(raw, &v)
	return McpServer{Name: name, Command: v.Command, Args: v.Args, URL: v.URL, Scope: "user"}
}

func (st cursorState) contro1() (McpServer, bool) {
	for _, m := range st.servers {
		if m.Key == cursorMcpName {
			return parseCursorServer(m.Key, m.Value), true
		}
	}
	return McpServer{}, false
}

func (c *cursor) McpChanges(_ context.Context, subjects []string) []Change {
	subjects = sortedUnique(subjects)
	if len(subjects) != 1 {
		return nil
	}
	subject := subjects[0]
	st := c.read()
	if st.err != nil {
		return []Change{{Kind: "mcp", Path: c.mcpPath(), Description: "Cursor's MCP config could not be read (" + st.err.Error() + "), so connect leaves it and names the block to add under mcpServers", After: cursorBlock(subject)}}
	}
	current, found := st.contro1()
	if found && current.ServesAgent(subject) {
		return nil
	}
	change := Change{Kind: "mcp", Path: c.mcpPath(), Description: "Register the Contro1 MCP server with Cursor, for every project (other servers are kept; a backup is made first)", After: cursorBlock(subject)}
	switch {
	case !st.exists:
		change.Description = "Register the Contro1 MCP server with Cursor, for every project (creates the file)"
	case found:
		// Never replaced silently: the preview says what runs now.
		change.Description = "Replace Cursor's Contro1 MCP server with one that acts as this agent (a backup is made first)"
		change.Before = current.Describe()
	}
	return []Change{change}
}

func (c *cursor) InstallMcp(_ context.Context, subjects []string, j *Journal) (McpOutcome, error) {
	var out McpOutcome
	subjects = sortedUnique(subjects)
	if len(subjects) != 1 {
		out.ToDo = append(out.ToDo, "Cursor has one Contro1 MCP server per computer. Choose the agent it acts as: contro1 apps enable cursor --agent <id>")
		return out, nil
	}
	subject := subjects[0]
	path := c.mcpPath()
	st := c.read()
	if st.err != nil {
		out.ToDo = append(out.ToDo, "Let Cursor use Contro1 (the MCP server): "+st.err.Error()+", so contro1 did not change it. Add this under \"mcpServers\" in "+path+", then open a new Cursor window: "+cursorBlock(subject))
		return out, nil
	}
	if current, found := st.contro1(); found && current.ServesAgent(subject) {
		out.Done = append(out.Done, "Cursor already has the Contro1 MCP server for this agent.")
		return out, nil
	}

	servers := append([]jsonMember(nil), st.servers...)
	replaced := false
	for i := range servers {
		if servers[i].Key == cursorMcpName {
			servers[i].Value = cursorEntry(subject)
			replaced = true
		}
	}
	if !replaced {
		servers = append(servers, jsonMember{Key: cursorMcpName, Value: cursorEntry(subject)})
	}
	if err := c.writeServers(st, servers, j, &out); err != nil {
		return out, err
	}
	out.Done = append(out.Done, "Registered the Contro1 MCP server with Cursor ("+path+"). A new Cursor window loads it; if it is off, turn contro1 on in Cursor Settings > MCP.")
	return out, nil
}

// writeServers writes mcpServers back, keeping every other top-level key, after
// a backup of the file as it was.
func (c *cursor) writeServers(st cursorState, servers []jsonMember, j *Journal, out *McpOutcome) error {
	path := c.mcpPath()
	encodedServers, err := encodeOrderedObject(servers)
	if err != nil {
		return err
	}
	top := append([]jsonMember(nil), st.top...)
	set := false
	for i := range top {
		if top[i].Key == "mcpServers" {
			top[i].Value = encodedServers
			set = true
		}
	}
	if !set {
		top = append(top, jsonMember{Key: "mcpServers", Value: encodedServers})
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

func (c *cursor) McpRemovalChanges(_ context.Context, subjects []string) []Change {
	st := c.read()
	current, found := st.contro1()
	if st.err != nil || !found || !servesAny(current, subjects) {
		return nil
	}
	return []Change{{Kind: "mcp", Path: c.mcpPath(), Description: "Remove Cursor's Contro1 MCP server for this agent (other servers are kept; a backup is made first)", Before: current.Describe()}}
}

func (c *cursor) RemoveMcp(_ context.Context, subjects []string, j *Journal) (McpOutcome, error) {
	var out McpOutcome
	st := c.read()
	if st.err != nil {
		out.ToDo = append(out.ToDo, "Cursor's MCP config could not be read ("+st.err.Error()+"). If it still has a contro1 server for this agent, remove it from mcpServers in "+c.mcpPath()+".")
		return out, nil
	}
	current, found := st.contro1()
	if !found || !servesAny(current, subjects) {
		return out, nil
	}
	kept := make([]jsonMember, 0, len(st.servers))
	for _, m := range st.servers {
		if m.Key != cursorMcpName {
			kept = append(kept, m)
		}
	}
	if err := c.writeServers(st, kept, j, &out); err != nil {
		return out, err
	}
	out.Done = append(out.Done, "Removed the Contro1 MCP server from Cursor ("+c.mcpPath()+").")
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

func (c *cursor) McpServerName(string) string { return cursorMcpName }

func (c *cursor) McpServers(context.Context) ([]McpServer, error) {
	st := c.read()
	if st.err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMcpConfigUnreadable, st.err)
	}
	out := make([]McpServer, 0, len(st.servers))
	for _, m := range st.servers {
		out = append(out, parseCursorServer(m.Key, m.Value))
	}
	return out, nil
}

// One agent per computer: there is nobody to be isolated from.
func (c *cursor) McpIsolation(context.Context, []string) ([]McpIsolationIssue, error) {
	return nil, ErrNotReported
}

func (c *cursor) ConfigStatus(context.Context) (ConfigState, error) {
	return ConfigState{}, ErrNotReported
}

// The interfaces connect, doctor and disconnect look for.
var (
	_ McpInstaller = (*cursor)(nil)
	_ McpInspector = (*cursor)(nil)
	_ McpRemover   = (*cursor)(nil)
	_ Adapter      = (*cursor)(nil)
)
