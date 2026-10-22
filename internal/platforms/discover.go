package platforms

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/contro1-hq/contro1-cli/internal/brokerpaths"
	"github.com/contro1-hq/contro1-cli/internal/runtimeproto"
)

// LocalConnection is one agent this computer already has an owner-approved
// connection for, read off the mapping files `contro1 connect` wrote.
type LocalConnection struct {
	Platform        string `json:"platform"`
	PlatformSubject string `json:"platform_subject"`
	DisplayName     string `json:"display_name,omitempty"`
	AgentID         string `json:"agent_id"`
	EnrollmentID    string `json:"enrollment_id"`
	EndpointMode    string `json:"endpoint_mode"`
	Endpoint        string `json:"endpoint"`
}

// PlatformsDir is where the broker publishes mapping files. The environment
// override exists for a development broker and for tests; it is a path to read,
// never a credential, so overriding it cannot widen anything.
func PlatformsDir() string {
	if dir := strings.TrimSpace(os.Getenv("CONTRO1_PLATFORMS_DIR")); dir != "" {
		return dir
	}
	return brokerpaths.Production(runtime.GOOS).PlatformsDir
}

/*
LocalConnections lists every connection published on this computer.

WHY THIS EXISTS. Everything needed to reach an agent's own endpoint is already
on disk after `contro1 connect`: the broker writes one mapping file per
platform, each entry naming an agent and the socket that serves it. Until this
existed, nothing read them on the client's behalf, so a person wiring up an MCP
server had to dig an endpoint out of JSON by hand and paste it into a config.
Most people will not do that. They fall back to the browser OAuth flow instead,
which gives them a weaker, person-bound connection than the one they already
had, and they never find out.

A mapping file that does not parse or does not match its digest is skipped
rather than failing the whole listing: one damaged file must not hide the
connections that are fine. It is reported so a caller can say so.
*/
func LocalConnections() ([]LocalConnection, []error) {
	all, problems := publishedConnections()
	inactive := inactiveEnrollments(PlatformsDir())
	out := all[:0:0]
	for _, c := range all {
		if _, gone := inactive[c.EnrollmentID]; !gone || c.EnrollmentID == "" {
			out = append(out, c)
		}
	}
	return out, problems
}

/*
inactiveEnrollments reads which published connections the Contro1 service on
this computer itself reports as no longer active (revoked, suspended, expired),
keyed by enrollment id to that state.

WHY. A real Codex test: `contro1 disconnect codex` revoked the connection in
Contro1 and left the mapping file, and `contro1 mcp serve` kept picking the
revoked agent and was refused on every call. The mapping is rewritten by the
service, and only when it notices; an older service, or one that has not
refreshed yet, keeps publishing an entry that can no longer work. status.json
is the same service's own secret-free account of each connection, so an entry
it calls revoked is treated as absent: `mcp serve` then behaves exactly as if
it had never been there (the only other agent, a person sign-in, or the setup
message), instead of insisting on a dead identity.

Only what the service says counts. No status, or a connection it does not
list, keeps the entry: guessing a connection away would silently move an agent
onto a person sign-in, which is the downgrade this whole selection avoids.
*/
func inactiveEnrollments(dir string) map[string]string {
	raw, err := os.ReadFile(filepath.Join(dir, "status.json"))
	if err != nil {
		return nil
	}
	var status struct {
		Enrollments []struct {
			EnrollmentID string `json:"enrollment_id"`
			State        string `json:"state"`
		} `json:"enrollments"`
	}
	if json.Unmarshal(raw, &status) != nil {
		return nil
	}
	active := map[string]bool{}
	out := map[string]string{}
	for _, e := range status.Enrollments {
		if e.EnrollmentID == "" {
			continue
		}
		if e.State == "active" {
			active[e.EnrollmentID] = true
			continue
		}
		if e.State != "" && e.State != "pending" {
			out[e.EnrollmentID] = e.State
		}
	}
	// A reconnect that reused the id is active again; active wins.
	for id := range active {
		delete(out, id)
	}
	return out
}

// InactiveLocalConnections are the published connections the service reports
// as no longer active, with that state, so a caller can say why one it was
// asked for is not used.
func InactiveLocalConnections() map[LocalConnection]string {
	all, _ := publishedConnections()
	inactive := inactiveEnrollments(PlatformsDir())
	out := map[LocalConnection]string{}
	for _, c := range all {
		if state, gone := inactive[c.EnrollmentID]; gone && c.EnrollmentID != "" {
			out[c] = state
		}
	}
	return out
}

// publishedConnections is every entry in every mapping file, active or not.
func publishedConnections() ([]LocalConnection, []error) {
	dir := PlatformsDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, []error{fmt.Errorf("could not read %s: %w", dir, err)}
	}

	var out []LocalConnection
	var problems []error
	for _, entry := range entries {
		if entry.IsDir() || !isMappingFileName(entry.Name()) {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		if !looksLikeMapping(path) {
			continue
		}
		mapping, err := ReadMapping(path)
		if err != nil {
			problems = append(problems, err)
			continue
		}
		for _, item := range mapping.Entries {
			out = append(out, LocalConnection{
				Platform:        mapping.Platform,
				PlatformSubject: item.PlatformSubject,
				DisplayName:     item.DisplayName,
				AgentID:         item.AgentID,
				EnrollmentID:    item.EnrollmentID,
				EndpointMode:    item.EndpointMode,
				Endpoint:        item.Endpoint,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Platform != out[j].Platform {
			return out[i].Platform < out[j].Platform
		}
		return out[i].PlatformSubject < out[j].PlatformSubject
	})
	return out, problems
}

/*
isMappingFileName and looksLikeMapping decide which files in the platforms
directory are mapping files at all.

WHY. The broker also publishes status.json there, a secret-free health copy
for doctor. It was read as a mapping, failed the digest check, and every
"several connections" or "not connected" message then ended with "1 mapping
file(s) could not be read ... does not match its digest", which reads exactly
like tampering on a computer where nothing was wrong. A file that is not a
mapping is not a damaged mapping, so it is skipped without a word.

What still counts as damaged: a mapping-named file that is not JSON, or JSON
that carries a mapping's fields and fails validation. Those keep being
reported, because silently skipping a truncated or edited mapping would make a
connected computer look unconnected.
*/
func isMappingFileName(name string) bool {
	if !strings.HasSuffix(name, ".json") || strings.HasPrefix(name, ".") {
		return false
	}
	return name != "status.json"
}

func looksLikeMapping(path string) bool {
	raw, err := os.ReadFile(path)
	if err != nil {
		// Unreadable: let ReadMapping report it.
		return true
	}
	var probe map[string]json.RawMessage
	if json.Unmarshal(raw, &probe) != nil {
		// Not JSON at all: damaged, reported by ReadMapping.
		return true
	}
	for _, key := range []string{"schema_version", "platform", "entries", "digest"} {
		if _, ok := probe[key]; ok {
			return true
		}
	}
	return false
}

// ClientPlatform names the agent platform whose process started this one, or
// "" when that cannot be told (Claude Code sets CLAUDECODE for its children).
//
// It only words a suggestion, such as which `contro1 connect <platform>` to
// run. It never chooses a connection: CLAUDECODE is inherited by everything a
// Claude Code session starts, Codex or an OpenClaw gateway included, so a
// choice made from it would let any of them act as the Claude Code agent.
// `contro1 connect` writes --agent into every server it installs instead.
func ClientPlatform(getenv func(string) string) string {
	if strings.TrimSpace(getenv("CLAUDECODE")) != "" {
		return "claude-code"
	}
	return ""
}

// ErrNoLocalConnection means this computer has no published connection, which
// is an ordinary state and not a failure: nobody has run `contro1 connect` yet.
var ErrNoLocalConnection = errors.New("no Contro1 connection is published on this computer")

// ErrInactiveConnection is a named connection the service reports revoked,
// suspended or expired.
var ErrInactiveConnection = errors.New("connection not active")

// AmbiguousConnectionError is returned when a selector is needed. It carries the
// candidates so the caller can print them rather than making the person go
// looking for ids.
type AmbiguousConnectionError struct {
	Candidates []LocalConnection
}

func (e *AmbiguousConnectionError) Error() string {
	names := make([]string, 0, len(e.Candidates))
	for _, c := range e.Candidates {
		label := c.DisplayName
		if label == "" {
			label = c.PlatformSubject
		}
		names = append(names, fmt.Sprintf("%s (%s, %s)", c.AgentID, label, c.Platform))
	}
	return "this computer has more than one connection, so one must be named with --agent: " + strings.Join(names, "; ")
}

/*
SelectLocalConnection picks the connection a command should act as.

Selecting by AGENT rather than by platform, because the identity is what
matters: "act as this agent" is the sentence a person means, and two agents on
one platform are two identities. A selector is matched against the Contro1
agent id and the platform's own id, since a person reading a NanoClaw group id
off their screen should not have to translate it first.

Ambiguity is never resolved by picking the first one. One agent, or a name.
*/
func SelectLocalConnection(selector string) (LocalConnection, error) {
	return SelectLocalConnectionFor("", selector)
}

// SelectLocalConnectionFor is SelectLocalConnection limited to one platform.
//
// A computer with Claude Code and three OpenClaw agents has four connections,
// and `contro1 apps enable claude-code` was refused as ambiguous although only
// one of them is Claude Code. The platform the person named narrows the list
// before anything is asked of them.
func SelectLocalConnectionFor(platform, selector string) (LocalConnection, error) {
	connections, problems := LocalConnections()
	if platform != "" {
		mine := connections[:0:0]
		for _, c := range connections {
			if c.Platform == platform {
				mine = append(mine, c)
			}
		}
		connections = mine
	}
	selector = strings.TrimSpace(selector)

	if selector != "" {
		for _, c := range connections {
			if c.AgentID == selector || c.PlatformSubject == selector {
				return c, nil
			}
		}
		for c, state := range InactiveLocalConnections() {
			if (platform == "" || c.Platform == platform) && (c.AgentID == selector || c.PlatformSubject == selector) {
				return LocalConnection{}, fmt.Errorf("the connection for %q is %s on this computer; run contro1 connect %s to connect it again: %w", selector, state, c.Platform, ErrInactiveConnection)
			}
		}
		if len(connections) == 0 {
			return LocalConnection{}, joinProblems(ErrNoLocalConnection, problems)
		}
		return LocalConnection{}, joinProblems(
			fmt.Errorf("no connection on this computer matches %q", selector),
			problems,
		)
	}

	switch len(connections) {
	case 0:
		return LocalConnection{}, joinProblems(ErrNoLocalConnection, problems)
	case 1:
		return connections[0], nil
	default:
		return LocalConnection{}, joinProblems(&AmbiguousConnectionError{Candidates: connections}, problems)
	}
}

// joinProblems keeps a damaged mapping file visible. Without it, a file that
// failed its digest check would look exactly like a computer that was never
// connected, and the person would be told to run connect again when the real
// answer is that something tampered with or truncated the file.
func joinProblems(primary error, problems []error) error {
	if len(problems) == 0 {
		return primary
	}
	return fmt.Errorf("%w (and %d mapping file(s) could not be read: %v)", primary, len(problems), errors.Join(problems...))
}

// ModeAllowsApplications reports whether this connection may reach company
// applications, which is what an MCP server is for. Approvals-only connections
// still serve MCP, with a smaller tool set, so this is for explaining rather
// than for gating: the server enforces the mode on every call.
func ModeAllowsApplications(mode string) bool { return mode == runtimeproto.ModeApplications }
