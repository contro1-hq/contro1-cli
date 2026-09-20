package platforms

import (
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
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
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

// ErrNoLocalConnection means this computer has no published connection, which
// is an ordinary state and not a failure: nobody has run `contro1 connect` yet.
var ErrNoLocalConnection = errors.New("no Contro1 connection is published on this computer")

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
	connections, problems := LocalConnections()
	selector = strings.TrimSpace(selector)

	if selector != "" {
		for _, c := range connections {
			if c.AgentID == selector || c.PlatformSubject == selector {
				return c, nil
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
