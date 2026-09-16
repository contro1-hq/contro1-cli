// Package localipc serves and dials the broker's local endpoints: named pipes
// on Windows, unix sockets elsewhere. Both sides verify the peer's operating
// system identity; a path name alone is never trusted.
package localipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// Endpoint is a parsed local endpoint address.
type Endpoint struct {
	Kind string // "npipe" or "unix"
	Path string // `\\.\pipe\name` or `/run/contro1/ep/x.sock`
}

func (e Endpoint) String() string {
	if e.Kind == "npipe" {
		return "npipe://" + strings.ReplaceAll(e.Path, `\`, "/")
	}
	return "unix://" + e.Path
}

var ErrBadEndpoint = errors.New("localipc: endpoint must be npipe:////./pipe/<name> or unix:///<absolute path>")

// ParseEndpoint accepts `npipe:////./pipe/contro1-ep-x` and
// `unix:///run/contro1/ep/ep_x.sock`. Remote pipe hosts are refused.
func ParseEndpoint(raw string) (Endpoint, error) {
	raw = strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(raw, "npipe:"):
		rest := strings.ReplaceAll(strings.TrimPrefix(raw, "npipe:"), `\`, "/")
		rest = strings.TrimLeft(rest, "/")
		// Expect "./pipe/<name>"
		if !strings.HasPrefix(rest, "./pipe/") {
			return Endpoint{}, ErrBadEndpoint
		}
		name := strings.TrimPrefix(rest, "./pipe/")
		if !validPipeName(name) {
			return Endpoint{}, ErrBadEndpoint
		}
		return Endpoint{Kind: "npipe", Path: `\\.\pipe\` + name}, nil
	case strings.HasPrefix(raw, "unix://"):
		path := strings.TrimPrefix(raw, "unix://")
		if !strings.HasPrefix(path, "/") || strings.Contains(path, "..") {
			return Endpoint{}, ErrBadEndpoint
		}
		return Endpoint{Kind: "unix", Path: path}, nil
	}
	return Endpoint{}, ErrBadEndpoint
}

func validPipeName(name string) bool {
	if name == "" || len(name) > 200 {
		return false
	}
	for _, r := range name {
		if !(r == '-' || r == '_' || r == '.' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

// PipeEndpoint builds the canonical pipe endpoint for a name.
func PipeEndpoint(name string) Endpoint { return Endpoint{Kind: "npipe", Path: `\\.\pipe\` + name} }

// Principal names an operating system identity allowed to connect.
//
// Windows: a SID string. A user SID matches the token user; a group SID
// (for example S-1-5-32-544, Administrators) matches only when the group is
// ENABLED in the caller's token, so a non-elevated administrator is refused.
// Unix: "uid:<n>" or "gid:<n>".
type Principal string

// Identity is what the operating system reports about a peer.
type Identity struct {
	PID    int
	User   string   // SID (Windows) or "uid:<n>"
	Groups []string // enabled group SIDs (Windows) or "gid:<n>"
}

// Allowed reports whether id matches any principal.
func (id Identity) Allowed(principals []Principal) bool {
	for _, p := range principals {
		if string(p) == id.User {
			return true
		}
		for _, g := range id.Groups {
			if string(p) == g {
				return true
			}
		}
	}
	return false
}

// ListenSpec describes a listener.
type ListenSpec struct {
	Endpoint Endpoint
	// AllowedPrincipals are checked on every accepted connection.
	AllowedPrincipals []Principal
	// SDDL is the Windows security descriptor for the pipe. Ignored on unix.
	SDDL string
	// SocketGroup is the unix group given access to the socket (0660). Ignored on Windows.
	SocketGroup int
}

// ErrPeerRejected is returned (and logged by the caller) when a connection
// comes from an identity that is not allowed.
var ErrPeerRejected = errors.New("localipc: peer identity not allowed")

// HTTPClient returns an HTTP client whose every connection goes to endpoint.
// `expectServer`, when set, is the identity the server process must run as.
func HTTPClient(ep Endpoint, expectServer Principal) *http.Client {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return Dial(ctx, ep, expectServer)
		},
		DisableCompression: true,
		// One request per connection. On Windows, reusing a pipe connection
		// after net/http aborts its background read leaves the next request's
		// context cancelled (os.File deadline emulation). Local connections
		// are cheap, so correctness wins.
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: 5 * time.Minute,
	}
	return &http.Client{Transport: transport}
}

// NewServer returns an http.Server for a local endpoint, with keep-alives off
// for the same reason as HTTPClient.
func NewServer(handler http.Handler) *http.Server {
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	srv.SetKeepAlivesEnabled(false)
	return srv
}

// BaseURL is the placeholder host used with HTTPClient.
const BaseURL = "http://contro1-broker"

// ---------------------------------------------------------------------------
// Windows security descriptors
// ---------------------------------------------------------------------------

// ControlSDDL: SYSTEM, Administrators and the broker service SID only.
func ControlSDDL(serviceSID string) string {
	return fmt.Sprintf("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;%s)", serviceSID)
}

// DataSDDL: read/write for the one caller identity, full for the service and SYSTEM.
func DataSDDL(callerSID, serviceSID string) string {
	return fmt.Sprintf("D:P(A;;GRGW;;;%s)(A;;GA;;;%s)(A;;GA;;;SY)", callerSID, serviceSID)
}
