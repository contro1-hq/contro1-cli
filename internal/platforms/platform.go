// Package platforms discovers agent platforms on this computer and points them
// at their Contro1 connections. Adapters are thin: they find platform agents
// (or groups), and they tell the platform where its mapping file is. They
// never hold credentials.
//
// VERIFICATION STATUS: discovery commands and config file locations for
// OpenClaw and NanoClaw are written from their documentation and the existing
// bridges, and are UNVERIFIED against real installations. Each is overridable
// with flags so the handoff machine can correct them without a rebuild.
package platforms

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/contro1-hq/contro1-cli/internal/localipc"
	"github.com/contro1-hq/contro1-cli/internal/runtimeproto"
)

type Subject struct {
	ID      string `json:"id"`
	Display string `json:"display"`
}

type Instance struct {
	Digest string `json:"digest"`
	Label  string `json:"label"`
}

// Change is one local change a person reviews before it happens.
type Change struct {
	Kind        string `json:"kind"` // file | role
	Path        string `json:"path,omitempty"`
	Description string `json:"description"`
	Before      string `json:"before,omitempty"`
	After       string `json:"after,omitempty"`
	// RoleChange changes who can resolve native approvals; never covered by --yes.
	RoleChange bool `json:"role_change,omitempty"`
}

// Journal records only what this tool created, so removal never touches
// anything the person had before.
type Journal struct {
	CreatedFiles []string `json:"created_files,omitempty"`
	WrittenFiles []string `json:"written_files,omitempty"`
	RoleCommands []string `json:"role_commands,omitempty"`
}

type Adapter interface {
	Name() string
	Discover(ctx context.Context) (Instance, []Subject, error)
	// PlanConfig lists the platform changes for a mapping file.
	PlanConfig(mappingPath string) []Change
	ApplyConfig(ctx context.Context, mappingPath string, m *runtimeproto.MappingFile, j *Journal) error
	RemoveConfig(ctx context.Context, j *Journal) error
	// RoleChanges are separate, explicit local confirmations (NanoClaw).
	RoleChanges(m *runtimeproto.MappingFile) []Change
	ApplyRoles(ctx context.Context, m *runtimeproto.MappingFile, j *Journal) error
	// AllowedPrincipal is the one operating system identity that may reach a
	// subject's endpoint.
	AllowedPrincipal(subject string) (string, error)
	// SafeTest is the suggestion printed once connected.
	SafeTest() string
}

// Runner executes platform CLIs; tests substitute a fake.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

func ExecRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Output()
}

// Options configure adapters. Every guessed location is overridable.
type Options struct {
	Runner Runner
	// Home is the platform user's home directory.
	Home string
	// Bin overrides the platform CLI (openclaw, ncl).
	Bin string
	// ConfigDir overrides where the adapter writes its env file.
	ConfigDir string
	// Principal overrides the endpoint caller identity.
	Principal string
	// Agents lists subjects explicitly, skipping discovery.
	Agents []string
}

func New(platform string, opts Options) (Adapter, error) {
	if opts.Runner == nil {
		opts.Runner = ExecRunner
	}
	if opts.Home == "" {
		opts.Home, _ = os.UserHomeDir()
	}
	switch platform {
	case "openclaw":
		return &openClaw{opts: opts}, nil
	case "nanoclaw":
		return &nanoClaw{opts: opts}, nil
	case "claude-code":
		return &claudeCode{opts: opts}, nil
	}
	return nil, fmt.Errorf("unsupported platform %q (openclaw, nanoclaw, claude-code)", platform)
}

// currentPrincipal is the default caller identity: the person running connect,
// who also runs the platform.
func currentPrincipal(override string) (string, error) {
	if override != "" {
		return override, nil
	}
	id, err := localipc.CurrentIdentity()
	if err != nil {
		return "", err
	}
	return id.User, nil
}

func digest(parts ...string) string {
	sorted := append([]string(nil), parts...)
	sort.Strings(sorted)
	sum := sha256.Sum256([]byte(strings.Join(sorted, "\x00")))
	return "sha256:" + hex.EncodeToString(sum[:12])
}

// writeEnvFile writes KEY=VALUE lines, recording whether the file was new.
func writeEnvFile(path string, values map[string]string, j *Journal) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	_, statErr := os.Stat(path)
	existing := map[string]string{}
	var order []string
	if raw, err := os.ReadFile(path); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && !strings.HasPrefix(k, "#") {
				if _, dup := existing[k]; !dup {
					order = append(order, k)
				}
				existing[k] = v
			}
		}
	}
	for k, v := range values {
		if _, ok := existing[k]; !ok {
			order = append(order, k)
		}
		existing[k] = v
	}
	var b strings.Builder
	b.WriteString("# Written by contro1 connect. Holds no secrets.\n")
	for _, k := range order {
		b.WriteString(k + "=" + existing[k] + "\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return err
	}
	if errors.Is(statErr, os.ErrNotExist) {
		j.CreatedFiles = append(j.CreatedFiles, path)
	} else {
		j.WrittenFiles = append(j.WrittenFiles, path)
	}
	return nil
}

func removeCreated(j *Journal) error {
	var errs []error
	for _, p := range j.CreatedFiles {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ReadMapping loads and validates a mapping file.
func ReadMapping(path string) (*runtimeproto.MappingFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m runtimeproto.MappingFile
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("mapping file %s is not valid JSON: %w", path, err)
	}
	if m.SchemaVersion != runtimeproto.SchemaVersion {
		return nil, fmt.Errorf("mapping file %s has schema %d", path, m.SchemaVersion)
	}
	if runtimeproto.MappingDigest(m.Entries) != m.Digest {
		return nil, fmt.Errorf("mapping file %s does not match its digest", path)
	}
	seen := map[string]bool{}
	for _, e := range m.Entries {
		if e.PlatformSubject == "" || e.AgentID == "" || seen[e.PlatformSubject] {
			return nil, fmt.Errorf("mapping file %s has an empty or duplicate subject", path)
		}
		seen[e.PlatformSubject] = true
		if _, err := localipc.ParseEndpoint(e.Endpoint); err != nil {
			return nil, fmt.Errorf("mapping file %s has an invalid endpoint for %s", path, e.PlatformSubject)
		}
	}
	return &m, nil
}

func explicit(agents []string) []Subject {
	var out []Subject
	for _, a := range agents {
		if a = strings.TrimSpace(a); a != "" {
			out = append(out, Subject{ID: a, Display: a})
		}
	}
	return out
}
