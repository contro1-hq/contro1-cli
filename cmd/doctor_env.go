package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/contro1-hq/contro1-cli/internal/brokerpaths"
	"github.com/contro1-hq/contro1-cli/internal/brokerstore"
	"github.com/contro1-hq/contro1-cli/internal/doctor"
	"github.com/contro1-hq/contro1-cli/internal/installer"
	"github.com/contro1-hq/contro1-cli/internal/localipc"
	"github.com/contro1-hq/contro1-cli/internal/output"
	"github.com/contro1-hq/contro1-cli/internal/platforms"
	"github.com/contro1-hq/contro1-cli/internal/runtimeproto"
)

type systemDoctorEnv struct {
	adapter     platforms.Adapter
	development bool
	layout      brokerpaths.Layout
}

func newSystemDoctorEnv(adapter platforms.Adapter, development bool) *systemDoctorEnv {
	layout := brokerpaths.Production(runtime.GOOS)
	if development {
		layout = brokerpaths.Development()
	}
	return &systemDoctorEnv{adapter: adapter, development: development, layout: layout}
}

func (e *systemDoctorEnv) GOOS() string { return runtime.GOOS }

func (e *systemDoctorEnv) ServiceStatus() (bool, bool, bool, string) {
	if e.development {
		st, err := e.PublicStatus()
		running := err == nil && st.PID > 0
		return running, running, false, "development (current user)"
	}
	return installer.ServiceStatus()
}

func (e *systemDoctorEnv) ControlReachableUnelevated(ctx context.Context) bool {
	if e.development {
		return false
	}
	ep, err := localipc.ParseEndpoint(e.layout.ControlEndpoint)
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	conn, err := localipc.Dial(ctx, ep, "")
	if err != nil {
		return false
	}
	// The dial opened the endpoint. A working ACL refuses the open itself; the
	// broker's peer check would still drop us, but the descriptor is too wide.
	conn.Close()
	return true
}

func (e *systemDoctorEnv) IsElevated() bool { return installer.IsElevated() }

func (e *systemDoctorEnv) PublicStatus() (*brokerstore.PublicStatus, error) {
	for _, dir := range []string{e.layout.PlatformsDir, e.layout.StateDir} {
		if st, err := brokerstore.OpenReadOnly(dir).ReadStatus(); err == nil {
			return st, nil
		}
	}
	return nil, errors.New("no Contro1 service status on this computer")
}

func (e *systemDoctorEnv) Mapping(platform string) (*runtimeproto.MappingFile, error) {
	return platforms.ReadMapping(filepath.Join(e.layout.PlatformsDir, platform+".json"))
}

func (e *systemDoctorEnv) Discover(ctx context.Context, _ string) ([]string, error) {
	_, subjects, err := e.adapter.Discover(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(subjects))
	for i, s := range subjects {
		out[i] = s.ID
	}
	return out, nil
}

func (e *systemDoctorEnv) EndpointPrincipals(endpoint string) ([]string, error) {
	ep, err := localipc.ParseEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	// In development the service runs as the caller, so there is no separate
	// service identity to discount.
	service := brokerpaths.WindowsServiceSID(brokerpaths.ServiceName)
	if e.development {
		service = ""
	}
	principals, err := endpointPrincipals(ep, service)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, p := range principals {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out, nil
}

func (e *systemDoctorEnv) ExpectedPrincipals(_, subject string) ([]string, error) {
	principal, err := e.adapter.AllowedPrincipal(subject)
	if err != nil {
		return nil, err
	}
	out := []string{principal}
	if gid := localipc.PrimaryGroupOf(principal); gid > 0 {
		out = append(out, "gid:"+strconv.Itoa(gid))
	}
	return out, nil
}

func (e *systemDoctorEnv) RuntimeStatus(ctx context.Context, entry runtimeproto.MappingEntry) (string, *runtimeproto.Remediation, error) {
	agentID, err := endpointVerifier{}.RuntimeStatus(ctx, entry)
	return agentID, remediationOf(err), err
}

func (e *systemDoctorEnv) ControlMapPreview(ctx context.Context, entry runtimeproto.MappingEntry) error {
	return endpointVerifier{}.ControlMapPreview(ctx, entry)
}

func (e *systemDoctorEnv) PlatformUser(string) string {
	if me, err := localipc.CurrentIdentity(); err == nil {
		return me.User
	}
	return ""
}

func (e *systemDoctorEnv) Development() bool { return e.development }

// remediationOf extracts a server remediation from a CLI client error.
func remediationOf(err error) *runtimeproto.Remediation {
	var ee *output.ExitError
	if errors.As(err, &ee) {
		return ee.Remediation
	}
	return nil
}

/*
How the platform is configured to reach Contro1, asked of the platform.

Read only, and a platform that cannot answer produces no finding rather than a
guess: `doctor` reporting a problem it inferred would be worse than reporting
nothing, because somebody would go and fix the wrong thing.
*/
func (e *systemDoctorEnv) McpServers(ctx context.Context, platform, subject string) ([]doctor.McpServerConfig, error) {
	if platform != "nanoclaw" {
		return nil, errors.New("not reported by this platform")
	}
	out, err := platforms.ExecRunner(ctx, nclBinary(), "config", "get", "--id", subject, "--json")
	if err != nil {
		return nil, err
	}
	var frame struct {
		OK   bool `json:"ok"`
		Data struct {
			McpServers []struct {
				Name    string   `json:"name"`
				Command string   `json:"command"`
				Args    []string `json:"args"`
				URL     string   `json:"url"`
			} `json:"mcp_servers"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out, &frame); err != nil || !frame.OK {
		return nil, errors.New("could not read the platform's MCP configuration")
	}
	servers := make([]doctor.McpServerConfig, 0, len(frame.Data.McpServers))
	for _, s := range frame.Data.McpServers {
		servers = append(servers, doctor.McpServerConfig{Name: s.Name, Command: s.Command, Args: s.Args, URL: s.URL})
	}
	return servers, nil
}

func (e *systemDoctorEnv) ContainerMounts(ctx context.Context, platform, subject string) ([]string, error) {
	if platform != "nanoclaw" {
		return nil, nil
	}
	out, err := platforms.ExecRunner(ctx, nclBinary(), "config", "get", "--id", subject, "--json")
	if err != nil {
		return nil, err
	}
	var frame struct {
		OK   bool `json:"ok"`
		Data struct {
			AdditionalMounts []struct {
				HostPath string `json:"hostPath"`
			} `json:"additional_mounts"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out, &frame); err != nil || !frame.OK {
		return nil, errors.New("could not read the platform's container configuration")
	}
	paths := make([]string, 0, len(frame.Data.AdditionalMounts))
	for _, m := range frame.Data.AdditionalMounts {
		paths = append(paths, m.HostPath)
	}
	return paths, nil
}

func nclBinary() string {
	if v := strings.TrimSpace(os.Getenv("CONTRO1_NCL_BIN")); v != "" {
		return v
	}
	return "ncl"
}

/*
Whether Contro1 is actually in the approval path, asked of the platform.

Three separate facts, because each can be true without the others and each
produces a different, silent failure: the channel can be absent, present but
without an approver account, or have one that holds no role in this group.
*/
func (e *systemDoctorEnv) ApproverStatus(ctx context.Context, platform, subject string) (doctor.ApproverStatus, error) {
	var out doctor.ApproverStatus
	if platform != "nanoclaw" {
		return out, errors.New("not reported by this platform")
	}

	// The platform's own view of its channels. A file on disk is not the same
	// as a channel the host loaded, and only the second one governs anything.
	groups, err := nclList(ctx, "messaging-groups")
	if err != nil {
		return out, err
	}
	for _, g := range groups {
		if strings.EqualFold(stringField(g, "channel_type"), contro1ChannelType) {
			out.ChannelPresent = true
			break
		}
	}

	users, err := nclList(ctx, "users")
	if err != nil {
		return out, err
	}
	for _, u := range users {
		if stringField(u, "id") == contro1ApproverUser {
			out.ApproverExists = true
			break
		}
	}
	if !out.ApproverExists {
		return out, nil
	}

	roles, err := nclList(ctx, "roles")
	if err != nil {
		return out, err
	}
	for _, r := range roles {
		if stringField(r, "user_id") != contro1ApproverUser {
			continue
		}
		// A global grant (no group) covers every group; otherwise it has to
		// name this one. Checked per subject because the grant is per group.
		group := stringField(r, "agent_group_id")
		if group == "" || group == subject {
			out.ApproverMayResolve = true
			break
		}
	}
	return out, nil
}

const (
	contro1ChannelType  = "contro1"
	contro1ApproverUser = "contro1:approvals"
)

// nclList reads one `ncl <resource> list --json` collection, accepting both the
// {ok,data} envelope and the bare array older builds returned.
func nclList(ctx context.Context, resource string) ([]map[string]any, error) {
	out, err := platforms.ExecRunner(ctx, nclBinary(), resource, "list", "--json")
	if err != nil {
		return nil, err
	}
	var rows []map[string]any
	if json.Unmarshal(out, &rows) == nil {
		return rows, nil
	}
	var frame struct {
		OK   bool             `json:"ok"`
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(out, &frame); err != nil || !frame.OK {
		return nil, errors.New("could not read " + resource + " from the platform")
	}
	return frame.Data, nil
}

func stringField(row map[string]any, key string) string {
	if v, ok := row[key].(string); ok {
		return v
	}
	return ""
}
