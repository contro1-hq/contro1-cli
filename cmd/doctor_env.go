package cmd

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/contro1-hq/contro1-cli/internal/brokerpaths"
	"github.com/contro1-hq/contro1-cli/internal/brokerstore"
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
