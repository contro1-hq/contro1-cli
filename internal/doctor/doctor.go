// Package doctor diagnoses a computer's Contro1 connections. Every check says
// what is wrong, who can fix it, and the next command. Repairs never loosen
// an access control: a check that finds exposure is `blocked`, not repairable.
package doctor

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/contro1-hq/contro1-cli/internal/brokerstore"
	"github.com/contro1-hq/contro1-cli/internal/installer"
	"github.com/contro1-hq/contro1-cli/internal/platforms"
	"github.com/contro1-hq/contro1-cli/internal/runtimeproto"
)

// Env is everything doctor reads. Production implements it against the
// operating system; tests use fakes.
type Env interface {
	GOOS() string
	ServiceStatus() (installed, running, automatic bool, account string)
	// ControlReachableUnelevated reports whether the CURRENT (unelevated)
	// process could open the control endpoint. True is a finding.
	ControlReachableUnelevated(ctx context.Context) bool
	IsElevated() bool
	PublicStatus() (*brokerstore.PublicStatus, error)
	Mapping(platform string) (*runtimeproto.MappingFile, error)
	// Discover returns the platform subjects present on this computer.
	Discover(ctx context.Context, platform string) ([]string, error)
	// EndpointPrincipals returns the identities allowed on an endpoint.
	EndpointPrincipals(endpoint string) ([]string, error)
	// ExpectedPrincipals are the identities that may appear on a subject's
	// endpoint: the caller, and on unix also the caller's primary group, which
	// is how a socket opens to one user before the peer-uid check narrows it.
	ExpectedPrincipals(platform, subject string) ([]string, error)
	// RuntimeStatus calls runtime status through the endpoint (no side effect).
	//
	// It returns the mode the SERVER reports, not the one in the mapping file.
	// The mapping is written once, when the agent is connected, and the owner
	// widens a connection afterwards: doctor used to ask the server and then
	// print the number off the file, so a connection that had been allowed
	// applications an hour earlier still read "Approvals only".
	RuntimeStatus(ctx context.Context, entry runtimeproto.MappingEntry) (agentID string, mode string, remediation *runtimeproto.Remediation, err error)
	// ControlMapPreview runs the no-side-effect round trip.
	ControlMapPreview(ctx context.Context, entry runtimeproto.MappingEntry) error
	PlatformUser(platform string) string
	// McpServers returns how the platform is configured to reach Contro1's MCP
	// server for one subject, as the platform itself reports it. Empty when
	// none is configured, which is ordinary: applications are opt in.
	McpServers(ctx context.Context, platform, subject string) ([]McpServerConfig, error)
	// ContainerMounts returns the host paths mounted into a subject's
	// container. Empty on platforms that do not use containers.
	ContainerMounts(ctx context.Context, platform, subject string) ([]string, error)
	// ApproverStatus reports whether the Contro1 channel is actually loaded in
	// the platform and whether it may resolve this subject's approvals.
	ApproverStatus(ctx context.Context, platform, subject string) (ApproverStatus, error)
	// LeaseExposure reports whether this subject's Contro1 MCP lease is held
	// by the platform's credential gateway, and which other agents receive it
	// too. An error means the gateway could not say, which is not a finding.
	LeaseExposure(ctx context.Context, platform, subject string) (stored bool, exposedTo []string, err error)
	// McpServerName is the MCP server name `contro1 connect` gives a subject,
	// on platforms where connect installs it. Empty elsewhere.
	McpServerName(platform, subject string) string
	// McpProbe runs MCP initialize and tools/list through the agent's own
	// endpoint, as `contro1 mcp serve` would, and counts the tools offered.
	McpProbe(ctx context.Context, entry runtimeproto.MappingEntry) (tools int, err error)
	// McpIsolation names each way one agent could use another agent's Contro1
	// MCP server. ErrNotApplicable on a platform with nothing to isolate.
	McpIsolation(ctx context.Context, platform string, subjects []string) ([]IsolationIssue, error)
	// ConfigStatus is the platform's own verdict on its configuration.
	// ErrNotApplicable when the platform has nothing to check.
	ConfigStatus(ctx context.Context, platform string) (ConfigState, error)
	Development() bool
}

// ServiceVersionEnv is optional on an Env: one that can set the installed
// service against this CLI, and name the command that updates it here.
type ServiceVersionEnv interface {
	ServiceVersion() (c installer.ServiceComparison, updateCommand string)
}

/*
ServiceVersionCheck says which version the installed Contro1 service runs and,
when it is older than (or a different build from) this CLI, the command that
updates it.

WHY. The service is a separate copy of contro1 that only an administrator
replaces. Nothing showed which copy was running, so a fix released in the CLI
looked missing on a computer whose service had simply never been updated.
*/
func ServiceVersionCheck(c installer.ServiceComparison, updateCommand string) runtimeproto.Check {
	check := runtimeproto.Check{ID: "service_version", Label: "Contro1 service", Status: runtimeproto.CheckOK}
	version := c.From
	if version == "" {
		version = "unknown"
	}
	switch {
	case c.Needed && c.From != "" && c.From != c.To:
		check.Status, check.Actor = runtimeproto.CheckRepairable, "administrator"
		check.Message = fmt.Sprintf("version %s, older than this CLI (%s). Update it with %s, or run contro1 connect again, which updates it in the same administrator approval.", c.From, c.To, updateCommand)
		check.NextCommand = updateCommand
	case c.Needed:
		check.Status, check.Actor = runtimeproto.CheckRepairable, "administrator"
		check.Message = fmt.Sprintf("version %s, a different build from this CLI (%s). Update it with %s.", version, c.To, updateCommand)
		check.NextCommand = updateCommand
	case c.Newer:
		check.Status, check.Actor = runtimeproto.CheckRepairable, "you"
		check.Message = fmt.Sprintf("version %s, newer than this CLI (%s). Update the CLI; the service is never replaced with an older one.", c.From, c.To)
	default:
		if c.From == "" {
			version = c.To
		}
		check.Message = fmt.Sprintf("version %s (matches the CLI).", version)
	}
	return check
}

// ErrNotApplicable is a question the platform has no answer to, which is not
// a finding.
var ErrNotApplicable = errors.New("not applicable on this platform")

// IsolationIssue is one agent whose MCP tool rules are not what connect writes.
type IsolationIssue struct {
	Agent   string
	Message string
	// Exposure: this agent can act as another one.
	Exposure bool
}

// ConfigState is whether the platform accepts its configuration.
type ConfigState struct {
	Valid   bool
	Problem string
}

/*
ApproverStatus is the difference between "Contro1 is connected" and "approvals
actually arrive".

Connecting an agent gives Contro1 a credential and an endpoint. It does not put
Contro1 in the path of anything. On NanoClaw that takes two more things a person
does by hand: the channel has to be loaded into the host, and the approver has
to hold a role in the group. Skip either and the installation looks finished
from every angle we had: the connection is live, the doctor is green, the agent
reports that it is connected, and not one approval is ever seen.
*/
type ApproverStatus struct {
	// ChannelPresent is true when the platform itself reports the Contro1
	// channel. Asked of the platform, because a file on disk is not the same as
	// a channel the host loaded.
	ChannelPresent bool
	// ApproverExists is the Contro1 approver account in the platform.
	ApproverExists bool
	// ApproverMayResolve is that account holding the role it needs in THIS
	// subject. Per subject, because the grant is per group.
	ApproverMayResolve bool
}

// McpServerConfig is one configured MCP server, flattened to what matters here.
type McpServerConfig struct {
	Name    string
	Command string
	Args    []string
	// URL is set when the entry reaches a server over the network instead of
	// running one locally. For Contro1 that is the older, key-based setup.
	URL string
}

type Report struct {
	SchemaVersion int                  `json:"schema_version"`
	Platform      string               `json:"platform"`
	State         string               `json:"state"` // connected | repairable | blocked
	Checks        []runtimeproto.Check `json:"checks"`
}

func add(r *Report, c runtimeproto.Check) { r.Checks = append(r.Checks, c) }

// Run executes the platform doctor.
func Run(ctx context.Context, env Env, platform string) Report {
	r := Report{SchemaVersion: runtimeproto.SchemaVersion, Platform: platform}
	repair := fmt.Sprintf("contro1 connect %s --repair", platform)

	installed, running, automatic, account := env.ServiceStatus()
	switch {
	case !installed:
		add(&r, runtimeproto.Check{ID: "service_installed", Label: "Contro1 service installed", Status: runtimeproto.CheckRepairable, Actor: "you", Message: "The Contro1 service is not installed on this computer.", NextCommand: fmt.Sprintf("contro1 connect %s", platform)})
	default:
		add(&r, runtimeproto.Check{ID: "service_installed", Label: "Contro1 service installed", Status: runtimeproto.CheckOK, Message: "Installed as " + account + "."})
	}
	if installed {
		if running {
			add(&r, runtimeproto.Check{ID: "service_running", Label: "Contro1 service running", Status: runtimeproto.CheckOK, Message: "Running."})
		} else {
			add(&r, runtimeproto.Check{ID: "service_running", Label: "Contro1 service running", Status: runtimeproto.CheckRepairable, Actor: "you", Message: "The Contro1 service is stopped.", NextCommand: repair})
		}
		if sv, ok := env.(ServiceVersionEnv); ok && !env.Development() {
			c, command := sv.ServiceVersion()
			add(&r, ServiceVersionCheck(c, command))
		}
		if env.Development() {
			add(&r, runtimeproto.Check{ID: "service_autostart", Label: "Starts automatically", Status: runtimeproto.CheckNotApplicable, Message: "Development service runs only while its terminal is open."})
		} else if automatic {
			add(&r, runtimeproto.Check{ID: "service_autostart", Label: "Starts automatically", Status: runtimeproto.CheckOK, Message: "Starts when the computer starts."})
		} else {
			add(&r, runtimeproto.Check{ID: "service_autostart", Label: "Starts automatically", Status: runtimeproto.CheckRepairable, Actor: "you", Message: "The Contro1 service will not start after a restart.", NextCommand: repair})
		}
		if pu := env.PlatformUser(platform); pu != "" && account != "" && strings.EqualFold(pu, account) {
			add(&r, runtimeproto.Check{ID: "service_user_separation", Label: "Service runs as its own identity", Status: runtimeproto.CheckBlocked, Actor: "administrator", Message: "The Contro1 service runs as the same account as " + platform + ", so the agent could read its keys.", NextCommand: repair})
		} else {
			add(&r, runtimeproto.Check{ID: "service_user_separation", Label: "Service runs as its own identity", Status: runtimeproto.CheckOK, Message: "Separate from the agent platform."})
		}
	}

	status, statusErr := env.PublicStatus()
	if statusErr == nil && status != nil {
		switch {
		case status.KeyProtection == "user_file_development" && !env.Development():
			add(&r, runtimeproto.Check{ID: "key_protection", Label: "Keys protected", Status: runtimeproto.CheckBlocked, Actor: "you", Message: "Keys are development files owned by your user. Production connections need the installed service.", NextCommand: fmt.Sprintf("contro1 connect %s", platform)})
		case status.Foreground && !env.Development():
			add(&r, runtimeproto.Check{ID: "key_protection", Label: "Keys protected", Status: runtimeproto.CheckBlocked, Actor: "you", Message: "A development Contro1 service is running in the foreground.", NextCommand: fmt.Sprintf("contro1 connect %s", platform)})
		default:
			add(&r, runtimeproto.Check{ID: "key_protection", Label: "Keys protected", Status: runtimeproto.CheckOK, Message: "Key protection: " + status.KeyProtection + "."})
		}
	}

	if installed && !env.IsElevated() {
		if env.ControlReachableUnelevated(ctx) {
			add(&r, runtimeproto.Check{ID: "control_endpoint_acl", Label: "Control endpoint restricted", Status: runtimeproto.CheckBlocked, Actor: "administrator", Message: "An unelevated process can reach the Contro1 control endpoint.", NextCommand: repair})
		} else {
			add(&r, runtimeproto.Check{ID: "control_endpoint_acl", Label: "Control endpoint restricted", Status: runtimeproto.CheckOK, Message: "Only administrators and the service can reach it."})
		}
	}

	mapping, mapErr := env.Mapping(platform)
	discovered, discErr := env.Discover(ctx, platform)
	switch {
	case mapErr != nil || mapping == nil:
		add(&r, runtimeproto.Check{ID: "mapping_complete", Label: "Every agent mapped", Status: runtimeproto.CheckRepairable, Actor: "you", Message: "No agent mapping for " + platform + " on this computer.", NextCommand: fmt.Sprintf("contro1 connect %s", platform)})
	case len(mapping.Entries) == 0:
		// An empty mapping is what the service leaves when every connection
		// ended (disconnected or revoked in Contro1). Reporting it as fine read
		// "claude-code is connected" over "0 connected", with no way forward.
		add(&r, runtimeproto.Check{ID: "mapping_complete", Label: "Every agent mapped", Status: runtimeproto.CheckRepairable, Actor: "you", Message: "No " + platform + " agent is connected on this computer. A connection that was disconnected in Contro1 is removed here too.", NextCommand: fmt.Sprintf("contro1 connect %s", platform)})
	case discErr != nil:
		add(&r, runtimeproto.Check{ID: "mapping_complete", Label: "Every agent mapped", Status: runtimeproto.CheckRepairable, Actor: "you", Message: "Could not list " + platform + " agents: " + discErr.Error(), NextCommand: repair})
	default:
		missing, extra := diff(discovered, mapping)
		if len(extra) > 0 {
			add(&r, runtimeproto.Check{ID: "mapping_complete", Label: "Every agent mapped", Status: runtimeproto.CheckRepairable, Actor: "you", Message: "Mapped but no longer present: " + strings.Join(extra, ", ") + ".", NextCommand: fmt.Sprintf("contro1 disconnect %s --dry-run", platform)})
		} else if len(missing) > 0 {
			// Connecting only some agents is a choice, not a fault. An agent that
			// is not connected keeps its platform's own approvers and has no
			// Contro1 identity, so nothing here is broken; it is reported so a
			// newly added agent does not go unnoticed, with the command to add it.
			add(&r, runtimeproto.Check{ID: "mapping_complete", Label: "Connected agents mapped", Status: runtimeproto.CheckOK,
				Message:     fmt.Sprintf("%d connected. Not connected: %s. They are not governed by Contro1 until you connect them.", len(mapping.Entries), strings.Join(missing, ", ")),
				NextCommand: fmt.Sprintf("contro1 connect %s --agent %s", platform, missing[0])})
		} else {
			add(&r, runtimeproto.Check{ID: "mapping_complete", Label: "Every agent mapped", Status: runtimeproto.CheckOK, Message: fmt.Sprintf("%d agent(s) mapped exactly.", len(discovered))})
		}
	}

	if mapping != nil {
		installsMcp := false
		for _, e := range mapping.Entries {
			addApproverChecks(ctx, &r, env, platform, e)
			if name := env.McpServerName(platform, e.PlatformSubject); name != "" {
				installsMcp = true
				addMcpServerChecks(ctx, &r, env, platform, name, e)
			} else {
				addApplicationChecks(ctx, &r, env, platform, e)
			}
			addLeaseExposureChecks(ctx, &r, env, e)
		}
		if installsMcp {
			addMcpIsolationChecks(ctx, &r, env, platform, mapping, discovered)
			addConfigCheck(ctx, &r, env, platform)
		}
	}

	if mapping != nil {
		endpointOwners := map[string][]string{}
		for _, e := range mapping.Entries {
			endpointOwners[e.Endpoint] = append(endpointOwners[e.Endpoint], e.PlatformSubject)
		}
		for _, e := range mapping.Entries {
			id := "endpoint_isolation:" + e.PlatformSubject
			if len(endpointOwners[e.Endpoint]) > 1 {
				add(&r, runtimeproto.Check{ID: id, Label: "Private endpoint for " + e.PlatformSubject, Status: runtimeproto.CheckBlocked, Actor: "administrator", Message: "Several agents share one endpoint: " + strings.Join(endpointOwners[e.Endpoint], ", ") + ".", NextCommand: repair})
				continue
			}
			expected, err1 := env.ExpectedPrincipals(platform, e.PlatformSubject)
			actual, err2 := env.EndpointPrincipals(e.Endpoint)
			switch {
			case err2 != nil:
				add(&r, runtimeproto.Check{ID: id, Label: "Private endpoint for " + e.PlatformSubject, Status: runtimeproto.CheckRepairable, Actor: "you", Message: "The endpoint is not available: " + err2.Error(), NextCommand: repair})
			case err1 == nil && !onlyPrincipal(actual, expected):
				// Exposure is never "repaired" by widening access: the fix
				// is to narrow it or reconnect, and until then it is blocked.
				add(&r, runtimeproto.Check{ID: id, Label: "Private endpoint for " + e.PlatformSubject, Status: runtimeproto.CheckBlocked, Actor: "administrator", Message: fmt.Sprintf("The endpoint for %s allows %s; only %s should reach it.", e.PlatformSubject, strings.Join(actual, ", "), strings.Join(expected, " or ")), NextCommand: repair})
			default:
				add(&r, runtimeproto.Check{ID: id, Label: "Private endpoint for " + e.PlatformSubject, Status: runtimeproto.CheckOK, Message: "Only " + e.PlatformSubject + " can use it."})
			}

			agentID, liveMode, rem, err := env.RuntimeStatus(ctx, e)
			rid := "runtime_status:" + e.PlatformSubject
			switch {
			case err != nil && rem != nil:
				add(&r, runtimeproto.Check{ID: rid, Label: "Contro1 recognises " + e.PlatformSubject, Status: runtimeproto.CheckBlocked, Actor: actorFor(rem), Message: rem.PublicMessage, NextCommand: rem.NextStep, ActionURL: rem.ActionURL})
			case err != nil:
				add(&r, runtimeproto.Check{ID: rid, Label: "Contro1 recognises " + e.PlatformSubject, Status: runtimeproto.CheckRepairable, Actor: "you", Message: err.Error(), NextCommand: repair})
			case agentID != e.AgentID:
				add(&r, runtimeproto.Check{ID: rid, Label: "Contro1 recognises " + e.PlatformSubject, Status: runtimeproto.CheckBlocked, Actor: "administrator", Message: fmt.Sprintf("The endpoint for %s speaks as %s, not %s.", e.PlatformSubject, agentID, e.AgentID), NextCommand: repair})
			default:
				mode := liveMode
				if mode == "" {
					// An older service that does not report it. The mapping is
					// the only answer available and is marked as possibly stale
					// rather than presented as current.
					mode = e.EndpointMode
				}
				message := runtimeproto.ModeLabel(mode) + "."
				if liveMode != "" && liveMode != e.EndpointMode && mappedMode(env, platform, e.PlatformSubject) != liveMode {
					/*
					 * Worth saying only while it is still true. The Contro1
					 * service records the mode from the status answer this check
					 * just received and rewrites the mapping, so the file is read
					 * again before calling it stale. It used to say "refreshed by
					 * contro1 connect", and connect did not refresh it: the
					 * sentence has to name what actually does.
					 */
					message += " The mapping file on this computer still says " + runtimeproto.ModeLabel(e.EndpointMode) +
						". The Contro1 service rewrites it when it renews this agent's credential or when the agent first uses an application; the endpoint already follows Contro1, so nothing is needed from you."
				}
				add(&r, runtimeproto.Check{ID: rid, Label: "Contro1 recognises " + e.PlatformSubject, Status: runtimeproto.CheckOK, Message: message})
				if err := env.ControlMapPreview(ctx, e); err != nil {
					add(&r, runtimeproto.Check{ID: "round_trip:" + e.PlatformSubject, Label: "Approval round trip", Status: runtimeproto.CheckRepairable, Actor: "you", Message: err.Error(), NextCommand: repair})
				} else {
					add(&r, runtimeproto.Check{ID: "round_trip:" + e.PlatformSubject, Label: "Approval round trip", Status: runtimeproto.CheckOK, Message: "A preview request reached Contro1 (nothing was created)."})
				}
			}
		}
	}

	r.State = "connected"
	for _, c := range r.Checks {
		if c.Status == runtimeproto.CheckBlocked {
			r.State = "blocked"
			break
		}
		if c.Status == runtimeproto.CheckRepairable {
			r.State = "repairable"
		}
	}
	return r
}

// mappedMode is the mode the mapping file records for one subject now, or ""
// when the file cannot be read.
func mappedMode(env Env, platform, subject string) string {
	m, err := env.Mapping(platform)
	if err != nil || m == nil {
		return ""
	}
	for _, e := range m.Entries {
		if e.PlatformSubject == subject {
			return e.EndpointMode
		}
	}
	return ""
}

func diff(discovered []string, m *runtimeproto.MappingFile) (missing, extra []string) {
	mapped := map[string]bool{}
	for _, e := range m.Entries {
		mapped[e.PlatformSubject] = true
	}
	seen := map[string]bool{}
	for _, d := range discovered {
		seen[d] = true
		if !mapped[d] {
			missing = append(missing, d)
		}
	}
	for s := range mapped {
		if !seen[s] {
			extra = append(extra, s)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return
}

// onlyPrincipal: the endpoint admits the expected caller and nothing else
// except the service and SYSTEM/root, which the environment filters out.
func onlyPrincipal(actual []string, expected []string) bool {
	if len(actual) == 0 {
		return false
	}
	for _, a := range actual {
		if !slices.Contains(expected, a) {
			return false
		}
	}
	return true
}

func actorFor(r *runtimeproto.Remediation) string {
	if r.Who != nil && r.Who.Role != "" {
		return r.Who.Role
	}
	return "you"
}

/*
Two ways an agent ends up believing it can reach applications when it cannot.

Both are quiet, which is what makes them worth a check. Seen in the field: an
agent kept an MCP entry pointing at the public API with no key, answered 401 to
every call, and told its owner over chat that it was connected. Its owner went
looking for a wrong address for an afternoon. Nothing had the whole picture,
because the MCP entry lives in the platform and the endpoint lives here.

Neither is a failure when no MCP server is configured at all. Applications are
opt in, and an agent that only asks for approvals is finished and correct.
*/
func addApplicationChecks(ctx context.Context, r *Report, env Env, platform string, e runtimeproto.MappingEntry) {
	id := "applications:" + e.PlatformSubject
	label := "Applications for " + e.PlatformSubject

	servers, err := env.McpServers(ctx, platform, e.PlatformSubject)
	if err != nil {
		// Not knowing is not a finding. The platform may simply not report it.
		return
	}
	var ours *McpServerConfig
	for i := range servers {
		if strings.EqualFold(servers[i].Name, "contro1") {
			ours = &servers[i]
			break
		}
	}
	if ours == nil {
		add(r, runtimeproto.Check{
			ID: id, Label: label, Status: runtimeproto.CheckOK,
			Message:     "Not set up, which is fine: this agent asks for approvals only.",
			NextCommand: fmt.Sprintf("contro1 apps enable %s --agent %s", platform, e.PlatformSubject),
		})
		return
	}

	// The older setup reached api.contro1.com with a key somebody pasted in. It
	// is not merely outdated: the agent then acts as whoever owns that key
	// rather than as itself, and when the key is absent every call is a 401
	// that reads to the agent like a misconfigured address.
	if ours.URL != "" || !strings.EqualFold(ours.Command, "contro1") {
		where := ours.URL
		if where == "" {
			where = ours.Command
		}
		add(r, runtimeproto.Check{
			ID: id, Label: label, Status: runtimeproto.CheckRepairable, Actor: "you",
			Message:     "The Contro1 MCP server here still points at " + where + ". It carries no agent identity and will answer 401.",
			NextCommand: fmt.Sprintf("contro1 apps enable %s --agent %s", platform, e.PlatformSubject),
		})
		return
	}

	// The entry is right, and on a container platform it still cannot work
	// unless this agent's own socket reaches inside.
	mounts, err := env.ContainerMounts(ctx, platform, e.PlatformSubject)
	if err != nil || len(mounts) == 0 {
		return
	}
	socket := strings.TrimPrefix(e.Endpoint, "unix://")
	mounted := false
	for _, m := range mounts {
		if m == socket {
			mounted = true
			break
		}
	}
	if !mounted {
		add(r, runtimeproto.Check{
			ID: id, Label: label, Status: runtimeproto.CheckRepairable, Actor: "you",
			Message:     "The MCP server is configured but this agent's endpoint is not mounted into its container, so every call fails as soon as it restarts.",
			NextCommand: fmt.Sprintf("contro1 apps enable %s --agent %s", platform, e.PlatformSubject),
		})
		return
	}
	add(r, runtimeproto.Check{ID: id, Label: label, Status: runtimeproto.CheckOK, Message: "Set up, pointed at this agent's own connection."})
}

/*
Does anyone besides this agent receive its Contro1 credential?

OneCLI 2.2.5 hands every secret in the vault to an agent in "all" mode, and a
new agent starts that way. `apps enable` and `apps renew` refuse while another
agent is in "all" mode, but a group created after the lease was stored would
receive it until the next renewal, and could act as this agent at Contro1.
Reported only when a lease is actually stored: without one there is nothing to
receive.
*/
func addLeaseExposureChecks(ctx context.Context, r *Report, env Env, e runtimeproto.MappingEntry) {
	stored, exposed, err := env.LeaseExposure(ctx, r.Platform, e.PlatformSubject)
	if err != nil || !stored {
		return
	}
	id := "lease_only_this_agent:" + e.PlatformSubject
	label := "Only " + e.PlatformSubject + " receives its Contro1 credential"
	if len(exposed) == 0 {
		add(r, runtimeproto.Check{ID: id, Label: label, Status: runtimeproto.CheckOK, Message: "No other agent receives it."})
		return
	}
	add(r, runtimeproto.Check{
		ID: id, Label: label, Status: runtimeproto.CheckBlocked, Actor: "you",
		Message: "OneCLI gives every secret to agents in \"all\" mode, so " + strings.Join(exposed, ", ") +
			" also receive this agent's Contro1 credential and could act as it.",
		NextCommand: "onecli agents set-secrets --id <id> --secret-ids <the secrets it needs>, then onecli agents set-secret-mode --id <id> --mode selective",
	})
}

/*
Is Contro1 actually in the path, or only connected to?

Checked per subject and after the connection checks, because it is the question
a person thinks they already answered by running connect. A connection that
carries no approvals is the most expensive kind of green: everything reports
success and nothing is governed.
*/
func addApproverChecks(ctx context.Context, r *Report, env Env, platform string, e runtimeproto.MappingEntry) {
	id := "approvals_reach_contro1:" + e.PlatformSubject
	label := "Approvals reach Contro1 for " + e.PlatformSubject

	status, err := env.ApproverStatus(ctx, platform, e.PlatformSubject)
	if err != nil {
		// A platform that cannot answer produces no finding. Guessing here
		// would send somebody to reinstall something that is already fine.
		return
	}
	switch {
	case !status.ChannelPresent:
		add(r, runtimeproto.Check{
			ID: id, Label: label, Status: runtimeproto.CheckBlocked, Actor: "you",
			Message: "The Contro1 channel is not loaded in " + platform + ". The connection is live, but no approval will ever reach Contro1.",
			// Named rather than automated: this copies code into the platform's
			// own source tree, which is the person's to change.
			NextCommand: "see skills/add-contro1 in the connector, or https://contro1.com/docs/" + platform + "-human-approval",
		})
	case !status.ApproverExists:
		add(r, runtimeproto.Check{
			ID: id, Label: label, Status: runtimeproto.CheckRepairable, Actor: "you",
			Message:     "The Contro1 approver account does not exist in " + platform + ", so cards cannot be routed to it.",
			NextCommand: fmt.Sprintf("contro1 connect %s --confirm-roles", platform),
		})
	case !status.ApproverMayResolve:
		add(r, runtimeproto.Check{
			ID: id, Label: label, Status: runtimeproto.CheckRepairable, Actor: "you",
			Message:     "Contro1 is not an approver of " + e.PlatformSubject + ", so this group's cards go somewhere else.",
			NextCommand: fmt.Sprintf("contro1 connect %s --confirm-roles --agent %s", platform, e.PlatformSubject),
		})
	default:
		add(r, runtimeproto.Check{ID: id, Label: label, Status: runtimeproto.CheckOK, Message: "Approvals for this agent come to Contro1."})
	}
}

/*
The Contro1 MCP server, on platforms where `contro1 connect` installs it.

Two questions, because each fails without the other: is the entry there and
pointed at THIS agent, and does Contro1 answer MCP for this agent at all. The
first is asked of the platform, the second of the agent's own endpoint, the
same way `contro1 mcp serve` reaches it. A customer's agent showed only
"MCP error -32000: Connection closed" in its chat; with both answers here the
cause is one line.
*/
func addMcpServerChecks(ctx context.Context, r *Report, env Env, platform, name string, e runtimeproto.MappingEntry) {
	subject := e.PlatformSubject
	fix := "contro1 connect " + platform
	servers, err := env.McpServers(ctx, platform, subject)
	if errors.Is(err, platforms.ErrMcpConfigUnreadable) {
		// A config file that exists and cannot be read is a finding, not a
		// platform with nothing to say: the client cannot load Contro1 from it.
		add(r, runtimeproto.Check{ID: "mcp_server:" + subject, Label: "MCP server for " + subject, Status: runtimeproto.CheckRepairable, Actor: "you",
			Message: err.Error() + ". Fix the file, then run " + fix + ".", NextCommand: fix})
	}
	if err == nil {
		id := "mcp_server:" + subject
		label := "MCP server for " + subject
		var ours *McpServerConfig
		for i := range servers {
			if strings.EqualFold(servers[i].Name, name) {
				ours = &servers[i]
				break
			}
		}
		entry := platforms.McpServer{}
		if ours != nil {
			entry = platforms.McpServer{Name: ours.Name, Command: ours.Command, Args: ours.Args, URL: ours.URL}
		}
		// Claude Code has used Contro1 for approvals alone since before connect
		// installed the MCP server, and that is still a finished setup: there
		// the server is an option, said with the command, never a failure.
		optional := platform == "claude-code"
		serves := entry.ServesAgent(subject)
		if optional {
			serves = platforms.ClaudeServesAgent(entry, subject)
		}
		switch {
		case ours == nil && optional:
			add(r, runtimeproto.Check{ID: id, Label: label, Status: runtimeproto.CheckOK,
				Message:     "MCP not set up: run " + fix + " to let it use applications through Contro1.",
				NextCommand: fix})
			return
		case ours == nil:
			add(r, runtimeproto.Check{ID: id, Label: label, Status: runtimeproto.CheckRepairable, Actor: "you",
				Message:     fmt.Sprintf("No Contro1 MCP server named %s is set up, so %s cannot use Contro1's tools.", name, subject),
				NextCommand: fix})
		case !serves && optional:
			add(r, runtimeproto.Check{ID: id, Label: label, Status: runtimeproto.CheckOK,
				Message:     fmt.Sprintf("The MCP server %s runs %q, not this agent. To use applications as this agent, run %s.", name, entry.Describe(), fix),
				NextCommand: fix})
			return
		case !serves:
			add(r, runtimeproto.Check{ID: id, Label: label, Status: runtimeproto.CheckRepairable, Actor: "you",
				Message:     fmt.Sprintf("The MCP server %s runs %q, not contro1 mcp serve --agent %s, so it does not act as this agent.", name, entry.Describe(), subject),
				NextCommand: fix})
		default:
			add(r, runtimeproto.Check{ID: id, Label: label, Status: runtimeproto.CheckOK, Message: fmt.Sprintf("%s runs contro1 mcp serve as %s.", name, subject)})
		}
	}

	tools, err := env.McpProbe(ctx, e)
	id := "mcp_live:" + subject
	label := "MCP answers for " + subject
	if err != nil {
		add(r, runtimeproto.Check{ID: id, Label: label, Status: runtimeproto.CheckRepairable, Actor: "you", Message: err.Error(), NextCommand: fmt.Sprintf("contro1 connect %s --repair", platform)})
		return
	}
	add(r, runtimeproto.Check{ID: id, Label: label, Status: runtimeproto.CheckOK, Message: fmt.Sprintf("MCP connected: %d actions available.", tools)})
}

/*
Can one agent act as another through its MCP server?

OpenClaw's MCP servers belong to the gateway, so every agent sees every server
unless its tool rules hide the others. An agent that can call another agent's
Contro1 server acts as that agent, with its owner's approvals and its access.
That is exposure, so it is blocked; the fix only narrows (connect writes the
deny rules), never widens.
*/
func addMcpIsolationChecks(ctx context.Context, r *Report, env Env, platform string, m *runtimeproto.MappingFile, discovered []string) {
	subjects := make([]string, 0, len(m.Entries))
	for _, e := range m.Entries {
		subjects = append(subjects, e.PlatformSubject)
	}
	everyone := map[string]bool{}
	for _, s := range append(append([]string(nil), subjects...), discovered...) {
		everyone[s] = true
	}
	fix := "contro1 connect " + platform
	issues, err := env.McpIsolation(ctx, platform, subjects)
	switch {
	case errors.Is(err, ErrNotApplicable):
		return
	case err != nil:
		if len(everyone) > 1 {
			add(r, runtimeproto.Check{ID: "mcp_isolation", Label: "Each agent sees only its own Contro1 server", Status: runtimeproto.CheckRepairable, Actor: "you",
				Message: "Could not confirm it: " + err.Error() + ". Each agent's agents.entries.<id>.tools.deny must list the other agents' contro1-<id>__* tools.", NextCommand: fix})
		}
		return
	}
	for _, issue := range issues {
		status := runtimeproto.CheckRepairable
		if issue.Exposure {
			status = runtimeproto.CheckBlocked
		}
		add(r, runtimeproto.Check{ID: "mcp_isolation:" + issue.Agent, Label: "Only " + issue.Agent + " uses its Contro1 server", Status: status, Actor: "you", Message: issue.Message, NextCommand: fix})
	}
	if len(issues) == 0 && len(everyone) > 1 {
		add(r, runtimeproto.Check{ID: "mcp_isolation", Label: "Each agent sees only its own Contro1 server", Status: runtimeproto.CheckOK, Message: "Every agent's tool rules hide the other agents' Contro1 servers."})
	}
}

/*
Does the platform accept its own configuration?

OpenClaw keeps running the last configuration it accepted. One it rejects, for
example a hand edit with a key the schema does not know, means every later
change is refused or never applied, the Contro1 servers included, while the
gateway looks healthy (docs/gateway/configuration/config-rpc.md).
*/
func addConfigCheck(ctx context.Context, r *Report, env Env, platform string) {
	state, err := env.ConfigStatus(ctx, platform)
	if err != nil {
		return
	}
	id, label := "platform_config_valid", platform+" accepts its configuration"
	if !state.Valid {
		add(r, runtimeproto.Check{ID: id, Label: label, Status: runtimeproto.CheckRepairable, Actor: "you",
			Message:     platform + " rejects its configuration (" + state.Problem + "). It keeps running the last good one, so changes such as the Contro1 servers do not apply.",
			NextCommand: platform + " config validate"})
		return
	}
	add(r, runtimeproto.Check{ID: id, Label: label, Status: runtimeproto.CheckOK, Message: "Valid."})
}
