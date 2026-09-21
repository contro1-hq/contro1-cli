// Package doctor diagnoses a computer's Contro1 connections. Every check says
// what is wrong, who can fix it, and the next command. Repairs never loosen
// an access control: a check that finds exposure is `blocked`, not repairable.
package doctor

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/contro1-hq/contro1-cli/internal/brokerstore"
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
	RuntimeStatus(ctx context.Context, entry runtimeproto.MappingEntry) (agentID string, remediation *runtimeproto.Remediation, err error)
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
	Development() bool
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
		for _, e := range mapping.Entries {
			addApproverChecks(ctx, &r, env, platform, e)
			addApplicationChecks(ctx, &r, env, platform, e)
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

			agentID, rem, err := env.RuntimeStatus(ctx, e)
			rid := "runtime_status:" + e.PlatformSubject
			switch {
			case err != nil && rem != nil:
				add(&r, runtimeproto.Check{ID: rid, Label: "Contro1 recognises " + e.PlatformSubject, Status: runtimeproto.CheckBlocked, Actor: actorFor(rem), Message: rem.PublicMessage, NextCommand: rem.NextStep, ActionURL: rem.ActionURL})
			case err != nil:
				add(&r, runtimeproto.Check{ID: rid, Label: "Contro1 recognises " + e.PlatformSubject, Status: runtimeproto.CheckRepairable, Actor: "you", Message: err.Error(), NextCommand: repair})
			case agentID != e.AgentID:
				add(&r, runtimeproto.Check{ID: rid, Label: "Contro1 recognises " + e.PlatformSubject, Status: runtimeproto.CheckBlocked, Actor: "administrator", Message: fmt.Sprintf("The endpoint for %s speaks as %s, not %s.", e.PlatformSubject, agentID, e.AgentID), NextCommand: repair})
			default:
				add(&r, runtimeproto.Check{ID: rid, Label: "Contro1 recognises " + e.PlatformSubject, Status: runtimeproto.CheckOK, Message: runtimeproto.ModeLabel(e.EndpointMode) + "."})
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
