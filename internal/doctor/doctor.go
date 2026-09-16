// Package doctor diagnoses a computer's Contro1 connections. Every check says
// what is wrong, who can fix it, and the next command. Repairs never loosen
// an access control: a check that finds exposure is `blocked`, not repairable.
package doctor

import (
	"context"
	"fmt"
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
	// ExpectedPrincipal is the one identity that should reach a subject's endpoint.
	ExpectedPrincipal(platform, subject string) (string, error)
	// RuntimeStatus calls runtime status through the endpoint (no side effect).
	RuntimeStatus(ctx context.Context, entry runtimeproto.MappingEntry) (agentID string, remediation *runtimeproto.Remediation, err error)
	// ControlMapPreview runs the no-side-effect round trip.
	ControlMapPreview(ctx context.Context, entry runtimeproto.MappingEntry) error
	PlatformUser(platform string) string
	Development() bool
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
		if len(missing) > 0 {
			add(&r, runtimeproto.Check{ID: "mapping_complete", Label: "Every agent mapped", Status: runtimeproto.CheckRepairable, Actor: "accountable_owner", Message: "Not connected yet: " + strings.Join(missing, ", ") + ". Adding them needs a new approval.", NextCommand: fmt.Sprintf("contro1 connect %s", platform)})
		} else if len(extra) > 0 {
			add(&r, runtimeproto.Check{ID: "mapping_complete", Label: "Every agent mapped", Status: runtimeproto.CheckRepairable, Actor: "you", Message: "Mapped but no longer present: " + strings.Join(extra, ", ") + ".", NextCommand: fmt.Sprintf("contro1 disconnect %s --dry-run", platform)})
		} else {
			add(&r, runtimeproto.Check{ID: "mapping_complete", Label: "Every agent mapped", Status: runtimeproto.CheckOK, Message: fmt.Sprintf("%d agent(s) mapped exactly.", len(discovered))})
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
			expected, err1 := env.ExpectedPrincipal(platform, e.PlatformSubject)
			actual, err2 := env.EndpointPrincipals(e.Endpoint)
			switch {
			case err2 != nil:
				add(&r, runtimeproto.Check{ID: id, Label: "Private endpoint for " + e.PlatformSubject, Status: runtimeproto.CheckRepairable, Actor: "you", Message: "The endpoint is not available: " + err2.Error(), NextCommand: repair})
			case err1 == nil && !onlyPrincipal(actual, expected):
				// Exposure is never "repaired" by widening access: the fix
				// is to narrow it or reconnect, and until then it is blocked.
				add(&r, runtimeproto.Check{ID: id, Label: "Private endpoint for " + e.PlatformSubject, Status: runtimeproto.CheckBlocked, Actor: "administrator", Message: fmt.Sprintf("The endpoint for %s allows %s; only %s should reach it.", e.PlatformSubject, strings.Join(actual, ", "), expected), NextCommand: repair})
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
func onlyPrincipal(actual []string, expected string) bool {
	if len(actual) != 1 {
		return false
	}
	return actual[0] == expected
}

func actorFor(r *runtimeproto.Remediation) string {
	if r.Who != nil && r.Who.Role != "" {
		return r.Who.Role
	}
	return "you"
}
