// Package connect runs `contro1 connect <platform>`: discover, preview,
// prepare, one elevation, wait for the owner, configure, verify. Every call
// returns a runtimeproto.NextStep, so a coding agent can finish every step it
// is allowed to using JSON alone, and hand the rest to a person.
//
// The persisted state holds no secret. The single-use connection ticket lives
// only in memory and, for the elevated phase, in a 0600 phase file that is
// deleted as soon as the service has registered the keys.
package connect

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/contro1-hq/contro1-cli/internal/broker"
	"github.com/contro1-hq/contro1-cli/internal/brokerstore"
	"github.com/contro1-hq/contro1-cli/internal/installer"
	"github.com/contro1-hq/contro1-cli/internal/platforms"
	"github.com/contro1-hq/contro1-cli/internal/runtimeproto"
)

// ---------------------------------------------------------------------------
// Ports
// ---------------------------------------------------------------------------

type Identity struct {
	Email       string
	DisplayName string
	OperatorID  string
	Scopes      []string
}

type PrepareItem struct {
	PlatformSubject string `json:"platform_subject"`
	DisplayName     string `json:"display_name,omitempty"`
	// Reach is every surface this subject answers on, so the owner approving
	// the connection can see who is able to instruct it. Omitted when the
	// adapter could not say, which Contro1 reads as exposure rather than as
	// privacy, so leaving it out never buys anything.
	Reach *runtimeproto.AgentReach `json:"reach,omitempty"`
}

type PrepareRequest struct {
	Platform               string            `json:"platform"`
	PlatformInstanceDigest string            `json:"platform_instance_digest,omitempty"`
	Host                   map[string]string `json:"host,omitempty"`
	Owner                  map[string]any    `json:"owner,omitempty"`
	Environment            string            `json:"environment,omitempty"`
	Items                  []PrepareItem     `json:"items"`
}

type PreparedItem struct {
	ItemID          string `json:"item_id"`
	PlatformSubject string `json:"platform_subject"`
	AgentID         string `json:"agent_id"`
	EnrollmentID    string `json:"enrollment_id"`
	AgentCreated    bool   `json:"agent_created"`
}

type PrepareResponse struct {
	BatchID          string         `json:"batch_id"`
	ConnectionTicket string         `json:"connection_ticket"`
	ExpiresAt        string         `json:"expires_at"`
	Items            []PreparedItem `json:"items"`
	Existing         []struct {
		PlatformSubject string `json:"platform_subject"`
		AgentID         string `json:"agent_id"`
		EnrollmentID    string `json:"enrollment_id"`
	} `json:"existing"`
}

type BatchView struct {
	BatchID    string `json:"batch_id"`
	State      string `json:"state"`
	UserCode   string `json:"user_code"`
	ExpiresAt  string `json:"expires_at"`
	Link       string `json:"verification_uri_complete"`
	WaitingFor *struct {
		DisplayName string `json:"display_name"`
		OperatorID  string `json:"operator_id"`
	} `json:"waiting_for"`
	Items []struct {
		ItemID          string `json:"item_id"`
		PlatformSubject string `json:"platform_subject"`
		AgentID         string `json:"agent_id"`
		State           string `json:"state"`
	} `json:"items"`
}

type API interface {
	Whoami(ctx context.Context) (*Identity, error)
	Prepare(ctx context.Context, req PrepareRequest) (*PrepareResponse, error)
	Batch(ctx context.Context, batchID string) (*BatchView, error)
	ReportItem(ctx context.Context, batchID, itemID, state, reason string) error
}

// Broker is the Contro1 service as seen from the unelevated connect process.
type Broker interface {
	// Healthy reports whether a service this command can use is running.
	Healthy(ctx context.Context) bool
	// Register installs the service when needed and hands it the connection
	// ticket. In production this is the one elevated phase; it may return
	// installer.ErrElevationDeclined or installer.ErrNeedsElevation.
	Register(ctx context.Context, apiURL string, req broker.ControlConnectionsRequest) ([]broker.ControlItemResult, error)
	PublicStatus() (*brokerstore.PublicStatus, error)
	MappingPath(platform string) string
	// SetPrincipals changes who may reach existing endpoints (--repair --principal).
	SetPrincipals(ctx context.Context, apiURL string, updates []broker.ControlPrincipalUpdate) error
}

type Verifier interface {
	RuntimeStatus(ctx context.Context, e runtimeproto.MappingEntry) (agentID string, err error)
	ControlMapPreview(ctx context.Context, e runtimeproto.MappingEntry) error
}

type Prompter interface {
	Interactive() bool
	// Terminal reports a person at a terminal, whatever the output format.
	// Role changes need one; JSON output alone does not rule a person out.
	Terminal() bool
	Confirm(title string, lines []string) bool
	Progress(line string)
}

type StateStore interface {
	Load(platform string) (*State, error)
	Save(platform string, st *State) error
	Clear(platform string) error
}

// State is persisted between runs. No secrets.
type State struct {
	Platform       string            `json:"platform"`
	InstanceDigest string            `json:"instance_digest"`
	BatchID        string            `json:"batch_id,omitempty"`
	BatchExpiresAt string            `json:"batch_expires_at,omitempty"`
	Step           string            `json:"step"`
	Items          []PreparedItem    `json:"items,omitempty"`
	Registered     bool              `json:"registered,omitempty"`
	Configured     bool              `json:"configured,omitempty"`
	RolesApplied   bool              `json:"roles_applied,omitempty"`
	Journal        platforms.Journal `json:"journal"`
	Results        map[string]string `json:"results,omitempty"`
	UpdatedAt      string            `json:"updated_at"`
}

// ---------------------------------------------------------------------------
// Orchestrator
// ---------------------------------------------------------------------------

type Options struct {
	Platform string
	APIURL   string
	Owner    string
	Resume   string
	NoWait   bool
	Yes      bool
	// Agents are the subjects named with --agent. Their presence is what tells
	// --yes apart from "and connect whatever discovery happens to find".
	Agents       []string
	ConfirmRoles bool
	Development  bool
	Repair       bool
	// Principal is an explicit --principal; with Repair it moves existing endpoints.
	Principal   string
	HostLabel   string
	HostOS      string
	HostArch    string
	WaitTimeout time.Duration
	PollEvery   time.Duration
}

type Orchestrator struct {
	API      API
	Broker   Broker
	Verifier Verifier
	Adapter  platforms.Adapter
	Prompt   Prompter
	States   StateStore
	Now      func() time.Time
}

func (o *Orchestrator) cmd(opts Options, extra string) string {
	c := "contro1 connect " + opts.Platform
	if opts.Development {
		c += " --development"
	}
	return strings.TrimSpace(c + " " + extra)
}

func step(platform, state, message string) runtimeproto.NextStep {
	return runtimeproto.NextStep{SchemaVersion: runtimeproto.SchemaVersion, State: state, Platform: platform, Message: message}
}

// Run advances as far as it can and returns where it stopped.
func (o *Orchestrator) Run(ctx context.Context, opts Options) runtimeproto.NextStep {
	if o.Now == nil {
		o.Now = time.Now
	}
	if opts.PollEvery == 0 {
		opts.PollEvery = 3 * time.Second
	}
	if opts.WaitTimeout == 0 {
		opts.WaitTimeout = 11 * time.Minute
	}
	p := opts.Platform

	// 1. Who is connecting. A person's login with runtime:connect is required.
	me, err := o.API.Whoami(ctx)
	if err != nil {
		ns := step(p, runtimeproto.StateBlocked, "Sign in to Contro1 on this computer first.")
		ns.NextCommand = "contro1 auth login"
		ns.Remediation = &runtimeproto.Remediation{Code: "LOGIN_REQUIRED", PublicMessage: "Connecting agents needs your own Contro1 login.", Missing: "A Contro1 login on this computer.", NextStep: "Run contro1 auth login, then run this command again."}
		return ns
	}
	if !contains(me.Scopes, "runtime:connect") {
		ns := step(p, runtimeproto.StateBlocked, "Your Contro1 login is older than agent connections. Sign in again.")
		ns.NextCommand = "contro1 auth login"
		ns.Remediation = &runtimeproto.Remediation{Code: "LOGIN_REQUIRED", PublicMessage: "Your login cannot connect agents yet.", Missing: "The runtime:connect permission on your login.", NextStep: "Run contro1 auth login again."}
		return ns
	}

	// 2. Discover.
	o.Prompt.Progress("Looking for " + p + " on this computer...")
	instance, subjects, err := o.Adapter.Discover(ctx)
	if err != nil || len(subjects) == 0 {
		ns := step(p, runtimeproto.StateBlocked, "No "+p+" agents were found on this computer.")
		if err != nil {
			ns.Message = err.Error()
		}
		ns.NextCommand = o.cmd(opts, "--agent <id>")
		return ns
	}
	sort.Slice(subjects, func(i, j int) bool { return subjects[i].ID < subjects[j].ID })
	names := make([]string, len(subjects))
	for i, s := range subjects {
		names[i] = s.Display
	}
	o.Prompt.Progress(fmt.Sprintf("Found %s with %d agent(s): %s", instance.Label, len(subjects), strings.Join(names, ", ")))

	st, _ := o.States.Load(p)
	if st == nil || st.InstanceDigest != instance.Digest || (opts.Resume != "" && st.BatchID != opts.Resume) {
		if opts.Resume != "" && (st == nil || st.BatchID != opts.Resume) {
			ns := step(p, runtimeproto.StateError, "There is no connection "+opts.Resume+" to resume on this computer.")
			ns.NextCommand = o.cmd(opts, "")
			return ns
		}
		st = &State{Platform: p, InstanceDigest: instance.Digest, Step: "discovered", Results: map[string]string{}}
	}
	if st.Results == nil {
		st.Results = map[string]string{}
	}
	save := func(stepName string) {
		st.Step = stepName
		st.UpdatedAt = o.Now().UTC().Format(time.RFC3339)
		_ = o.States.Save(p, st)
	}

	// A batch that expired before the service registered it is abandoned.
	if st.BatchID != "" && !st.Registered {
		if exp, err := time.Parse(time.RFC3339, st.BatchExpiresAt); err == nil && o.Now().After(exp) {
			st.BatchID, st.Items = "", nil
		}
	}

	ownerLabel := me.Email + " (you)"
	if opts.Owner != "" && !strings.EqualFold(opts.Owner, me.Email) {
		ownerLabel = opts.Owner
	}

	// 3. Local preview. Nothing has changed yet.
	if st.BatchID == "" {
		lines := []string{
			"Agents: " + strings.Join(names, ", "),
			"Accountable owner: " + ownerLabel,
			"They can: ask people for approval. They cannot use organization applications.",
		}
		if !opts.Development {
			plan := installer.Plan(hostGOOS(opts), installer.Options{APIURL: opts.APIURL})
			if !o.Broker.Healthy(ctx) {
				lines = append(lines, plan.Summary...)
			}
		}
		for _, c := range o.Adapter.PlanConfig(o.Broker.MappingPath(p)) {
			lines = append(lines, c.Description+" ("+c.Path+")")
		}
		/*
		 * --yes APPROVES THE LOCAL CHANGES, NOT THE LIST OF IDENTITIES.
		 *
		 * Discovery returns every agent the platform has. On a NanoClaw host
		 * that is every group, including ones whose owner deliberately left
		 * them unconnected. Letting --yes stand in for "and connect all of
		 * them" turns a flag people use to skip a file-change prompt into a
		 * blank cheque over identities, and the mistake is silent: the agents
		 * are simply connected.
		 *
		 * The same rule already applies to NanoClaw role changes, which need a
		 * confirmation even with --yes. Scope is at least as consequential.
		 */
		if opts.Yes && len(opts.Agents) == 0 && len(subjects) > 1 {
			ns := step(p, runtimeproto.StateNeedsLocalConfirmation,
				fmt.Sprintf("This computer has %d %s. Name the ones to connect, or drop --yes to choose from a list.", len(subjects), platformNoun(p, len(subjects))))
			ns.Checks = previewChecks(lines)
			for _, sub := range subjects {
				ns.Agents = append(ns.Agents, runtimeproto.AgentState{PlatformName: sub.ID, State: runtimeproto.StateNeedsLocalConfirmation})
			}
			ns.NextCommand = o.cmd(opts, "--agent <id>")
			return ns
		}
		if !opts.Yes {
			if !o.Prompt.Interactive() || !o.Prompt.Confirm("Connect these agents?", lines) {
				ns := step(p, runtimeproto.StateNeedsLocalConfirmation, "Review what will change on this computer, then confirm.")
				ns.NextCommand = o.cmd(opts, "--yes")
				ns.Checks = previewChecks(lines)
				for _, s := range subjects {
					ns.Agents = append(ns.Agents, runtimeproto.AgentState{PlatformName: s.ID, State: runtimeproto.StateNeedsLocalConfirmation})
				}
				return ns
			}
		}

		// 4. Prepare (idempotent on the server: existing Agents are reused).
		req := PrepareRequest{Platform: p, PlatformInstanceDigest: instance.Digest, Host: map[string]string{"label": opts.HostLabel, "os": opts.HostOS, "arch": opts.HostArch}}
		if opts.Owner != "" {
			req.Owner = map[string]any{"email": opts.Owner}
		}
		if opts.Development {
			req.Environment = "development"
		}
		for _, s := range subjects {
			item := PrepareItem{PlatformSubject: s.ID, DisplayName: s.Display}
			// A reach that cannot be read never blocks a connection. It is
			// simply not sent, and the agent is treated as reachable by people
			// Contro1 cannot name until a later run reports otherwise.
			if reach, err := o.Adapter.Reach(ctx, s.ID); err == nil {
				item.Reach = &reach
			}
			req.Items = append(req.Items, item)
		}
		prepared, err := o.API.Prepare(ctx, req)
		if err != nil {
			ns := step(p, runtimeproto.StateError, "Contro1 could not prepare the connection: "+err.Error())
			ns.NextCommand = o.cmd(opts, "")
			return ns
		}
		if len(prepared.Items) == 0 {
			// Everything is already connected; this is a repair run.
			st.Registered = true
			save("registered")
		} else {
			st.BatchID, st.BatchExpiresAt, st.Items, st.Registered = prepared.BatchID, prepared.ExpiresAt, prepared.Items, false
			save("prepared")

			/*
			 * 5. The one elevated phase.
			 *
			 * This asks for an administrator even when the service is already
			 * installed and answering, because registering an agent's key goes
			 * through the control channel and control refuses unelevated
			 * callers by design. Saying "setting up the service" here read as
			 * a reinstall and sent a reader looking for a broken service
			 * instead of approving an ordinary administrative act.
			 */
			o.Prompt.Progress("Registering the agent keys with the Contro1 service on this computer (administrator approval required)...")
			creq := broker.ControlConnectionsRequest{APIURL: opts.APIURL, BatchID: prepared.BatchID, ConnectionTicket: prepared.ConnectionTicket, HostFacts: req.Host}
			for _, it := range prepared.Items {
				principal, err := o.Adapter.AllowedPrincipal(it.PlatformSubject)
				if err != nil {
					return step(p, runtimeproto.StateError, "Could not determine who runs "+it.PlatformSubject+": "+err.Error())
				}
				creq.Items = append(creq.Items, broker.ControlItem{ItemID: it.ItemID, AgentID: it.AgentID, EnrollmentID: it.EnrollmentID, Platform: p, PlatformInstanceDigest: instance.Digest, PlatformSubject: it.PlatformSubject, DisplayName: displayFor(subjects, it.PlatformSubject), EndpointMode: runtimeproto.ModeApprovalsOnly, AllowedPrincipals: []string{principal}})
			}
			results, err := o.Broker.Register(ctx, opts.APIURL, creq)
			if errors.Is(err, installer.ErrElevationDeclined) || errors.Is(err, installer.ErrNeedsElevation) {
				ns := step(p, runtimeproto.StateNeedsLocalConfirmation, "Registering an agent key with the local Contro1 service needs an administrator on this computer. The service itself may already be running: its control channel refuses unelevated callers by design.")
				ns.WaitingFor = &runtimeproto.WaitingFor{Kind: "local_administrator"}
				ns.NextCommand = o.cmd(opts, "--yes")
				if hint := installer.SudoHint(o.cmd(opts, "--yes")); hint != "" {
					ns.NextCommand = hint
				}
				// The ticket was not used; a fresh prepare will issue a new one.
				st.BatchID, st.Items = "", nil
				save("elevation_needed")
				return ns
			}
			if err != nil {
				ns := step(p, runtimeproto.StateError, "The Contro1 service could not register the agents: "+err.Error())
				ns.NextCommand = "contro1 doctor " + p
				st.BatchID, st.Items = "", nil
				save("register_failed")
				return ns
			}
			for _, r := range results {
				if r.State != "awaiting_approval" {
					st.Results[r.ItemID] = "failed: " + r.Error
				}
			}
			st.Registered = true
			save("registered")
		}
	}

	// 6. Waiting for the owner.
	if st.BatchID != "" {
		deadline := o.Now().Add(opts.WaitTimeout)
		announced := false
		for {
			view, err := o.API.Batch(ctx, st.BatchID)
			if err != nil {
				return step(p, runtimeproto.StateError, "Could not check the connection: "+err.Error())
			}
			switch view.State {
			case "declined":
				_ = o.States.Clear(p)
				ns := step(p, runtimeproto.StateBlocked, "The owner declined this connection. Nothing was connected.")
				ns.NextCommand = o.cmd(opts, "")
				return ns
			case "expired":
				st.BatchID, st.Items, st.Registered = "", nil, false
				save("expired")
				ns := step(p, runtimeproto.StateError, "The approval request expired before the owner approved it.")
				ns.NextCommand = o.cmd(opts, "")
				return ns
			case "pending", "collecting_keys":
				ns := step(p, runtimeproto.StateWaitingForOwner, "")
				who := "the owner"
				if view.WaitingFor != nil && view.WaitingFor.DisplayName != "" {
					who = view.WaitingFor.DisplayName
					ns.WaitingFor = &runtimeproto.WaitingFor{Kind: "accountable_owner", DisplayName: view.WaitingFor.DisplayName, OperatorID: view.WaitingFor.OperatorID}
				}
				ns.Message = fmt.Sprintf("%s needs to approve %d agent(s) on this computer.", who, len(st.Items))
				ns.UserCode, ns.ExpiresAt, ns.ShareThisLink = view.UserCode, view.ExpiresAt, view.Link
				ns.NextCommand = o.cmd(opts, "--resume "+st.BatchID)
				for _, it := range st.Items {
					ns.Agents = append(ns.Agents, runtimeproto.AgentState{PlatformName: it.PlatformSubject, AgentID: it.AgentID, State: runtimeproto.StateWaitingForOwner})
				}
				if !announced && view.UserCode != "" {
					o.Prompt.Progress(fmt.Sprintf("Approve at %s   Code: %s", view.Link, view.UserCode))
					announced = true
				}
				if opts.NoWait || o.Now().After(deadline) {
					return ns
				}
				select {
				case <-ctx.Done():
					return ns
				case <-time.After(opts.PollEvery):
				}
				continue
			}
			break
		}
		o.Prompt.Progress("Approved.")
		save("approved")
	}

	// 7. Configuring: the service writes the mapping once connections are active.
	o.Prompt.Progress("Configuring " + p + "...")
	mappingPath := o.Broker.MappingPath(p)
	var mapping *runtimeproto.MappingFile
	deadline := o.Now().Add(90 * time.Second)
	for {
		mapping, err = platforms.ReadMapping(mappingPath)
		if err == nil && coversItems(mapping, st.Items) {
			break
		}
		if o.Now().After(deadline) || opts.NoWait {
			ns := step(p, runtimeproto.StateConfiguring, "The Contro1 service has not activated the connections yet.")
			ns.NextCommand = o.cmd(opts, "--resume "+st.BatchID)
			return ns
		}
		select {
		case <-ctx.Done():
			return step(p, runtimeproto.StateConfiguring, "Interrupted while configuring.")
		case <-time.After(opts.PollEvery):
		}
	}
	if opts.Repair && opts.Principal != "" {
		// An explicit --principal on a repair is the one way to move existing
		// endpoints to another account without reconnecting.
		var updates []broker.ControlPrincipalUpdate
		for _, e := range mapping.Entries {
			updates = append(updates, broker.ControlPrincipalUpdate{Platform: p, PlatformSubject: e.PlatformSubject, AllowedPrincipals: []string{opts.Principal}})
		}
		if len(updates) > 0 {
			o.Prompt.Progress("Changing who can reach these agents' endpoints...")
			if err := o.Broker.SetPrincipals(ctx, opts.APIURL, updates); err != nil {
				if errors.Is(err, installer.ErrElevationDeclined) || errors.Is(err, installer.ErrNeedsElevation) {
					ns := step(p, runtimeproto.StateNeedsLocalConfirmation, "Changing who can reach the agents needs administrator approval on this computer.")
					ns.WaitingFor = &runtimeproto.WaitingFor{Kind: "local_administrator"}
					ns.NextCommand = installer.SudoHint(o.cmd(opts, "--repair"))
					return ns
				}
				ns := step(p, runtimeproto.StateError, "Could not change who can reach the agents: "+err.Error())
				ns.NextCommand = "contro1 doctor " + p
				return ns
			}
		}
	}
	if !st.Configured || opts.Repair {
		if err := o.Adapter.ApplyConfig(ctx, mappingPath, mapping, &st.Journal); err != nil {
			ns := step(p, runtimeproto.StateError, "Could not configure "+p+": "+err.Error())
			ns.NextCommand = o.cmd(opts, "--repair")
			return ns
		}
		st.Configured = true
		save("configured")
	}

	// NanoClaw roles: a separate, explicit confirmation at a terminal.
	if roles := o.Adapter.RoleChanges(mapping); len(roles) > 0 && !st.RolesApplied {
		var lines []string
		for _, r := range roles {
			line := r.Description
			if r.Before != "" {
				line += " (before: " + r.Before + ")"
			}
			lines = append(lines, line+" -> "+r.After)
		}
		confirmed := o.Prompt.Terminal() && (opts.ConfirmRoles || (o.Prompt.Interactive() && o.Prompt.Confirm("Change who can resolve approvals in these groups?", lines)))
		if !confirmed {
			msg := "Changing NanoClaw approval roles needs a person at this terminal. --yes does not cover it."
			if !o.Prompt.Terminal() {
				msg = "Changing who approves in NanoClaw needs a person. Run the next command yourself in a terminal, not through an agent; --yes does not cover it."
			}
			ns := step(p, runtimeproto.StateNeedsLocalConfirmation, msg)
			ns.WaitingFor = &runtimeproto.WaitingFor{Kind: "local_administrator"}
			ns.NextCommand = o.cmd(opts, "--resume "+st.BatchID+" --confirm-roles")
			ns.Checks = previewChecks(lines)
			return ns
		}
		if err := o.Adapter.ApplyRoles(ctx, mapping, &st.Journal); err != nil {
			return step(p, runtimeproto.StateError, "Could not change NanoClaw roles: "+err.Error())
		}
		st.RolesApplied = true
		save("roles_applied")
	}

	// 8. Verifying, per agent, without side effects.
	o.Prompt.Progress("Checking each agent...")
	ns := step(p, runtimeproto.StateConnected, "")
	allOK := true
	for _, e := range mapping.Entries {
		agent := runtimeproto.AgentState{PlatformName: e.PlatformSubject, AgentID: e.AgentID, State: runtimeproto.StateConnected}
		agentID, err := o.Verifier.RuntimeStatus(ctx, e)
		if err == nil && agentID != e.AgentID {
			err = fmt.Errorf("endpoint speaks as %s", agentID)
		}
		if err == nil {
			err = o.Verifier.ControlMapPreview(ctx, e)
		}
		item := itemFor(st.Items, e.PlatformSubject)
		if err != nil {
			allOK = false
			agent.State = "failed"
			ns.Checks = append(ns.Checks, runtimeproto.Check{ID: "verify:" + e.PlatformSubject, Label: e.PlatformSubject, Status: runtimeproto.CheckRepairable, Actor: "you", Message: err.Error(), NextCommand: "contro1 doctor " + p})
			if item != nil && st.Results[item.ItemID] == "" {
				_ = o.API.ReportItem(ctx, st.BatchID, item.ItemID, "failed", "verify_failed")
				st.Results[item.ItemID] = "failed"
			}
		} else if item != nil && st.Results[item.ItemID] == "" {
			_ = o.API.ReportItem(ctx, st.BatchID, item.ItemID, "configured", "")
			st.Results[item.ItemID] = "configured"
		}
		ns.Agents = append(ns.Agents, agent)
	}
	save("verified")
	if !allOK {
		ns.State = runtimeproto.StateError
		ns.Message = "Some agents are connected but did not pass the check."
		ns.NextCommand = "contro1 doctor " + p
		return ns
	}
	/*
	 * CONNECTED IS NOT THE SAME AS GOVERNED, and saying so here is the point.
	 *
	 * A connection gives Contro1 a credential and an endpoint. On NanoClaw it
	 * takes two more things a person does by hand before a single approval
	 * arrives: the channel has to be loaded into the host, and Contro1 has to
	 * hold a role in the group. Skip either and everything reports success
	 * while nothing is governed, which is the most expensive kind of green.
	 *
	 * So the last word of a successful connect names what is still missing,
	 * rather than leaving somebody to discover it from the absence of
	 * approvals that were never going to come.
	 */
	remaining := o.Adapter.RemainingSetup()
	ns.Message = fmt.Sprintf("%s is connected (%d agent(s), Approvals only). %s", instanceLabel(p), len(mapping.Entries), o.Adapter.SafeTest())
	if len(remaining) > 0 {
		ns.Message = fmt.Sprintf("%s is connected (%d agent(s), Approvals only), but approvals will not reach Contro1 yet.", instanceLabel(p), len(mapping.Entries))
		for i, step := range remaining {
			ns.Checks = append(ns.Checks, runtimeproto.Check{
				ID:      fmt.Sprintf("remaining_%d", i+1),
				Label:   "Still to do",
				Status:  runtimeproto.CheckWaiting,
				Actor:   "you",
				Message: step,
			})
		}
		ns.NextCommand = "contro1 doctor " + p
	}
	return ns
}

// ---------------------------------------------------------------------------

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func previewChecks(lines []string) []runtimeproto.Check {
	out := make([]runtimeproto.Check, 0, len(lines))
	for i, l := range lines {
		out = append(out, runtimeproto.Check{ID: fmt.Sprintf("change_%d", i+1), Label: "Will change", Status: runtimeproto.CheckWaiting, Actor: "you", Message: l})
	}
	return out
}

func displayFor(subjects []platforms.Subject, id string) string {
	for _, s := range subjects {
		if s.ID == id {
			return s.Display
		}
	}
	return id
}

func itemFor(items []PreparedItem, subject string) *PreparedItem {
	for i := range items {
		if items[i].PlatformSubject == subject {
			return &items[i]
		}
	}
	return nil
}

func coversItems(m *runtimeproto.MappingFile, items []PreparedItem) bool {
	for _, it := range items {
		if _, ok := m.Lookup(it.PlatformSubject); !ok {
			return false
		}
	}
	return len(m.Entries) > 0
}

func instanceLabel(p string) string {
	switch p {
	case "openclaw":
		return "OpenClaw"
	case "nanoclaw":
		return "NanoClaw"
	case "claude-code":
		return "Claude Code"
	}
	return p
}

// hostGOOS is overridable in tests through HostOS.
func hostGOOS(opts Options) string {
	if opts.HostOS != "" {
		return opts.HostOS
	}
	return runtime.GOOS
}

// ExitCode maps a NextStep to the documented exit codes.
func ExitCode(ns runtimeproto.NextStep, noWait bool) int {
	switch ns.State {
	case runtimeproto.StateConnected:
		return 0
	case runtimeproto.StateWaitingForOwner, runtimeproto.StateConfiguring:
		if noWait {
			return 0
		}
		return 6
	case runtimeproto.StateNeedsLocalConfirmation:
		return 10
	case runtimeproto.StateBlocked:
		if ns.NextCommand == "contro1 auth login" {
			return 3
		}
		return 4
	default:
		return 1
	}
}

// platformNoun names what was discovered in the platform's own words, so a
// person reading the refusal recognises the things it is talking about.
func platformNoun(platform string, count int) string {
	switch platform {
	case "nanoclaw":
		if count == 1 {
			return "agent group"
		}
		return "agent groups"
	default:
		if count == 1 {
			return "agent"
		}
		return "agents"
	}
}
