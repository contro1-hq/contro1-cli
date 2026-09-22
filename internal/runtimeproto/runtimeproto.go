// Package runtimeproto mirrors packages/protocol/src/runtime (schema version 1):
// the NextStep and Remediation JSON, the platform mapping file, endpoint modes
// and the broker data allowlist. Change the TypeScript contract first, then here.
package runtimeproto

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

const SchemaVersion = 1

// Endpoint modes. User-visible labels come from ModeLabel.
const (
	ModeApprovalsOnly = "approval_bridge_only"
	ModeApplications  = "agent_runtime"
)

func ModeLabel(mode string) string {
	if mode == ModeApplications {
		return "Approvals + applications"
	}
	return "Approvals only"
}

func ValidMode(mode string) bool { return mode == ModeApprovalsOnly || mode == ModeApplications }

// OAuth wire constants.
const (
	ClientID              = "contro1-runtime"
	DeviceAuthorizePath   = "/api/centcom/v1/runtime/oauth/device_authorization"
	TokenPath             = "/api/centcom/v1/runtime/oauth/token"
	RevokePath            = "/api/centcom/v1/runtime/oauth/revoke"
	KeyRotationPath       = "/api/centcom/v1/runtime/oauth/key_rotation"
	PreparePath           = "/api/centcom/v1/runtime/connections/prepare"
	ConnectionsStatusPath = "/api/centcom/v1/runtime/connections/status"
	DeviceCodeGrant       = "urn:ietf:params:oauth:grant-type:device_code"
	RefreshGrant          = "refresh_token"
	ResourceAPI           = "api"
	ResourceMCP           = "mcp"
	LeasePrefix           = "ccr_live_"
	RefreshPrefix         = "ccrt_"
	DeviceCodePrefix      = "ccdc_"
	ConnectionTicketPfx   = "ccct_"
)

// Remediation is required on every identity, setup, scope, grant, connection,
// ownership or policy failure. Safe to repeat in chat.
type Remediation struct {
	Code          string `json:"code"`
	PublicMessage string `json:"public_message"`
	Missing       string `json:"missing"`
	Who           *Who   `json:"who"`
	NextStep      string `json:"next_step"`
	ActionURL     string `json:"action_url,omitempty"`
	Retryable     bool   `json:"retryable"`
}

type Who struct {
	DisplayName string `json:"display_name"`
	Role        string `json:"role"`
	OperatorID  string `json:"operator_id,omitempty"`
}

// NextStep states.
const (
	StateDiscovering            = "discovering"
	StateNeedsLocalConfirmation = "needs_local_confirmation"
	StateWaitingForOwner        = "waiting_for_owner"
	StateConfiguring            = "configuring"
	StateVerifying              = "verifying"
	StateConnected              = "connected"
	StateBlocked                = "blocked"
	StateError                  = "error"
)

// Check statuses.
const (
	CheckOK            = "ok"
	CheckRepairable    = "repairable"
	CheckBlocked       = "blocked"
	CheckWaiting       = "waiting"
	CheckNotApplicable = "not_applicable"
)

type Check struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Status      string `json:"status"`
	Actor       string `json:"actor,omitempty"`
	Message     string `json:"message"`
	NextCommand string `json:"next_command,omitempty"`
	ActionURL   string `json:"action_url,omitempty"`
}

type WaitingFor struct {
	Kind        string `json:"kind"`
	DisplayName string `json:"display_name,omitempty"`
	OperatorID  string `json:"operator_id,omitempty"`
}

type AgentState struct {
	PlatformName string `json:"platform_name"`
	AgentID      string `json:"agent_id,omitempty"`
	State        string `json:"state"`
}

type NextStep struct {
	SchemaVersion int          `json:"schema_version"`
	State         string       `json:"state"`
	Platform      string       `json:"platform"`
	Message       string       `json:"message"`
	WaitingFor    *WaitingFor  `json:"waiting_for,omitempty"`
	UserCode      string       `json:"user_code,omitempty"`
	ExpiresAt     string       `json:"expires_at,omitempty"`
	NextCommand   string       `json:"next_command,omitempty"`
	ShareThisLink string       `json:"share_this_link,omitempty"`
	Agents        []AgentState `json:"agents,omitempty"`
	Checks        []Check      `json:"checks,omitempty"`
	Remediation   *Remediation `json:"remediation,omitempty"`
}

// ---------------------------------------------------------------------------
// Platform mapping file
// ---------------------------------------------------------------------------

type MappingEntry struct {
	PlatformSubject string `json:"platform_subject"`
	DisplayName     string `json:"display_name,omitempty"`
	AgentID         string `json:"agent_id"`
	EnrollmentID    string `json:"enrollment_id"`
	EndpointMode    string `json:"endpoint_mode"`
	Endpoint        string `json:"endpoint"`
	// ServerPrincipal is the identity the Contro1 service runs as; clients
	// verify it before sending a request.
	ServerPrincipal string `json:"server_principal,omitempty"`
}

type MappingFile struct {
	SchemaVersion          int            `json:"schema_version"`
	Platform               string         `json:"platform"`
	PlatformInstanceDigest string         `json:"platform_instance_digest,omitempty"`
	GeneratedAt            string         `json:"generated_at"`
	Digest                 string         `json:"digest"`
	Entries                []MappingEntry `json:"entries"`
}

// MappingDigest is sha256 over the entries sorted by subject, as canonical JSON
// (Go struct field order is fixed, so json.Marshal is stable for this type).
func MappingDigest(entries []MappingEntry) string {
	sorted := append([]MappingEntry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].PlatformSubject < sorted[j].PlatformSubject })
	raw, _ := json.Marshal(sorted)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Lookup returns the entry for a subject. Unknown subjects fail closed: there is
// no default identity.
func (m *MappingFile) Lookup(subject string) (MappingEntry, bool) {
	for _, e := range m.Entries {
		if e.PlatformSubject == subject {
			return e, true
		}
	}
	return MappingEntry{}, false
}

// ---------------------------------------------------------------------------
// Broker data allowlist
// ---------------------------------------------------------------------------

type DataRoute struct {
	Method string
	Path   string
}

var approvalsOnlyRoutes = []DataRoute{
	{"GET", "/api/centcom/v1/runtime/status"},
	// Host-only DPoP claim after the accountable owner approved a NanoClaw MCP
	// card. The API rejects bearer leases and enforces one-time consumption.
	{"POST", "/api/centcom/v1/runtime/nanoclaw/mcp-lease"},
	{"POST", "/api/centcom/v1/runtime/nanoclaw/mcp-lease/release"},
	{"POST", "/api/centcom/v1/requests"},
	{"POST", "/api/centcom/v1/requests/control-map"},
	{"GET", "/api/centcom/v1/requests"},
	{"GET", "/api/centcom/v1/requests/:id"},
	{"DELETE", "/api/centcom/v1/requests/:id"},
	{"POST", "/api/centcom/v1/audit-records"},
	// An agent saying how exposed it is. On the approvals-only list because
	// the answer matters most for a connection that has not been widened yet,
	// and because the server only ever lets a declaration tighten things.
	{"POST", "/api/centcom/v1/runtime/reach"},
	{"POST", "/mcp"},
	{"GET", "/broker/v1/endpoint"},
}

var applicationRoutes = []DataRoute{
	{"POST", "/api/centcom/v1/actions/invoke"},
	{"GET", "/api/centcom/v1/actions/:invocation_id"},
	{"POST", "/api/centcom/v1/actions/:invocation_id/cancel"},
	{"GET", "/api/centcom/v1/skills/*"},
}

func DataAllowlist(mode string) []DataRoute {
	out := append([]DataRoute(nil), approvalsOnlyRoutes...)
	if mode == ModeApplications {
		out = append(out, applicationRoutes...)
	}
	return out
}

// StrippedHeaders are never forwarded from the local caller.
var StrippedHeaders = []string{"Authorization", "Cookie", "Dpop", "Host", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded"}

// RejectedQuery are identity selectors; a request carrying one is refused.
var RejectedQuery = []string{"agent_id", "profile", "enrollment", "enrollment_id"}

// AllowedRoute reports whether method+path is on the allowlist for mode.
// `:param` matches exactly one non-empty segment; a trailing `*` matches one or
// more segments. Paths with `..`, empty segments or encoded slashes never match.
func AllowedRoute(mode, method, path string) bool {
	if strings.Contains(path, "..") || strings.Contains(path, "//") || strings.Contains(strings.ToLower(path), "%2f") {
		return false
	}
	path = strings.TrimSuffix(path, "/")
	for _, r := range DataAllowlist(mode) {
		if r.Method == method && matchPattern(r.Path, path) {
			return true
		}
	}
	return false
}

func matchPattern(pattern, path string) bool {
	ps := strings.Split(strings.Trim(pattern, "/"), "/")
	xs := strings.Split(strings.Trim(path, "/"), "/")
	for i, p := range ps {
		if p == "*" {
			return i == len(ps)-1 && len(xs) > i && allNonEmpty(xs[i:])
		}
		if i >= len(xs) {
			return false
		}
		if strings.HasPrefix(p, ":") {
			if xs[i] == "" {
				return false
			}
			continue
		}
		if p != xs[i] {
			return false
		}
	}
	return len(xs) == len(ps)
}

func allNonEmpty(parts []string) bool {
	for _, p := range parts {
		if p == "" {
			return false
		}
	}
	return true
}

// EndpointInfo is GET /broker/v1/endpoint on a data endpoint.
type EndpointInfo struct {
	AgentID         string `json:"agent_id"`
	EnrollmentID    string `json:"enrollment_id"`
	EndpointMode    string `json:"endpoint_mode"`
	ModeLabel       string `json:"mode_label"`
	PlatformSubject string `json:"platform_subject"`
	State           string `json:"state"`
}

// ---------------------------------------------------------------------------
// Agent reach: who can instruct an agent
// ---------------------------------------------------------------------------

// An agent more than one person can instruct, holding standing authority over
// one person's data, is a confused deputy: it acts with ITS authority and so
// cannot tell its owner from a stranger who arrived through the same surface.
//
// Contro1 never infers this from a platform's architecture. Each adapter
// REPORTS its reach, and whatever it cannot state is ReachUnknown, which is
// treated exactly like ReachShared. Silence is never read as privacy.
const (
	ReachPrivate = "private"
	ReachShared  = "shared"
	ReachUnknown = "unknown"
)

const (
	PostureSoleOperator  = "sole_operator"
	PostureSharedSurface = "shared_surface"
)

// ReachContext is one surface an agent answers on: a conversation, a host, a
// gateway.
type ReachContext struct {
	// ContextID is stable, opaque and scoped to the platform. It is the binding
	// key for origin-conditioned grants, so it must be the platform's own
	// internal id.
	//
	// NEVER a phone number, email address or handle: this crosses into Contro1
	// and is stored. NanoClaw sends its mg-... id, never the WhatsApp JID.
	ContextID string `json:"context_id"`
	// Label is display only, for the approval screen.
	Label string `json:"label,omitempty"`
	Kind  string `json:"kind"`
	// ParticipantsKnown is true only when the platform restricts this surface to
	// an enumerated set of people.
	ParticipantsKnown bool `json:"participants_known"`
	// ParticipantCount is set only when the platform actually counts them.
	// Display only, never a gate.
	ParticipantCount int `json:"participant_count,omitempty"`
}

type AgentReach struct {
	SchemaVersion int    `json:"schema_version"`
	Platform      string `json:"platform"`
	ObservedAt    string `json:"observed_at"`
	// Complete is false when the adapter could not enumerate every surface. A
	// partial list can only understate exposure, so it is treated as unknown.
	Complete bool           `json:"complete"`
	Contexts []ReachContext `json:"contexts"`
}

// PostureForReach fails closed at every branch. No reach, an incomplete list,
// one shared surface, or one surface open to unnamed people, and the whole
// agent is PostureSharedSurface. An agent earns PostureSoleOperator only when
// every surface it answers on is private AND limited to known people.
func PostureForReach(reach *AgentReach) string {
	if reach == nil || !reach.Complete || len(reach.Contexts) == 0 {
		return PostureSharedSurface
	}
	for _, context := range reach.Contexts {
		if context.Kind != ReachPrivate || !context.ParticipantsKnown {
			return PostureSharedSurface
		}
	}
	return PostureSoleOperator
}
