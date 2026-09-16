package broker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/contro1-hq/contro1-cli/internal/brokerstore"
	"github.com/contro1-hq/contro1-cli/internal/dpop"
	"github.com/contro1-hq/contro1-cli/internal/runtimeproto"
	"github.com/contro1-hq/contro1-cli/internal/tokenprovider"
)

// ControlConnectionsRequest mirrors packages/protocol ControlConnectionsRequest.
type ControlConnectionsRequest struct {
	APIURL           string            `json:"api_url"`
	BatchID          string            `json:"batch_id"`
	ConnectionTicket string            `json:"connection_ticket"`
	HostFacts        map[string]string `json:"host_facts,omitempty"`
	Items            []ControlItem     `json:"items"`
	// PrincipalUpdates, when set, is the whole request: change who may reach
	// existing endpoints. No ticket, no new connection.
	PrincipalUpdates []ControlPrincipalUpdate `json:"principal_updates,omitempty"`
}

// ControlPrincipalUpdate replaces the identities allowed on one agent's endpoint.
type ControlPrincipalUpdate struct {
	Platform          string   `json:"platform"`
	PlatformSubject   string   `json:"platform_subject"`
	AllowedPrincipals []string `json:"allowed_principals"`
}

type ControlItem struct {
	ItemID                 string   `json:"item_id"`
	AgentID                string   `json:"agent_id"`
	EnrollmentID           string   `json:"enrollment_id"`
	Platform               string   `json:"platform"`
	PlatformInstanceDigest string   `json:"platform_instance_digest,omitempty"`
	PlatformSubject        string   `json:"platform_subject"`
	DisplayName            string   `json:"display_name,omitempty"`
	EndpointMode           string   `json:"endpoint_mode"`
	AllowedPrincipals      []string `json:"allowed_principals"`
}

type ControlItemResult struct {
	ItemID   string `json:"item_id"`
	LocalID  string `json:"local_id,omitempty"`
	JKT      string `json:"jkt,omitempty"`
	State    string `json:"state"`
	UserCode string `json:"user_code,omitempty"`
	Error    string `json:"error,omitempty"`
}

type ControlEnrollment struct {
	LocalID         string `json:"local_id"`
	EnrollmentID    string `json:"enrollment_id"`
	AgentID         string `json:"agent_id"`
	Platform        string `json:"platform"`
	PlatformSubject string `json:"platform_subject"`
	EndpointMode    string `json:"endpoint_mode"`
	ModeLabel       string `json:"mode_label"`
	Endpoint        string `json:"endpoint"`
	State           string `json:"state"`
	BatchID         string `json:"batch_id,omitempty"`
	ApprovalExpires string `json:"approval_expires_at,omitempty"`
	LastErrorCode   string `json:"last_error_code,omitempty"`
	KeyThumbprint   string `json:"key_thumbprint,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeRemediation(w http.ResponseWriter, status int, r runtimeproto.Remediation) {
	writeJSON(w, status, map[string]any{"ok": false, "error": map[string]any{"code": r.Code, "message": r.PublicMessage, "retryable": r.Retryable, "remediation": r}})
}

func (b *Broker) controlHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /control/v1/health", b.handleHealth)
	mux.HandleFunc("POST /control/v1/connections", b.handleConnections)
	mux.HandleFunc("GET /control/v1/enrollments", b.handleEnrollments)
	mux.HandleFunc("POST /control/v1/enrollments/{local_id}/verify", b.handleVerify)
	mux.HandleFunc("POST /control/v1/enrollments/{local_id}/revoke", b.handleRevoke)
	mux.HandleFunc("POST /control/v1/enrollments/{local_id}/rotate-key", b.handleRotateKey)
	mux.HandleFunc("POST /control/v1/mappings", b.handleMappings)
	mux.HandleFunc("POST /control/v1/principals", b.handlePrincipals)
	mux.HandleFunc("POST /control/v1/shutdown", b.handleShutdown)
	return http.MaxBytesHandler(mux, 256<<10)
}

func (b *Broker) handleHealth(w http.ResponseWriter, _ *http.Request) {
	st, _ := b.store.LoadState()
	n := 0
	if st != nil {
		n = len(st.Enrollments)
	}
	writeJSON(w, 200, map[string]any{
		"version": b.cfg.Version, "pid": os.Getpid(), "started_at": b.startedAt.UTC().Format(time.RFC3339),
		"key_protection": b.cfg.Keys.Protection(), "enrollments": n, "foreground": b.cfg.Foreground,
		"api_url": b.cfg.APIURL, "dev_current_user_control": b.cfg.DevAllowCurrentUserControl,
	})
}

func (b *Broker) handleConnections(w http.ResponseWriter, r *http.Request) {
	var req ControlConnectionsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid_request"})
		return
	}
	if !strings.HasPrefix(req.ConnectionTicket, runtimeproto.ConnectionTicketPfx) || len(req.Items) == 0 {
		writeJSON(w, 400, map[string]any{"error": "invalid_request", "message": "connection_ticket and items are required"})
		return
	}
	if req.APIURL != "" && b.cfg.APIURL != "" && strings.TrimRight(req.APIURL, "/") != strings.TrimRight(b.cfg.APIURL, "/") {
		writeJSON(w, 409, map[string]any{"error": "api_url_mismatch", "message": "this Contro1 service is connected to " + b.cfg.APIURL})
		return
	}
	if b.cfg.APIURL == "" {
		b.cfg.APIURL = strings.TrimRight(req.APIURL, "/")
		b.provider.APIURL = b.cfg.APIURL
		_, _ = b.store.UpdateState(func(st *brokerstore.State) error { st.APIURL = b.cfg.APIURL; return nil })
	}
	results := make([]ControlItemResult, 0, len(req.Items))
	for _, item := range req.Items {
		results = append(results, b.registerItem(r.Context(), req, item))
	}
	writeJSON(w, 200, map[string]any{"items": results})
}

func (b *Broker) registerItem(ctx context.Context, req ControlConnectionsRequest, item ControlItem) ControlItemResult {
	fail := func(msg string) ControlItemResult {
		return ControlItemResult{ItemID: item.ItemID, State: "failed", Error: msg}
	}
	if !runtimeproto.ValidMode(item.EndpointMode) || item.PlatformSubject == "" || len(item.AllowedPrincipals) == 0 {
		return fail("item needs endpoint_mode, platform_subject and allowed_principals")
	}
	localID := randomID("loc_")
	keyRef := randomID("k_")
	signer, err := b.cfg.Keys.Create(keyRef)
	if err != nil {
		return fail("could not create a key: " + err.Error())
	}
	jkt, _ := dpop.KeyThumbprint(signer.Public())
	auth, err := b.provider.RegisterItem(ctx, signer, req.ConnectionTicket, item.ItemID)
	if err != nil {
		_ = b.cfg.Keys.Delete(keyRef)
		return fail(err.Error())
	}
	if err := b.store.SaveSecrets(localID, brokerstore.Secrets{DeviceCode: auth.DeviceCode}); err != nil {
		_ = b.cfg.Keys.Delete(keyRef)
		return fail("could not store the approval code: " + err.Error())
	}
	now := time.Now().UTC()
	_, err = b.store.UpdateState(func(st *brokerstore.State) error {
		st.Enrollments = append(st.Enrollments, brokerstore.Enrollment{
			LocalID: localID, EnrollmentID: firstNonEmpty(auth.EnrollmentID, item.EnrollmentID), AgentID: item.AgentID,
			BatchID: firstNonEmpty(auth.BatchID, req.BatchID), ItemID: item.ItemID, Platform: item.Platform,
			PlatformInstanceDigest: item.PlatformInstanceDigest, PlatformSubject: item.PlatformSubject, DisplayName: item.DisplayName,
			EndpointMode: item.EndpointMode, Endpoint: b.DataEndpointFor(localID).String(), AllowedPrincipals: item.AllowedPrincipals,
			KeyRef: keyRef, KeyThumbprint: jkt, State: "pending", PollIntervalS: auth.Interval,
			DeviceExpiresAt: now.Add(time.Duration(auth.ExpiresIn) * time.Second).Format(time.RFC3339),
			CreatedAt:       now.Format(time.RFC3339),
		})
		return nil
	})
	if err != nil {
		return fail(err.Error())
	}
	return ControlItemResult{ItemID: item.ItemID, LocalID: localID, JKT: jkt, State: "awaiting_approval", UserCode: auth.UserCode}
}

func (b *Broker) handleEnrollments(w http.ResponseWriter, _ *http.Request) {
	st, err := b.store.LoadState()
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	out := make([]ControlEnrollment, 0, len(st.Enrollments))
	for _, en := range st.Enrollments {
		out = append(out, ControlEnrollment{
			LocalID: en.LocalID, EnrollmentID: en.EnrollmentID, AgentID: en.AgentID, Platform: en.Platform,
			PlatformSubject: en.PlatformSubject, EndpointMode: en.EndpointMode, ModeLabel: runtimeproto.ModeLabel(en.EndpointMode),
			Endpoint: en.Endpoint, State: en.State, BatchID: en.BatchID, ApprovalExpires: en.ApprovalExpires,
			LastErrorCode: en.LastErrorCode, KeyThumbprint: en.KeyThumbprint,
		})
	}
	writeJSON(w, 200, map[string]any{"enrollments": out})
}

func (b *Broker) handleVerify(w http.ResponseWriter, r *http.Request) {
	localID := r.PathValue("local_id")
	en, err := b.enrollment(localID)
	if err != nil {
		writeJSON(w, 404, map[string]any{"error": "not_found"})
		return
	}
	req, _ := http.NewRequestWithContext(r.Context(), "GET", b.cfg.APIURL+"/api/centcom/v1/runtime/status", nil)
	if err := b.provider.Authorize(r.Context(), req, localID, runtimeproto.ResourceAPI); err != nil {
		b.writeTokenError(w, err)
		return
	}
	resp, err := b.provider.HTTP.Do(req)
	if err != nil {
		writeRemediation(w, 502, runtimeproto.Remediation{Code: "RUNTIME_IDENTITY_UNAVAILABLE", PublicMessage: "Contro1 could not be reached.", NextStep: "Check the network and run contro1 doctor.", Retryable: true})
		return
	}
	defer resp.Body.Close()
	b.provider.ObserveNonce(resp.Header)
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var parsed map[string]any
	_ = json.Unmarshal(body, &parsed)
	auth, _ := parsed["auth"].(map[string]any)
	ok := resp.StatusCode == 200 && auth != nil && auth["agent_id"] == en.AgentID && auth["credential_kind"] == "agent_runtime"
	writeJSON(w, 200, map[string]any{"ok": ok, "status": resp.StatusCode, "agent_id": en.AgentID, "mode_label": runtimeproto.ModeLabel(en.EndpointMode), "server": parsed})
}

func (b *Broker) handleRevoke(w http.ResponseWriter, r *http.Request) {
	localID := r.PathValue("local_id")
	en, err := b.enrollment(localID)
	if err != nil {
		writeJSON(w, 404, map[string]any{"error": "not_found"})
		return
	}
	var body struct {
		Remote bool `json:"remote"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	remoteErr := ""
	if body.Remote {
		if err := b.provider.RevokeRemote(r.Context(), localID); err != nil {
			remoteErr = err.Error()
		}
	}
	b.stopData(localID)
	_ = b.store.DeleteSecrets(localID)
	_ = b.store.ClearJournal(localID)
	_ = b.cfg.Keys.Delete(en.KeyRef)
	b.markLocal(localID, "revoked", "revoked_locally")
	_, _, _ = b.writeMapping(en.Platform, "")
	b.writeStatus()
	writeJSON(w, 200, map[string]any{"local_id": localID, "state": "revoked", "remote_revoked": body.Remote && remoteErr == "", "remote_error": remoteErr})
}

func (b *Broker) handleRotateKey(w http.ResponseWriter, r *http.Request) {
	localID := r.PathValue("local_id")
	en, err := b.enrollment(localID)
	if err != nil || en.State != "active" {
		writeJSON(w, 404, map[string]any{"error": "not_found_or_not_active"})
		return
	}
	newRef := randomID("k_")
	newKey, err := b.cfg.Keys.Create(newRef)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": "key_create_failed"})
		return
	}
	rotationURL := b.cfg.APIURL + runtimeproto.KeyRotationPath
	newProof, err := dpop.NewKeyRotationProof(newKey, rotationURL, en.KeyThumbprint, time.Now())
	if err != nil {
		_ = b.cfg.Keys.Delete(newRef)
		writeJSON(w, 500, map[string]any{"error": "proof_failed"})
		return
	}
	req, _ := http.NewRequestWithContext(r.Context(), "POST", rotationURL, strings.NewReader(`{"new_key_proof":"`+newProof+`"}`))
	req.Header.Set("Content-Type", "application/json")
	if err := b.provider.Authorize(r.Context(), req, localID, runtimeproto.ResourceAPI); err != nil {
		_ = b.cfg.Keys.Delete(newRef)
		b.writeTokenError(w, err)
		return
	}
	resp, err := b.provider.HTTP.Do(req)
	if err != nil || resp.StatusCode != 200 {
		_ = b.cfg.Keys.Delete(newRef)
		status := 502
		if resp != nil {
			status = resp.StatusCode
			resp.Body.Close()
		}
		writeJSON(w, status, map[string]any{"error": "key_rotation_refused"})
		return
	}
	resp.Body.Close()
	newJKT, _ := dpop.KeyThumbprint(newKey.Public())
	oldRef, oldJKT := en.KeyRef, en.KeyThumbprint
	_, _ = b.store.UpdateState(func(st *brokerstore.State) error {
		for i := range st.Enrollments {
			if st.Enrollments[i].LocalID == localID {
				st.Enrollments[i].KeyRef, st.Enrollments[i].KeyThumbprint = newRef, newJKT
			}
		}
		return nil
	})
	b.provider.Invalidate(localID, runtimeproto.ResourceAPI)
	b.provider.Invalidate(localID, runtimeproto.ResourceMCP)
	if _, err := b.provider.AccessToken(r.Context(), localID, runtimeproto.ResourceAPI); err != nil {
		// The new key is still pending server-side; keep using the old one.
		_, _ = b.store.UpdateState(func(st *brokerstore.State) error {
			for i := range st.Enrollments {
				if st.Enrollments[i].LocalID == localID {
					st.Enrollments[i].KeyRef, st.Enrollments[i].KeyThumbprint = oldRef, oldJKT
				}
			}
			return nil
		})
		writeJSON(w, 502, map[string]any{"error": "rotation_not_completed", "message": err.Error()})
		return
	}
	_ = b.cfg.Keys.Delete(oldRef)
	writeJSON(w, 200, map[string]any{"local_id": localID, "key_thumbprint": newJKT})
}

// handlePrincipals changes who may reach existing endpoints and restarts them.
// Control is administrators only, so this is an administrator decision; it is
// how a connection made from the wrong account is repaired without reconnecting.
func (b *Broker) handlePrincipals(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Updates []ControlPrincipalUpdate `json:"updates"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil || len(body.Updates) == 0 {
		writeJSON(w, 400, map[string]any{"error": "invalid_request"})
		return
	}
	for _, u := range body.Updates {
		if !validPlatformName(u.Platform) || u.PlatformSubject == "" || len(u.AllowedPrincipals) != 1 || u.AllowedPrincipals[0] == "" {
			writeJSON(w, 400, map[string]any{"error": "each update needs platform, platform_subject and exactly one allowed principal"})
			return
		}
	}
	var changed []string
	_, err := b.store.UpdateState(func(st *brokerstore.State) error {
		for _, u := range body.Updates {
			for i := range st.Enrollments {
				en := &st.Enrollments[i]
				if en.Platform != u.Platform || en.PlatformSubject != u.PlatformSubject {
					continue
				}
				if en.State != "active" && en.State != "pending" {
					continue
				}
				en.AllowedPrincipals = append([]string(nil), u.AllowedPrincipals...)
				changed = append(changed, en.LocalID)
			}
		}
		return nil
	})
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": "state_update_failed"})
		return
	}
	var failures []string
	for _, localID := range changed {
		en, err := b.enrollment(localID)
		if err != nil {
			continue
		}
		b.stopData(localID)
		if en.State == "active" {
			if err := b.startData(*en); err != nil {
				failures = append(failures, localID+": "+err.Error())
			}
		}
	}
	b.writeStatus()
	if len(failures) > 0 {
		writeJSON(w, 500, map[string]any{"updated": len(changed), "error": strings.Join(failures, "; ")})
		return
	}
	writeJSON(w, 200, map[string]any{"updated": len(changed)})
}

func (b *Broker) handleMappings(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Platform               string `json:"platform"`
		PlatformInstanceDigest string `json:"platform_instance_digest"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || !validPlatformName(body.Platform) {
		writeJSON(w, 400, map[string]any{"error": "invalid_request"})
		return
	}
	path, file, err := b.writeMapping(body.Platform, body.PlatformInstanceDigest)
	if err != nil {
		status := 500
		if errors.Is(err, errConflictingMapping) {
			status = 409
		}
		writeJSON(w, status, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"path": path, "digest": file.Digest, "mapping": file})
}

var errConflictingMapping = errors.New("conflicting_mapping: a platform agent has more than one connection; revoke the extra one first")

func validPlatformName(p string) bool {
	return p != "" && len(p) <= 40 && !strings.ContainsAny(p, `/\.: `)
}

// writeMapping regenerates the mapping file for a platform from active and
// pending connections. It is called after every activation and revocation,
// so the file on disk always matches what the service will actually serve.
func (b *Broker) writeMapping(platform, instanceDigest string) (string, runtimeproto.MappingFile, error) {
	file := runtimeproto.MappingFile{SchemaVersion: runtimeproto.SchemaVersion, Platform: platform, PlatformInstanceDigest: instanceDigest, GeneratedAt: time.Now().UTC().Format(time.RFC3339)}
	st, err := b.store.LoadState()
	if err != nil {
		return "", file, err
	}
	seen := map[string]bool{}
	for _, en := range st.Enrollments {
		if en.Platform != platform || en.State != "active" {
			continue
		}
		if instanceDigest != "" && en.PlatformInstanceDigest != instanceDigest {
			continue
		}
		if seen[en.PlatformSubject] {
			return "", file, errConflictingMapping
		}
		seen[en.PlatformSubject] = true
		if file.PlatformInstanceDigest == "" {
			file.PlatformInstanceDigest = en.PlatformInstanceDigest
		}
		file.Entries = append(file.Entries, runtimeproto.MappingEntry{PlatformSubject: en.PlatformSubject, DisplayName: en.DisplayName, AgentID: en.AgentID, EnrollmentID: en.EnrollmentID, EndpointMode: en.EndpointMode, Endpoint: en.Endpoint, ServerPrincipal: b.cfg.ServicePrincipal})
	}
	file.Digest = runtimeproto.MappingDigest(file.Entries)
	raw, _ := json.MarshalIndent(file, "", "  ")
	path := b.store.MappingPath(platform)
	if b.cfg.PlatformsDir != "" {
		if err := os.MkdirAll(b.cfg.PlatformsDir, 0o755); err == nil {
			path = filepath.Join(b.cfg.PlatformsDir, platform+".json")
		}
	}
	return path, file, brokerstore.WriteFileAtomic(path, append(raw, '\n'), 0o644)
}

func (b *Broker) handleShutdown(w http.ResponseWriter, _ *http.Request) {
	if !b.cfg.Foreground {
		writeJSON(w, 403, map[string]any{"error": "service_shutdown_uses_the_service_manager"})
		return
	}
	writeJSON(w, 200, map[string]any{"stopping": true})
	go func() {
		time.Sleep(50 * time.Millisecond)
		if b.stop != nil {
			b.stop()
		}
	}()
}

func (b *Broker) writeTokenError(w http.ResponseWriter, err error) {
	var te *tokenprovider.Error
	if errors.As(err, &te) {
		if te.Remediation != nil {
			writeRemediation(w, 401, *te.Remediation)
			return
		}
		writeRemediation(w, 401, runtimeproto.Remediation{Code: "CONNECTION_NOT_ACTIVE", PublicMessage: "This connection cannot be used right now (" + te.Kind + ").", Missing: "A working connection for this agent.", NextStep: "Run contro1 doctor, then contro1 connect --repair if needed.", Retryable: !te.Terminal()})
		return
	}
	writeRemediation(w, 502, runtimeproto.Remediation{Code: "RUNTIME_IDENTITY_UNAVAILABLE", PublicMessage: "The Contro1 service could not get a credential.", NextStep: "Run contro1 doctor.", Retryable: true})
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
