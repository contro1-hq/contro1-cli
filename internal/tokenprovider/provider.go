// Package tokenprovider is the broker's RuntimeTokenProvider: DPoP access
// tokens per connection and resource, refreshed at most once at a time.
//
// Rules it never breaks:
//   - One refresh per connection at a time (single flight). Two hundred callers
//     waiting on an expired token cause one refresh.
//   - The rotated refresh token is persisted BEFORE any waiter is released. A
//     crash after the server rotated but before persistence is recovered on the
//     next start from the journal, using the server's short allowance for the
//     previous token.
//   - Terminal failures (revoked, reuse, expired approval) are reported with a
//     remediation and never fall back to anything else, least of all a human
//     login.
package tokenprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/contro1-hq/contro1-cli/internal/brokerstore"
	"github.com/contro1-hq/contro1-cli/internal/dpop"
	"github.com/contro1-hq/contro1-cli/internal/keystore"
	"github.com/contro1-hq/contro1-cli/internal/runtimeproto"
)

const refreshMargin = 60 * time.Second

// Error is a token failure with its OAuth code and, when the server can name
// what is missing, a remediation.
type Error struct {
	Kind        string // revoked | reuse_suspended | approval_expired | declined | expired | pending | slow_down | network | server | not_connected
	OAuthError  string
	Reason      string
	Remediation *runtimeproto.Remediation
	Interval    int
	cause       error
}

func (e *Error) Error() string {
	msg := "runtime token: " + e.Kind
	if e.OAuthError != "" {
		msg += " (" + e.OAuthError + ")"
	}
	if e.Reason != "" {
		msg += ": " + e.Reason
	}
	if e.cause != nil {
		msg += ": " + e.cause.Error()
	}
	return msg
}

func (e *Error) Unwrap() error { return e.cause }

// Terminal errors need a person; retrying will not help.
func (e *Error) Terminal() bool {
	switch e.Kind {
	case "revoked", "reuse_suspended", "approval_expired", "declined", "expired", "not_connected":
		return true
	}
	return false
}

func IsTerminal(err error) bool {
	var te *Error
	return errors.As(err, &te) && te.Terminal()
}

type cached struct {
	token   string
	expires time.Time
}

type entry struct {
	mu    sync.Mutex
	cache map[string]cached
}

// Provider holds no secrets in memory longer than a refresh.
type Provider struct {
	Store  *brokerstore.Store
	Keys   keystore.Store
	HTTP   *http.Client
	APIURL string
	Now    func() time.Time

	mu       sync.Mutex
	entries  map[string]*entry
	signers  map[string]keystore.Signer
	nonceMu  sync.Mutex
	nonce    string
	refreshN atomic.Int64
}

func New(store *brokerstore.Store, keys keystore.Store, hc *http.Client, apiURL string) *Provider {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &Provider{Store: store, Keys: keys, HTTP: hc, APIURL: strings.TrimRight(apiURL, "/"), Now: time.Now}
}

// RefreshCount is how many refresh round trips have been made (tests, doctor).
func (p *Provider) RefreshCount() int64 { return p.refreshN.Load() }

func (p *Provider) entryFor(localID string) *entry {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.entries == nil {
		p.entries = map[string]*entry{}
	}
	e := p.entries[localID]
	if e == nil {
		e = &entry{cache: map[string]cached{}}
		p.entries[localID] = e
	}
	return e
}

// Signer opens (and caches) the key for a key reference.
func (p *Provider) Signer(keyRef string) (keystore.Signer, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.signers == nil {
		p.signers = map[string]keystore.Signer{}
	}
	if s := p.signers[keyRef]; s != nil {
		return s, nil
	}
	s, err := p.Keys.Open(keyRef)
	if err != nil {
		return nil, err
	}
	p.signers[keyRef] = s
	return s, nil
}

func (p *Provider) enrollment(localID string) (*brokerstore.Enrollment, error) {
	st, err := p.Store.LoadState()
	if err != nil {
		return nil, err
	}
	for i := range st.Enrollments {
		if st.Enrollments[i].LocalID == localID {
			return &st.Enrollments[i], nil
		}
	}
	return nil, &Error{Kind: "not_connected", Reason: "no such connection on this computer"}
}

// Invalidate drops a cached token after the server refused it.
func (p *Provider) Invalidate(localID, resource string) {
	e := p.entryFor(localID)
	e.mu.Lock()
	delete(e.cache, resource)
	e.mu.Unlock()
}

// AccessToken returns a valid token for (connection, resource).
func (p *Provider) AccessToken(ctx context.Context, localID, resource string) (string, error) {
	e := p.entryFor(localID)
	e.mu.Lock()
	defer e.mu.Unlock()
	if c, ok := e.cache[resource]; ok && p.Now().Add(refreshMargin).Before(c.expires) {
		return c.token, nil
	}
	enr, err := p.enrollment(localID)
	if err != nil {
		return "", err
	}
	if enr.State != "active" {
		return "", &Error{Kind: "not_connected", Reason: "connection is " + enr.State}
	}
	signer, err := p.Signer(enr.KeyRef)
	if err != nil {
		return "", fmt.Errorf("runtime token: open key: %w", err)
	}
	sec, err := p.Store.LoadSecrets(localID)
	if err != nil {
		return "", err
	}
	if sec.RefreshToken == "" {
		return "", &Error{Kind: "not_connected", Reason: "no refresh credential; connect this computer again"}
	}
	sum := sha256.Sum256([]byte(sec.RefreshToken))
	if err := p.Store.WriteJournal(brokerstore.Journal{LocalID: localID, StartedAt: p.Now().UTC().Format(time.RFC3339), PresentedHashPrefix: hex.EncodeToString(sum[:4])}); err != nil {
		return "", err
	}
	p.refreshN.Add(1)
	resp, err := p.tokenRequest(ctx, signer, url.Values{
		"grant_type":    {runtimeproto.RefreshGrant},
		"refresh_token": {sec.RefreshToken},
		"client_id":     {runtimeproto.ClientID},
		"resource":      {resource},
	})
	if err != nil {
		var te *Error
		if errors.As(err, &te) && te.Terminal() {
			// The family is gone server-side; the journal no longer matters.
			_ = p.Store.ClearJournal(localID)
			p.markState(localID, stateForKind(te.Kind), te.Kind)
		}
		return "", err
	}
	if resp.RefreshToken != "" {
		sec.RefreshToken = resp.RefreshToken
		// Durable before anyone sees the new access token.
		if err := p.Store.SaveSecrets(localID, sec); err != nil {
			return "", fmt.Errorf("runtime token: persist rotated refresh token: %w", err)
		}
	}
	_ = p.Store.ClearJournal(localID)
	e.cache[resource] = cached{token: resp.AccessToken, expires: p.Now().Add(time.Duration(resp.ExpiresIn) * time.Second)}
	return resp.AccessToken, nil
}

func stateForKind(kind string) string {
	switch kind {
	case "reuse_suspended":
		return "suspended"
	case "approval_expired", "expired":
		return "expired"
	case "declined":
		return "declined"
	default:
		return "revoked"
	}
}

func (p *Provider) markState(localID, state, code string) {
	_, _ = p.Store.UpdateState(func(st *brokerstore.State) error {
		for i := range st.Enrollments {
			if st.Enrollments[i].LocalID == localID {
				st.Enrollments[i].State = state
				st.Enrollments[i].LastErrorCode = code
			}
		}
		return nil
	})
}

// Authorize sets the DPoP Authorization and proof headers on req.
func (p *Provider) Authorize(ctx context.Context, req *http.Request, localID, resource string) error {
	token, err := p.AccessToken(ctx, localID, resource)
	if err != nil {
		return err
	}
	enr, err := p.enrollment(localID)
	if err != nil {
		return err
	}
	signer, err := p.Signer(enr.KeyRef)
	if err != nil {
		return err
	}
	proof, err := dpop.NewProof(signer, dpop.ProofInput{Method: req.Method, URL: req.URL.String(), AccessToken: token, Nonce: p.currentNonce(), Now: p.Now()})
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "DPoP "+token)
	req.Header.Set("DPoP", proof)
	return nil
}

func (p *Provider) currentNonce() string {
	p.nonceMu.Lock()
	defer p.nonceMu.Unlock()
	return p.nonce
}

// ObserveNonce records a DPoP-Nonce header from any response.
func (p *Provider) ObserveNonce(h http.Header) {
	if n := h.Get("DPoP-Nonce"); n != "" {
		p.nonceMu.Lock()
		p.nonce = n
		p.nonceMu.Unlock()
	}
}

// TokenResponse mirrors the server's token endpoint body.
type TokenResponse struct {
	AccessToken       string `json:"access_token"`
	TokenType         string `json:"token_type"`
	ExpiresIn         int    `json:"expires_in"`
	RefreshToken      string `json:"refresh_token"`
	Scope             string `json:"scope"`
	EnrollmentID      string `json:"enrollment_id"`
	AgentID           string `json:"agent_id"`
	ApprovalExpiresAt string `json:"approval_expires_at"`
}

type oauthErrorBody struct {
	Error       string                    `json:"error"`
	Description string                    `json:"error_description"`
	Reason      string                    `json:"contro1_reason"`
	Remediation *runtimeproto.Remediation `json:"remediation"`
	Interval    int                       `json:"interval"`
}

// tokenRequest posts to the token endpoint with a fresh proof, retrying once
// when the server asks for a nonce.
func (p *Provider) tokenRequest(ctx context.Context, signer dpop.Signer, form url.Values) (*TokenResponse, error) {
	endpoint := p.APIURL + runtimeproto.TokenPath
	for attempt := 0; attempt < 2; attempt++ {
		proof, err := dpop.NewProof(signer, dpop.ProofInput{Method: "POST", URL: endpoint, Nonce: p.currentNonce(), Now: p.Now()})
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("DPoP", proof)
		resp, err := p.HTTP.Do(req)
		if err != nil {
			return nil, &Error{Kind: "network", cause: err}
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		p.ObserveNonce(resp.Header)
		if resp.StatusCode == http.StatusOK {
			var out TokenResponse
			if err := json.Unmarshal(body, &out); err != nil || out.AccessToken == "" {
				return nil, &Error{Kind: "server", Reason: "malformed token response"}
			}
			return &out, nil
		}
		var oe oauthErrorBody
		_ = json.Unmarshal(body, &oe)
		if oe.Error == "use_dpop_nonce" && attempt == 0 {
			continue
		}
		return nil, classify(resp.StatusCode, oe)
	}
	return nil, &Error{Kind: "server", Reason: "nonce retry failed"}
}

func classify(status int, oe oauthErrorBody) *Error {
	e := &Error{OAuthError: oe.Error, Reason: oe.Reason, Remediation: oe.Remediation, Interval: oe.Interval}
	switch {
	case oe.Error == "authorization_pending":
		e.Kind = "pending"
	case oe.Error == "slow_down":
		e.Kind = "slow_down"
	case oe.Error == "access_denied":
		e.Kind = "declined"
	case oe.Error == "expired_token":
		e.Kind = "expired"
	case oe.Reason == "refresh_reuse" || oe.Reason == "refresh_key_mismatch":
		e.Kind = "reuse_suspended"
	case oe.Reason == "approval_expired" || oe.Reason == "refresh_expired":
		e.Kind = "approval_expired"
	case oe.Error == "invalid_grant":
		e.Kind = "revoked"
	case status >= 500 || status == 429:
		e.Kind = "server"
	default:
		e.Kind = "server"
		if e.Reason == "" {
			e.Reason = oe.Description
		}
	}
	return e
}

// ---------------------------------------------------------------------------
// Enrollment: register a key, then poll until the owner decides.
// ---------------------------------------------------------------------------

type DeviceAuthorization struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
	BatchID                 string `json:"batch_id"`
	EnrollmentID            string `json:"enrollment_id"`
	ItemID                  string `json:"item_id"`
	Sealed                  bool   `json:"sealed"`
}

// RegisterItem sends one item's public key, proven by a DPoP proof, with the
// single-use connection ticket.
func (p *Provider) RegisterItem(ctx context.Context, signer dpop.Signer, ticket, itemID string) (*DeviceAuthorization, error) {
	endpoint := p.APIURL + runtimeproto.DeviceAuthorizePath
	proof, err := dpop.NewProof(signer, dpop.ProofInput{Method: "POST", URL: endpoint, Now: p.Now()})
	if err != nil {
		return nil, err
	}
	form := url.Values{"connection_ticket": {ticket}, "item_id": {itemID}, "client_id": {runtimeproto.ClientID}}
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", proof)
	resp, err := p.HTTP.Do(req)
	if err != nil {
		return nil, &Error{Kind: "network", cause: err}
	}
	defer resp.Body.Close()
	p.ObserveNonce(resp.Header)
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var oe oauthErrorBody
		_ = json.Unmarshal(body, &oe)
		return nil, &Error{Kind: "server", OAuthError: oe.Error, Reason: firstNonEmpty(oe.Reason, oe.Description)}
	}
	var out DeviceAuthorization
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, &Error{Kind: "server", Reason: "malformed device authorization response"}
	}
	return &out, nil
}

// PollOnce redeems the stored device code once. It returns nil when the
// connection became active; a *Error with Kind pending or slow_down means
// wait Interval seconds and try again.
func (p *Provider) PollOnce(ctx context.Context, localID string) error {
	e := p.entryFor(localID)
	e.mu.Lock()
	defer e.mu.Unlock()
	enr, err := p.enrollment(localID)
	if err != nil {
		return err
	}
	sec, err := p.Store.LoadSecrets(localID)
	if err != nil {
		return err
	}
	if sec.DeviceCode == "" {
		return &Error{Kind: "not_connected", Reason: "no pending approval"}
	}
	signer, err := p.Signer(enr.KeyRef)
	if err != nil {
		return err
	}
	resp, err := p.tokenRequest(ctx, signer, url.Values{
		"grant_type":  {runtimeproto.DeviceCodeGrant},
		"device_code": {sec.DeviceCode},
		"client_id":   {runtimeproto.ClientID},
		"resource":    {runtimeproto.ResourceAPI},
	})
	if err != nil {
		var te *Error
		if errors.As(err, &te) {
			switch te.Kind {
			case "pending", "slow_down":
				if te.Interval > 0 {
					p.updateEnrollment(localID, func(en *brokerstore.Enrollment) { en.PollIntervalS = te.Interval })
				}
			case "declined", "expired", "revoked":
				_ = p.Store.SaveSecrets(localID, brokerstore.Secrets{})
				p.markState(localID, stateForKind(te.Kind), te.Kind)
			}
		}
		return err
	}
	// Persist the refresh token and drop the device code before activating.
	if err := p.Store.SaveSecrets(localID, brokerstore.Secrets{RefreshToken: resp.RefreshToken}); err != nil {
		return fmt.Errorf("runtime token: persist refresh token: %w", err)
	}
	p.updateEnrollment(localID, func(en *brokerstore.Enrollment) {
		en.State = "active"
		en.ApprovalExpires = resp.ApprovalExpiresAt
		en.LastErrorCode = ""
		en.AgentID = firstNonEmpty(resp.AgentID, en.AgentID)
	})
	e.cache[runtimeproto.ResourceAPI] = cached{token: resp.AccessToken, expires: p.Now().Add(time.Duration(resp.ExpiresIn) * time.Second)}
	return nil
}

func (p *Provider) updateEnrollment(localID string, fn func(*brokerstore.Enrollment)) {
	_, _ = p.Store.UpdateState(func(st *brokerstore.State) error {
		for i := range st.Enrollments {
			if st.Enrollments[i].LocalID == localID {
				fn(&st.Enrollments[i])
			}
		}
		return nil
	})
}

// RevokeRemote revokes the refresh family at the server (RFC 7009).
func (p *Provider) RevokeRemote(ctx context.Context, localID string) error {
	sec, err := p.Store.LoadSecrets(localID)
	if err != nil || sec.RefreshToken == "" {
		return err
	}
	form := url.Values{"token": {sec.RefreshToken}, "client_id": {runtimeproto.ClientID}}
	req, err := http.NewRequestWithContext(ctx, "POST", p.APIURL+runtimeproto.RevokePath, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.HTTP.Do(req)
	if err != nil {
		return &Error{Kind: "network", cause: err}
	}
	resp.Body.Close()
	return nil
}

// RecoverJournals is called at broker start. A leftover journal means a
// refresh may have rotated server-side without being persisted; the next
// AccessToken presents the previous token inside the server allowance, so all
// that is needed here is to drop any cached token.
func (p *Provider) RecoverJournals() []string {
	st, err := p.Store.LoadState()
	if err != nil {
		return nil
	}
	var recovered []string
	for _, en := range st.Enrollments {
		if j, _ := p.Store.ReadJournal(en.LocalID); j != nil {
			p.Invalidate(en.LocalID, runtimeproto.ResourceAPI)
			p.Invalidate(en.LocalID, runtimeproto.ResourceMCP)
			recovered = append(recovered, en.LocalID)
		}
	}
	return recovered
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
