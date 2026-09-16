package tokenprovider

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/contro1-hq/contro1-cli/internal/brokerstore"
	"github.com/contro1-hq/contro1-cli/internal/dpop"
	"github.com/contro1-hq/contro1-cli/internal/keystore"
	"github.com/contro1-hq/contro1-cli/internal/runtimeproto"
)

// fakeAS is a minimal authorization server that really verifies DPoP proofs.
type fakeAS struct {
	t          *testing.T
	mu         sync.Mutex
	jkt        string
	current    string
	previous   string
	successor  bool
	refreshes  int
	nonce      string
	demandOnce bool
	approved   bool
	srv        *httptest.Server
}

func (f *fakeAS) verify(r *http.Request) (map[string]any, error) {
	parts := strings.Split(r.Header.Get("DPoP"), ".")
	if len(parts) != 3 {
		return nil, errors.New("no proof")
	}
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	pb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	var header struct {
		JWK dpop.JWK `json:"jwk"`
	}
	var payload map[string]any
	_ = json.Unmarshal(hb, &header)
	_ = json.Unmarshal(pb, &payload)
	x, _ := base64.RawURLEncoding.DecodeString(header.JWK.X)
	y, _ := base64.RawURLEncoding.DecodeString(header.JWK.Y)
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !dpop.VerifyRaw(pub, digest[:], sig) {
		return nil, errors.New("bad signature")
	}
	if payload["htu"] != f.srv.URL+r.URL.Path || payload["htm"] != r.Method {
		return nil, errors.New("htu/htm mismatch")
	}
	payload["jkt"] = dpop.Thumbprint(header.JWK)
	return payload, nil
}

func (f *fakeAS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	write := func(status int, v any) {
		w.Header().Set("DPoP-Nonce", f.nonce)
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	payload, err := f.verify(r)
	if err != nil {
		write(400, map[string]any{"error": "invalid_dpop_proof", "error_description": err.Error()})
		return
	}
	if payload["nonce"] != f.nonce {
		if f.demandOnce {
			write(400, map[string]any{"error": "use_dpop_nonce"})
			return
		}
	}
	_ = r.ParseForm()
	if payload["jkt"] != f.jkt {
		write(400, map[string]any{"error": "invalid_grant", "contro1_reason": "refresh_key_mismatch"})
		return
	}
	switch r.Form.Get("grant_type") {
	case runtimeproto.DeviceCodeGrant:
		if !f.approved {
			write(400, map[string]any{"error": "authorization_pending", "interval": 5})
			return
		}
		f.current = "ccrt_1"
		write(200, map[string]any{"access_token": "at_device", "token_type": "DPoP", "expires_in": 300, "refresh_token": f.current})
	case runtimeproto.RefreshGrant:
		f.refreshes++
		presented := r.Form.Get("refresh_token")
		next := fmt.Sprintf("ccrt_%d", f.refreshes+1)
		switch {
		case presented == f.current:
			f.previous, f.current, f.successor = presented, next, false
		case presented == f.previous && !f.successor:
			f.current = next // crash allowance
		default:
			write(400, map[string]any{"error": "invalid_grant", "contro1_reason": "refresh_reuse", "remediation": map[string]any{"code": "CONNECTION_NOT_ACTIVE", "next_step": "Connect this computer again."}})
			return
		}
		write(200, map[string]any{"access_token": fmt.Sprintf("at_%s_%d", r.Form.Get("resource"), f.refreshes), "token_type": "DPoP", "expires_in": 300, "refresh_token": next})
	default:
		write(400, map[string]any{"error": "unsupported_grant_type"})
	}
}

func setup(t *testing.T) (*Provider, *fakeAS, *brokerstore.Store) {
	t.Helper()
	dir := t.TempDir()
	store, err := brokerstore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	keys := &keystore.FileStore{Dir: dir + "/keys"}
	signer, err := keys.Create("key_1")
	if err != nil {
		t.Fatal(err)
	}
	jkt, _ := dpop.KeyThumbprint(signer.Public())
	as := &fakeAS{t: t, jkt: jkt, nonce: "nonce-1"}
	as.srv = httptest.NewServer(as)
	t.Cleanup(as.srv.Close)
	_, err = store.UpdateState(func(st *brokerstore.State) error {
		st.Enrollments = []brokerstore.Enrollment{{LocalID: "loc_1", EnrollmentID: "enr_1", AgentID: "agt_1", KeyRef: "key_1", State: "pending", EndpointMode: runtimeproto.ModeApprovalsOnly}}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveSecrets("loc_1", brokerstore.Secrets{DeviceCode: "ccdc_x"}); err != nil {
		t.Fatal(err)
	}
	p := New(store, keys, as.srv.Client(), as.srv.URL)
	return p, as, store
}

func activate(t *testing.T, p *Provider, as *fakeAS) {
	t.Helper()
	ctx := context.Background()
	err := p.PollOnce(ctx, "loc_1")
	var te *Error
	if !errors.As(err, &te) || te.Kind != "pending" || te.Interval != 5 {
		t.Fatalf("before approval: %v", err)
	}
	as.mu.Lock()
	as.approved = true
	as.mu.Unlock()
	if err := p.PollOnce(ctx, "loc_1"); err != nil {
		t.Fatalf("after approval: %v", err)
	}
}

func expireCache(p *Provider) {
	for _, e := range p.entries {
		e.mu.Lock()
		e.cache = map[string]cached{}
		e.mu.Unlock()
	}
}

func TestSingleFlightAndCaching(t *testing.T) {
	p, as, store := setup(t)
	activate(t, p, as)
	sec, _ := store.LoadSecrets("loc_1")
	if sec.DeviceCode != "" || sec.RefreshToken != "ccrt_1" {
		t.Fatalf("activation must replace the device code with the refresh token: %+v", sec)
	}
	expireCache(p)

	var wg sync.WaitGroup
	tokens := make([]string, 200)
	errs := make([]error, 200)
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tokens[i], errs[i] = p.AccessToken(context.Background(), "loc_1", runtimeproto.ResourceAPI)
		}(i)
	}
	wg.Wait()
	for i := range tokens {
		if errs[i] != nil || tokens[i] != tokens[0] {
			t.Fatalf("caller %d: %q %v", i, tokens[i], errs[i])
		}
	}
	if p.RefreshCount() != 1 {
		t.Fatalf("200 concurrent callers made %d refreshes, want 1", p.RefreshCount())
	}
	mcp, err := p.AccessToken(context.Background(), "loc_1", runtimeproto.ResourceMCP)
	if err != nil || !strings.HasPrefix(mcp, "at_mcp_") || p.RefreshCount() != 2 {
		t.Fatalf("resources are cached separately: %q %v %d", mcp, err, p.RefreshCount())
	}
	sec, _ = store.LoadSecrets("loc_1")
	if sec.RefreshToken != "ccrt_3" {
		t.Fatalf("the latest refresh token must be persisted, got %s", sec.RefreshToken)
	}
}

func TestNonceRetry(t *testing.T) {
	p, as, _ := setup(t)
	activate(t, p, as)
	expireCache(p)
	as.mu.Lock()
	as.demandOnce = true
	as.nonce = "fresh-nonce"
	as.mu.Unlock()
	if _, err := p.AccessToken(context.Background(), "loc_1", runtimeproto.ResourceAPI); err != nil {
		t.Fatalf("one nonce challenge must be retried transparently: %v", err)
	}
}

func TestCrashBetweenRotateAndPersist(t *testing.T) {
	p, as, store := setup(t)
	activate(t, p, as)
	expireCache(p)
	realSeal := store.Seal
	failures := 1
	store.Seal = func(b []byte) ([]byte, error) {
		if failures > 0 {
			failures--
			return nil, errors.New("disk full")
		}
		if realSeal == nil {
			return b, nil
		}
		return realSeal(b)
	}
	if _, err := p.AccessToken(context.Background(), "loc_1", runtimeproto.ResourceAPI); err == nil {
		t.Fatal("a failed persist must not hand out a token")
	}
	if j, _ := store.ReadJournal("loc_1"); j == nil {
		t.Fatal("the journal must survive so a restart knows a refresh was in flight")
	}
	// Restart: the old refresh token is still on disk; the server allowance accepts it.
	p2 := New(store, p.Keys, p.HTTP, p.APIURL)
	if got := p2.RecoverJournals(); len(got) != 1 {
		t.Fatalf("recover journals: %v", got)
	}
	if _, err := p2.AccessToken(context.Background(), "loc_1", runtimeproto.ResourceAPI); err != nil {
		t.Fatalf("recovery through the allowance must work: %v", err)
	}
	if j, _ := store.ReadJournal("loc_1"); j != nil {
		t.Fatal("journal must clear after a persisted refresh")
	}
}

func TestReuseIsTerminal(t *testing.T) {
	p, as, store := setup(t)
	activate(t, p, as)
	as.mu.Lock()
	as.current = "ccrt_someone_else_rotated"
	as.previous = "ccrt_older"
	as.mu.Unlock()
	expireCache(p)
	_, err := p.AccessToken(context.Background(), "loc_1", runtimeproto.ResourceAPI)
	var te *Error
	if !errors.As(err, &te) || te.Kind != "reuse_suspended" || !te.Terminal() || te.Remediation == nil {
		t.Fatalf("reuse must be terminal with remediation: %v", err)
	}
	st, _ := store.LoadState()
	if st.Enrollments[0].State != "suspended" {
		t.Fatalf("local state must reflect suspension, got %s", st.Enrollments[0].State)
	}
	if _, err := p.AccessToken(context.Background(), "loc_1", runtimeproto.ResourceAPI); !IsTerminal(err) {
		t.Fatalf("a suspended connection stays refused: %v", err)
	}
}

func TestAuthorizeSetsHeaders(t *testing.T) {
	p, as, _ := setup(t)
	activate(t, p, as)
	req, _ := http.NewRequest("GET", as.srv.URL+"/api/centcom/v1/runtime/status", nil)
	if err := p.Authorize(context.Background(), req, "loc_1", runtimeproto.ResourceAPI); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(req.Header.Get("Authorization"), "DPoP at_") || strings.Count(req.Header.Get("DPoP"), ".") != 2 {
		t.Fatalf("headers %v", req.Header)
	}
	_ = time.Second
}
