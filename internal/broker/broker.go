// Package broker is the Contro1 service: one long-running process per computer
// that holds every connection's key, keeps its tokens fresh, and serves one
// isolated local endpoint per Agent.
//
// Two planes:
//   - Control (administrators and the installer only): create connections,
//     inspect, verify, revoke, rotate keys, write platform mappings.
//   - Data (one endpoint per connection, one allowed caller identity): a narrow
//     HTTP proxy to Contro1 that adds the credential. The caller never sees a
//     token and cannot choose an identity.
package broker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/contro1-hq/contro1-cli/internal/brokerstore"
	"github.com/contro1-hq/contro1-cli/internal/keystore"
	"github.com/contro1-hq/contro1-cli/internal/localipc"
	"github.com/contro1-hq/contro1-cli/internal/tokenprovider"
)

type Config struct {
	StateDir   string
	APIURL     string
	Version    string
	Foreground bool

	// ControlEndpoint and who may use it. In production: SYSTEM,
	// Administrators and the service SID on Windows; root and the broker user
	// on unix.
	ControlEndpoint   localipc.Endpoint
	ControlPrincipals []localipc.Principal
	// ServicePrincipal is the identity this broker runs as. Data endpoint
	// descriptors grant it full access, and clients verify it.
	ServicePrincipal string
	// EndpointDir holds unix data sockets.
	EndpointDir string
	// PlatformsDir receives platform mapping files (readable by platforms).
	// Empty keeps them in the state directory.
	PlatformsDir string
	// DevAllowCurrentUserControl lets the current user drive control in
	// foreground development. Doctor reports this as blocked for production.
	DevAllowCurrentUserControl bool

	Keys keystore.Store
	HTTP *http.Client
	Logf func(format string, args ...any)
}

type Broker struct {
	cfg       Config
	store     *brokerstore.Store
	provider  *tokenprovider.Provider
	startedAt time.Time

	mu        sync.Mutex
	endpoints map[string]*dataServer
	control   *http.Server
	stop      context.CancelFunc
}

func New(cfg Config) (*Broker, error) {
	if cfg.StateDir == "" {
		return nil, errors.New("broker: state directory is required")
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	store, err := brokerstore.Open(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	st, err := store.LoadState()
	if err != nil {
		store.Close()
		return nil, err
	}
	if cfg.APIURL == "" {
		cfg.APIURL = st.APIURL
	}
	if cfg.Keys == nil {
		cfg.Keys, err = keystore.Default(keystore.Options{Dir: filepath.Join(cfg.StateDir, "keys"), Machine: !cfg.Foreground && runtime.GOOS == "windows", Development: cfg.Foreground})
		if err != nil {
			store.Close()
			return nil, err
		}
	}
	b := &Broker{cfg: cfg, store: store, startedAt: time.Now(), endpoints: map[string]*dataServer{}}
	b.provider = tokenprovider.New(store, cfg.Keys, cfg.HTTP, cfg.APIURL)
	return b, nil
}

// Provider is exposed for tests.
func (b *Broker) Provider() *tokenprovider.Provider { return b.provider }

// Store is exposed for tests.
func (b *Broker) Store() *brokerstore.Store { return b.store }

func (b *Broker) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	b.stop = cancel
	defer cancel()
	defer b.store.Close()

	for _, id := range b.provider.RecoverJournals() {
		b.cfg.Logf("recovering an interrupted refresh for %s", id)
	}
	if err := b.startControl(); err != nil {
		return err
	}
	st, err := b.store.LoadState()
	if err != nil {
		return err
	}
	for _, en := range st.Enrollments {
		if en.State == "active" {
			if err := b.startData(en); err != nil {
				b.cfg.Logf("endpoint for %s failed to start: %v", en.LocalID, err)
			}
		}
	}
	go b.pollLoop(ctx)
	go b.statusLoop(ctx)
	<-ctx.Done()
	b.shutdown()
	return nil
}

func (b *Broker) shutdown() {
	b.mu.Lock()
	if b.control != nil {
		_ = b.control.Close()
	}
	for id, ds := range b.endpoints {
		ds.close()
		delete(b.endpoints, id)
	}
	b.mu.Unlock()
	b.writeStatus()
}

func (b *Broker) startControl() error {
	principals := append([]localipc.Principal(nil), b.cfg.ControlPrincipals...)
	if b.cfg.DevAllowCurrentUserControl {
		me, err := localipc.CurrentIdentity()
		if err != nil {
			return err
		}
		principals = append(principals, localipc.Principal(me.User))
	}
	if len(principals) == 0 {
		return errors.New("broker: control endpoint has no allowed principals")
	}
	sddl := ""
	if runtime.GOOS == "windows" {
		sddl = localipc.ControlSDDL(b.cfg.ServicePrincipal)
		if b.cfg.DevAllowCurrentUserControl {
			sddl += fmt.Sprintf("(A;;GA;;;%s)", principals[len(principals)-1])
		}
	}
	l, err := localipc.Listen(localipc.ListenSpec{Endpoint: b.cfg.ControlEndpoint, AllowedPrincipals: principals, SDDL: sddl})
	if err != nil {
		return fmt.Errorf("broker: control endpoint: %w", err)
	}
	srv := localipc.NewServer(b.controlHandler())
	b.mu.Lock()
	b.control = srv
	b.mu.Unlock()
	go func() {
		if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			b.cfg.Logf("control endpoint stopped: %v", err)
		}
	}()
	return nil
}

func (b *Broker) startData(en brokerstore.Enrollment) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.endpoints[en.LocalID]; ok {
		return nil
	}
	ep, err := localipc.ParseEndpoint(en.Endpoint)
	if err != nil {
		return err
	}
	principals := make([]localipc.Principal, 0, len(en.AllowedPrincipals))
	for _, p := range en.AllowedPrincipals {
		principals = append(principals, localipc.Principal(p))
	}
	sddl := ""
	if runtime.GOOS == "windows" {
		if len(en.AllowedPrincipals) != 1 {
			return errors.New("broker: a data endpoint on Windows has exactly one caller identity")
		}
		sddl = localipc.DataSDDL(en.AllowedPrincipals[0], b.cfg.ServicePrincipal)
	}
	l, err := localipc.Listen(localipc.ListenSpec{Endpoint: ep, AllowedPrincipals: principals, SDDL: sddl})
	if err != nil {
		return err
	}
	ds := newDataServer(b, en.LocalID, l)
	b.endpoints[en.LocalID] = ds
	return nil
}

func (b *Broker) stopData(localID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ds, ok := b.endpoints[localID]; ok {
		ds.close()
		delete(b.endpoints, localID)
	}
}

// pollLoop redeems pending device codes at the server's interval.
func (b *Broker) pollLoop(ctx context.Context) {
	next := map[string]time.Time{}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		st, err := b.store.LoadState()
		if err != nil {
			continue
		}
		now := time.Now()
		for _, en := range st.Enrollments {
			if en.State != "pending" || now.Before(next[en.LocalID]) {
				continue
			}
			if en.DeviceExpiresAt != "" {
				if exp, err := time.Parse(time.RFC3339, en.DeviceExpiresAt); err == nil && now.After(exp.Add(30*time.Second)) {
					b.markLocal(en.LocalID, "expired", "device_code_expired")
					continue
				}
			}
			err := b.provider.PollOnce(ctx, en.LocalID)
			interval := en.PollIntervalS
			if interval <= 0 {
				interval = 5
			}
			var te *tokenprovider.Error
			switch {
			case err == nil:
				fresh, _ := b.enrollment(en.LocalID)
				if fresh != nil {
					if err := b.startData(*fresh); err != nil {
						b.cfg.Logf("endpoint for %s failed to start: %v", en.LocalID, err)
					}
					if _, _, err := b.writeMapping(fresh.Platform, ""); err != nil {
						b.cfg.Logf("mapping for %s: %v", fresh.Platform, err)
					}
				}
				b.writeStatus()
			case errors.As(err, &te) && (te.Kind == "pending" || te.Kind == "slow_down"):
				if te.Interval > 0 {
					interval = te.Interval
				}
			default:
				b.cfg.Logf("approval poll for %s: %v", en.LocalID, err)
				interval *= 2
			}
			next[en.LocalID] = now.Add(time.Duration(interval) * time.Second)
		}
	}
}

func (b *Broker) statusLoop(ctx context.Context) {
	b.writeStatus()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.writeStatus()
		}
	}
}

func (b *Broker) writeStatus() {
	st, err := b.store.LoadState()
	if err != nil {
		return
	}
	b.mu.Lock()
	listening := make(map[string]bool, len(b.endpoints))
	for id := range b.endpoints {
		listening[id] = true
	}
	b.mu.Unlock()
	out := brokerstore.PublicStatus{BrokerVersion: b.cfg.Version, PID: os.Getpid(), KeyProtection: string(b.cfg.Keys.Protection()), Foreground: b.cfg.Foreground}
	for _, en := range st.Enrollments {
		health := "stopped"
		if listening[en.LocalID] {
			health = "listening"
		}
		out.Enrollments = append(out.Enrollments, brokerstore.EnrollmentStatus{
			LocalID: en.LocalID, EnrollmentID: en.EnrollmentID, AgentID: en.AgentID, Platform: en.Platform,
			Subject: en.PlatformSubject, EndpointMode: en.EndpointMode, Endpoint: en.Endpoint, State: en.State,
			LastErrorCode: en.LastErrorCode, EndpointHealth: health,
		})
	}
	_ = b.store.WriteStatus(out)
	// The state directory is private to the service; a copy of the
	// secret-free status goes where platforms and doctor can read it.
	if b.cfg.PlatformsDir != "" {
		if raw, err := os.ReadFile(filepath.Join(b.cfg.StateDir, "status.json")); err == nil {
			_ = os.MkdirAll(b.cfg.PlatformsDir, 0o755)
			_ = brokerstore.WriteFileAtomic(filepath.Join(b.cfg.PlatformsDir, "status.json"), raw, 0o644)
		}
	}
}

func (b *Broker) enrollment(localID string) (*brokerstore.Enrollment, error) {
	st, err := b.store.LoadState()
	if err != nil {
		return nil, err
	}
	for i := range st.Enrollments {
		if st.Enrollments[i].LocalID == localID {
			return &st.Enrollments[i], nil
		}
	}
	return nil, os.ErrNotExist
}

func (b *Broker) markLocal(localID, state, code string) {
	_, _ = b.store.UpdateState(func(st *brokerstore.State) error {
		for i := range st.Enrollments {
			if st.Enrollments[i].LocalID == localID {
				st.Enrollments[i].State = state
				st.Enrollments[i].LastErrorCode = code
			}
		}
		return nil
	})
}

func randomID(prefix string) string {
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	return prefix + hex.EncodeToString(buf)
}

// DataEndpointFor names the endpoint for a new connection.
func (b *Broker) DataEndpointFor(localID string) localipc.Endpoint {
	if runtime.GOOS == "windows" {
		return localipc.PipeEndpoint("contro1-ep-" + localID)
	}
	dir := b.cfg.EndpointDir
	if dir == "" {
		dir = "/run/contro1/ep"
	}
	return localipc.Endpoint{Kind: "unix", Path: filepath.Join(dir, localID+".sock")}
}
