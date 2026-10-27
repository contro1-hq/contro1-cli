package privateconnector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/contro1-hq/contro1-cli/internal/keystore"
)

const heartbeatInterval = 30 * time.Second

var installationPattern = regexp.MustCompile(`^pci_[a-f0-9]{32}$`)

// ServiceConfig is installed locally by an administrator. Provider credentials
// and the one-use enrollment code live in separate protected files, never here.
type ServiceConfig struct {
	APIURL         string               `json:"api_url"`
	InstallationID string               `json:"installation_id"`
	Provider       *LocalProviderConfig `json:"provider,omitempty"`
	// ProxyURL is the corporate HTTPS proxy for traffic to Contro1 only. The
	// local provider is always dialed directly at its pinned address.
	ProxyURL string `json:"proxy_url,omitempty"`
}

type LocalProviderConfig struct {
	BaseURL    string              `json:"base_url"`
	PinnedIP   string              `json:"pinned_ip,omitempty"`
	Operations []ProviderOperation `json:"operations,omitempty"`
	AuthMode   string              `json:"auth_mode"`
	HeaderName string              `json:"header_name,omitempty"`
	Username   string              `json:"username,omitempty"`
	Probe      *ProbeConfig        `json:"probe,omitempty"`
}

type ProbeConfig struct {
	OperationDigest string `json:"operation_digest"`
	// The selected JSON field must equal Expected. A transport success alone
	// does not prove that a provider accepted the request.
	ResultField string `json:"result_field"`
	Expected    string `json:"expected"`
}

type PublicStatus struct {
	InstallationID string    `json:"installation_id"`
	LastAttempt    time.Time `json:"last_attempt,omitempty"`
	LastSuccess    time.Time `json:"last_success,omitempty"`
	CloudStatus    string    `json:"cloud_status"`
	ProviderStatus string    `json:"provider_status"`
	ProviderDetail string    `json:"provider_detail,omitempty"`
	ProviderCheck  string    `json:"provider_check,omitempty"`
	Version        string    `json:"version"`
}

func ReadConfig(stateDir string) (ServiceConfig, error) {
	var cfg ServiceConfig
	raw, err := os.ReadFile(filepath.Join(stateDir, "config.json"))
	if err != nil {
		return cfg, err
	}
	if len(raw) > 256<<10 {
		return cfg, errors.New("connector configuration exceeded limit")
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, errors.New("connector configuration is invalid")
	}
	if !installationPattern.MatchString(cfg.InstallationID) {
		return cfg, errors.New("connector installation ID is invalid")
	}
	if cfg.Provider != nil {
		if err := validateLocalProviderConfig(cfg.Provider); err != nil {
			return cfg, err
		}
	}
	return cfg, nil
}

func validateLocalProviderConfig(p *LocalProviderConfig) error {
	if p.AuthMode == "" {
		return errors.New("provider authentication mode is required")
	}
	if p.Probe == nil {
		return nil
	}
	if p.Probe.ResultField == "" || p.Probe.Expected == "" {
		return errors.New("provider probe success rule is required")
	}
	for _, op := range p.Operations {
		if op.Digest == p.Probe.OperationDigest && op.Method == "GET" && !op.AcceptsBody && len(op.QueryFields) == 0 && len(segmentVariable.FindAllString(op.Path, -1)) == 0 {
			return nil
		}
	}
	return errors.New("provider probe must be a pinned parameterless GET")
}

func writePrivateJSON(path string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".connector-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// InstallationDir isolates the identity, provider and status of each local app.
func InstallationDir(root, installationID string) string {
	return filepath.Join(root, "installations", installationID)
}

// Run hosts every configured installation under one OS service, so additional
// private applications do not require another privileged daemon.
func Run(ctx context.Context, root, version string, report func(string)) error {
	entries, err := os.ReadDir(filepath.Join(root, "installations"))
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("no installation is set up here yet: run `contro1 private-connector install` (or `provision` in Docker) with the setup file from Contro1")
	}
	if err != nil {
		return err
	}
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() || !installationPattern.MatchString(entry.Name()) {
			continue
		}
		count++
		if count > 32 {
			return errors.New("private connector installation limit exceeded")
		}
		id := entry.Name()
		stateDir := InstallationDir(root, id)
		go func() {
			for ctx.Err() == nil {
				if err := runInstallation(ctx, stateDir, id, version, report); err != nil && report != nil {
					report(id + ": " + err.Error())
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(30 * time.Second):
				}
			}
		}()
	}
	if count == 0 {
		return errors.New("no private connector installations are configured")
	}
	<-ctx.Done()
	return nil
}

// runInstallation has no listener and can only reach its configured HTTPS
// cloud origin and locally pinned provider endpoint.
func runInstallation(ctx context.Context, stateDir, directoryID, version string, report func(string)) error {
	cfg, err := ReadConfig(stateDir)
	if err != nil {
		return fmt.Errorf("read private connector config: %w", err)
	}
	if cfg.InstallationID != directoryID {
		return errors.New("installation directory and configuration disagree")
	}
	store, err := keystore.Default(keystore.Options{Dir: filepath.Join(stateDir, "keys")})
	if err != nil {
		return err
	}
	signer, err := store.Open(cfg.InstallationID)
	if errors.Is(err, keystore.ErrNotFound) {
		signer, err = store.Create(cfg.InstallationID)
	}
	if err != nil {
		return fmt.Errorf("open private connector identity: %w", err)
	}
	if closer, ok := signer.(interface{ Close() }); ok {
		defer closer.Close()
	}
	client, err := NewClient(cfg.APIURL, signer)
	if err != nil {
		return err
	}
	if cfg.ProxyURL != "" {
		if err := client.UseProxy(cfg.ProxyURL); err != nil {
			return err
		}
	}
	provider, err := localProvider(cfg.Provider, stateDir)
	if err != nil {
		return err
	}
	if version == "" || version == "dev" {
		version = "0.0.0-dev"
	}
	codePath := filepath.Join(stateDir, "enrollment-code")
	if code, err := os.ReadFile(codePath); err == nil {
		for {
			enrollment, enrollErr := client.Enroll(ctx, cfg.InstallationID, string(code))
			// The key that signs jobs, kept for checking every job before it runs.
			if enrollErr == nil {
				if err := SaveJobKey(stateDir, enrollment.JobSigningPublicKey); err != nil {
					return fmt.Errorf("save job verification key: %w", err)
				}
			}
			if enrollErr == nil || client.HeartbeatWithProviderStatus(ctx, cfg.InstallationID, version, "unknown") == nil {
				if err := os.Remove(codePath); err != nil {
					return fmt.Errorf("remove used enrollment code: %w", err)
				}
				break
			} else if report != nil {
				report("enrollment attempt failed: " + enrollErr.Error())
			}
			_ = writePrivateJSON(filepath.Join(stateDir, "status.json"), PublicStatus{
				InstallationID: cfg.InstallationID, LastAttempt: time.Now().UTC(), CloudStatus: "enrollment_pending", ProviderStatus: "unknown", Version: version,
			})
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(15 * time.Second):
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// Jobs are pulled beside the heartbeat, and stop with it.
	jobsCtx, stopJobs := context.WithCancel(ctx)
	defer stopJobs()
	go runJobs(jobsCtx, client, provider, stateDir, cfg.InstallationID, report)
	status := PublicStatus{InstallationID: cfg.InstallationID, CloudStatus: "connecting", ProviderStatus: "not_configured", Version: version}
	for {
		status.LastAttempt = time.Now().UTC()
		status.ProviderStatus, status.ProviderDetail, status.ProviderCheck = probeProviderDetail(ctx, provider, cfg.Provider)
		if err := client.Report(ctx, cfg.InstallationID, version, HeartbeatReport{
			ProviderStatus: status.ProviderStatus, ProviderDetail: status.ProviderDetail,
			ProviderCheck: status.ProviderCheck, HostName: connectorName(),
		}); err != nil {
			status.CloudStatus = "disconnected"
			if report != nil {
				report("heartbeat failed: " + err.Error())
			}
		} else {
			status.CloudStatus = "connected_authenticated"
			status.LastSuccess = time.Now().UTC()
		}
		if err := writePrivateJSON(filepath.Join(stateDir, "status.json"), status); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(heartbeatInterval):
		}
	}
}

func localProvider(cfg *LocalProviderConfig, stateDir string) (*Provider, error) {
	if cfg == nil {
		return nil, nil
	}
	auth := ProviderAuth{Mode: cfg.AuthMode, HeaderName: cfg.HeaderName, Username: cfg.Username}
	if cfg.AuthMode != "none" {
		secret, err := ReadSecret(filepath.Join(stateDir, "provider-secret"))
		if err != nil {
			return nil, fmt.Errorf("read provider credential: %w", err)
		}
		auth.Secret = secret
	}
	return NewProvider(ProviderConfig{BaseURL: cfg.BaseURL, PinnedIP: cfg.PinnedIP, Operations: cfg.Operations, Auth: auth})
}

func probeProvider(ctx context.Context, provider *Provider, cfg *LocalProviderConfig) string {
	status, _, _ := probeProviderDetail(ctx, provider, cfg)
	return status
}

// probeProviderDetail checks the local application on every heartbeat and
// says which check it ran. With a configured probe ("probe"), a pinned GET must
// return the expected value. Without one ("address"), the application must
// accept a connection at its address: that tells "wrong address or stopped"
// from "answering" with no request sent, but proves nothing about the key,
// the certificate or the API path.
func probeProviderDetail(ctx context.Context, provider *Provider, cfg *LocalProviderConfig) (string, string, string) {
	if provider == nil {
		return "not_configured", "", ""
	}
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if cfg.Probe == nil {
		if ok, detail := provider.Reach(probeCtx); !ok {
			return "unreachable", detail, "address"
		}
		return "reachable", "", "address"
	}
	status, result, err := provider.Execute(probeCtx, cfg.Probe.OperationDigest, nil)
	if err != nil {
		return "unreachable", reachFailure(err), "probe"
	}
	if status < 200 || status >= 300 {
		return "unreachable", "http_error", "probe"
	}
	var body map[string]any
	if json.Unmarshal(result, &body) != nil {
		return "unreachable", "bad_response", "probe"
	}
	if value, ok := body[cfg.Probe.ResultField]; ok && fmt.Sprint(value) == cfg.Probe.Expected {
		return "reachable", "", "probe"
	}
	return "unreachable", "bad_response", "probe"
}

// connectorName is how this connector appears in Contro1: the computer's name,
// or CONTRO1_CONNECTOR_NAME (useful in a container, whose name is random).
func connectorName() string {
	name := strings.TrimSpace(os.Getenv("CONTRO1_CONNECTOR_NAME"))
	if name == "" {
		name, _ = os.Hostname()
	}
	var clean strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			clean.WriteRune(r)
		}
		if clean.Len() == 64 {
			break
		}
	}
	return clean.String()
}
