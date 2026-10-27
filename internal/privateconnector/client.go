// Package privateconnector implements the outbound identity protocol used by a
// customer-hosted connector. It has no inbound listener and no provider secret.
package privateconnector

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxResponse = 16 << 10

// Signer is satisfied by the existing non-exportable Windows CNG key store.
type Signer interface {
	Public() *ecdsa.PublicKey
	SignDigest([]byte) ([]byte, error)
}

type Client struct {
	base   *url.URL
	http   *http.Client
	signer Signer
}

func NewClient(baseURL string, signer Signer) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("connector API URL must be an HTTPS origin without credentials")
	}
	if u.Path != "" && u.Path != "/" {
		return nil, errors.New("connector API URL must not include a path")
	}
	if signer == nil || signer.Public() == nil {
		return nil, errors.New("connector signer is required")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &Client{base: u, signer: signer, http: &http.Client{
		Transport: transport, Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

// UseProxy sends traffic to Contro1 through an explicit corporate proxy.
// Credentials in the proxy URL are refused: they would sit in a config file
// that is readable wherever the configuration is.
func (c *Client) UseProxy(raw string) error {
	u, err := ParseProxyURL(raw)
	if err != nil {
		return err
	}
	transport, ok := c.http.Transport.(*http.Transport)
	if !ok {
		return errors.New("connector transport cannot use a proxy")
	}
	transport.Proxy = http.ProxyURL(u)
	return nil
}

// ParseProxyURL accepts an http or https proxy origin without credentials.
func ParseProxyURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("proxy_url must be an http(s) proxy origin without credentials, for example http://proxy.corp:3128")
	}
	return u, nil
}

func signStatement(signer Signer, statement string) (string, error) {
	digest := sha256.Sum256([]byte(statement))
	signature, err := signer.SignDigest(digest[:])
	if err != nil {
		return "", err
	}
	if len(signature) != 64 {
		return "", errors.New("connector signer returned a non-P-256 signature")
	}
	return base64.RawURLEncoding.EncodeToString(signature), nil
}

func (c *Client) endpoint(path string) string {
	u := *c.base
	u.Path = path
	return u.String()
}

func (c *Client) post(ctx context.Context, path string, body []byte, headers http.Header) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint(path), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for name, values := range headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, &HTTPStatusError{Code: res.StatusCode}
	}
	bounded := io.LimitReader(res.Body, maxResponse+1)
	response, err := io.ReadAll(bounded)
	if err != nil {
		return nil, err
	}
	if len(response) > maxResponse {
		return nil, errors.New("connector API response exceeded limit")
	}
	return response, nil
}

type Enrollment struct {
	InstallationID      string `json:"installation_id"`
	JobSigningPublicKey string `json:"job_signing_public_key"`
}

func (c *Client) Enroll(ctx context.Context, installationID, code string) (Enrollment, error) {
	if !strings.HasPrefix(installationID, "pci_") || len(code) != 43 {
		return Enrollment{}, errors.New("invalid connector enrollment data")
	}
	publicDER, err := x509.MarshalPKIXPublicKey(c.signer.Public())
	if err != nil {
		return Enrollment{}, err
	}
	publicPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}))
	proof, err := signStatement(c.signer, "contro1.private-connector.enroll.v1\n"+installationID+"\n"+code)
	if err != nil {
		return Enrollment{}, err
	}
	request, err := json.Marshal(map[string]string{
		"installation_id": installationID, "enrollment_code": code,
		"public_key_pem": publicPEM, "proof": proof,
	})
	if err != nil {
		return Enrollment{}, err
	}
	response, err := c.post(ctx, "/api/centcom/v1/private-connectors/enroll", request, nil)
	if err != nil {
		return Enrollment{}, err
	}
	var result struct {
		OK                  bool   `json:"ok"`
		InstallationID      string `json:"installation_id"`
		JobSigningPublicKey string `json:"job_signing_public_key"`
	}
	if err := json.Unmarshal(response, &result); err != nil || !result.OK || result.InstallationID != installationID {
		return Enrollment{}, errors.New("connector enrollment response is invalid")
	}
	if result.JobSigningPublicKey == "" {
		return Enrollment{}, errors.New("connector job verification key is missing")
	}
	return Enrollment{InstallationID: installationID,
		JobSigningPublicKey: result.JobSigningPublicKey}, nil
}

func (c *Client) Heartbeat(ctx context.Context, installationID, version string) error {
	return c.HeartbeatWithProviderStatus(ctx, installationID, version, "unknown")
}

// HeartbeatWithProviderStatus reports the worker's local probe result. The
// cloud authenticates the reporter but cannot independently verify the LAN API.
func (c *Client) HeartbeatWithProviderStatus(ctx context.Context, installationID, version, providerStatus string) error {
	return c.Report(ctx, installationID, version, HeartbeatReport{ProviderStatus: providerStatus})
}

// HeartbeatReport is what a heartbeat says besides "alive": whether the local
// application answers, why not, and the name of the computer the connector
// runs on, so a person can tell which server to look at.
type HeartbeatReport struct {
	ProviderStatus string
	ProviderDetail string
	// ProviderCheck says what "reachable" rests on: "address" when only a
	// connection was opened, "probe" when a configured request answered right.
	ProviderCheck string
	HostName      string
}

// Report sends a heartbeat with the local check and the connector's name.
func (c *Client) Report(ctx context.Context, installationID, version string, report HeartbeatReport) error {
	if !strings.HasPrefix(installationID, "pci_") || version == "" || len(version) > 100 || len(report.HostName) > 64 {
		return errors.New("invalid connector heartbeat data")
	}
	switch report.ProviderStatus {
	case "unknown", "reachable", "unreachable", "not_configured":
	default:
		return errors.New("invalid local provider status")
	}
	switch report.ProviderDetail {
	case "", "refused", "timeout", "no_route", "http_error", "bad_response", "other":
	default:
		return errors.New("invalid local provider detail")
	}
	switch report.ProviderCheck {
	case "", "address", "probe":
	default:
		return errors.New("invalid local provider check")
	}
	const path = "/api/centcom/v1/private-connectors/heartbeat"
	body, err := json.Marshal(struct {
		ProviderStatus string `json:"provider_status"`
		ProviderDetail string `json:"provider_detail,omitempty"`
		ProviderCheck  string `json:"provider_check,omitempty"`
		HostName       string `json:"host_name,omitempty"`
		Version        string `json:"version"`
	}{report.ProviderStatus, report.ProviderDetail, report.ProviderCheck, report.HostName, version})
	if err != nil {
		return err
	}
	timestamp := fmt.Sprint(time.Now().UnixMilli())
	nonceBytes := make([]byte, 24)
	if _, err := rand.Read(nonceBytes); err != nil {
		return err
	}
	nonce := hex.EncodeToString(nonceBytes)
	bodyHash := sha256.Sum256(body)
	statement := "contro1.private-connector.request.v1\nPOST\n" + path + "\n" + timestamp + "\n" + nonce + "\n" + hex.EncodeToString(bodyHash[:])
	signature, err := signStatement(c.signer, statement)
	if err != nil {
		return err
	}
	headers := http.Header{}
	headers.Set("X-Contro1-Connector-Id", installationID)
	headers.Set("X-Contro1-Timestamp", timestamp)
	headers.Set("X-Contro1-Nonce", nonce)
	headers.Set("X-Contro1-Signature", signature)
	response, err := c.post(ctx, path, body, headers)
	if err != nil {
		return err
	}
	var result struct {
		OK     bool   `json:"ok"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(response, &result); err != nil || !result.OK || result.Status != "active" {
		return errors.New("connector heartbeat response is invalid")
	}
	return nil
}
