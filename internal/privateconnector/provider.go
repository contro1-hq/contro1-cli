package privateconnector

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const maxProviderResult = 1 << 20
const maxProviderBody = 256 << 10

var segmentVariable = regexp.MustCompile(`\{([A-Za-z][A-Za-z0-9_]*)\}`)
var safeRelativePath = regexp.MustCompile(`^/[A-Za-z0-9_./{}-]*$`)
var safeHeaderName = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// ErrProviderUncertain means the request may have reached the application:
// the connection failed or the answer could not be read after sending. A write
// that ends this way is reported indeterminate and never sent again.
var ErrProviderUncertain = errors.New("provider request failed")

// ProviderOperation is an installation-pinned mapping. No field in an agent
// request or cloud job may replace its method, path or query allowlist.
type ProviderOperation struct {
	Digest      string   `json:"digest"`
	Method      string   `json:"method"`
	Path        string   `json:"path"`
	QueryFields []string `json:"query_fields,omitempty"`
	AcceptsBody bool     `json:"accepts_body,omitempty"`
}

type ProviderAuth struct {
	Mode       string // none, header_key, bearer, basic
	HeaderName string // local configuration only; e.g. Armaor KEY
	Secret     string // load from the OS secret store under the service identity
	Username   string
}

type ProviderConfig struct {
	BaseURL    string
	PinnedIP   string // required for DNS names; resolved and approved at installation
	Operations []ProviderOperation
	Auth       ProviderAuth
}

// Provider calls one customer-hosted API. It has no listener and never follows
// a redirect or a system proxy. A credentialed LAN HTTP target is refused.
type Provider struct {
	base       *url.URL
	address    string // the pinned IP and port every request dials
	client     *http.Client
	operations map[string]ProviderOperation
	auth       ProviderAuth
}

func NewProvider(cfg ProviderConfig) (*Provider, error) {
	base, err := url.Parse(cfg.BaseURL)
	if err != nil || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" ||
		(base.Scheme != "https" && base.Scheme != "http") || !strings.HasSuffix(base.Path, "/") ||
		base.Opaque != "" || base.RawPath != "" || strings.Contains(base.Path, "..") || strings.Contains(base.Path, "//") ||
		strings.ContainsAny(base.Path, "\\%") {
		return nil, errors.New("provider base URL must be an HTTP(S) API directory without credentials")
	}
	host := base.Hostname()
	if cfg.PinnedIP != "" && net.ParseIP(cfg.PinnedIP) == nil {
		return nil, errors.New("provider destination requires an approved pinned IP")
	}
	pinned := net.ParseIP(cfg.PinnedIP)
	if pinned == nil {
		pinned = net.ParseIP(host)
	}
	if pinned == nil || (cfg.PinnedIP != "" && net.ParseIP(host) != nil && !pinned.Equal(net.ParseIP(host))) {
		return nil, errors.New("provider destination requires an approved pinned IP")
	}
	if base.Scheme == "http" && !pinned.IsLoopback() {
		return nil, errors.New("plain HTTP is allowed only on loopback")
	}
	if cfg.Auth.Mode == "" {
		return nil, errors.New("provider authentication mode must be explicit")
	}
	switch cfg.Auth.Mode {
	case "none":
		if cfg.Auth.Secret != "" || cfg.Auth.Username != "" || cfg.Auth.HeaderName != "" {
			return nil, errors.New("no-credential mode cannot contain a provider credential")
		}
	case "header_key":
		if cfg.Auth.Secret == "" || !safeHeaderName.MatchString(cfg.Auth.HeaderName) ||
			strings.EqualFold(cfg.Auth.HeaderName, "Host") || strings.EqualFold(cfg.Auth.HeaderName, "Authorization") {
			return nil, errors.New("provider header-key configuration is invalid")
		}
	case "bearer", "basic":
		if cfg.Auth.Secret == "" || (cfg.Auth.Mode == "basic" && cfg.Auth.Username == "") {
			return nil, errors.New("provider authentication configuration is invalid")
		}
	default:
		return nil, errors.New("unsupported provider authentication mode")
	}
	if base.Scheme == "http" && cfg.Auth.Mode != "none" {
		return nil, errors.New("provider credentials require TLS")
	}
	operations := make(map[string]ProviderOperation, len(cfg.Operations))
	for _, op := range cfg.Operations {
		withoutVariables := segmentVariable.ReplaceAllString(op.Path, "x")
		if !strings.HasPrefix(op.Digest, "sha256:") || len(op.Digest) != 71 ||
			(op.Method != "GET" && op.Method != "POST" && op.Method != "PUT" && op.Method != "PATCH" && op.Method != "DELETE") ||
			!safeRelativePath.MatchString(op.Path) || strings.HasPrefix(op.Path, "//") || strings.Contains(op.Path, "..") ||
			strings.Contains(op.Path, "//") || strings.ContainsAny(withoutVariables, "{}") {
			return nil, errors.New("provider operation contract is invalid")
		}
		if _, exists := operations[op.Digest]; exists {
			return nil, errors.New("duplicate provider operation digest")
		}
		seen := make(map[string]bool)
		for _, name := range op.QueryFields {
			if !safeHeaderName.MatchString(name) || seen[name] || strings.Contains(op.Path, "{"+name+"}") {
				return nil, errors.New("provider query field is invalid")
			}
			seen[name] = true
		}
		operations[op.Digest] = op
	}
	port := base.Port()
	if port == "" {
		if base.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return nil, errors.New("provider port is invalid")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, net.JoinHostPort(pinned.String(), port))
	}
	return &Provider{base: base, address: net.JoinHostPort(pinned.String(), port), operations: operations, auth: cfg.Auth, client: &http.Client{
		Transport: transport, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

// Reach says whether something answers at the application's pinned address.
// It opens a TCP connection and closes it: no request is sent, so checking
// has no effect on the application. The second value says why it failed.
func (p *Provider) Reach(ctx context.Context) (bool, string) {
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", p.address)
	if err != nil {
		return false, reachFailure(err)
	}
	_ = conn.Close()
	return true, ""
}

// reachFailure names a connection failure in the words the cloud accepts.
// Read from the message too, because Windows and Unix report refusals with
// different error numbers.
func reachFailure(err error) string {
	var netErr net.Error
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "refused"):
		return "refused"
	case errors.As(err, &netErr) && netErr.Timeout(), strings.Contains(message, "timeout"), strings.Contains(message, "timed out"):
		return "timeout"
	case strings.Contains(message, "unreachable"), strings.Contains(message, "no route"):
		return "no_route"
	default:
		return "other"
	}
}

func queryScalar(value any) (string, bool) {
	switch v := value.(type) {
	case string:
		return v, true
	case bool:
		return strconv.FormatBool(v), true
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true
	case json.Number:
		return string(v), true
	default:
		return "", false
	}
}

func (p *Provider) Execute(ctx context.Context, digest string, input map[string]any) (int, json.RawMessage, error) {
	op, ok := p.operations[digest]
	if !ok {
		return 0, nil, errors.New("operation is not pinned on this installation")
	}
	if input == nil {
		input = map[string]any{}
	}
	path := op.Path
	allowed := make(map[string]bool)
	for _, match := range segmentVariable.FindAllStringSubmatch(op.Path, -1) {
		name := match[1]
		value, present := queryScalar(input[name])
		if !present || value == "" {
			return 0, nil, errors.New("required path parameter is missing")
		}
		if strings.ContainsAny(value, "/\\%") || value == "." || value == ".." {
			return 0, nil, errors.New("path parameter contains a separator")
		}
		path = strings.ReplaceAll(path, "{"+name+"}", url.PathEscape(value))
		allowed[name] = true
	}
	query := url.Values{}
	for _, name := range op.QueryFields {
		allowed[name] = true
		if value, present := input[name]; present {
			encoded, valid := queryScalar(value)
			if !valid {
				return 0, nil, errors.New("query parameter must be scalar")
			}
			query.Set(name, encoded)
		}
	}
	if op.AcceptsBody {
		allowed["body"] = true
	}
	for name := range input {
		if !allowed[name] {
			return 0, nil, errors.New("input field is not in the pinned operation")
		}
	}
	var body []byte
	if value, present := input["body"]; present {
		var err error
		body, err = json.Marshal(value)
		if err != nil || len(body) > maxProviderBody {
			return 0, nil, errors.New("provider request body is invalid or too large")
		}
	}
	target := *p.base
	unescapedPath, err := url.PathUnescape(path)
	if err != nil {
		return 0, nil, errors.New("provider path could not be constructed")
	}
	target.Path = strings.TrimSuffix(p.base.Path, "/") + unescapedPath
	target.RawPath = strings.TrimSuffix(p.base.EscapedPath(), "/") + path
	target.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, op.Method, target.String(), bytes.NewReader(body))
	if err != nil {
		return 0, nil, errors.New("provider request could not be constructed")
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	switch p.auth.Mode {
	case "header_key":
		req.Header.Set(p.auth.HeaderName, p.auth.Secret)
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+p.auth.Secret)
	case "basic":
		req.SetBasicAuth(p.auth.Username, p.auth.Secret)
	}
	res, err := p.client.Do(req)
	if err != nil {
		return 0, nil, ErrProviderUncertain
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 && res.StatusCode < 400 {
		return res.StatusCode, nil, errors.New("provider redirected the request")
	}
	result, err := io.ReadAll(io.LimitReader(res.Body, maxProviderResult+1))
	if err != nil {
		return res.StatusCode, nil, ErrProviderUncertain
	}
	if len(result) > maxProviderResult {
		return res.StatusCode, nil, errors.New("provider response exceeded limit")
	}
	if !json.Valid(result) {
		return res.StatusCode, nil, fmt.Errorf("provider returned a non-JSON response (HTTP %d)", res.StatusCode)
	}
	return res.StatusCode, result, nil
}
