// Package client is a thin HTTP client for the Contro1 API. It attaches the
// bearer token, parses JSON, and maps transport/HTTP failures to CLI exit codes.
package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/contro1-hq/contro1-cli/internal/output"
	"github.com/contro1-hq/contro1-cli/internal/runtimeproto"
)

type Client struct {
	BaseURL   string
	Token     string
	UserAgent string
	// NetworkRemediation is attached to transport failures (e.g. the local
	// Contro1 service is not running).
	NetworkRemediation *runtimeproto.Remediation
	http               *http.Client
}

// NewWithHTTPClient uses a caller-supplied transport, e.g. the broker's local
// endpoint. Token may be empty: the broker adds the credential.
func NewWithHTTPClient(baseURL, token, userAgent string, hc *http.Client) *Client {
	c := New(baseURL, token, userAgent)
	if hc != nil {
		c.http = hc
	}
	return c
}

func New(baseURL, token, userAgent string) *Client {
	return &Client{
		BaseURL:   strings.TrimRight(baseURL, "/"),
		Token:     token,
		UserAgent: userAgent,
		http:      &http.Client{Timeout: 30 * time.Second},
	}
}

// Do performs a request and returns the parsed JSON object. Non-2xx responses are
// returned as *output.ExitError with an appropriate exit code.
func (c *Client) Do(method, path string, body any) (map[string]any, error) {
	return c.DoWithHeaders(method, path, body, nil)
}

// DoWithHeaders is Do with extra request headers, e.g. Idempotency-Key.
func (c *Client) DoWithHeaders(method, path string, body any, headers map[string]string) (map[string]any, error) {
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, output.Errf(output.CodeGeneral, "encoding request body: %v", err)
		}
		reader = bytes.NewReader(buf)
	}

	req, err := http.NewRequest(method, c.BaseURL+path, reader)
	if err != nil {
		return nil, output.Errf(output.CodeBadArgs, "building request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	for k, v := range headers {
		if strings.TrimSpace(k) != "" && strings.TrimSpace(v) != "" {
			req.Header.Set(k, v)
		}
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, output.Errf(output.CodeNetwork, "network error: %v", err).WithRemediation(c.NetworkRemediation)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	var parsed map[string]any
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &parsed)
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if parsed == nil {
			parsed = map[string]any{}
		}
		return parsed, nil
	}

	code, msg := extractError(parsed, raw)
	exitErr := output.Errf(httpExitCode(resp.StatusCode, code), "%s", msg)
	exitErr.Remediation = ExtractRemediation(parsed)
	return parsed, exitErr
}

// Data unwraps the {ok,data} envelope used by CLI-specific endpoints; for plain
// v1 responses it returns the whole object.
func Data(resp map[string]any) any {
	if resp == nil {
		return nil
	}
	if d, ok := resp["data"]; ok {
		return d
	}
	return resp
}

// ExtractRemediation reads `error.remediation` or a top-level `remediation`.
func ExtractRemediation(parsed map[string]any) *runtimeproto.Remediation {
	if parsed == nil {
		return nil
	}
	var raw any
	if e, ok := parsed["error"].(map[string]any); ok && e["remediation"] != nil {
		raw = e["remediation"]
	} else if parsed["remediation"] != nil {
		raw = parsed["remediation"]
	}
	if raw == nil {
		return nil
	}
	buf, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	var r runtimeproto.Remediation
	if json.Unmarshal(buf, &r) != nil || r.Code == "" {
		return nil
	}
	return &r
}

func extractError(parsed map[string]any, raw []byte) (string, string) {
	if parsed != nil {
		// {ok:false,error:{code,message,required_scope}}
		if e, ok := parsed["error"].(map[string]any); ok {
			code, _ := e["code"].(string)
			msg, _ := e["message"].(string)
			if rs, ok := e["required_scope"].(string); ok && rs != "" {
				msg = fmt.Sprintf("%s (required scope: %s)", msg, rs)
			}
			if msg == "" {
				msg = code
			}
			return code, msg
		}
		// {error:"...",message:"...",details:[{field,message}]}
		if msg, ok := parsed["message"].(string); ok && msg != "" {
			code, _ := parsed["error"].(string)
			return code, msg + validationDetails(parsed["details"])
		}
		if msg, ok := parsed["error"].(string); ok && msg != "" {
			return msg, msg
		}
	}
	if len(raw) > 0 {
		return "", strings.TrimSpace(string(raw))
	}
	return "", "request failed"
}

// validationDetails names the fields a request was refused for. Without them
// "Invalid request body" leaves the caller guessing which part to fix.
func validationDetails(raw any) string {
	items, ok := raw.([]any)
	if !ok || len(items) == 0 {
		return ""
	}
	var parts []string
	for _, item := range items {
		d, ok := item.(map[string]any)
		if !ok {
			continue
		}
		field, _ := d["field"].(string)
		message, _ := d["message"].(string)
		switch {
		case field != "" && message != "":
			parts = append(parts, field+": "+message)
		case message != "":
			parts = append(parts, message)
		}
		if len(parts) == 5 {
			break
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, "; ") + ")"
}

func httpExitCode(status int, errCode string) int {
	switch {
	case status == 401:
		return output.CodeAuth
	case status == 403 && errCode == "INSUFFICIENT_SCOPE":
		return output.CodeInsufficient
	case status == 404:
		return output.CodeNotFound
	case status == 409 || status == 412:
		return output.CodeConflict
	case status >= 500:
		return output.CodeGeneral
	default:
		return output.CodeGeneral
	}
}
