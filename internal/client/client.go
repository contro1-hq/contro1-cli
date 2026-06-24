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
)

type Client struct {
	BaseURL   string
	Token     string
	UserAgent string
	http      *http.Client
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

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, output.Errf(output.CodeNetwork, "network error: %v", err)
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
	return parsed, output.Errf(httpExitCode(resp.StatusCode, code), "%s", msg)
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
		// {error:"...",message:"..."}
		if msg, ok := parsed["message"].(string); ok && msg != "" {
			code, _ := parsed["error"].(string)
			return code, msg
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

func httpExitCode(status int, errCode string) int {
	switch {
	case status == 401:
		return output.CodeAuth
	case status == 403 && errCode == "INSUFFICIENT_SCOPE":
		return output.CodeInsufficient
	case status >= 500:
		return output.CodeGeneral
	default:
		return output.CodeGeneral
	}
}
