package mcpbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

/*
Probe asks an agent's own Contro1 endpoint what an MCP client asks first:
initialize, then tools/list.

WHY THIS EXISTS. "Connected" used to be said by `contro1 connect` without
anything having spoken MCP at all, and the first MCP call was the agent's own,
inside a chat, where a failure read "MCP error -32000: Connection closed" and
nobody could tell which of five pieces was missing. Asking the same two
questions here, through the same endpoint `contro1 mcp serve` forwards to, turns
that into one line at the end of connect and one check in doctor.

It goes through the endpoint and not through the platform, on purpose: this
proves that Contro1 answers for this agent. Whether the platform then starts the
server is a separate question, which doctor asks of the platform.
*/
func Probe(ctx context.Context, client *http.Client, baseURL string) (int, error) {
	endpoint := strings.TrimRight(baseURL, "/") + "/mcp"
	session := ""
	call := func(id int, method string, params any) (json.RawMessage, error) {
		body := map[string]any{"jsonrpc": "2.0", "method": method}
		if id != 0 {
			body["id"] = id
		}
		if params != nil {
			body["params"] = params
		}
		raw, _ := json.Marshal(body)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		if session != "" {
			req.Header.Set("Mcp-Session-Id", session)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("the Contro1 service on this computer is not reachable: %w", err)
		}
		defer resp.Body.Close()
		if s := resp.Header.Get("Mcp-Session-Id"); s != "" {
			session = s
		}
		payload, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		if id == 0 {
			// A notification: nothing is expected back.
			return nil, nil
		}
		var parsed struct {
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(payload, &parsed)
		if parsed.Error != nil && parsed.Error.Message != "" {
			return nil, errors.New(parsed.Error.Message)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("Contro1 refused %s (HTTP %d)", method, resp.StatusCode)
		}
		if len(parsed.Result) == 0 {
			return nil, fmt.Errorf("Contro1 returned no answer to %s", method)
		}
		return parsed.Result, nil
	}

	if _, err := call(1, "initialize", map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]string{"name": "contro1 connection check", "version": "1"},
	}); err != nil {
		return 0, fmt.Errorf("MCP initialize failed: %w", err)
	}
	_, _ = call(0, "notifications/initialized", nil)

	tools := 0
	cursor := ""
	// A bounded walk over pages: a server that kept returning a cursor must not
	// hold connect forever.
	for page := 0; page < 20; page++ {
		var params any
		if cursor != "" {
			params = map[string]string{"cursor": cursor}
		}
		result, err := call(2+page, "tools/list", params)
		if err != nil {
			return 0, fmt.Errorf("MCP tools/list failed: %w", err)
		}
		var listed struct {
			Tools      []json.RawMessage `json:"tools"`
			NextCursor string            `json:"nextCursor"`
		}
		if err := json.Unmarshal(result, &listed); err != nil {
			return 0, fmt.Errorf("MCP tools/list returned something this version cannot read: %w", err)
		}
		tools += len(listed.Tools)
		if listed.NextCursor == "" {
			break
		}
		cursor = listed.NextCursor
	}
	return tools, nil
}
