package mcpbridge

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// The case this exists for: OpenClaw started `contro1 mcp serve` without
// --agent on a computer with three agents, the process exited, and the person
// saw "Connection closed". The fix has to arrive through the protocol.
func TestSetupServerAnswersEveryRequestWithTheFix(t *testing.T) {
	fix := "Several agents are connected on this computer: main, dash. Start this server with --agent <id>, e.g. contro1 mcp serve --agent main"
	in := strings.NewReader(strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"contro1_setup_required"}}`,
		`{"jsonrpc":"2.0","id":4,"method":"something/else"}`,
	}, "\n") + "\n")
	var out bytes.Buffer
	if err := ServeSetupRequired(fix, "test", in, &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("four requests, four answers, and nothing for the notification: %q", out.String())
	}

	var initialize struct {
		Result struct {
			ProtocolVersion string `json:"protocolVersion"`
			Instructions    string `json:"instructions"`
			Capabilities    struct {
				Tools map[string]any `json:"tools"`
			} `json:"capabilities"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &initialize); err != nil || initialize.Result.ProtocolVersion != "2025-03-26" ||
		initialize.Result.Capabilities.Tools == nil || !strings.Contains(initialize.Result.Instructions, "--agent main") {
		t.Fatalf("initialize must succeed and carry the fix: %s", lines[0])
	}

	var list struct {
		Result struct {
			Tools []struct {
				Name        string `json:"name"`
				Description string `json:"description"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[1]), &list); err != nil || len(list.Result.Tools) != 1 ||
		list.Result.Tools[0].Name != SetupToolName || !strings.Contains(list.Result.Tools[0].Description, fix) {
		t.Fatalf("exactly one tool, describing the fix: %s", lines[1])
	}

	var call struct {
		Result struct {
			IsError bool `json:"isError"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[2]), &call); err != nil || !call.Result.IsError || len(call.Result.Content) != 1 || call.Result.Content[0].Text != fix {
		t.Fatalf("calling the tool returns the fix as an error result: %s", lines[2])
	}

	if !strings.Contains(lines[3], `"id":4`) || !strings.Contains(lines[3], "-32601") || !strings.Contains(lines[3], "--agent main") {
		t.Fatalf("an unknown method is refused with the fix: %s", lines[3])
	}
}
