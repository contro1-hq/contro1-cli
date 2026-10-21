package mcpbridge

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"sync"
)

// SetupToolName is the one tool a server that cannot connect offers.
const SetupToolName = "contro1_setup_required"

// defaultProtocolVersion is answered when a client does not name one.
const defaultProtocolVersion = "2025-06-18"

/*
ServeSetupRequired speaks MCP over stdio without being connected to anything,
and uses every answer to say what has to be fixed.

WHY A SERVER AND NOT AN EXIT. `contro1 mcp serve` that could not pick a
connection printed its reason on stderr and exited. No MCP client shows a
server's stderr to the person: OpenClaw reported "MCP error -32000: Connection
closed" and nothing else, and the person found out what was wrong only by
asking another assistant to read the code. The only thing a client reliably
shows is what the server says in the protocol: the instructions returned by
`initialize`, the tool list, and a tool's result. So the server stays up and
puts the fix in all three, and the agent reads it out in the chat where the
person already is.

It offers exactly one tool and no Action, so a misconfigured server can never
be mistaken for a working one: the tool's only effect is to repeat the fix,
and its result is marked as an error.
*/
func ServeSetupRequired(message, version string, input io.Reader, output io.Writer) error {
	scanner := bufio.NewScanner(withoutBOM(input))
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	var writes sync.Mutex
	var firstWriteError error
	write := func(payload []byte) {
		if len(payload) == 0 {
			return
		}
		writes.Lock()
		defer writes.Unlock()
		if firstWriteError != nil {
			return
		}
		_, firstWriteError = output.Write(append(payload, '\n'))
	}
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		write(setupAnswer(line, message, version))
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return firstWriteError
}

type setupRequest struct {
	ID     *json.RawMessage `json:"id"`
	Method string           `json:"method"`
	Params struct {
		ProtocolVersion string `json:"protocolVersion"`
	} `json:"params"`
}

// setupAnswer is the reply to one JSON-RPC line, or nil for a notification.
func setupAnswer(line []byte, message, version string) []byte {
	var request setupRequest
	if err := json.Unmarshal(line, &request); err != nil {
		return rpcError(nil, -32700, "Parse error. "+message)
	}
	// A notification has no id and must not receive a response.
	if request.ID == nil {
		return nil
	}
	switch request.Method {
	case "initialize":
		protocol := request.Params.ProtocolVersion
		if protocol == "" {
			protocol = defaultProtocolVersion
		}
		return rpcResult(request.ID, map[string]any{
			"protocolVersion": protocol,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "contro1", "version": version},
			"instructions":    "Contro1 is not set up for this agent yet. " + message,
		})
	case "ping":
		return rpcResult(request.ID, map[string]any{})
	case "tools/list":
		return rpcResult(request.ID, map[string]any{"tools": []any{map[string]any{
			"name":        SetupToolName,
			"title":       "Contro1 setup required",
			"description": "Contro1 is not set up for this agent yet, so no Contro1 tools are available. Call this tool, or tell the person: " + message,
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		}}})
	case "tools/call":
		return rpcResult(request.ID, map[string]any{
			"content": []any{map[string]any{"type": "text", "text": message}},
			"isError": true,
		})
	case "resources/list":
		return rpcResult(request.ID, map[string]any{"resources": []any{}})
	case "prompts/list":
		return rpcResult(request.ID, map[string]any{"prompts": []any{}})
	}
	return rpcError(request.ID, -32601, "Contro1 is not set up for this agent yet. "+message)
}

func rpcResult(id *json.RawMessage, result any) []byte {
	raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
	return raw
}

func rpcError(id *json.RawMessage, code int, message string) []byte {
	var rawID any
	if id != nil {
		rawID = id
	}
	raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": rawID, "error": map[string]any{"code": code, "message": message}})
	return raw
}
