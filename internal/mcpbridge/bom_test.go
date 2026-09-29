package mcpbridge

import (
	"io"
	"strings"
	"testing"
)

// A Windows shell with UTF-8 output encoding prefixes piped input with a BOM,
// which made the first JSON-RPC line unparseable on the server.
func TestWithoutBOMDropsALeadingByteOrderMark(t *testing.T) {
	bom := string([]byte{0xEF, 0xBB, 0xBF})
	got, _ := io.ReadAll(withoutBOM(strings.NewReader(bom + `{"jsonrpc":"2.0"}` + "\n")))
	if string(got) != `{"jsonrpc":"2.0"}`+"\n" {
		t.Fatalf("BOM not removed: %q", got)
	}
	plain, _ := io.ReadAll(withoutBOM(strings.NewReader(`{"a":1}` + "\n")))
	if string(plain) != `{"a":1}`+"\n" {
		t.Fatalf("input without a BOM changed: %q", plain)
	}
	short, _ := io.ReadAll(withoutBOM(strings.NewReader("{}")))
	if string(short) != "{}" {
		t.Fatalf("short input changed: %q", short)
	}
}
