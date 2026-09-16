package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// The staleness check answers two different questions, and only one of them is
// obvious. Getting the second wrong leaves a hand-edited skill file in place
// forever, silently feeding an agent instructions its organization never
// published - the failure this whole phase exists to prevent, arriving through
// the back door.
func TestLocalIsCurrent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "refunds.md")

	body := "Approve refunds under $50.\n"
	bodySum := sha256.Sum256([]byte(body))
	serverDigest := "abc123"

	write := func(headerDigest, headerBody, fileBody string) {
		contents := "<!-- contro1 skill refunds v4\n" +
			"     digest " + headerDigest + "\n" +
			"     body " + headerBody + "\n" +
			"     Do not edit. -->\n\n" + fileBody
		if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Written by us, untouched since. Nothing to do.
	write(serverDigest, hex.EncodeToString(bodySum[:]), body)
	if !localIsCurrent(path, serverDigest) {
		t.Fatal("an untouched file that matches the manifest must be current")
	}

	// The organization published something new. The file is stale even though
	// nobody touched it locally.
	if localIsCurrent(path, "different-digest") {
		t.Fatal("a moved manifest digest must force a re-download")
	}

	// Somebody edited the file by hand. The header still claims the old digest,
	// so a check that trusted the header alone would call this current and the
	// agent would keep following text nobody published.
	write(serverDigest, hex.EncodeToString(bodySum[:]), "Approve refunds under $5000.\n")
	if localIsCurrent(path, serverDigest) {
		t.Fatal("a hand-edited body must force a re-download")
	}

	// A file with no header at all, or a truncated one, is not current. Failing
	// closed here costs one download; failing open leaves unknown text in place.
	if err := os.WriteFile(path, []byte("just some text"), 0o644); err != nil {
		t.Fatal(err)
	}
	if localIsCurrent(path, serverDigest) {
		t.Fatal("a file without our header must not be treated as current")
	}

	if localIsCurrent(filepath.Join(dir, "missing.md"), serverDigest) {
		t.Fatal("a missing file is not current")
	}
}

func TestHeaderField(t *testing.T) {
	header := "<!-- contro1 skill refunds v4\n     digest abc\n     body def\n"
	if got := headerField(header, "digest "); got != "abc" {
		t.Fatalf("digest: got %q", got)
	}
	if got := headerField(header, "body "); got != "def" {
		t.Fatalf("body: got %q", got)
	}
	if got := headerField(header, "missing "); got != "" {
		t.Fatalf("absent field should be empty, got %q", got)
	}
}
