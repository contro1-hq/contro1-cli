package installer

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompareServiceByVersion(t *testing.T) {
	never := func() (bool, error) { t.Fatal("versions decide; the binary is not read"); return false, nil }
	if c := CompareService("0.2.28", "0.2.30", never); !c.Needed || c.Newer || c.UpdateLine() != "Update the Contro1 service (from 0.2.28 to 0.2.30)" {
		t.Fatalf("older service: %+v %q", c, c.UpdateLine())
	}
	if c := CompareService("v0.3.0", "0.2.30", never); c.Needed || !c.Newer {
		t.Fatalf("a newer service is never downgraded: %+v", c)
	}
	if c := CompareService("0.2.9", "0.2.10", never); !c.Needed {
		t.Fatal("versions compare as numbers, not strings")
	}
}

func TestCompareServiceFallsBackToTheBinary(t *testing.T) {
	differs := func() (bool, error) { return true, nil }
	same := func() (bool, error) { return false, nil }
	unreadable := func() (bool, error) { return false, errors.New("permission denied") }
	if c := CompareService("0.2.30", "0.2.30", same); c.Needed {
		t.Fatal("same version, same binary: nothing to do")
	}
	if c := CompareService("0.2.30", "0.2.30", differs); !c.Needed || !strings.Contains(c.UpdateLine(), "another 0.2.30 build") {
		t.Fatalf("same version, other build: %+v %q", c, c.UpdateLine())
	}
	if c := CompareService("dev", "dev", differs); !c.Needed {
		t.Fatal("development builds are told apart by their binaries")
	}
	if c := CompareService("", "0.2.30", differs); !c.Needed || !strings.Contains(c.UpdateLine(), "different build") {
		t.Fatalf("unknown service version: %+v", c)
	}
	if c := CompareService("dev", "0.2.30", unreadable); c.Needed {
		t.Fatal("a binary that cannot be read is not a reason to ask for an administrator")
	}
}

func TestUpdateCommandPerOS(t *testing.T) {
	if got := UpdateCommand("windows", `C:\Tools\contro1.exe`); got != "contro1 broker install" {
		t.Fatalf("windows asks for approval itself: %q", got)
	}
	if got := UpdateCommand("linux", "/home/dana/.local/bin/contro1"); got != "sudo /home/dana/.local/bin/contro1 broker install" {
		t.Fatalf("unix names the executable, which sudo's PATH may not hold: %q", got)
	}
	if got := UpdateCommand("darwin", "/Users/Dana Smith/bin/contro1"); got != "sudo '/Users/Dana Smith/bin/contro1' broker install" {
		t.Fatalf("a path with a space is quoted: %q", got)
	}
}

// A failed upgrade restores the binary it replaced instead of deleting it.
func TestPreviousBinaryIsRestored(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "contro1")
	_ = os.WriteFile(dest, []byte("old"), 0o755)
	if err := keepPrevious(dest); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(dest, []byte("new"), 0o755)
	if !restorePrevious(dest) {
		t.Fatal("the previous binary is put back")
	}
	if raw, _ := os.ReadFile(dest); string(raw) != "old" {
		t.Fatalf("restored: %q", raw)
	}
	// A first install has no previous binary: nothing to restore.
	fresh := filepath.Join(t.TempDir(), "contro1")
	if err := keepPrevious(fresh); err != nil || restorePrevious(fresh) {
		t.Fatal("no previous binary on a first install")
	}
}

func TestBinaryDiffers(t *testing.T) {
	dir := t.TempDir()
	a, b, c := filepath.Join(dir, "a"), filepath.Join(dir, "b"), filepath.Join(dir, "c")
	_ = os.WriteFile(a, []byte("one"), 0o644)
	_ = os.WriteFile(b, []byte("one"), 0o644)
	_ = os.WriteFile(c, []byte("two"), 0o644)
	if d, err := BinaryDiffers(a, b); err != nil || d {
		t.Fatal("same bytes")
	}
	if d, err := BinaryDiffers(a, c); err != nil || !d {
		t.Fatal("other bytes")
	}
	if _, err := BinaryDiffers(a, filepath.Join(dir, "missing")); err == nil {
		t.Fatal("a missing binary is an error, not a difference")
	}
}
