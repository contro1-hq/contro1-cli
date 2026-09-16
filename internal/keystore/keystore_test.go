package keystore

import (
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/contro1-hq/contro1-cli/internal/dpop"
)

func exercise(t *testing.T, store Store, id string) {
	t.Helper()
	signer, err := store.Create(id)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = store.Delete(id) })
	if _, err := store.Create(id); !errors.Is(err, ErrExists) {
		t.Fatalf("second create must report ErrExists, got %v", err)
	}
	digest := sha256.Sum256([]byte("contro1"))
	sig, err := signer.SignDigest(digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !dpop.VerifyRaw(signer.Public(), digest[:], sig) {
		t.Fatal("signature does not verify with the exported public key")
	}
	reopened, err := store.Open(id)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	a, _ := dpop.KeyThumbprint(signer.Public())
	b, _ := dpop.KeyThumbprint(reopened.Public())
	if a != b {
		t.Fatal("reopened key has a different thumbprint")
	}
	sig2, err := reopened.SignDigest(digest[:])
	if err != nil || !dpop.VerifyRaw(signer.Public(), digest[:], sig2) {
		t.Fatalf("reopened key must sign for the same public key: %v", err)
	}
	if err := store.Delete(id); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := store.Open(id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted key must be gone, got %v", err)
	}
}

func TestFileStore(t *testing.T) {
	dir := t.TempDir()
	store := &FileStore{Dir: dir}
	exercise(t, store, "file_key_1")
	if _, err := store.Create("../escape"); !errors.Is(err, ErrInvalidID) {
		t.Fatal("path-like ids must be refused")
	}
	signer, err := store.Create("persisted")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "persisted.key"))
	if runtime.GOOS == "windows" {
		if len(raw) == 0 || raw[0] == 0x30 {
			t.Fatal("on Windows the key file must be DPAPI-sealed, not raw PKCS#8")
		}
	} else {
		info, _ := os.Stat(filepath.Join(dir, "persisted.key"))
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("key file mode %v, want 0600", info.Mode().Perm())
		}
	}
	if signer.Protection() != ProtectionServiceIdentityFile {
		t.Fatal("protection label")
	}
}
