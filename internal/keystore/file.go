package keystore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/contro1-hq/contro1-cli/internal/dpop"
)

// FileStore keeps PKCS#8 keys in Dir, mode 0600, written atomically. On Windows
// the bytes are DPAPI-sealed to the account that wrote them (see seal_*.go).
type FileStore struct {
	Dir         string
	Development bool
}

func (f *FileStore) Protection() Protection {
	if f.Development {
		return ProtectionUserFileDevelopment
	}
	return ProtectionServiceIdentityFile
}

func (f *FileStore) path(id string) string { return filepath.Join(f.Dir, id+".key") }

func (f *FileStore) Create(id string) (Signer, error) {
	if err := ValidID(id); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(f.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("keystore: %w", err)
	}
	if _, err := os.Stat(f.path(id)); err == nil {
		return nil, ErrExists
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("keystore: generate: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("keystore: marshal: %w", err)
	}
	sealed, err := sealBytes(der)
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(f.path(id), sealed, 0o600); err != nil {
		return nil, err
	}
	return &fileSigner{id: id, key: key, protection: f.Protection()}, nil
}

func (f *FileStore) Open(id string) (Signer, error) {
	if err := ValidID(id); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(f.path(id))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("keystore: read: %w", err)
	}
	der, err := unsealBytes(raw)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("keystore: parse: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("keystore: stored key is not P-256")
	}
	return &fileSigner{id: id, key: key, protection: f.Protection()}, nil
}

func (f *FileStore) Delete(id string) error {
	if err := ValidID(id); err != nil {
		return err
	}
	err := os.Remove(f.path(id))
	if errors.Is(err, os.ErrNotExist) {
		return ErrNotFound
	}
	return err
}

type fileSigner struct {
	id         string
	key        *ecdsa.PrivateKey
	protection Protection
}

func (s *fileSigner) ID() string               { return s.id }
func (s *fileSigner) Protection() Protection   { return s.protection }
func (s *fileSigner) Public() *ecdsa.PublicKey { return &s.key.PublicKey }
func (s *fileSigner) SignDigest(d []byte) ([]byte, error) {
	return dpop.SoftwareSigner{Key: s.key}.SignDigest(d)
}

// writeFileAtomic writes to a temp file in the same directory, syncs it, and
// renames it over the target so a crash never leaves a half-written key.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("keystore: temp: %w", err)
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(perm); err != nil && !isWindows() {
		tmp.Close()
		return fmt.Errorf("keystore: chmod: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("keystore: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("keystore: sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
