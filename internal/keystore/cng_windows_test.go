//go:build windows

package keystore

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestCNGStore(t *testing.T) {
	store := &CNGStore{}
	if _, err := store.provider(); err != nil {
		t.Skipf("CNG software provider unavailable: %v", err)
	}
	id := fmt.Sprintf("test_%d", time.Now().UnixNano())
	signer, err := store.Create(id)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if signer.Protection() != ProtectionCNGNonExportable {
		t.Fatal("protection label")
	}
	if err := store.TryExportPrivate(id); err == nil {
		t.Fatal("a CNG key must not be exportable")
	}
	exercise(t, &reusingStore{CNGStore: store, first: signer, id: id}, id)
}

// reusingStore lets exercise() run its Create against the key made above.
type reusingStore struct {
	*CNGStore
	first Signer
	id    string
	used  bool
}

func (r *reusingStore) Create(id string) (Signer, error) {
	if id == r.id && !r.used {
		r.used = true
		return r.first, nil
	}
	if id == r.id {
		return nil, ErrExists
	}
	return nil, errors.New("unexpected")
}
