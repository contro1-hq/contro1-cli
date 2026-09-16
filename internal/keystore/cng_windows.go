//go:build windows

package keystore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// CNG (Cryptography API: Next Generation) key storage through ncrypt.dll.
// Keys are created with an export policy of zero, so neither this process nor
// an administrator can read the private key back out of the provider.

const (
	msSoftwareKSP = "Microsoft Software Key Storage Provider"
	msPlatformKSP = "Microsoft Platform Crypto Provider"

	ncryptMachineKeyFlag   = 0x00000020
	ncryptOverwriteKeyFlag = 0x00000080
	ncryptPersistFlag      = 0x80000000
	ncryptSilentFlag       = 0x00000040
	nteBadKeyset           = 0x80090016
	nteExists              = 0x8009000F
	bcryptECDSAPublicP256  = 0x31534345 // "ECS1"
	keyNamePrefix          = "contro1-broker-"
)

var (
	modNcrypt               = windows.NewLazySystemDLL("ncrypt.dll")
	procOpenStorageProvider = modNcrypt.NewProc("NCryptOpenStorageProvider")
	procCreatePersistedKey  = modNcrypt.NewProc("NCryptCreatePersistedKey")
	procSetProperty         = modNcrypt.NewProc("NCryptSetProperty")
	procFinalizeKey         = modNcrypt.NewProc("NCryptFinalizeKey")
	procOpenKey             = modNcrypt.NewProc("NCryptOpenKey")
	procExportKey           = modNcrypt.NewProc("NCryptExportKey")
	procSignHash            = modNcrypt.NewProc("NCryptSignHash")
	procDeleteKey           = modNcrypt.NewProc("NCryptDeleteKey")
	procFreeObject          = modNcrypt.NewProc("NCryptFreeObject")
)

type cngStatus uintptr

func (s cngStatus) Error() string { return fmt.Sprintf("CNG status 0x%08X", uint32(s)) }

func call(p *windows.LazyProc, args ...uintptr) error {
	if err := p.Find(); err != nil {
		return ErrUnavailable
	}
	r, _, _ := p.Call(args...)
	if r != 0 {
		return cngStatus(r)
	}
	return nil
}

func utf16(s string) *uint16 {
	p, _ := windows.UTF16PtrFromString(s)
	return p
}

// CNGStore keeps non-exportable keys in a CNG key storage provider.
type CNGStore struct {
	Machine bool
	TPM     bool

	once sync.Once
	prov uintptr
	err  error
}

func (c *CNGStore) Protection() Protection {
	if c.TPM {
		return ProtectionTPM
	}
	return ProtectionCNGNonExportable
}

func (c *CNGStore) provider() (uintptr, error) {
	c.once.Do(func() {
		name := msSoftwareKSP
		if c.TPM {
			name = msPlatformKSP
		}
		var h uintptr
		c.err = call(procOpenStorageProvider, uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(utf16(name))), 0)
		if c.err != nil {
			c.err = fmt.Errorf("%w: %v", ErrUnavailable, c.err)
			return
		}
		c.prov = h
	})
	return c.prov, c.err
}

func (c *CNGStore) flags() uintptr {
	if c.Machine {
		return ncryptMachineKeyFlag
	}
	return 0
}

func (c *CNGStore) Create(id string) (Signer, error) {
	if err := ValidID(id); err != nil {
		return nil, err
	}
	prov, err := c.provider()
	if err != nil {
		return nil, err
	}
	var key uintptr
	err = call(procCreatePersistedKey, prov, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(utf16("ECDSA_P256"))),
		uintptr(unsafe.Pointer(utf16(keyNamePrefix+id))), 0, c.flags())
	if err != nil {
		var st cngStatus
		if errors.As(err, &st) && uint32(st) == nteExists {
			return nil, ErrExists
		}
		return nil, fmt.Errorf("keystore: create CNG key: %w", err)
	}
	policy := uint32(0) // not exportable, not even once
	if err := call(procSetProperty, key, uintptr(unsafe.Pointer(utf16("Export Policy"))), uintptr(unsafe.Pointer(&policy)), 4, ncryptPersistFlag); err != nil {
		call(procFreeObject, key)
		return nil, fmt.Errorf("keystore: set export policy: %w", err)
	}
	if err := call(procFinalizeKey, key, 0); err != nil {
		call(procFreeObject, key)
		return nil, fmt.Errorf("keystore: finalize CNG key: %w", err)
	}
	return c.wrap(id, key)
}

func (c *CNGStore) Open(id string) (Signer, error) {
	if err := ValidID(id); err != nil {
		return nil, err
	}
	prov, err := c.provider()
	if err != nil {
		return nil, err
	}
	var key uintptr
	if err := call(procOpenKey, prov, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(utf16(keyNamePrefix+id))), 0, c.flags()); err != nil {
		var st cngStatus
		if errors.As(err, &st) && uint32(st) == nteBadKeyset {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("keystore: open CNG key: %w", err)
	}
	return c.wrap(id, key)
}

func (c *CNGStore) Delete(id string) error {
	s, err := c.Open(id)
	if err != nil {
		return err
	}
	cs := s.(*cngSigner)
	cs.mu.Lock()
	defer cs.mu.Unlock()
	// NCryptDeleteKey frees the handle on success.
	if err := call(procDeleteKey, cs.handle, 0); err != nil {
		return fmt.Errorf("keystore: delete CNG key: %w", err)
	}
	cs.handle = 0
	return nil
}

func (c *CNGStore) wrap(id string, key uintptr) (Signer, error) {
	pub, err := exportPublic(key)
	if err != nil {
		call(procFreeObject, key)
		return nil, err
	}
	return &cngSigner{id: id, handle: key, pub: pub, protection: c.Protection()}, nil
}

func exportPublic(key uintptr) (*ecdsa.PublicKey, error) {
	buf := make([]byte, 8+64)
	var n uint32
	if err := call(procExportKey, key, 0, uintptr(unsafe.Pointer(utf16("ECCPUBLICBLOB"))), 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&n)), 0); err != nil {
		return nil, fmt.Errorf("keystore: export public key: %w", err)
	}
	if n != 72 || binary.LittleEndian.Uint32(buf[0:4]) != bcryptECDSAPublicP256 || binary.LittleEndian.Uint32(buf[4:8]) != 32 {
		return nil, errors.New("keystore: unexpected CNG public key blob")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(buf[8:40]), Y: new(big.Int).SetBytes(buf[40:72])}, nil
}

// TryExportPrivate attempts to export the private key; it must fail for keys
// this store creates. Used by tests and doctor.
func (c *CNGStore) TryExportPrivate(id string) error {
	s, err := c.Open(id)
	if err != nil {
		return err
	}
	cs := s.(*cngSigner)
	defer cs.Close()
	buf := make([]byte, 256)
	var n uint32
	return call(procExportKey, cs.handle, 0, uintptr(unsafe.Pointer(utf16("ECCPRIVATEBLOB"))), 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&n)), 0)
}

type cngSigner struct {
	mu         sync.Mutex
	id         string
	handle     uintptr
	pub        *ecdsa.PublicKey
	protection Protection
}

func (s *cngSigner) ID() string               { return s.id }
func (s *cngSigner) Protection() Protection   { return s.protection }
func (s *cngSigner) Public() *ecdsa.PublicKey { return s.pub }

// SignDigest returns CNG's native raw R||S signature.
func (s *cngSigner) SignDigest(digest []byte) ([]byte, error) {
	if len(digest) != 32 {
		return nil, errors.New("keystore: digest must be SHA-256")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle == 0 {
		return nil, errors.New("keystore: key closed")
	}
	sig := make([]byte, 64)
	var n uint32
	if err := call(procSignHash, s.handle, 0, uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		uintptr(unsafe.Pointer(&sig[0])), uintptr(len(sig)), uintptr(unsafe.Pointer(&n)), ncryptSilentFlag); err != nil {
		return nil, fmt.Errorf("keystore: CNG sign: %w", err)
	}
	if n != 64 {
		return nil, fmt.Errorf("keystore: CNG signature is %d bytes", n)
	}
	return sig, nil
}

func (s *cngSigner) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle != 0 {
		call(procFreeObject, s.handle)
		s.handle = 0
	}
}

func platformDefault(opts Options) (Store, error) {
	store := &CNGStore{Machine: opts.Machine, TPM: opts.PreferTPM}
	if _, err := store.provider(); err == nil {
		return store, nil
	}
	if opts.Dir == "" {
		return nil, ErrUnavailable
	}
	return &FileStore{Dir: opts.Dir, Development: opts.Development}, nil
}

var _ = ncryptOverwriteKeyFlag
