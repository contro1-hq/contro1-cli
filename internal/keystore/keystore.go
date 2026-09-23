// Package keystore holds the broker's per-connection P-256 keys.
//
// A Signer never exposes private key bytes. On Windows the default store is a
// non-exportable CNG key (optionally in the TPM provider); elsewhere, and as a
// Windows fallback, keys are PKCS#8 files readable only by the broker's
// service identity (DPAPI-sealed on Windows). Releases are built with
// CGO_ENABLED=0, so macOS Keychain and Secure Enclave are not available; the
// spec allows a dedicated service identity with a 0600 file instead.
package keystore

import (
	"errors"
	"regexp"

	"github.com/contro1-hq/contro1-cli/internal/dpop"
)

// Protection describes how a key is held. Doctor reports it; production
// connections refuse `user_file_development`.
type Protection string

const (
	ProtectionCNGNonExportable    Protection = "cng_nonexportable"
	ProtectionTPM                 Protection = "tpm"
	ProtectionServiceIdentityFile Protection = "service_identity_file"
	ProtectionUserFileDevelopment Protection = "user_file_development"
)

var (
	ErrNotFound    = errors.New("keystore: key not found")
	ErrExists      = errors.New("keystore: key already exists")
	ErrInvalidID   = errors.New("keystore: invalid key id")
	ErrRequiresCGO = errors.New("keystore: this key protection needs a CGO build and is not available in release binaries")
	ErrUnavailable = errors.New("keystore: key provider unavailable on this system")
)

// Signer is a dpop.Signer that also reports its protection.
type Signer interface {
	dpop.Signer
	ID() string
	Protection() Protection
}

// Store creates, opens and deletes keys by id.
type Store interface {
	Create(id string) (Signer, error)
	Open(id string) (Signer, error)
	Delete(id string) error
	Protection() Protection
}

var idPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// ValidID keeps ids safe as file names and CNG key names.
func ValidID(id string) error {
	if !idPattern.MatchString(id) {
		return ErrInvalidID
	}
	return nil
}

// Options select the default store for this platform.
type Options struct {
	// Dir holds file keys. Required for file stores.
	Dir string
	// Machine puts CNG keys in the machine key container. The Windows service
	// does NOT use it: its account cannot write there (see broker.New).
	Machine bool
	// PreferTPM uses the Microsoft Platform Crypto Provider on Windows.
	PreferTPM bool
	// Development marks file keys as user-owned development keys.
	Development bool
}

// Default returns the strongest store available without CGO on this platform.
func Default(opts Options) (Store, error) {
	return platformDefault(opts)
}
