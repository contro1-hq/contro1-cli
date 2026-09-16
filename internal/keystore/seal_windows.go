//go:build windows

package keystore

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

func isWindows() bool { return true }

var dpapiEntropy = []byte("contro1-broker-keystore-v1")

// sealBytes DPAPI-protects data for the current account (the broker service
// identity in production). Another account, including a local administrator
// reading the raw file, cannot unseal it without that account's credentials.
func sealBytes(plain []byte) ([]byte, error) {
	return DPAPIProtect(plain)
}

func unsealBytes(sealed []byte) ([]byte, error) {
	return DPAPIUnprotect(sealed)
}

// DPAPIProtect is exported for brokerstore secrets.
func DPAPIProtect(plain []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, fmt.Errorf("keystore: nothing to seal")
	}
	in := windows.DataBlob{Size: uint32(len(plain)), Data: &plain[0]}
	entropy := windows.DataBlob{Size: uint32(len(dpapiEntropy)), Data: &dpapiEntropy[0]}
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, &entropy, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, fmt.Errorf("keystore: DPAPI protect: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

// DPAPIUnprotect reverses DPAPIProtect for the same account.
func DPAPIUnprotect(sealed []byte) ([]byte, error) {
	if len(sealed) == 0 {
		return nil, fmt.Errorf("keystore: nothing to unseal")
	}
	in := windows.DataBlob{Size: uint32(len(sealed)), Data: &sealed[0]}
	entropy := windows.DataBlob{Size: uint32(len(dpapiEntropy)), Data: &dpapiEntropy[0]}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, &entropy, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, fmt.Errorf("keystore: DPAPI unprotect: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}
