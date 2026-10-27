//go:build windows

package privateconnector

import (
	"errors"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

var machineEntropy = []byte("contro1-private-connector-provider-secret-v1")

// Machine DPAPI permits an elevated setup process to provision the secret for
// the separate service account. The containing directory is ACL-limited to
// SYSTEM, Administrators and this service SID.
func protectSecret(plain []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, errors.New("empty provider secret")
	}
	in := windows.DataBlob{Size: uint32(len(plain)), Data: &plain[0]}
	entropy := windows.DataBlob{Size: uint32(len(machineEntropy)), Data: &machineEntropy[0]}
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, &entropy, 0, nil,
		windows.CRYPTPROTECT_UI_FORBIDDEN|windows.CRYPTPROTECT_LOCAL_MACHINE, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

func unprotectSecret(sealed []byte) ([]byte, error) {
	if len(sealed) == 0 {
		return nil, errors.New("empty provider secret")
	}
	in := windows.DataBlob{Size: uint32(len(sealed)), Data: &sealed[0]}
	entropy := windows.DataBlob{Size: uint32(len(machineEntropy)), Data: &machineEntropy[0]}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, &entropy, 0, nil,
		windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

func WriteSecret(path, secret string) error {
	sealed, err := protectSecret([]byte(secret))
	if err != nil {
		return err
	}
	return os.WriteFile(path, sealed, 0o600)
}

func ReadSecret(path string) (string, error) {
	sealed, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	plain, err := unprotectSecret(sealed)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
