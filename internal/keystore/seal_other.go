//go:build !windows

package keystore

func isWindows() bool { return false }

// On unix the file is protected by ownership: a 0600 file owned by the
// dedicated broker user in a 0700 directory. There is no account-bound
// encryption primitive available without CGO.
func sealBytes(plain []byte) ([]byte, error) { return plain, nil }

func unsealBytes(sealed []byte) ([]byte, error) { return sealed, nil }
