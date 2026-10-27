//go:build !windows

package privateconnector

import "os"

// On macOS the daemon runs as a dedicated non-login account. Only that
// account and root can read its 0700 state directory and 0600 secret file.
func WriteSecret(path, secret string) error { return os.WriteFile(path, []byte(secret), 0o600) }
func ReadSecret(path string) (string, error) {
	raw, err := os.ReadFile(path)
	return string(raw), err
}
