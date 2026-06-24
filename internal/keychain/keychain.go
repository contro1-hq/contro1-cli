// Package keychain stores the CLI access token in the OS credential store, with a
// 0600 file fallback for environments without a keychain (containers, minimal Linux).
package keychain

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/contro1-hq/contro1-cli/internal/config"
	"github.com/zalando/go-keyring"
)

const service = "contro1-cli"

var warnOnce sync.Once

func fallbackPath() (string, error) {
	dir, err := config.Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "credentials.json"), nil
}

func readFallback() (map[string]string, error) {
	p, err := fallbackPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	if err := json.Unmarshal(data, &m); err != nil {
		return map[string]string{}, nil
	}
	return m, nil
}

func writeFallback(m map[string]string) error {
	p, err := fallbackPath()
	if err != nil {
		return err
	}
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o600)
}

func warnPlaintext() {
	warnOnce.Do(func() {
		os.Stderr.WriteString("warning: OS keychain unavailable; storing token in ~/.contro1/credentials.json (0600)\n")
	})
}

// Store saves the token for a profile. forcePlaintext skips the keychain entirely.
func Store(profile, token string, forcePlaintext bool) error {
	if !forcePlaintext {
		if err := keyring.Set(service, profile, token); err == nil {
			return nil
		}
	}
	warnPlaintext()
	m, err := readFallback()
	if err != nil {
		return err
	}
	m[profile] = token
	return writeFallback(m)
}

// Retrieve returns the token for a profile (env override handled by caller).
func Retrieve(profile string) (string, error) {
	if tok, err := keyring.Get(service, profile); err == nil && tok != "" {
		return tok, nil
	}
	m, err := readFallback()
	if err != nil {
		return "", err
	}
	if tok, ok := m[profile]; ok && tok != "" {
		return tok, nil
	}
	return "", errors.New("no stored credentials for this profile; run 'contro1 auth login'")
}

// Delete removes the token for a profile from both stores.
func Delete(profile string) error {
	_ = keyring.Delete(service, profile)
	m, err := readFallback()
	if err != nil {
		return nil
	}
	delete(m, profile)
	return writeFallback(m)
}
