// Package brokerstore is the broker's durable state directory:
//
//	broker.lock           singleton lock (one broker per state directory)
//	state.json            enrollments, pending device codes, mappings (no secrets)
//	secrets/<local>.json  refresh token and device code, sealed (DPAPI on Windows,
//	                      0600 under the service identity on unix)
//	journal/<local>.json  refresh in progress, for crash recovery
//	status.json           public, secret-free health for doctor without elevation
//
// Every write is temp file, fsync, rename.
package brokerstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/contro1-hq/contro1-cli/internal/runtimeproto"
)

const stateSchema = 1

type Enrollment struct {
	LocalID                string   `json:"local_id"`
	EnrollmentID           string   `json:"enrollment_id"`
	AgentID                string   `json:"agent_id"`
	OrgID                  string   `json:"org_id,omitempty"`
	BatchID                string   `json:"batch_id,omitempty"`
	ItemID                 string   `json:"item_id,omitempty"`
	Platform               string   `json:"platform"`
	PlatformInstanceDigest string   `json:"platform_instance_digest,omitempty"`
	PlatformSubject        string   `json:"platform_subject"`
	DisplayName            string   `json:"display_name,omitempty"`
	EndpointMode           string   `json:"endpoint_mode"`
	Endpoint               string   `json:"endpoint"`
	AllowedPrincipals      []string `json:"allowed_principals"`
	KeyRef                 string   `json:"key_ref"`
	PendingKeyRef          string   `json:"pending_key_ref,omitempty"`
	KeyThumbprint          string   `json:"key_thumbprint"`
	// pending | active | suspended | revoked | expired | declined | error
	State           string `json:"state"`
	ApprovalExpires string `json:"approval_expires_at,omitempty"`
	PollIntervalS   int    `json:"poll_interval_s,omitempty"`
	DeviceExpiresAt string `json:"device_expires_at,omitempty"`
	LastErrorCode   string `json:"last_error_code,omitempty"`
	CreatedAt       string `json:"created_at"`
}

type State struct {
	SchemaVersion int                        `json:"schema_version"`
	APIURL        string                     `json:"api_url"`
	Enrollments   []Enrollment               `json:"enrollments"`
	Mappings      []runtimeproto.MappingFile `json:"mappings,omitempty"`
}

// Secrets never appear in state.json, logs, or any control response.
type Secrets struct {
	RefreshToken string `json:"refresh_token,omitempty"`
	DeviceCode   string `json:"device_code,omitempty"`
}

// Journal records a refresh that may have reached the server.
type Journal struct {
	LocalID             string `json:"local_id"`
	StartedAt           string `json:"started_at"`
	PresentedHashPrefix string `json:"presented_hash_prefix"`
}

type EnrollmentStatus struct {
	LocalID        string `json:"local_id"`
	EnrollmentID   string `json:"enrollment_id"`
	AgentID        string `json:"agent_id"`
	Platform       string `json:"platform"`
	Subject        string `json:"platform_subject"`
	EndpointMode   string `json:"endpoint_mode"`
	Endpoint       string `json:"endpoint"`
	State          string `json:"state"`
	LastRefreshAt  string `json:"last_refresh_at,omitempty"`
	LastErrorCode  string `json:"last_error_code,omitempty"`
	EndpointHealth string `json:"endpoint_health,omitempty"`
}

type PublicStatus struct {
	SchemaVersion int                `json:"schema_version"`
	UpdatedAt     string             `json:"updated_at"`
	BrokerVersion string             `json:"broker_version"`
	PID           int                `json:"pid"`
	KeyProtection string             `json:"key_protection"`
	Foreground    bool               `json:"foreground"`
	Enrollments   []EnrollmentStatus `json:"enrollments"`
}

var ErrLocked = errors.New("brokerstore: another Contro1 service is already using this state directory")

type Store struct {
	Dir  string
	mu   sync.Mutex
	lock *fileLock
	// Seal and Unseal protect secrets at rest. Nil means plaintext (unix, where
	// ownership and 0600 are the protection).
	Seal   func([]byte) ([]byte, error)
	Unseal func([]byte) ([]byte, error)
}

// Open creates the directory layout and takes the singleton lock.
func Open(dir string) (*Store, error) {
	for _, sub := range []string{"", "secrets", "journal", "keys", "mappings"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return nil, fmt.Errorf("brokerstore: %w", err)
		}
	}
	lock, err := acquireLock(filepath.Join(dir, "broker.lock"))
	if err != nil {
		return nil, err
	}
	s := &Store{Dir: dir, lock: lock}
	s.Seal, s.Unseal = platformSealers()
	return s, nil
}

// OpenReadOnly reads without the lock (doctor, status).
func OpenReadOnly(dir string) *Store {
	s := &Store{Dir: dir}
	s.Seal, s.Unseal = platformSealers()
	return s
}

func (s *Store) Close() error {
	if s.lock != nil {
		return s.lock.release()
	}
	return nil
}

func (s *Store) LoadState() (*State, error) {
	raw, err := os.ReadFile(filepath.Join(s.Dir, "state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return &State{SchemaVersion: stateSchema}, nil
	}
	if err != nil {
		return nil, err
	}
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("brokerstore: state.json is corrupt: %w", err)
	}
	if st.SchemaVersion > stateSchema {
		return nil, fmt.Errorf("brokerstore: state.json schema %d is newer than this broker", st.SchemaVersion)
	}
	return &st, nil
}

func (s *Store) SaveState(st *State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st.SchemaVersion = stateSchema
	sort.Slice(st.Enrollments, func(i, j int) bool { return st.Enrollments[i].LocalID < st.Enrollments[j].LocalID })
	return writeJSONAtomic(filepath.Join(s.Dir, "state.json"), st, 0o600)
}

// UpdateState applies fn under the store mutex and persists the result.
func (s *Store) UpdateState(fn func(*State) error) (*State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.LoadState()
	if err != nil {
		return nil, err
	}
	if err := fn(st); err != nil {
		return nil, err
	}
	st.SchemaVersion = stateSchema
	sort.Slice(st.Enrollments, func(i, j int) bool { return st.Enrollments[i].LocalID < st.Enrollments[j].LocalID })
	return st, writeJSONAtomic(filepath.Join(s.Dir, "state.json"), st, 0o600)
}

func (s *Store) secretPath(localID string) string {
	return filepath.Join(s.Dir, "secrets", localID+".json")
}

func (s *Store) LoadSecrets(localID string) (Secrets, error) {
	raw, err := os.ReadFile(s.secretPath(localID))
	if errors.Is(err, os.ErrNotExist) {
		return Secrets{}, nil
	}
	if err != nil {
		return Secrets{}, err
	}
	if s.Unseal != nil {
		if raw, err = s.Unseal(raw); err != nil {
			return Secrets{}, fmt.Errorf("brokerstore: unseal secrets: %w", err)
		}
	}
	var out Secrets
	if err := json.Unmarshal(raw, &out); err != nil {
		return Secrets{}, fmt.Errorf("brokerstore: secrets corrupt: %w", err)
	}
	return out, nil
}

// SaveSecrets is durable before it returns. The token provider relies on this:
// a rotated refresh token is persisted before any waiter is released.
func (s *Store) SaveSecrets(localID string, sec Secrets) error {
	raw, err := json.Marshal(sec)
	if err != nil {
		return err
	}
	if s.Seal != nil {
		if raw, err = s.Seal(raw); err != nil {
			return fmt.Errorf("brokerstore: seal secrets: %w", err)
		}
	}
	return writeFileAtomic(s.secretPath(localID), raw, 0o600)
}

func (s *Store) DeleteSecrets(localID string) error {
	err := os.Remove(s.secretPath(localID))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (s *Store) journalPath(localID string) string {
	return filepath.Join(s.Dir, "journal", localID+".json")
}

func (s *Store) WriteJournal(j Journal) error {
	return writeJSONAtomic(s.journalPath(j.LocalID), j, 0o600)
}

func (s *Store) ReadJournal(localID string) (*Journal, error) {
	raw, err := os.ReadFile(s.journalPath(localID))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var j Journal
	if err := json.Unmarshal(raw, &j); err != nil {
		return nil, nil
	}
	return &j, nil
}

func (s *Store) ClearJournal(localID string) error {
	err := os.Remove(s.journalPath(localID))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (s *Store) WriteStatus(st PublicStatus) error {
	st.SchemaVersion = 1
	st.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	// World-readable on purpose: it holds no secrets and doctor reads it
	// without elevation. The directory itself stays 0700 on unix, so the broker
	// also mirrors this file to a readable location when installed.
	return writeJSONAtomic(filepath.Join(s.Dir, "status.json"), st, 0o644)
}

func (s *Store) ReadStatus() (*PublicStatus, error) {
	raw, err := os.ReadFile(filepath.Join(s.Dir, "status.json"))
	if err != nil {
		return nil, err
	}
	var st PublicStatus
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// MappingPath is where the platform mapping file for a platform is written.
func (s *Store) MappingPath(platform string) string {
	return filepath.Join(s.Dir, "mappings", platform+".json")
}

func writeJSONAtomic(path string, v any, perm os.FileMode) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(raw, '\n'), perm)
}

// WriteFileAtomic is exported for the platform-files control call.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	return writeFileAtomic(path, data, perm)
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("brokerstore: temp: %w", err)
	}
	name := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			os.Remove(name)
		}
	}()
	_ = tmp.Chmod(perm)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("brokerstore: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("brokerstore: sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := renameWithRetry(name, path); err != nil {
		return fmt.Errorf("brokerstore: rename: %w", err)
	}
	cleanup = false
	syncDir(dir)
	return nil
}
