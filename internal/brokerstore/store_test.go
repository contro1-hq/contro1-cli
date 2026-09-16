package brokerstore

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestStateAndSecrets(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if _, err := Open(dir); !errors.Is(err, ErrLocked) {
		t.Fatalf("a second broker on the same directory must be refused, got %v", err)
	}

	_, err = s.UpdateState(func(st *State) error {
		st.APIURL = "https://api.contro1.test"
		st.Enrollments = append(st.Enrollments, Enrollment{LocalID: "loc_b", EnrollmentID: "enr_b", State: "pending"}, Enrollment{LocalID: "loc_a", EnrollmentID: "enr_a", State: "active"})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	st, err := s.LoadState()
	if err != nil || len(st.Enrollments) != 2 || st.Enrollments[0].LocalID != "loc_a" {
		t.Fatalf("state round trip failed: %+v %v", st, err)
	}

	secret := "ccrt_super_secret_value"
	if err := s.SaveSecrets("loc_a", Secrets{RefreshToken: secret}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "secrets", "loc_a.json"))
	if runtime.GOOS == "windows" && bytes.Contains(raw, []byte(secret)) {
		t.Fatal("on Windows secrets must be sealed at rest")
	}
	stateRaw, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	if bytes.Contains(stateRaw, []byte(secret)) {
		t.Fatal("state.json must never contain a secret")
	}
	got, err := s.LoadSecrets("loc_a")
	if err != nil || got.RefreshToken != secret {
		t.Fatalf("secrets round trip: %+v %v", got, err)
	}

	if err := s.WriteJournal(Journal{LocalID: "loc_a", StartedAt: "now", PresentedHashPrefix: "abcd"}); err != nil {
		t.Fatal(err)
	}
	j, _ := s.ReadJournal("loc_a")
	if j == nil || j.PresentedHashPrefix != "abcd" {
		t.Fatal("journal round trip")
	}
	_ = s.ClearJournal("loc_a")
	if j, _ := s.ReadJournal("loc_a"); j != nil {
		t.Fatal("journal must clear")
	}
}

// A crash after the temp file is written but before rename leaves the old
// state intact and readable.
func TestCrashBeforeRenameKeepsOldState(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.SaveState(&State{APIURL: "https://old.test"}); err != nil {
		t.Fatal(err)
	}
	// Simulate the partial write.
	if err := os.WriteFile(filepath.Join(dir, ".tmp-crashed"), []byte(`{"api_url":"https://half`), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := s.LoadState()
	if err != nil || st.APIURL != "https://old.test" {
		t.Fatalf("old state must survive: %+v %v", st, err)
	}
}

// The lock holds across processes, not only goroutines.
func TestLockAcrossProcesses(t *testing.T) {
	if os.Getenv("BROKERSTORE_LOCK_CHILD") != "" {
		_, err := Open(os.Getenv("BROKERSTORE_LOCK_CHILD"))
		if errors.Is(err, ErrLocked) {
			os.Exit(3)
		}
		os.Exit(0)
	}
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cmd := exec.Command(os.Args[0], "-test.run", "TestLockAcrossProcesses")
	cmd.Env = append(os.Environ(), "BROKERSTORE_LOCK_CHILD="+dir)
	err = cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 3 {
		t.Fatalf("child process must see ErrLocked, got %v", err)
	}
}
