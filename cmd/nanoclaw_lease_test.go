package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRenewDueAWeekBeforeExpiry(t *testing.T) {
	now := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		expires time.Time
		due     bool
	}{
		{now.Add(30 * 24 * time.Hour), false},
		{now.Add(8 * 24 * time.Hour), false},
		{now.Add(7 * 24 * time.Hour), true},
		{now.Add(time.Hour), true},
		{time.Time{}, true}, // unknown expiry: renew rather than guess
	}
	for _, c := range cases {
		if got := renewDue(nanoLease{ExpiresAt: c.expires}, now); got != c.due {
			t.Fatalf("expires %v: due=%v, want %v", c.expires, got, c.due)
		}
	}
}

func TestNanoLeaseStateReplacesSameSubject(t *testing.T) {
	// os.UserHomeDir reads USERPROFILE on Windows, not HOME: set both, or the
	// test reads and writes the real ~/.contro1 of whoever runs it.
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("USERPROFILE", homeDir)
	first := nanoLease{Subject: "g1", LeaseID: "lse_aaaaaaaa", ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Second)}
	if err := recordNanoLease(first); err != nil {
		t.Fatal(err)
	}
	if err := recordNanoLease(nanoLease{Subject: "g2", LeaseID: "lse_bbbbbbbb"}); err != nil {
		t.Fatal(err)
	}
	if err := recordNanoLease(nanoLease{Subject: "g1", LeaseID: "lse_cccccccc"}); err != nil {
		t.Fatal(err)
	}
	path, _ := nanoLeasePath()
	if filepath.Base(path) != "nanoclaw-leases.json" {
		t.Fatalf("unexpected path %s", path)
	}
	state, err := loadNanoLeases(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Leases) != 2 {
		t.Fatalf("want one entry per subject, got %+v", state.Leases)
	}
	for _, l := range state.Leases {
		if l.Subject == "g1" && l.LeaseID != "lse_cccccccc" {
			t.Fatalf("g1 kept the old lease: %+v", l)
		}
	}
}

func fakeOnecli(t *testing.T, secret *string) onecliRunner {
	return func(_ context.Context, args ...string) ([]byte, error) {
		switch args[0] + " " + args[1] {
		case "agents list":
			return []byte(`[{"id":"onecli-agent-1","identifier":"g1"}]`), nil
		case "secrets create":
			*secret = "created"
			return []byte(`{"id":"secret-new"}`), nil
		case "agents grants":
			return []byte(`{}`), nil
		case "secrets list":
			return []byte(`[]`), nil
		}
		t.Fatalf("unexpected OneCLI call %v", args)
		return nil, nil
	}
}

func TestRenewNanoLeaseHandsNewLeaseToOnecliAndRecordsIt(t *testing.T) {
	// os.UserHomeDir reads USERPROFILE on Windows, not HOME: set both, or the
	// test reads and writes the real ~/.contro1 of whoever runs it.
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("USERPROFILE", homeDir)
	var gotPath, gotBody string
	prev := brokerPoster
	brokerPoster = func(_ context.Context, endpoint, path string, body []byte) (int, []byte, error) {
		if endpoint != "unix:///run/contro1/ep/loc_x.sock" {
			t.Fatalf("renewal went through the wrong endpoint: %s", endpoint)
		}
		gotPath, gotBody = path, string(body)
		raw, _ := json.Marshal(map[string]string{"lease": "ccr_live_new", "lease_id": "lse_newnewnew", "expires_at": "2026-10-29T00:00:00Z"})
		return 200, raw, nil
	}
	defer func() { brokerPoster = prev }()

	var secret string
	old := nanoLease{Subject: "g1", LeaseID: "lse_oldoldold", Endpoint: "unix:///run/contro1/ep/loc_x.sock"}
	renewed, err := renewNanoLease(context.Background(), old, fakeOnecli(t, &secret))
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/centcom/v1/runtime/nanoclaw/mcp-lease/renew" || !strings.Contains(gotBody, "lse_oldoldold") {
		t.Fatalf("wrong renewal request: %s %s", gotPath, gotBody)
	}
	if secret != "created" || renewed.LeaseID != "lse_newnewnew" || renewed.ExpiresAt.Format("2006-01-02") != "2026-10-29" {
		t.Fatalf("renewal not applied: %+v", renewed)
	}
	path, _ := nanoLeasePath()
	state, _ := loadNanoLeases(path)
	if len(state.Leases) != 1 || state.Leases[0].LeaseID != "lse_newnewnew" {
		t.Fatalf("new lease not recorded: %+v", state.Leases)
	}
}

func TestRenewNanoLeaseLapsedNeedsOwner(t *testing.T) {
	// os.UserHomeDir reads USERPROFILE on Windows, not HOME: set both, or the
	// test reads and writes the real ~/.contro1 of whoever runs it.
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("USERPROFILE", homeDir)
	prev := brokerPoster
	brokerPoster = func(context.Context, string, string, []byte) (int, []byte, error) {
		return 409, []byte(`{"error":"lease_not_live"}`), nil
	}
	defer func() { brokerPoster = prev }()
	_, err := renewNanoLease(context.Background(), nanoLease{Subject: "g1", LeaseID: "lse_oldoldold", Endpoint: "unix:///x.sock"},
		func(context.Context, ...string) ([]byte, error) { return nil, errors.New("OneCLI must not be called") })
	if err == nil || !strings.Contains(err.Error(), "approve the connection again") {
		t.Fatalf("a lapsed lease must send the person to the owner, got %v", err)
	}
}
