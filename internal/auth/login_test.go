package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

// TestPKCEChallenge verifies the S256 relationship the backend re-checks:
// challenge == base64url(sha256(verifier)).
func TestPKCEChallenge(t *testing.T) {
	verifier, challenge, err := pkce()
	if err != nil {
		t.Fatalf("pkce() error: %v", err)
	}
	if verifier == "" || challenge == "" {
		t.Fatal("pkce returned empty values")
	}
	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if challenge != want {
		t.Errorf("challenge mismatch: got %q want %q", challenge, want)
	}
	if strings.ContainsAny(challenge, "+/=") {
		t.Errorf("challenge must be base64url (no +/=): %q", challenge)
	}
}

func TestBuildAuthorizeURL(t *testing.T) {
	loop := buildAuthorizeURL("http://localhost:3000", "CH", "ST", "dev box", "http://127.0.0.1:5000/callback", false)
	if !strings.Contains(loop, "challenge=CH") || !strings.Contains(loop, "redirect=") || strings.Contains(loop, "mode=manual") {
		t.Errorf("loopback URL malformed: %s", loop)
	}
	manual := buildAuthorizeURL("http://localhost:3000", "CH", "ST", "dev box", "", true)
	if !strings.Contains(manual, "mode=manual") || strings.Contains(manual, "redirect=") {
		t.Errorf("manual URL malformed: %s", manual)
	}
}
