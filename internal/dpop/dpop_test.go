package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type vectorFile struct {
	Key struct {
		PrivateJWK struct{ D, X, Y string } `json:"private_jwk"`
		PublicJWK  JWK                      `json:"public_jwk"`
		JKT        string                   `json:"jkt"`
	} `json:"key"`
	AccessToken struct {
		Value string `json:"value"`
		Ath   string `json:"ath"`
	} `json:"access_token"`
	Valid []struct {
		Name  string `json:"name"`
		Proof string `json:"proof"`
	} `json:"valid"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	path := filepath.Join("..", "..", "..", "packages", "protocol", "test-vectors", "runtime", "dpop-vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("shared vectors not available: %v", err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func vectorKey(t *testing.T, v vectorFile) *ecdsa.PrivateKey {
	t.Helper()
	d, _ := base64.RawURLEncoding.DecodeString(v.Key.PrivateJWK.D)
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestSharedVectors(t *testing.T) {
	v := loadVectors(t)
	if got := Thumbprint(v.Key.PublicJWK); got != v.Key.JKT {
		t.Fatalf("thumbprint %s want %s", got, v.Key.JKT)
	}
	if got := AccessTokenHash(v.AccessToken.Value); got != v.AccessToken.Ath {
		t.Fatalf("ath %s want %s", got, v.AccessToken.Ath)
	}
	key := vectorKey(t, v)
	jwk, err := PublicJWK(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if jwk != v.Key.PublicJWK {
		t.Fatalf("public JWK derived from d does not match the vector: %+v", jwk)
	}
	// The valid server-side vectors verify with the same key in Go.
	for _, c := range v.Valid {
		parts := strings.Split(c.Proof, ".")
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if !VerifyRaw(&key.PublicKey, digest[:], sig) {
			t.Fatalf("vector %s does not verify in Go", c.Name)
		}
	}
}

func TestNewProofShape(t *testing.T) {
	v := loadVectors(t)
	signer := SoftwareSigner{Key: vectorKey(t, v)}
	proof, err := NewProof(signer, ProofInput{
		Method: "get", URL: "https://api.contro1.test/api/centcom/v1/runtime/status?x=1#f",
		AccessToken: v.AccessToken.Value, Nonce: "n1", Now: time.Unix(1767225600, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatal("compact JWS expected")
	}
	var header struct {
		Typ, Alg string
		JWK      JWK
	}
	var payload map[string]any
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	pb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(hb, &header)
	_ = json.Unmarshal(pb, &payload)
	if header.Typ != "dpop+jwt" || header.Alg != "ES256" || Thumbprint(header.JWK) != v.Key.JKT {
		t.Fatalf("bad header %+v", header)
	}
	if payload["htm"] != "GET" || payload["htu"] != "https://api.contro1.test/api/centcom/v1/runtime/status" {
		t.Fatalf("bad htm/htu %+v", payload)
	}
	if payload["ath"] != v.AccessToken.Ath || payload["nonce"] != "n1" || payload["iat"].(float64) != 1767225600 {
		t.Fatalf("bad claims %+v", payload)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if len(sig) != 64 || !VerifyRaw(signer.Public(), digest[:], sig) {
		t.Fatal("signature must be 64-byte R||S and verify")
	}
	if _, err := NewProof(signer, ProofInput{Method: "GET", URL: "/relative"}); err == nil {
		t.Fatal("relative htu must be refused")
	}
}
