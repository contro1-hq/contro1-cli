// Package dpop builds RFC 9449 DPoP proofs for the Contro1 runtime. The private
// key never leaves its Signer: this package only sees public keys and digests.
package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"
)

// Signer signs a SHA-256 digest with a P-256 key and returns the raw 64-byte
// R||S signature. Hardware-backed keystores implement it without exposing the
// private key.
type Signer interface {
	Public() *ecdsa.PublicKey
	SignDigest(digest []byte) ([]byte, error)
}

// JWK is the public P-256 JWK carried in a proof header.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

var b64 = base64.RawURLEncoding

func pad32(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// PublicJWK encodes a P-256 public key.
func PublicJWK(pub *ecdsa.PublicKey) (JWK, error) {
	if pub == nil || pub.Curve != elliptic.P256() {
		return JWK{}, errors.New("dpop: key must be P-256")
	}
	raw, err := pub.ECDH()
	if err != nil {
		return JWK{}, fmt.Errorf("dpop: %w", err)
	}
	b := raw.Bytes() // 0x04 || X || Y
	return JWK{Kty: "EC", Crv: "P-256", X: b64.EncodeToString(b[1:33]), Y: b64.EncodeToString(b[33:65])}, nil
}

// Thumbprint is the RFC 7638 SHA-256 JWK thumbprint (base64url).
func Thumbprint(j JWK) string {
	canonical := fmt.Sprintf(`{"crv":"%s","kty":"%s","x":"%s","y":"%s"}`, j.Crv, j.Kty, j.X, j.Y)
	sum := sha256.Sum256([]byte(canonical))
	return b64.EncodeToString(sum[:])
}

// KeyThumbprint is Thumbprint(PublicJWK(pub)).
func KeyThumbprint(pub *ecdsa.PublicKey) (string, error) {
	j, err := PublicJWK(pub)
	if err != nil {
		return "", err
	}
	return Thumbprint(j), nil
}

// AccessTokenHash is the `ath` claim.
func AccessTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return b64.EncodeToString(sum[:])
}

// ProofInput describes one request.
type ProofInput struct {
	Method      string
	URL         string // absolute; query and fragment are dropped
	AccessToken string // optional; sets ath
	Nonce       string // optional
	Now         time.Time
	Extra       map[string]any // extra payload members (key rotation)
}

// NewProof returns a compact JWS DPoP proof.
func NewProof(s Signer, in ProofInput) (string, error) {
	jwk, err := PublicJWK(s.Public())
	if err != nil {
		return "", err
	}
	htu, err := normalizeHTU(in.URL)
	if err != nil {
		return "", err
	}
	jti := make([]byte, 18)
	if _, err := rand.Read(jti); err != nil {
		return "", fmt.Errorf("dpop: jti: %w", err)
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	payload := map[string]any{
		"htm": strings.ToUpper(in.Method),
		"htu": htu,
		"iat": now.Unix(),
		"jti": b64.EncodeToString(jti),
	}
	if in.AccessToken != "" {
		payload["ath"] = AccessTokenHash(in.AccessToken)
	}
	if in.Nonce != "" {
		payload["nonce"] = in.Nonce
	}
	for k, v := range in.Extra {
		payload[k] = v
	}
	header := map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	signingInput := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := s.SignDigest(digest[:])
	if err != nil {
		return "", fmt.Errorf("dpop: sign: %w", err)
	}
	if len(sig) != 64 {
		return "", fmt.Errorf("dpop: signer returned %d bytes, want 64", len(sig))
	}
	return signingInput + "." + b64.EncodeToString(sig), nil
}

// NewKeyRotationProof is signed by the NEW key and names the current key.
func NewKeyRotationProof(newKey Signer, rotationURL, oldJKT string, now time.Time) (string, error) {
	return NewProof(newKey, ProofInput{Method: "POST", URL: rotationURL, Now: now, Extra: map[string]any{"old_jkt": oldJKT}})
}

func normalizeHTU(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "", fmt.Errorf("dpop: htu must be an absolute http(s) URL")
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

// ---------------------------------------------------------------------------
// Software signer, for tests and development file keys.
// ---------------------------------------------------------------------------

// SoftwareSigner wraps an in-memory ECDSA key.
type SoftwareSigner struct{ Key *ecdsa.PrivateKey }

func (s SoftwareSigner) Public() *ecdsa.PublicKey { return &s.Key.PublicKey }

func (s SoftwareSigner) SignDigest(digest []byte) ([]byte, error) {
	r, sv, err := ecdsa.Sign(rand.Reader, s.Key, digest)
	if err != nil {
		return nil, err
	}
	return append(pad32(r.Bytes()), pad32(sv.Bytes())...), nil
}

// VerifyRaw verifies a raw R||S signature (tests and self-checks).
func VerifyRaw(pub *ecdsa.PublicKey, digest, sig []byte) bool {
	if len(sig) != 64 {
		return false
	}
	return ecdsa.Verify(pub, digest, new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
}

// ASN1ToRaw converts a DER ECDSA signature into 64-byte R||S.
func ASN1ToRaw(der []byte) ([]byte, error) {
	// SEQUENCE { INTEGER r, INTEGER s }
	if len(der) < 8 || der[0] != 0x30 {
		return nil, errors.New("dpop: bad DER signature")
	}
	idx := 2
	if der[1]&0x80 != 0 {
		idx = 2 + int(der[1]&0x7f)
	}
	readInt := func() ([]byte, error) {
		if idx+2 > len(der) || der[idx] != 0x02 {
			return nil, errors.New("dpop: bad DER integer")
		}
		l := int(der[idx+1])
		start := idx + 2
		if start+l > len(der) {
			return nil, errors.New("dpop: short DER integer")
		}
		idx = start + l
		return der[start : start+l], nil
	}
	r, err := readInt()
	if err != nil {
		return nil, err
	}
	s, err := readInt()
	if err != nil {
		return nil, err
	}
	return append(pad32(trimZero(r)), pad32(trimZero(s))...), nil
}

func trimZero(b []byte) []byte {
	for len(b) > 1 && b[0] == 0 {
		b = b[1:]
	}
	return b
}
