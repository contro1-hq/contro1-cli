package privateconnector

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
)

type softwareSigner struct{ key *ecdsa.PrivateKey }

func (s softwareSigner) Public() *ecdsa.PublicKey { return &s.key.PublicKey }
func (s softwareSigner) SignDigest(digest []byte) ([]byte, error) {
	r, v, err := ecdsa.Sign(rand.Reader, s.key, digest)
	if err != nil {
		return nil, err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	v.FillBytes(sig[32:])
	return sig, nil
}

func verifySignature(pub *ecdsa.PublicKey, statement, signature string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil || len(raw) != 64 {
		return false
	}
	digest := sha256.Sum256([]byte(statement))
	return ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:]))
}

func TestEnrollAndHeartbeatSignExactRequests(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := softwareSigner{key}
	id := "pci_0123456789abcdef0123456789abcdef"
	code := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	hits := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Method != http.MethodPost {
			t.Errorf("method: %s", r.Method)
			w.WriteHeader(405)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		switch r.URL.Path {
		case "/api/centcom/v1/private-connectors/enroll":
			var request struct {
				InstallationID string `json:"installation_id"`
				EnrollmentCode string `json:"enrollment_code"`
				PublicKeyPEM   string `json:"public_key_pem"`
				Proof          string `json:"proof"`
			}
			if err := json.Unmarshal(body, &request); err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			block, _ := pem.Decode([]byte(request.PublicKeyPEM))
			if block == nil {
				t.Error("missing public key")
				w.WriteHeader(400)
				return
			}
			parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			statement := "contro1.private-connector.enroll.v1\n" + id + "\n" + code
			if request.InstallationID != id || request.EnrollmentCode != code || !verifySignature(parsed.(*ecdsa.PublicKey), statement, request.Proof) {
				t.Error("enrollment proof mismatch")
				w.WriteHeader(403)
				return
			}
			_, _ = w.Write([]byte(fmt.Sprintf(`{"ok":true,"installation_id":%q,"job_signing_public_key":"test"}`, id)))
		case "/api/centcom/v1/private-connectors/heartbeat":
			if string(body) != `{"provider_status":"reachable","version":"1.0.0"}` {
				t.Errorf("body: %s", body)
			}
			hash := sha256.Sum256(body)
			statement := "contro1.private-connector.request.v1\nPOST\n" + r.URL.Path + "\n" +
				r.Header.Get("X-Contro1-Timestamp") + "\n" + r.Header.Get("X-Contro1-Nonce") + "\n" + hex.EncodeToString(hash[:])
			if r.Header.Get("X-Contro1-Connector-Id") != id || !verifySignature(&key.PublicKey, statement, r.Header.Get("X-Contro1-Signature")) {
				t.Error("heartbeat proof mismatch")
				w.WriteHeader(403)
				return
			}
			_, _ = w.Write([]byte(`{"ok":true,"status":"active"}`))
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	client, err := NewClient(server.URL, signer)
	if err != nil {
		t.Fatal(err)
	}
	client.http = server.Client()
	if _, err := client.Enroll(context.Background(), id, code); err != nil {
		t.Fatal(err)
	}
	if err := client.HeartbeatWithProviderStatus(context.Background(), id, "1.0.0", "reachable"); err != nil {
		t.Fatal(err)
	}
	if hits != 2 {
		t.Fatalf("wanted two calls; got %d", hits)
	}
}

func TestRejectsPlainHTTP(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := NewClient("http://192.168.1.162:3001", softwareSigner{key}); err == nil {
		t.Fatal("cloud connection accepted plain HTTP")
	}
}
