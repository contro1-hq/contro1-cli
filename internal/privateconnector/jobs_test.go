package privateconnector

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testInstallation = "pci_0123456789abcdef0123456789abcdef"

func jobKeys(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return priv, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func signJob(priv ed25519.PrivateKey, jobJSON string) *SignedJob {
	return &SignedJob{JobJSON: jobJSON, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(jobJSON)))}
}

func jobJSON(digest string, input string, deadline time.Time) string {
	return `{"action_id":"armaor.get_machines_by_id.call","action_version":1,"contract":"contro1.private-job.v1",` +
		`"deadline":"` + deadline.UTC().Format(time.RFC3339Nano) + `","input":` + input + `,"input_digest":"sha256:x",` +
		`"installation_id":"` + testInstallation + `","invocation_id":"inv_1","lease_token":"lease-1","operation_digest":"` + digest + `"}`
}

// localApp is the customer's application: plain HTTP on loopback, as the
// provider allows only there.
func localApp(t *testing.T, handler http.HandlerFunc) (*Provider, string, string) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	u, _ := url.Parse(server.URL)
	readDigest := "sha256:" + strings.Repeat("1", 64)
	writeDigest := "sha256:" + strings.Repeat("2", 64)
	provider, err := NewProvider(ProviderConfig{
		BaseURL: server.URL + "/rest/", PinnedIP: u.Hostname(),
		Operations: []ProviderOperation{
			{Digest: readDigest, Method: "GET", Path: "/machines/{code}"},
			{Digest: writeDigest, Method: "POST", Path: "/orders", AcceptsBody: true},
		},
		// Plain HTTP on loopback carries no credential (the provider refuses one).
		Auth: ProviderAuth{Mode: "none"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return provider, readDigest, writeDigest
}

func TestVerifyJobChecksTheBytesAndTheInstallation(t *testing.T) {
	priv, pubPEM := jobKeys(t)
	key, err := parseJobKey(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Minute)
	good := jobJSON("sha256:"+strings.Repeat("1", 64), `{"code":"M1","big":12345678901234567890}`, future)
	job, err := VerifyJob(key, signJob(priv, good), testInstallation, time.Now())
	if err != nil {
		t.Fatalf("a valid job was refused: %v", err)
	}
	if job.Input["big"].(json.Number).String() != "12345678901234567890" {
		t.Fatalf("a large number changed on its way through: %v", job.Input["big"])
	}
	tampered := signJob(priv, good)
	tampered.JobJSON = strings.Replace(tampered.JobJSON, "M1", "M2", 1)
	if _, err := VerifyJob(key, tampered, testInstallation, time.Now()); err == nil {
		t.Fatal("a changed job passed its signature")
	}
	if _, err := VerifyJob(key, signJob(priv, good), "pci_ffffffffffffffffffffffffffffffff", time.Now()); err == nil {
		t.Fatal("another installation's job was accepted")
	}
	late := jobJSON("sha256:"+strings.Repeat("1", 64), `{}`, time.Now().Add(-time.Second))
	if _, err := VerifyJob(key, signJob(priv, late), testInstallation, time.Now()); err == nil {
		t.Fatal("a job past its deadline was accepted")
	}
}

func TestExecuteJobSaysWhatHappened(t *testing.T) {
	var gotPath string
	provider, readDigest, writeDigest := localApp(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if strings.HasSuffix(r.URL.Path, "/M9") {
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"error":"no such machine"}`))
			return
		}
		_, _ = w.Write([]byte(`{"name":"Press 4"}`))
	})
	ctx := context.Background()
	deadline := time.Now().Add(time.Minute)
	ok := executeJob(ctx, provider, &Job{InvocationID: "inv_1", LeaseToken: "l", OperationDigest: readDigest, Input: map[string]any{"code": "M1"}, Deadline: deadline})
	if ok.Outcome != "ok" || ok.HTTPStatus != 200 || string(ok.Body) != `{"name":"Press 4"}` || gotPath != "/rest/machines/M1" {
		t.Fatalf("read: %+v path=%q", ok, gotPath)
	}
	missing := executeJob(ctx, provider, &Job{OperationDigest: readDigest, Input: map[string]any{"code": "M9"}, Deadline: deadline})
	if missing.Outcome != "failed" || missing.HTTPStatus != 404 || missing.ErrorCode != "PROVIDER_ERROR" {
		t.Fatalf("a 404 was not a failure: %+v", missing)
	}
	unpinned := executeJob(ctx, provider, &Job{OperationDigest: "sha256:" + strings.Repeat("9", 64), Deadline: deadline})
	if unpinned.Outcome != "failed" || unpinned.ErrorCode != "OPERATION_NOT_PINNED" {
		t.Fatalf("an operation outside the local configuration ran: %+v", unpinned)
	}
	extra := executeJob(ctx, provider, &Job{OperationDigest: readDigest, Input: map[string]any{"code": "M1", "admin": true}, Deadline: deadline})
	if extra.Outcome != "failed" || extra.ErrorCode != "OPERATION_REFUSED" {
		t.Fatalf("an input field outside the pinned operation was sent: %+v", extra)
	}
	nothing := executeJob(ctx, nil, &Job{OperationDigest: readDigest, Deadline: deadline})
	if nothing.Outcome != "failed" || nothing.ErrorCode != "NOT_CONFIGURED" {
		t.Fatalf("no local application, yet: %+v", nothing)
	}

	// The application drops the connection: a read failed, a write may have landed.
	broken, readDigest2, writeDigest2 := localApp(t, func(w http.ResponseWriter, r *http.Request) {
		hijacker, _ := w.(http.Hijacker)
		conn, _, _ := hijacker.Hijack()
		_ = conn.Close()
	})
	read := executeJob(ctx, broken, &Job{OperationDigest: readDigest2, Input: map[string]any{"code": "M1"}, Deadline: deadline})
	if read.Outcome != "failed" {
		t.Fatalf("a dropped read: %+v", read)
	}
	write := executeJob(ctx, broken, &Job{OperationDigest: writeDigest2, Input: map[string]any{"body": map[string]any{"item": "bolt"}}, Deadline: deadline})
	if write.Outcome != "indeterminate" {
		t.Fatalf("a dropped write was called %s; it may have run", write.Outcome)
	}
	_ = writeDigest
}

// A whole run: Contro1 hands out one signed job, the connector runs it against
// the local application and reports; a job left "started" by a crash is
// reported indeterminate and never run again.
func TestRunJobsClaimsRunsAndReports(t *testing.T) {
	priv, pubPEM := jobKeys(t)
	provider, readDigest, _ := localApp(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"name":"Press 4"}`))
	})
	var mu sync.Mutex
	handedOut := false
	reports := []JobReport{}
	cloud := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/api/centcom/v1/private-connectors/jobs/claim":
			if handedOut {
				_, _ = w.Write([]byte(`{"ok":true,"job_json":null}`))
				return
			}
			handedOut = true
			signed := signJob(priv, jobJSON(readDigest, `{"code":"M1"}`, time.Now().Add(time.Minute)))
			raw, _ := json.Marshal(map[string]any{"ok": true, "job_json": signed.JobJSON, "signature": signed.Signature})
			_, _ = w.Write(raw)
		case "/api/centcom/v1/private-connectors/jobs/report":
			var report JobReport
			_ = json.Unmarshal(body, &report)
			reports = append(reports, report)
			_, _ = w.Write([]byte(`{"ok":true,"status":"accepted"}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer cloud.Close()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(cloud.URL, softwareSigner{key})
	if err != nil {
		t.Fatal(err)
	}
	client.http = cloud.Client()
	state := t.TempDir()
	if err := SaveJobKey(state, pubPEM); err != nil {
		t.Fatal(err)
	}
	// A call a previous run started and never finished.
	if err := writePrivateJSON(journalPath(state, "inv_crashed"), journalEntry{State: "started", Method: "POST", LeaseToken: "lease-crashed"}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { runJobs(ctx, client, provider, state, testInstallation, nil); close(done) }()
	for i := 0; i < 100; i++ {
		mu.Lock()
		n := len(reports)
		mu.Unlock()
		if n >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	<-done

	mu.Lock()
	defer mu.Unlock()
	if len(reports) != 2 {
		t.Fatalf("reports: %+v", reports)
	}
	if reports[0].InvocationID != "inv_crashed" || reports[0].Outcome != "indeterminate" || reports[0].LeaseToken != "lease-crashed" {
		t.Fatalf("the crashed call: %+v", reports[0])
	}
	if reports[1].InvocationID != "inv_1" || reports[1].Outcome != "ok" || string(reports[1].Body) != `{"name":"Press 4"}` {
		t.Fatalf("the job: %+v", reports[1])
	}
	if entries, _ := os.ReadDir(filepath.Join(state, "journal")); len(entries) != 0 {
		t.Fatalf("delivered reports were left in the journal: %d", len(entries))
	}
}
