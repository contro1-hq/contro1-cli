package privateconnector

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Job is one call Contro1 authorized for this installation. It is parsed only
// after its signature verified over the exact bytes received (VerifyJob).
type Job struct {
	Contract        string         `json:"contract"`
	InvocationID    string         `json:"invocation_id"`
	InstallationID  string         `json:"installation_id"`
	ActionID        string         `json:"action_id"`
	ActionVersion   int            `json:"action_version"`
	OperationDigest string         `json:"operation_digest"`
	InputDigest     string         `json:"input_digest"`
	Input           map[string]any `json:"input"`
	Deadline        time.Time      `json:"deadline"`
	LeaseToken      string         `json:"lease_token"`
}

// JobReport is what goes back: the outcome, and the application's answer.
type JobReport struct {
	InvocationID string          `json:"invocation_id"`
	LeaseToken   string          `json:"lease_token"`
	Outcome      string          `json:"outcome"` // ok, failed, indeterminate
	HTTPStatus   int             `json:"http_status,omitempty"`
	Body         json.RawMessage `json:"body,omitempty"`
	ErrorCode    string          `json:"error_code,omitempty"`
	ErrorMessage string          `json:"error_message,omitempty"`
}

const jobKeyFile = "job-signing-key.pem"

var invocationIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,120}$`)

// SaveJobKey keeps Contro1's job-signing key, received at enrollment over the
// authenticated channel. Jobs not signed by it are refused.
func SaveJobKey(stateDir, publicKeyPEM string) error {
	if _, err := parseJobKey(publicKeyPEM); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(stateDir, jobKeyFile), []byte(publicKeyPEM), 0o600)
}

func parseJobKey(publicKeyPEM string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("job signing key is not a PEM public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("job signing key is not Ed25519")
	}
	return key, nil
}

func loadJobKey(stateDir string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(filepath.Join(stateDir, jobKeyFile))
	if err != nil {
		return nil, err
	}
	return parseJobKey(string(raw))
}

// VerifyJob checks Contro1's signature over the received bytes, then that the
// job is for this installation and still within its time. Numbers keep their
// exact text (UseNumber), so a large id is sent to the application unchanged.
func VerifyJob(key ed25519.PublicKey, signed *SignedJob, installationID string, now time.Time) (*Job, error) {
	signature, err := base64.RawURLEncoding.DecodeString(signed.Signature)
	if err != nil || !ed25519.Verify(key, []byte(signed.JobJSON), signature) {
		return nil, errors.New("job signature is invalid")
	}
	decoder := json.NewDecoder(strings.NewReader(signed.JobJSON))
	decoder.UseNumber()
	var job Job
	if err := decoder.Decode(&job); err != nil {
		return nil, fmt.Errorf("job is unreadable: %w", err)
	}
	if job.Contract != "contro1.private-job.v1" {
		return nil, errors.New("job contract is unknown")
	}
	if job.InstallationID != installationID {
		return nil, errors.New("job is for another installation")
	}
	if !invocationIDPattern.MatchString(job.InvocationID) || job.LeaseToken == "" {
		return nil, errors.New("job is malformed")
	}
	if !job.Deadline.After(now) {
		return nil, errors.New("job deadline has passed")
	}
	return &job, nil
}

// executeJob runs the one pinned operation the job names and says what happened.
// A write that may have reached the application without an answer is
// indeterminate, never "failed", so nobody repeats it believing it did not run.
func executeJob(ctx context.Context, provider *Provider, job *Job) JobReport {
	report := JobReport{InvocationID: job.InvocationID, LeaseToken: job.LeaseToken}
	if provider == nil {
		report.Outcome, report.ErrorCode = "failed", "NOT_CONFIGURED"
		report.ErrorMessage = "The local application is not configured on this connector; nothing ran."
		return report
	}
	op, pinned := provider.operations[job.OperationDigest]
	if !pinned {
		report.Outcome, report.ErrorCode = "failed", "OPERATION_NOT_PINNED"
		report.ErrorMessage = "This operation is not in the connector's local configuration; nothing ran. Update the setup and reinstall."
		return report
	}
	runCtx, cancel := context.WithDeadline(ctx, job.Deadline)
	defer cancel()
	status, body, err := provider.Execute(runCtx, job.OperationDigest, job.Input)
	switch {
	case errors.Is(err, ErrProviderUncertain):
		if strings.EqualFold(op.Method, "GET") {
			report.Outcome, report.ErrorCode = "failed", "PROVIDER_UNREACHABLE"
			report.ErrorMessage = "The local application did not answer."
		} else {
			report.Outcome = "indeterminate"
		}
	case err != nil && status >= 200 && status < 300:
		// It ran and answered without JSON: done, with nothing to show.
		report.Outcome, report.HTTPStatus = "ok", status
	case err != nil && status == 0:
		report.Outcome, report.ErrorCode = "failed", "OPERATION_REFUSED"
		report.ErrorMessage = err.Error() + "; nothing ran."
	case err != nil || status < 200 || status >= 300:
		report.Outcome, report.ErrorCode, report.HTTPStatus = "failed", "PROVIDER_ERROR", status
		report.ErrorMessage = fmt.Sprintf("The local application answered HTTP %d.", status)
	default:
		report.Outcome, report.HTTPStatus, report.Body = "ok", status, body
	}
	return report
}

// journalEntry is written before the application is called and again after,
// so a crash in between is reported indeterminate rather than run twice.
type journalEntry struct {
	State      string     `json:"state"` // started, finished
	Method     string     `json:"method"`
	LeaseToken string     `json:"lease_token"`
	Report     *JobReport `json:"report,omitempty"`
	Started    time.Time  `json:"started"`
}

func journalPath(stateDir, invocationID string) string {
	return filepath.Join(stateDir, "journal", invocationID+".json")
}

// sendReport delivers a report and forgets the journal entry once Contro1
// took it or refused it for good. Any other failure leaves it for a retry.
func sendReport(ctx context.Context, client *Client, stateDir, installationID string, report JobReport) error {
	raw, err := json.Marshal(report)
	if err != nil {
		return err
	}
	err = client.ReportJob(ctx, installationID, raw)
	if err == nil || errors.Is(err, ErrReportRefused) {
		_ = os.Remove(journalPath(stateDir, report.InvocationID))
		return nil
	}
	return err
}

// replayJournal settles what a previous run left: a finished job's report is
// sent again, a started one is reported indeterminate (a read: failed). Nothing
// in the journal is ever executed again.
func replayJournal(ctx context.Context, client *Client, stateDir, installationID string) {
	entries, err := os.ReadDir(filepath.Join(stateDir, "journal"))
	if err != nil {
		return
	}
	for _, entry := range entries {
		id := strings.TrimSuffix(entry.Name(), ".json")
		if entry.IsDir() || !invocationIDPattern.MatchString(id) {
			continue
		}
		raw, err := os.ReadFile(journalPath(stateDir, id))
		if err != nil {
			continue
		}
		var saved journalEntry
		if json.Unmarshal(raw, &saved) != nil {
			continue
		}
		report := saved.Report
		if saved.State != "finished" || report == nil {
			report = &JobReport{InvocationID: id, LeaseToken: saved.LeaseToken, Outcome: "indeterminate"}
			if strings.EqualFold(saved.Method, "GET") {
				report.Outcome, report.ErrorCode = "failed", "CONNECTOR_RESTARTED"
				report.ErrorMessage = "The connector restarted during the call."
			}
		}
		_ = sendReport(ctx, client, stateDir, installationID, *report)
	}
}

// runJobs pulls and runs this installation's jobs until ctx ends. One at a
// time: an on-prem application is usually a single server, and a queue that
// runs in order is easier for its owner to reason about.
func runJobs(ctx context.Context, client *Client, provider *Provider, stateDir, installationID string, report func(string)) {
	say := func(message string) {
		if report != nil {
			report(message)
		}
	}
	key, err := loadJobKey(stateDir)
	if err != nil {
		say("jobs: no job verification key; reinstall this installation from a new setup file")
		return
	}
	replayJournal(ctx, client, stateDir, installationID)
	for ctx.Err() == nil {
		signed, err := client.ClaimJob(ctx, installationID)
		if err != nil {
			say("jobs: claim failed: " + err.Error())
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}
		if signed == nil {
			continue
		}
		job, err := VerifyJob(key, signed, installationID, time.Now())
		if err != nil {
			// Not answerable: without a verified job there is no lease to report under.
			say("jobs: refused a job: " + err.Error())
			continue
		}
		method := ""
		if provider != nil {
			method = provider.operations[job.OperationDigest].Method
		}
		// Journal first. If it cannot be written, the call is not made.
		if err := writePrivateJSON(journalPath(stateDir, job.InvocationID), journalEntry{State: "started", Method: method, LeaseToken: job.LeaseToken, Started: time.Now().UTC()}); err != nil {
			say("jobs: journal unavailable, not running " + job.InvocationID + ": " + err.Error())
			continue
		}
		result := executeJob(ctx, provider, job)
		_ = writePrivateJSON(journalPath(stateDir, job.InvocationID), journalEntry{State: "finished", Method: method, LeaseToken: job.LeaseToken, Report: &result, Started: time.Now().UTC()})
		if err := sendReport(ctx, client, stateDir, installationID, result); err != nil {
			say("jobs: report for " + job.InvocationID + " not delivered yet: " + err.Error())
		}
	}
}
