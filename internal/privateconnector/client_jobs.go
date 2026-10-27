package privateconnector

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// HTTPStatusError is a non-2xx answer from Contro1.
type HTTPStatusError struct{ Code int }

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("connector API returned HTTP %d", e.Code)
}

// maxJobResponse bounds a claim answer, which carries the job's input.
const maxJobResponse = 2 << 20

// signedHeaders signs one request over the exact body bytes sent.
func (c *Client) signedHeaders(installationID, path string, body []byte) (http.Header, error) {
	timestamp := fmt.Sprint(time.Now().UnixMilli())
	nonceBytes := make([]byte, 24)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, err
	}
	nonce := hex.EncodeToString(nonceBytes)
	bodyHash := sha256.Sum256(body)
	statement := "contro1.private-connector.request.v1\nPOST\n" + path + "\n" + timestamp + "\n" + nonce + "\n" + hex.EncodeToString(bodyHash[:])
	signature, err := signStatement(c.signer, statement)
	if err != nil {
		return nil, err
	}
	headers := http.Header{}
	headers.Set("X-Contro1-Connector-Id", installationID)
	headers.Set("X-Contro1-Timestamp", timestamp)
	headers.Set("X-Contro1-Nonce", nonce)
	headers.Set("X-Contro1-Signature", signature)
	return headers, nil
}

// SignedJob is a job as Contro1 sent it: the signed bytes and their signature.
// The bytes are verified before they are parsed (VerifyJob).
type SignedJob struct {
	JobJSON   string `json:"job_json"`
	Signature string `json:"signature"`
}

// ClaimJob asks for the next job. Contro1 holds the request open for up to 20
// seconds while there is none, so work is picked up within a moment without
// asking every second. Nil means nothing is waiting.
func (c *Client) ClaimJob(ctx context.Context, installationID string) (*SignedJob, error) {
	const path = "/api/centcom/v1/private-connectors/jobs/claim"
	body := []byte("{}")
	headers, err := c.signedHeaders(installationID, path, body)
	if err != nil {
		return nil, err
	}
	claimCtx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(claimCtx, http.MethodPost, c.endpoint(path), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header = headers
	req.Header.Set("Content-Type", "application/json")
	// The long poll outlives the client's usual timeout; the context bounds it.
	long := *c.http
	long.Timeout = 0
	res, err := long.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, &HTTPStatusError{Code: res.StatusCode}
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxJobResponse+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxJobResponse {
		return nil, errors.New("connector claim response exceeded limit")
	}
	var result struct {
		OK        bool    `json:"ok"`
		JobJSON   *string `json:"job_json"`
		Signature string  `json:"signature"`
	}
	if err := json.Unmarshal(raw, &result); err != nil || !result.OK {
		return nil, errors.New("connector claim response is invalid")
	}
	if result.JobJSON == nil {
		return nil, nil
	}
	return &SignedJob{JobJSON: *result.JobJSON, Signature: result.Signature}, nil
}

// ErrReportRefused means Contro1 will not take this report: the job is not held
// by this installation, the lease token is wrong, or its time ran out. The
// report is final either way and is not sent again.
var ErrReportRefused = errors.New("connector report refused")

// ReportJob sends the result of a job.
func (c *Client) ReportJob(ctx context.Context, installationID string, report []byte) error {
	const path = "/api/centcom/v1/private-connectors/jobs/report"
	headers, err := c.signedHeaders(installationID, path, report)
	if err != nil {
		return err
	}
	_, err = c.post(ctx, path, report, headers)
	var status *HTTPStatusError
	if errors.As(err, &status) && status.Code == http.StatusConflict {
		return ErrReportRefused
	}
	return err
}
