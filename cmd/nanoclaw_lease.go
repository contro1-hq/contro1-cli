package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/contro1-hq/contro1-cli/internal/config"
	"github.com/contro1-hq/contro1-cli/internal/localipc"
	"github.com/contro1-hq/contro1-cli/internal/platforms"
)

/*
KEEPING THE NANOCLAW MCP LEASE ALIVE.

A NanoClaw agent reaches Contro1's MCP server through OneCLI, which injects a
bearer lease the host gave it. A lease expires in at most 30 days and nothing
renewed it, so every NanoClaw agent lost Contro1 a month after setup: OneCLI
kept sending a dead lease and every call came back 401, which read to everyone
involved like a server bug.

OneCLI refreshes OAuth tokens only for the providers compiled into it; a
custom service is a static secret to it. So the host renews: this file records
which lease was handed to OneCLI, and `contro1 apps renew-nanoclaw`, run on a
schedule, swaps it for a new one well before it expires. The broker proves the
request with its DPoP key, and the server only extends a lease that is still
live, so a lapsed one still needs the owner.
*/

// renewBefore is how long before expiry a lease is renewed. Wide on purpose:
// a host that is off for a week should still come back with a working agent.
const renewBefore = 7 * 24 * time.Hour

const renewCronMarker = "# contro1-nanoclaw-lease-renew"

type nanoLease struct {
	Subject   string    `json:"subject"`
	LeaseID   string    `json:"lease_id"`
	ExpiresAt time.Time `json:"expires_at"`
	// The agent's broker endpoint. Empty when the lease was issued from the
	// operator CLI; renewal then looks the connection up by subject.
	Endpoint string `json:"endpoint,omitempty"`
}

type nanoLeaseFile struct {
	Leases []nanoLease `json:"leases"`
}

func nanoLeasePath() (string, error) {
	dir, err := config.Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "nanoclaw-leases.json"), nil
}

func loadNanoLeases(path string) (nanoLeaseFile, error) {
	var f nanoLeaseFile
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return f, err
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return f, fmt.Errorf("%s is unreadable: %w", path, err)
	}
	return f, nil
}

// saveNanoLeases writes atomically: a half-written file would lose the only
// record of which lease OneCLI holds.
func saveNanoLeases(path string, f nanoLeaseFile) error {
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// recordNanoLease remembers the lease just handed to OneCLI, replacing any
// earlier one for the same agent group.
func recordNanoLease(l nanoLease) error {
	path, err := nanoLeasePath()
	if err != nil {
		return err
	}
	f, err := loadNanoLeases(path)
	if err != nil {
		return err
	}
	kept := f.Leases[:0]
	for _, existing := range f.Leases {
		if existing.Subject != l.Subject {
			kept = append(kept, existing)
		}
	}
	f.Leases = append(kept, l)
	return saveNanoLeases(path, f)
}

func renewDue(l nanoLease, now time.Time) bool {
	return l.ExpiresAt.IsZero() || !now.Add(renewBefore).Before(l.ExpiresAt)
}

type renewedLease struct {
	Lease     string `json:"lease"`
	LeaseID   string `json:"lease_id"`
	ExpiresAt string `json:"expires_at"`
}

// brokerPoster sends one JSON POST through the agent's own broker endpoint and
// returns the status and body. A variable so tests can stand in for the broker.
var brokerPoster = func(ctx context.Context, endpoint, path string, body []byte) (int, []byte, error) {
	ep, err := localipc.ParseEndpoint(endpoint)
	if err != nil {
		return 0, nil, errors.New("invalid broker endpoint")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, localipc.BaseURL+path, strings.NewReader(string(body)))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := localipc.HTTPClient(ep, brokerServerPrincipal()).Do(req)
	if err != nil {
		return 0, nil, errors.New("the Contro1 host service did not answer")
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return resp.StatusCode, raw, nil
}

// renewNanoLease swaps one lease for a new one and hands it to OneCLI. The old
// lease stays valid for the server's overlap window, so the agent never sees a
// gap while OneCLI switches over.
func renewNanoLease(ctx context.Context, l nanoLease, run onecliRunner) (nanoLease, error) {
	endpoint := l.Endpoint
	if endpoint == "" {
		conn, err := platforms.SelectLocalConnection(l.Subject)
		if err != nil {
			return l, fmt.Errorf("no connection on this computer for %s: %w", l.Subject, err)
		}
		endpoint = conn.Endpoint
	}
	body, _ := json.Marshal(map[string]string{"lease_id": l.LeaseID})
	status, raw, err := brokerPoster(ctx, endpoint, "/api/centcom/v1/runtime/nanoclaw/mcp-lease/renew", body)
	if err != nil {
		return l, err
	}
	if status != http.StatusOK {
		var refusal struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(raw, &refusal)
		if refusal.Error == "lease_not_live" {
			return l, errors.New("the lease already expired or was revoked. Its owner has to approve the connection again: contro1 apps enable nanoclaw --agent " + l.Subject)
		}
		return l, fmt.Errorf("Contro1 refused the renewal (HTTP %d %s)", status, refusal.Error)
	}
	var next renewedLease
	if err := json.Unmarshal(raw, &next); err != nil || next.Lease == "" || next.LeaseID == "" {
		return l, errors.New("Contro1 returned an unreadable renewal")
	}
	if err := installOnecliLease(ctx, platforms.LocalConnection{PlatformSubject: l.Subject}, mcpURL(), next.Lease, run); err != nil {
		// The new lease exists but OneCLI does not hold it. The old one keeps
		// working through the overlap window. The replaced id can never be
		// renewed again, so record the new one with no expiry: the next run
		// sees it as due and hands it (renewed once more) to OneCLI.
		_ = recordNanoLease(nanoLease{Subject: l.Subject, LeaseID: next.LeaseID, Endpoint: l.Endpoint})
		return l, fmt.Errorf("renewed in Contro1 but OneCLI would not take the new credential: %w", err)
	}
	expires, err := time.Parse(time.RFC3339, next.ExpiresAt)
	if err != nil {
		expires = time.Time{}
	}
	renewed := nanoLease{Subject: l.Subject, LeaseID: next.LeaseID, ExpiresAt: expires, Endpoint: l.Endpoint}
	if err := recordNanoLease(renewed); err != nil {
		return renewed, fmt.Errorf("renewed, but could not record it locally: %w", err)
	}
	return renewed, nil
}

// ensureRenewalSchedule adds one crontab line that runs the renewal every six
// hours. Idempotent, and never touches the person's other entries. Returns a
// human-readable reason when it could not, so the caller can say what to do.
func ensureRenewalSchedule(ctx context.Context) (bool, string) {
	if _, err := exec.LookPath("crontab"); err != nil {
		return false, "crontab is not installed on this computer"
	}
	bin, err := os.Executable()
	if err != nil {
		return false, "could not resolve the contro1 binary path"
	}
	if resolved, err := filepath.EvalSymlinks(bin); err == nil {
		bin = resolved
	}
	current, _ := exec.CommandContext(ctx, "crontab", "-l").Output()
	if strings.Contains(string(current), renewCronMarker) {
		return true, ""
	}
	line := fmt.Sprintf("17 */6 * * * %s apps renew-nanoclaw --quiet >/dev/null 2>&1 %s", shellQuote(bin), renewCronMarker)
	next := strings.TrimRight(string(current), "\n")
	if next != "" {
		next += "\n"
	}
	next += line + "\n"
	cmd := exec.CommandContext(ctx, "crontab", "-")
	cmd.Stdin = strings.NewReader(next)
	if err := cmd.Run(); err != nil {
		return false, "crontab refused the entry"
	}
	return true, ""
}

func shellQuote(s string) string {
	if !strings.ContainsAny(s, " '\"$`\\") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// afterNanoLeaseInstalled records the lease and makes sure something renews
// it. Neither failure undoes the setup; both are said out loud.
func afterNanoLeaseInstalled(ctx context.Context, l nanoLease, progress func(string)) {
	if err := recordNanoLease(l); err != nil {
		progress("Warning: could not record the credential for renewal (" + err.Error() + "). It will stop working when it expires.")
		return
	}
	if ok, reason := ensureRenewalSchedule(ctx); !ok {
		progress("Warning: " + reason + ", so nothing will renew this credential automatically. Run `contro1 apps renew-nanoclaw` at least weekly, or schedule it.")
		return
	}
	progress("The credential renews itself: checked every 6 hours, renewed a week before it expires.")
}
