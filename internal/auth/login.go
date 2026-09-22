// Package auth implements the gcloud-style browser login (loopback + PKCE) and the
// token exchange against the Contro1 backend.
package auth

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/contro1-hq/contro1-cli/internal/config"
	"github.com/pkg/browser"
)

// TokenResult is the outcome of a successful login.
type TokenResult struct {
	AccessToken   string
	TokenID       string
	OperatorEmail string
	OrgName       string
	Scopes        []string
	ExpiresAt     string
	AccessProfile string
}

func base64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64url(b), nil
}

func pkce() (verifier, challenge string, err error) {
	verifier, err = randomString(48)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64url(sum[:]), nil
}

// Login runs the full browser (or manual) login flow and returns a token.
func Login(pr *config.Profile, deviceName, cliVersion, accessProfile string, noBrowser bool) (*TokenResult, error) {
	verifier, challenge, err := pkce()
	if err != nil {
		return nil, err
	}
	state, err := randomString(16)
	if err != nil {
		return nil, err
	}

	var code string
	if noBrowser {
		code, err = manualFlow(pr, challenge, state, deviceName, accessProfile)
	} else {
		code, err = relayFlow(pr, challenge, state, deviceName, accessProfile)
	}
	if err != nil {
		return nil, err
	}

	return exchange(pr, code, verifier, deviceName, cliVersion)
}

// relayFlow lets the approval happen on any device. The CLI polls Contro1 over
// its already-outbound HTTPS connection, so no browser needs to reach a local
// port on this computer. The approval code is still useless without this
// process's PKCE verifier.
func relayFlow(pr *config.Profile, challenge, state, deviceName, accessProfile string) (string, error) {
	payload, _ := json.Marshal(map[string]string{
		"code_challenge": challenge,
		"name":           deviceName,
		"access_profile": accessProfile,
	})
	base := strings.TrimRight(pr.APIURL, "/") + "/api/centcom/auth/cli/relay"
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Post(base, "application/json", strings.NewReader(string(payload)))
	if err != nil {
		return "", fmt.Errorf("starting remote sign-in: %w", err)
	}
	defer resp.Body.Close()
	var created struct {
		OK   bool `json:"ok"`
		Data struct {
			RelayID string `json:"relay_id"`
		} `json:"data"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return "", fmt.Errorf("reading remote sign-in response: %w", err)
	}
	if resp.StatusCode != http.StatusCreated || !created.OK || created.Data.RelayID == "" {
		if created.Error.Message == "" {
			created.Error.Message = "could not start remote sign-in"
		}
		return "", errors.New(created.Error.Message)
	}

	u, err := url.Parse(buildAuthorizeURL(pr.WebURL, challenge, state, deviceName, accessProfile, "", true))
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("mode", "relay")
	q.Set("relay_id", created.Data.RelayID)
	u.RawQuery = q.Encode()
	authURL := u.String()
	fmt.Fprintln(os.Stderr, "Open this URL on any device to authorize the contro1 CLI:")
	fmt.Fprintln(os.Stderr, "  "+authURL)
	_ = browser.OpenURL(authURL)

	deadline := time.Now().Add(5 * time.Minute)
	for time.Now().Before(deadline) {
		time.Sleep(2 * time.Second)
		check, err := http.Get(base + "/" + url.PathEscape(created.Data.RelayID))
		if err != nil {
			continue
		}
		var status struct {
			OK   bool `json:"ok"`
			Data struct {
				State string `json:"state"`
				Code  string `json:"code"`
			} `json:"data"`
		}
		err = json.NewDecoder(check.Body).Decode(&status)
		check.Body.Close()
		if err != nil || !status.OK {
			continue
		}
		if status.Data.State == "approved" && status.Data.Code != "" {
			return status.Data.Code, nil
		}
		if status.Data.State == "denied" {
			return "", errors.New("authorization denied")
		}
	}
	return "", errors.New("timed out waiting for remote authorization")
}

func loopbackFlow(pr *config.Profile, challenge, state, deviceName, accessProfile string) (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("starting local server: %w", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	redirect := fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	type result struct {
		code string
		err  error
	}
	resultCh := make(chan result, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if e := q.Get("error"); e != "" {
			writeResultPage(w, pr.WebURL, resultPage{Title: "Sign-in was not completed", Body: "The request was declined, so the contro1 CLI on this computer is not signed in. Return to your terminal and run contro1 auth login again when you are ready."})
			resultCh <- result{err: fmt.Errorf("authorization denied")}
			return
		}
		if q.Get("state") != state {
			writeResultPage(w, pr.WebURL, resultPage{Title: "Sign-in was not completed", Body: "This sign-in link did not match the request your terminal started, so nothing was signed in. Run contro1 auth login again from your terminal."})
			resultCh <- result{err: fmt.Errorf("state mismatch (possible CSRF)")}
			return
		}
		code := q.Get("code")
		if code == "" {
			writeResultPage(w, pr.WebURL, resultPage{Title: "Sign-in was not completed", Body: "Contro1 did not return a sign-in code. Run contro1 auth login again from your terminal."})
			resultCh <- result{err: fmt.Errorf("no authorization code returned")}
			return
		}
		writeResultPage(w, pr.WebURL, resultPage{OK: true, Title: "You're signed in", Body: "The contro1 CLI on this computer is signed in to your Contro1 organization. Return to your terminal to continue, or open your dashboard."})
		resultCh <- result{code: code}
	})

	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	defer srv.Close()

	authURL := buildAuthorizeURL(pr.WebURL, challenge, state, deviceName, accessProfile, redirect, false)
	fmt.Fprintln(os.Stderr, "Opening your browser to authorize the contro1 CLI...")
	fmt.Fprintln(os.Stderr, "If it does not open, visit:\n  "+authURL)
	_ = browser.OpenURL(authURL)

	select {
	case res := <-resultCh:
		return res.code, res.err
	case <-time.After(5 * time.Minute):
		return "", fmt.Errorf("timed out waiting for browser authorization")
	}
}

func manualFlow(pr *config.Profile, challenge, state, deviceName, accessProfile string) (string, error) {
	authURL := buildAuthorizeURL(pr.WebURL, challenge, state, deviceName, accessProfile, "", true)
	fmt.Fprintln(os.Stderr, "Open this URL in any browser, approve, then paste the code below:")
	fmt.Fprintln(os.Stderr, "  "+authURL)
	fmt.Fprint(os.Stderr, "\nEnter code: ")
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	code := strings.TrimSpace(line)
	if code == "" {
		return "", fmt.Errorf("no code entered")
	}
	return code, nil
}

func buildAuthorizeURL(webURL, challenge, state, deviceName, accessProfile, redirect string, manual bool) string {
	u := strings.TrimRight(webURL, "/") + "/cli/authorize"
	q := url.Values{}
	q.Set("challenge", challenge)
	q.Set("state", state)
	q.Set("name", deviceName)
	q.Set("access_profile", accessProfile)
	if manual {
		q.Set("mode", "manual")
	} else {
		q.Set("redirect", redirect)
	}
	return u + "?" + q.Encode()
}

func exchange(pr *config.Profile, code, verifier, deviceName, cliVersion string) (*TokenResult, error) {
	hostname, _ := os.Hostname()
	payload := map[string]any{
		"code":          code,
		"code_verifier": verifier,
		"hostname":      hostname,
		"os":            runtime.GOOS,
		"cli_version":   cliVersion,
	}
	buf, _ := json.Marshal(payload)
	endpoint := strings.TrimRight(pr.APIURL, "/") + "/api/centcom/auth/cli/token"

	httpClient := &http.Client{Timeout: 30 * time.Second}
	resp, err := httpClient.Post(endpoint, "application/json", strings.NewReader(string(buf)))
	if err != nil {
		return nil, fmt.Errorf("network error during token exchange: %w", err)
	}
	defer resp.Body.Close()

	var body struct {
		OK   bool `json:"ok"`
		Data struct {
			AccessToken   string   `json:"access_token"`
			TokenID       string   `json:"token_id"`
			ExpiresAt     string   `json:"expires_at"`
			Scopes        []string `json:"scopes"`
			AccessProfile string   `json:"access_profile"`
			Operator      struct {
				Email       string `json:"email"`
				DisplayName string `json:"display_name"`
			} `json:"operator"`
			Org struct {
				Name string `json:"name"`
			} `json:"org"`
		} `json:"data"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decoding token response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || !body.OK {
		msg := body.Error.Message
		if msg == "" {
			msg = "token exchange failed"
		}
		return nil, fmt.Errorf("%s", msg)
	}

	return &TokenResult{
		AccessToken:   body.Data.AccessToken,
		TokenID:       body.Data.TokenID,
		OperatorEmail: body.Data.Operator.Email,
		OrgName:       body.Data.Org.Name,
		Scopes:        body.Data.Scopes,
		ExpiresAt:     body.Data.ExpiresAt,
		AccessProfile: body.Data.AccessProfile,
	}, nil
}

type resultPage struct {
	OK        bool
	Title     string
	Body      string
	Dashboard string
	Logo      template.HTML
}

//go:embed contro1-logo.svg
var contro1Logo string

// The page a browser lands on after contro1 auth login. It is the first thing a
// person sees of Contro1 from the CLI, so it looks like Contro1: the logo, the
// brand colors, a plain sentence about what happened, and a way to the dashboard.
var resultPageTemplate = template.Must(template.New("result").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}} | Contro1</title>
<style>
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;background:#f6f6f7;
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;color:#374151}
  .wrap{width:100%;max-width:440px;text-align:center}
  .logo svg{width:148px;height:auto;display:block;margin:0 auto 28px}
  .card{background:#fff;border-radius:16px;padding:40px 36px 32px;box-shadow:0 1px 2px rgba(12,0,74,.06),0 12px 32px rgba(12,0,74,.08)}
  .badge{width:56px;height:56px;border-radius:50%;margin:0 auto 20px;display:flex;align-items:center;justify-content:center}
  .ok{background:rgba(96,70,215,.1);color:#6046d7}
  .err{background:#fef2f2;color:#b91c1c}
  h1{margin:0 0 10px;font-size:22px;line-height:30px;font-weight:700;letter-spacing:-.01em;color:#0c004a}
  p{margin:0;font-size:15px;line-height:24px}
  .btn{display:inline-block;margin-top:28px;padding:12px 28px;border-radius:999px;background:#0c004a;color:#fff;
    font-size:15px;font-weight:600;text-decoration:none}
  .btn:hover{background:#6046d7}
  .foot{margin-top:18px;font-size:13px;color:#9ca3af}
</style></head>
<body><div class="wrap">
  <div class="logo">{{.Logo}}</div>
  <div class="card">
    {{if .OK}}<div class="badge ok"><svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg></div>
    {{else}}<div class="badge err"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><path d="M12 8v5M12 16.5v.01"/></svg></div>{{end}}
    <h1>{{.Title}}</h1>
    <p>{{.Body}}</p>
    {{if .Dashboard}}<a class="btn" href="{{.Dashboard}}">Go to dashboard</a>{{end}}
  </div>
  <p class="foot">You can close this tab.</p>
</div></body></html>`))

func writeResultPage(w http.ResponseWriter, webURL string, page resultPage) {
	page.Logo = template.HTML(contro1Logo)
	if u, err := url.Parse(strings.TrimRight(webURL, "/")); err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" {
		page.Dashboard = u.String() + "/centcom"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = resultPageTemplate.Execute(w, page)
}
