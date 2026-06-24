// Package auth implements the gcloud-style browser login (loopback + PKCE) and the
// token exchange against the Contro1 backend.
package auth

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
func Login(pr *config.Profile, deviceName, cliVersion string, noBrowser bool) (*TokenResult, error) {
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
		code, err = manualFlow(pr, challenge, state, deviceName)
	} else {
		code, err = loopbackFlow(pr, challenge, state, deviceName)
	}
	if err != nil {
		return nil, err
	}

	return exchange(pr, code, verifier, deviceName, cliVersion)
}

func loopbackFlow(pr *config.Profile, challenge, state, deviceName string) (string, error) {
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
			writeClosePage(w, "Authorization denied. You can close this window.")
			resultCh <- result{err: fmt.Errorf("authorization denied")}
			return
		}
		if q.Get("state") != state {
			writeClosePage(w, "State mismatch. You can close this window.")
			resultCh <- result{err: fmt.Errorf("state mismatch (possible CSRF)")}
			return
		}
		code := q.Get("code")
		if code == "" {
			writeClosePage(w, "Missing code. You can close this window.")
			resultCh <- result{err: fmt.Errorf("no authorization code returned")}
			return
		}
		writeClosePage(w, "You're signed in to the contro1 CLI. You can close this window.")
		resultCh <- result{code: code}
	})

	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	defer srv.Close()

	authURL := buildAuthorizeURL(pr.WebURL, challenge, state, deviceName, redirect, false)
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

func manualFlow(pr *config.Profile, challenge, state, deviceName string) (string, error) {
	authURL := buildAuthorizeURL(pr.WebURL, challenge, state, deviceName, "", true)
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

func buildAuthorizeURL(webURL, challenge, state, deviceName, redirect string, manual bool) string {
	u := strings.TrimRight(webURL, "/") + "/cli/authorize"
	q := url.Values{}
	q.Set("challenge", challenge)
	q.Set("state", state)
	q.Set("name", deviceName)
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
		OK    bool `json:"ok"`
		Data  struct {
			AccessToken string   `json:"access_token"`
			TokenID     string   `json:"token_id"`
			ExpiresAt   string   `json:"expires_at"`
			Scopes      []string `json:"scopes"`
			Operator    struct {
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
	}, nil
}

func writeClosePage(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8"><title>contro1 CLI</title></head>
<body style="font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#f7f7f8">
<div style="text-align:center"><div style="font-size:40px">&#9989;</div><p style="color:#111">%s</p></div>
</body></html>`, msg)
}
