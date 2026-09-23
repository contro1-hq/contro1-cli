// Package mcpbridge connects stdio-only MCP clients to Contro1's authoritative
// remote MCP server. It stores only OAuth credentials; policy, grants and tool
// execution always remain on the server.
package mcpbridge

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/contro1-hq/contro1-cli/internal/keychain"
	"github.com/pkg/browser"
)

const defaultScopes = "mcp:whoami mcp:skills:read mcp:actions:read mcp:actions:preview mcp:capabilities:request mcp:agents:register"

func resourceURL(apiURL string) string {
	return strings.TrimRight(apiURL, "/") + "/api/centcom/mcp"
}

type Credentials struct {
	ClientID     string `json:"client_id"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	ExpiresAt    int64  `json:"expires_at"`
}

func storageProfile(profile string) string { return "mcp:" + profile }

func Store(profile string, credentials Credentials) error {
	raw, err := json.Marshal(credentials)
	if err != nil {
		return err
	}
	return keychain.Store(storageProfile(profile), string(raw), false)
}

func Load(profile string) (*Credentials, error) {
	raw, err := keychain.Retrieve(storageProfile(profile))
	if err != nil {
		return nil, fmt.Errorf("no MCP login for this profile; run 'contro1 mcp login'")
	}
	var credentials Credentials
	if err := json.Unmarshal([]byte(raw), &credentials); err != nil {
		return nil, fmt.Errorf("stored MCP credentials are invalid")
	}
	return &credentials, nil
}

func postJSON(endpoint string, payload any, out any) error {
	raw, _ := json.Marshal(payload)
	response, err := (&http.Client{Timeout: 30 * time.Second}).Post(endpoint, "application/json", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("OAuth endpoint returned %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	return json.NewDecoder(response.Body).Decode(out)
}

func exchange(apiURL string, form url.Values) (*Credentials, error) {
	request, _ := http.NewRequest(http.MethodPost, strings.TrimRight(apiURL, "/")+"/api/centcom/mcp/oauth/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := (&http.Client{Timeout: 30 * time.Second}).Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	var result struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		Scope        string `json:"scope"`
		Error        string `json:"error"`
		Description  string `json:"error_description"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("%s", first(result.Description, result.Error, "token exchange failed"))
	}
	return &Credentials{AccessToken: result.AccessToken, RefreshToken: result.RefreshToken, Scope: result.Scope, ExpiresAt: time.Now().Add(time.Duration(result.ExpiresIn) * time.Second).Unix()}, nil
}

const deviceCodeGrant = "urn:ietf:params:oauth:grant-type:device_code"

// ExecuteScope lets the connection run Actions with the approving person's own
// authority. It is never in the default set: the person asks for it by name.
const ExecuteScope = "mcp:actions:execute"

// minPollInterval is RFC 8628's default of five seconds. A variable only so a
// test does not have to wait for it.
var minPollInterval = 5 * time.Second

// openURL is swapped in tests so they do not open a real browser.
var openURL = browser.OpenURL

// Login connects with the device grant (RFC 8628). It used to open a loopback
// listener and register a 127.0.0.1 redirect, which the server refuses: a code
// sent to loopback only reaches the machine that opened the link, and the
// person approving is often holding a phone. The device grant needs no
// redirect, so the approval can happen on any device.
func Login(apiURL, profile, clientName string, execute bool) (*Credentials, error) {
	credentials, err := deviceLogin(apiURL, clientName, execute)
	if err != nil {
		return nil, err
	}
	if err := Store(profile, *credentials); err != nil {
		return nil, err
	}
	return credentials, nil
}

func deviceLogin(apiURL, clientName string, execute bool) (*Credentials, error) {
	base := strings.TrimRight(apiURL, "/")
	scope := defaultScopes
	if execute {
		scope += " " + ExecuteScope
	}
	var registered struct {
		ClientID string `json:"client_id"`
	}
	if err := postJSON(base+"/api/centcom/mcp/oauth/register", map[string]any{
		"client_name": clientName, "grant_types": []string{deviceCodeGrant, "refresh_token"}, "scope": scope,
	}, &registered); err != nil {
		return nil, fmt.Errorf("dynamic client registration: %w", err)
	}

	var started struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int64  `json:"expires_in"`
		Interval                int64  `json:"interval"`
	}
	if err := postForm(base+"/api/centcom/mcp/oauth/device_authorization", url.Values{
		"client_id": {registered.ClientID}, "scope": {scope}, "resource": {resourceURL(apiURL)},
	}, &started); err != nil {
		return nil, fmt.Errorf("starting device authorization: %w", err)
	}

	// The code and the address are printed separately, because typing the code
	// on another device is the path that always works.
	fmt.Fprintln(os.Stderr, "To connect, open this address on any device and approve:")
	fmt.Fprintln(os.Stderr, "  "+started.VerificationURI)
	fmt.Fprintln(os.Stderr, "and enter the code:  "+started.UserCode)
	if started.VerificationURIComplete != "" {
		_ = openURL(started.VerificationURIComplete)
	}

	interval := max(time.Duration(started.Interval)*time.Second, minPollInterval)
	deadline := time.Now().Add(time.Duration(max(started.ExpiresIn, 60)) * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(interval)
		credentials, oauthError, err := exchangeDevice(apiURL, url.Values{
			"grant_type": {deviceCodeGrant}, "device_code": {started.DeviceCode}, "client_id": {registered.ClientID},
		})
		switch {
		case err != nil:
			return nil, err
		case oauthError == "authorization_pending":
			continue
		case oauthError == "slow_down":
			interval += minPollInterval
			continue
		case oauthError == "access_denied":
			return nil, fmt.Errorf("the connection was declined in Contro1")
		case oauthError == "expired_token":
			return nil, fmt.Errorf("the code expired before it was approved; run 'contro1 mcp login' again")
		case oauthError != "":
			return nil, fmt.Errorf("device authorization failed: %s", oauthError)
		}
		credentials.ClientID = registered.ClientID
		return credentials, nil
	}
	return nil, fmt.Errorf("the code expired before it was approved; run 'contro1 mcp login' again")
}

func postForm(endpoint string, form url.Values, out any) error {
	response, err := (&http.Client{Timeout: 30 * time.Second}).PostForm(endpoint, form)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("OAuth endpoint returned %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	return json.NewDecoder(response.Body).Decode(out)
}

// exchangeDevice polls the token endpoint once. A pending or slowed-down poll
// is not an error: it comes back as the OAuth error code for the caller to
// branch on, and only a transport or decoding failure is returned as err.
func exchangeDevice(apiURL string, form url.Values) (*Credentials, string, error) {
	response, err := (&http.Client{Timeout: 30 * time.Second}).PostForm(strings.TrimRight(apiURL, "/")+"/api/centcom/mcp/oauth/token", form)
	if err != nil {
		return nil, "", err
	}
	defer response.Body.Close()
	var result struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		Scope        string `json:"scope"`
		Error        string `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return nil, "", fmt.Errorf("token endpoint returned %d with an unreadable body", response.StatusCode)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, first(result.Error, fmt.Sprintf("http_%d", response.StatusCode)), nil
	}
	return &Credentials{AccessToken: result.AccessToken, RefreshToken: result.RefreshToken, Scope: result.Scope, ExpiresAt: time.Now().Add(time.Duration(result.ExpiresIn) * time.Second).Unix()}, "", nil
}

func refresh(apiURL, profile string, credentials *Credentials) error {
	rotated, err := exchange(apiURL, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {credentials.RefreshToken}, "client_id": {credentials.ClientID}, "resource": {resourceURL(apiURL)}})
	if err != nil {
		return err
	}
	rotated.ClientID = credentials.ClientID
	*credentials = *rotated
	return Store(profile, *credentials)
}

func Logout(apiURL, profile string) error {
	credentials, err := Load(profile)
	if err != nil {
		return err
	}
	if err := revoke(apiURL, first(credentials.RefreshToken, credentials.AccessToken)); err != nil {
		return err
	}
	return keychain.Delete(storageProfile(profile))
}

func revoke(apiURL, token string) error {
	form := url.Values{"token": {token}}
	request, err := http.NewRequest(http.MethodPost, strings.TrimRight(apiURL, "/")+"/api/centcom/mcp/oauth/revoke", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := (&http.Client{Timeout: 15 * time.Second}).Do(request)
	if err != nil {
		return fmt.Errorf("revoking MCP credentials: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("revoking MCP credentials: server returned %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func Serve(apiURL, profile string, input io.Reader, output io.Writer) error {
	credentials, err := Load(profile)
	if err != nil {
		return err
	}
	return serveWithCredentials(apiURL, profile, credentials, input, output)
}

// serveWithCredentials is the transport seam used by Serve and its tests.
// Credential persistence remains outside the wire protocol; the local adapter
// forwards the remote server's JSON-RPC response without interpreting tools,
// grants or authorization results.
func serveWithCredentials(apiURL, profile string, credentials *Credentials, input io.Reader, output io.Writer) error {
	endpoint := strings.TrimRight(apiURL, "/") + "/api/centcom/mcp"
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	var writes sync.Mutex
	var credentialAccess sync.Mutex
	var workers sync.WaitGroup
	var firstWriteError error

	write := func(payload []byte) {
		if len(bytes.TrimSpace(payload)) == 0 {
			return
		}
		writes.Lock()
		defer writes.Unlock()
		if firstWriteError != nil {
			return
		}
		_, firstWriteError = output.Write(append(bytes.TrimSpace(payload), '\n'))
	}

	refreshIfNeeded := func(force bool) (string, error) {
		credentialAccess.Lock()
		defer credentialAccess.Unlock()
		if force || time.Now().Unix() >= credentials.ExpiresAt-30 {
			if err := refresh(apiURL, profile, credentials); err != nil {
				return "", err
			}
		}
		return credentials.AccessToken, nil
	}

	for scanner.Scan() {
		line := append([]byte(nil), bytes.TrimSpace(scanner.Bytes())...)
		if len(line) == 0 {
			continue
		}
		workers.Add(1)
		go func(line []byte) {
			defer workers.Done()
			accessToken, err := refreshIfNeeded(false)
			if err != nil {
				write(jsonRPCRelayError(line, -32001, "MCP authorization refresh failed"))
				return
			}
			body, status, err := relay(endpoint, line, accessToken)
			if err != nil {
				write(jsonRPCRelayError(line, -32000, "Remote MCP is unavailable"))
				return
			}
			if status == http.StatusUnauthorized {
				accessToken, err = refreshIfNeeded(true)
				if err != nil {
					write(jsonRPCRelayError(line, -32001, "MCP authorization refresh failed"))
					return
				}
				body, status, err = relay(endpoint, line, accessToken)
				if err != nil {
					write(jsonRPCRelayError(line, -32000, "Remote MCP is unavailable"))
					return
				}
			}
			if status < 200 || status >= 300 {
				write(jsonRPCRelayError(line, -32002, fmt.Sprintf("Remote MCP refused the request (HTTP %d)", status)))
				return
			}
			write(body)
		}(line)
	}
	workers.Wait()
	if err := scanner.Err(); err != nil {
		return err
	}
	return firstWriteError
}

func relay(endpoint string, line []byte, accessToken string) ([]byte, int, error) {
	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(line))
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+accessToken)
	response, err := (&http.Client{Timeout: 90 * time.Second}).Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	return body, response.StatusCode, err
}

func jsonRPCRelayError(line []byte, code int, message string) []byte {
	var request struct {
		ID *json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(line, &request); err != nil {
		return []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":null,"error":{"code":%d,"message":%q}}`, code, message))
	}
	// Notifications do not carry an id and must not receive a response.
	if request.ID == nil {
		return nil
	}
	return []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":%d,"message":%q}}`, *request.ID, code, message))
}

func first(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// ServeViaEndpoint forwards stdio JSON-RPC to an agent's Contro1 service
// endpoint (POST /mcp). The service adds the agent's credential; this process
// holds none and cannot choose an identity.
func ServeViaEndpoint(client *http.Client, baseURL string, input io.Reader, output io.Writer) error {
	endpoint := strings.TrimRight(baseURL, "/") + "/mcp"
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	var writes sync.Mutex
	var workers sync.WaitGroup
	var firstWriteError error
	write := func(payload []byte) {
		if len(bytes.TrimSpace(payload)) == 0 {
			return
		}
		writes.Lock()
		defer writes.Unlock()
		if firstWriteError != nil {
			return
		}
		_, firstWriteError = output.Write(append(bytes.TrimSpace(payload), '\n'))
	}
	for scanner.Scan() {
		line := append([]byte(nil), bytes.TrimSpace(scanner.Bytes())...)
		if len(line) == 0 {
			continue
		}
		workers.Add(1)
		go func(line []byte) {
			defer workers.Done()
			request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(line))
			if err != nil {
				write(jsonRPCRelayError(line, -32000, "invalid request"))
				return
			}
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Accept", "application/json")
			response, err := client.Do(request)
			if err != nil {
				write(jsonRPCRelayError(line, -32000, "The Contro1 service on this computer is not reachable; run contro1 doctor"))
				return
			}
			body, _ := io.ReadAll(io.LimitReader(response.Body, 8<<20))
			response.Body.Close()
			if response.StatusCode == http.StatusAccepted || len(bytes.TrimSpace(body)) == 0 {
				// A notification has no id and gets nothing back. A REQUEST
				// must be answered: returning silently left the client
				// waiting for an id that never came, which is how one of
				// three calls in a session simply vanished.
				write(jsonRPCRelayError(line, -32000, "Contro1 returned no answer to this request; try it again"))
				return
			}
			if response.StatusCode < 200 || response.StatusCode >= 300 {
				// A refusal from the service carries a remediation; pass the
				// message through so the agent can explain it.
				var parsed struct {
					Error struct {
						Message string `json:"message"`
					} `json:"error"`
				}
				_ = json.Unmarshal(body, &parsed)
				message := first(parsed.Error.Message, fmt.Sprintf("Contro1 refused the request (HTTP %d)", response.StatusCode))
				write(jsonRPCRelayError(line, -32002, message))
				return
			}
			write(body)
		}(line)
	}
	workers.Wait()
	if err := scanner.Err(); err != nil {
		return err
	}
	return firstWriteError
}
