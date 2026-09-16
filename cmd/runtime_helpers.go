package cmd

import (
	"os"
	"runtime"
	"strings"

	"github.com/contro1-hq/contro1-cli/internal/brokerpaths"
	"github.com/contro1-hq/contro1-cli/internal/client"
	"github.com/contro1-hq/contro1-cli/internal/config"
	"github.com/contro1-hq/contro1-cli/internal/localipc"
	"github.com/contro1-hq/contro1-cli/internal/output"
	"github.com/contro1-hq/contro1-cli/internal/runtimeproto"
)

const browserCliTokenPrefix = "cco_cli_"

// envToken returns the normal CLI environment token. It intentionally ignores
// CONTRO1_AGENT_TOKEN_FILE and CONTRO1_AGENT_TOKEN; those are runtime-only and
// must not silently change the identity used by interactive commands.
func envToken() (string, string, error) {
	if token := strings.TrimSpace(os.Getenv("CONTRO1_TOKEN")); token != "" {
		return token, "CONTRO1_TOKEN", nil
	}
	return "", "", nil
}

// runtimeEnvToken returns a token supplied through the runtime environment, and
// which variable it came from. Order: CONTRO1_AGENT_TOKEN_FILE,
// CONTRO1_AGENT_TOKEN, CONTRO1_TOKEN. It returns an empty token (and no error)
// when none is set.
//
// The two AGENT variables promise an Agent Credential by name, so a browser-issued
// cco_cli_ token in them is refused outright rather than silently used.
// CONTRO1_TOKEN keeps its original meaning: any token, for agent/CI use.
func runtimeEnvToken() (string, string, error) {
	if path := strings.TrimSpace(os.Getenv("CONTRO1_AGENT_TOKEN_FILE")); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return "", "", output.Errf(output.CodeAuth, "reading CONTRO1_AGENT_TOKEN_FILE: %v", err)
		}
		token := strings.TrimSpace(string(raw))
		if token == "" {
			return "", "", output.Errf(output.CodeAuth, "CONTRO1_AGENT_TOKEN_FILE is empty")
		}
		if strings.HasPrefix(token, browserCliTokenPrefix) {
			return "", "", output.Errf(output.CodeUnsafeBlocked, "CONTRO1_AGENT_TOKEN_FILE holds a browser-issued CLI token; it must hold an Agent Credential")
		}
		return token, "CONTRO1_AGENT_TOKEN_FILE", nil
	}
	if token := strings.TrimSpace(os.Getenv("CONTRO1_AGENT_TOKEN")); token != "" {
		if strings.HasPrefix(token, browserCliTokenPrefix) {
			return "", "", output.Errf(output.CodeUnsafeBlocked, "CONTRO1_AGENT_TOKEN holds a browser-issued CLI token; it must hold an Agent Credential")
		}
		return token, "CONTRO1_AGENT_TOKEN", nil
	}
	if token := strings.TrimSpace(os.Getenv("CONTRO1_TOKEN")); token != "" {
		return token, "CONTRO1_TOKEN", nil
	}
	return "", "", nil
}

// anyEnvTokenConfigured reports whether any env token source is set, valid or
// not. It is used by operator-mode guards.
func anyEnvTokenConfigured() bool {
	for _, name := range []string{"CONTRO1_AGENT_TOKEN_FILE", "CONTRO1_AGENT_TOKEN", "CONTRO1_TOKEN"} {
		if strings.TrimSpace(os.Getenv(name)) != "" {
			return true
		}
	}
	return false
}

// resolveRuntimeToken is the token for runtime-only commands. It never falls back
// to the keychain, and never accepts a browser-issued token from any source: a
// token minted by clicking a link must not be able to execute an Action.
func resolveRuntimeToken() (string, string, error) {
	token, source, err := runtimeEnvToken()
	if err != nil {
		return "", "", err
	}
	if token == "" {
		return "", "", output.Errf(output.CodeAuth, "runtime commands require CONTRO1_AGENT_TOKEN_FILE, CONTRO1_AGENT_TOKEN or CONTRO1_TOKEN holding an Agent Credential; the keychain login is never used")
	}
	if strings.HasPrefix(token, browserCliTokenPrefix) {
		return "", "", output.Errf(output.CodeUnsafeBlocked, "runtime commands require an Agent Credential, not a browser-issued CLI token")
	}
	return token, source, nil
}

// flagBrokerEndpoint selects the Contro1 service's local endpoint for this
// agent. It is exclusive with every token variable: one process, one identity.
var flagBrokerEndpoint string

func resolveBrokerEndpoint() string {
	if flagBrokerEndpoint != "" {
		return strings.TrimSpace(flagBrokerEndpoint)
	}
	return strings.TrimSpace(os.Getenv("CONTRO1_BROKER_ENDPOINT"))
}

// brokerServerPrincipal is the identity the endpoint's server must run as.
// CONTRO1_BROKER_PRINCIPAL overrides (development brokers run as a user);
// otherwise the production service identity on Windows. On unix the socket
// directory is owned by the service user, so squatting needs privileges the
// caller does not have; the peer check still runs when a principal is set.
func brokerServerPrincipal() localipc.Principal {
	if p := strings.TrimSpace(os.Getenv("CONTRO1_BROKER_PRINCIPAL")); p != "" {
		return localipc.Principal(p)
	}
	if runtime.GOOS == "windows" {
		return localipc.Principal(brokerpaths.WindowsServiceSID(brokerpaths.ServiceName))
	}
	return ""
}

var twoIdentitiesRemediation = runtimeproto.Remediation{
	Code:          "TWO_RUNTIME_IDENTITIES_CONFIGURED",
	PublicMessage: "This process is configured with both a Contro1 service endpoint and a token.",
	Missing:       "Exactly one runtime identity per process.",
	NextStep:      "Remove CONTRO1_AGENT_TOKEN_FILE, CONTRO1_AGENT_TOKEN and CONTRO1_TOKEN from this agent's environment.",
}

var brokerUnreachableRemediation = runtimeproto.Remediation{
	Code:          "BROKER_UNREACHABLE",
	PublicMessage: "The Contro1 service on this computer is not reachable.",
	Missing:       "A running Contro1 service with this agent's endpoint.",
	NextStep:      "Run contro1 doctor on this computer.",
	Retryable:     true,
}

func newRuntimeClient() (*client.Client, *config.Profile, string, error) {
	if raw := resolveBrokerEndpoint(); raw != "" {
		if anyEnvTokenConfigured() {
			return nil, nil, "", output.Errf(output.CodeUnsafeBlocked, "a Contro1 service endpoint and a runtime token are both configured").WithRemediation(&twoIdentitiesRemediation)
		}
		ep, err := localipc.ParseEndpoint(raw)
		if err != nil {
			return nil, nil, "", output.Errf(output.CodeBadArgs, "%v", err)
		}
		pr := &config.Profile{APIURL: localipc.BaseURL}
		c := client.NewWithHTTPClient(localipc.BaseURL, "", userAgent(), localipc.HTTPClient(ep, brokerServerPrincipal()))
		c.NetworkRemediation = &brokerUnreachableRemediation
		return c, pr, "broker_endpoint", nil
	}
	_, pr, _, err := loadCtx()
	if err != nil {
		return nil, nil, "", err
	}
	apiURL := pr.APIURL
	if flagAPIURL != "" {
		apiURL = flagAPIURL
	}
	token, source, err := resolveRuntimeToken()
	if err != nil {
		return nil, nil, "", err
	}
	return client.New(apiURL, token, userAgent()), pr, source, nil
}

// requireRuntimeStatus confirms the credential is an agent-bound runtime
// credential carrying the scopes a command needs. This is an early, readable
// refusal only: the server enforces scopes, grants and agent binding regardless.
func requireRuntimeStatus(c *client.Client, requiredScopes ...string) (map[string]any, error) {
	resp, err := c.Do("GET", "/api/centcom/v1/runtime/status", nil)
	if err != nil {
		return nil, err
	}
	if err := checkRuntimeAuth(asMap(resp["auth"]), requiredScopes...); err != nil {
		return nil, err
	}
	return resp, nil
}

func checkRuntimeAuth(auth map[string]any, requiredScopes ...string) error {
	if str(auth["credential_kind"]) != "agent_runtime" {
		return output.Errf(output.CodeUnsafeBlocked, "runtime commands require an agent_runtime credential (got %q)", str(auth["credential_kind"]))
	}
	if str(auth["agent_id"]) == "" {
		return output.Errf(output.CodeUnsafeBlocked, "runtime credential is not bound to an agent")
	}
	granted := map[string]bool{}
	for _, s := range asSlice(auth["scopes"]) {
		granted[str(s)] = true
	}
	for _, scope := range requiredScopes {
		if !granted[scope] {
			return output.Errf(output.CodeInsufficient, "runtime credential is missing required scope: %s", scope)
		}
	}
	return nil
}
